# crowdsec_bouncer.py
"""Minimal CrowdSec bouncer client.

Polls a CrowdSec Local API (LAPI) decisions stream and keeps an in-memory
cache of banned IPs/ranges that the app middleware can check synchronously
on every request. Disabled (no-op) unless CROWDSEC_LAPI_URL and
CROWDSEC_BOUNCER_KEY are both set.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Union

import aiohttp
from prometheus_client import Counter, Gauge

import db

log = logging.getLogger("app.crowdsec")

CROWDSEC_LAPI_URL = (os.getenv("CROWDSEC_LAPI_URL") or "").strip().rstrip("/")
CROWDSEC_BOUNCER_KEY = (os.getenv("CROWDSEC_BOUNCER_KEY") or "").strip()
CROWDSEC_POLL_INTERVAL_SEC = max(5, int(os.getenv("CROWDSEC_POLL_INTERVAL_SEC", "15")))

# Bouncer keys can only *read* decisions. Removing one (e.g. to clear a false positive)
# requires a CrowdSec "machine" credential instead (`cscli machines add <name> --auto`
# on the CrowdSec host), used to obtain a short-lived JWT for the decisions-delete API.
CROWDSEC_MACHINE_ID = (os.getenv("CROWDSEC_MACHINE_ID") or "").strip()
CROWDSEC_MACHINE_PASSWORD = (os.getenv("CROWDSEC_MACHINE_PASSWORD") or "").strip()

ENABLED = bool(CROWDSEC_LAPI_URL and CROWDSEC_BOUNCER_KEY)
UNBAN_ENABLED = bool(ENABLED and CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD)

_machine_jwt: Optional[str] = None
_machine_jwt_expiry: Optional[datetime] = None

_METRIC_BLOCKED_TOTAL = Counter(
    "antiscammer_crowdsec_blocked_total",
    "Requests rejected because CrowdSec flagged the client IP",
)
_METRIC_POLL_FAILURES_TOTAL = Counter(
    "antiscammer_crowdsec_poll_failures_total",
    "Failed attempts to refresh decisions from the CrowdSec LAPI",
)
_METRIC_BANNED_IPS = Gauge(
    "antiscammer_crowdsec_banned_entries",
    "Number of IP/range decisions currently cached from CrowdSec",
)

_banned_ips: Set[str] = set()
_banned_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
_stream_started = False

# Decisions made by hand (cscli or the admin panel) rather than by a detection scenario.
# These don't apply to /admin, so a mistaken manual ban can't lock admins out.
MANUAL_ORIGINS = {"cscli"}
_manual_values: Set[str] = set()


def record_block() -> None:
    _METRIC_BLOCKED_TOTAL.inc()


def ban_kind(ip: str) -> Optional[str]:
    """"auto" if any scenario-driven decision covers ip, "manual" if only manual
    decisions do, None if it isn't banned."""
    if not ENABLED or not ip:
        return None
    matches: List[str] = []
    if ip in _banned_ips:
        matches.append(ip)
    if _banned_networks:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None:
            matches.extend(str(net) for net in _banned_networks if addr in net)
    if not matches:
        return None
    return "manual" if all(m in _manual_values for m in matches) else "auto"


def is_banned(ip: str) -> bool:
    return ban_kind(ip) is not None


def _decision_key(value: str) -> str:
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    return value


def _parse_until(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.strip()
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        return datetime.fromisoformat(v)
    except Exception:
        return None


async def _apply_decisions(new: Optional[list], deleted: Optional[list], full_sync: bool) -> None:
    global _banned_networks
    deleted_values: List[str] = []
    for item in deleted or []:
        value = item.get("value")
        if not value:
            continue
        deleted_values.append(value)
        _manual_values.discard(_decision_key(value))
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            _banned_networks = [n for n in _banned_networks if n != net]
        else:
            _banned_ips.discard(value)

    upsert_entries: List[Dict[str, Any]] = []
    for item in new or []:
        if (item.get("type") or "ban").lower() != "ban":
            continue
        value = item.get("value")
        if not value:
            continue
        if "/" in value:
            try:
                _banned_networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                continue
        else:
            _banned_ips.add(value)
        if (item.get("origin") or "").lower() in MANUAL_ORIGINS:
            _manual_values.add(_decision_key(value))
        else:
            _manual_values.discard(_decision_key(value))
        upsert_entries.append({
            "value": value,
            "scope": item.get("scope") or "Ip",
            "decision_type": item.get("type") or "ban",
            "scenario": item.get("scenario"),
            "origin": item.get("origin"),
            "duration": item.get("duration"),
            "decision_id": item.get("id"),
            "until_at": _parse_until(item.get("until")),
        })

    _METRIC_BANNED_IPS.set(len(_banned_ips) + len(_banned_networks))

    try:
        if full_sync:
            await db.crowdsec_bans_replace_all(upsert_entries)
        else:
            await db.crowdsec_bans_upsert_many(upsert_entries)
            await db.crowdsec_bans_delete_many(deleted_values)
    except Exception:
        log.exception("Failed to persist CrowdSec decisions to DB")


async def get_banned_entries() -> List[Dict[str, Any]]:
    """Currently-active mirrored decisions (for the admin panel), newest-seen first."""
    return await db.crowdsec_bans_get_all()


class CrowdsecWriteError(Exception):
    """Raised when a CrowdSec decision couldn't be added or removed upstream."""


async def _get_machine_token(session: aiohttp.ClientSession) -> str:
    global _machine_jwt, _machine_jwt_expiry
    now = datetime.now(timezone.utc)
    if _machine_jwt and _machine_jwt_expiry and now < _machine_jwt_expiry:
        return _machine_jwt

    url = f"{CROWDSEC_LAPI_URL}/v1/watchers/login"
    try:
        async with session.post(
            url, json={"machine_id": CROWDSEC_MACHINE_ID, "password": CROWDSEC_MACHINE_PASSWORD},
        ) as resp:
            if resp.status != 200:
                raise CrowdsecWriteError(f"CrowdSec machine login failed (HTTP {resp.status})")
            data = await resp.json(content_type=None)
    except aiohttp.ClientError as e:
        raise CrowdsecWriteError(f"CrowdSec machine login failed: {e}")

    token = data.get("token")
    if not token:
        raise CrowdsecWriteError("CrowdSec machine login response missing token")
    _machine_jwt = token
    # Refresh a bit early rather than trusting the server's "expire" down to the second.
    _machine_jwt_expiry = now + timedelta(hours=1) - timedelta(minutes=5)
    return token


_WRITE_NOT_CONFIGURED = (
    "set CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD "
    "(create one with `cscli machines add <name> --auto` on the CrowdSec host)"
)


async def ban(session: aiohttp.ClientSession, value: str, duration: str, reason: str) -> None:
    """Add a manual ban decision to CrowdSec (via the alerts API, like `cscli decisions add`),
    so it is enforced everywhere CrowdSec is, and apply it locally right away."""
    if not UNBAN_ENABLED:
        raise CrowdsecWriteError("Manual ban is not configured: " + _WRITE_NOT_CONFIGURED)

    net = ipaddress.ip_network(value, strict=False)
    is_range = "/" in value
    scope = "Range" if is_range else "Ip"
    value = str(net) if is_range else str(net.network_address)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    scenario = f"manual 'ban' from admin panel: {reason}" if reason else "manual 'ban' from admin panel"
    alert = {
        "scenario": scenario,
        "scenario_hash": "",
        "scenario_version": "",
        "message": scenario,
        "events_count": 1,
        "events": [],
        "start_at": now,
        "stop_at": now,
        "capacity": 0,
        "leakspeed": "0",
        "simulated": False,
        "remediation": True,
        "source": {"scope": scope, "value": value, "ip": "" if is_range else value, "range": value if is_range else ""},
        "decisions": [{
            "duration": duration,
            "origin": "cscli",
            "scenario": scenario,
            "scope": scope,
            "type": "ban",
            "value": value,
        }],
    }

    token = await _get_machine_token(session)
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with session.post(f"{CROWDSEC_LAPI_URL}/v1/alerts", headers=headers, json=[alert]) as resp:
            if resp.status not in (200, 201):
                body = await resp.text()
                raise CrowdsecWriteError(f"CrowdSec refused to add decision (HTTP {resp.status}): {body[:300]}")
    except aiohttp.ClientError as e:
        raise CrowdsecWriteError(f"CrowdSec alerts create failed: {e}")

    # Enforce immediately; the next poll delta will fill in decision_id/until from LAPI.
    await _apply_decisions(
        [{"value": value, "scope": scope, "type": "ban", "scenario": scenario, "origin": "cscli", "duration": duration}],
        None,
        False,
    )


async def unban(session: aiohttp.ClientSession, value: str) -> None:
    """Remove a decision from CrowdSec itself (not just our local mirror), so it doesn't
    reappear on the next poll. Requires CROWDSEC_MACHINE_ID/CROWDSEC_MACHINE_PASSWORD —
    bouncer keys are read-only for decisions."""
    if not UNBAN_ENABLED:
        raise CrowdsecWriteError("Unban is not configured: " + _WRITE_NOT_CONFIGURED)

    ban = await db.crowdsec_ban_get(value)
    token = await _get_machine_token(session)
    headers = {"Authorization": f"Bearer {token}"}

    if ban and ban.get("decision_id"):
        url = f"{CROWDSEC_LAPI_URL}/v1/decisions/{ban['decision_id']}"
        params = None
    else:
        scope = (ban or {}).get("scope") or "Ip"
        param = "range" if scope.lower() == "range" else "ip"
        url = f"{CROWDSEC_LAPI_URL}/v1/decisions"
        params = {param: value}

    try:
        async with session.delete(url, headers=headers, params=params) as resp:
            if resp.status not in (200, 404):
                body = await resp.text()
                raise CrowdsecWriteError(f"CrowdSec refused to delete decision (HTTP {resp.status}): {body[:300]}")
    except aiohttp.ClientError as e:
        raise CrowdsecWriteError(f"CrowdSec decisions delete failed: {e}")

    # Drop it locally right away instead of waiting for the next poll's delta.
    global _banned_networks
    _banned_ips.discard(value)
    _manual_values.discard(_decision_key(value))
    try:
        net = ipaddress.ip_network(value, strict=False)
        _banned_networks = [n for n in _banned_networks if n != net]
    except ValueError:
        pass
    await db.crowdsec_bans_delete_many([value])


async def poll_loop(session: aiohttp.ClientSession) -> None:
    if not ENABLED:
        log.info("CrowdSec bouncer disabled (CROWDSEC_LAPI_URL / CROWDSEC_BOUNCER_KEY not set)")
        return

    global _stream_started
    headers = {"X-Api-Key": CROWDSEC_BOUNCER_KEY}
    url = f"{CROWDSEC_LAPI_URL}/v1/decisions/stream"

    while True:
        try:
            full_sync = not _stream_started
            params = {"startup": "false" if _stream_started else "true"}
            async with session.get(url, headers=headers, params=params) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"LAPI returned {resp.status}")
                data = await resp.json(content_type=None)
                await _apply_decisions(data.get("new"), data.get("deleted"), full_sync)
                if not _stream_started:
                    log.info("CrowdSec bouncer stream started")
                _stream_started = True
        except asyncio.CancelledError:
            raise
        except Exception as e:
            _METRIC_POLL_FAILURES_TOTAL.inc()
            log.warning("CrowdSec LAPI poll failed: %s", e)
        await asyncio.sleep(CROWDSEC_POLL_INTERVAL_SEC)
