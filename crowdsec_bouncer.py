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
from typing import List, Optional, Set, Union

import aiohttp
from prometheus_client import Counter, Gauge

log = logging.getLogger("app.crowdsec")

CROWDSEC_LAPI_URL = (os.getenv("CROWDSEC_LAPI_URL") or "").strip().rstrip("/")
CROWDSEC_BOUNCER_KEY = (os.getenv("CROWDSEC_BOUNCER_KEY") or "").strip()
CROWDSEC_POLL_INTERVAL_SEC = max(5, int(os.getenv("CROWDSEC_POLL_INTERVAL_SEC", "15")))

ENABLED = bool(CROWDSEC_LAPI_URL and CROWDSEC_BOUNCER_KEY)

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


def record_block() -> None:
    _METRIC_BLOCKED_TOTAL.inc()


def is_banned(ip: str) -> bool:
    if not ENABLED or not ip:
        return False
    if ip in _banned_ips:
        return True
    if not _banned_networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _banned_networks)


def _apply_decisions(new: Optional[list], deleted: Optional[list]) -> None:
    global _banned_networks
    for item in deleted or []:
        value = item.get("value")
        if not value:
            continue
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            _banned_networks = [n for n in _banned_networks if n != net]
        else:
            _banned_ips.discard(value)

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

    _METRIC_BANNED_IPS.set(len(_banned_ips) + len(_banned_networks))


async def poll_loop(session: aiohttp.ClientSession) -> None:
    if not ENABLED:
        log.info("CrowdSec bouncer disabled (CROWDSEC_LAPI_URL / CROWDSEC_BOUNCER_KEY not set)")
        return

    global _stream_started
    headers = {"X-Api-Key": CROWDSEC_BOUNCER_KEY}
    url = f"{CROWDSEC_LAPI_URL}/v1/decisions/stream"

    while True:
        try:
            params = {"startup": "false" if _stream_started else "true"}
            async with session.get(url, headers=headers, params=params) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"LAPI returned {resp.status}")
                data = await resp.json(content_type=None)
                _apply_decisions(data.get("new"), data.get("deleted"))
                if not _stream_started:
                    log.info("CrowdSec bouncer stream started")
                _stream_started = True
        except asyncio.CancelledError:
            raise
        except Exception as e:
            _METRIC_POLL_FAILURES_TOTAL.inc()
            log.warning("CrowdSec LAPI poll failed: %s", e)
        await asyncio.sleep(CROWDSEC_POLL_INTERVAL_SEC)
