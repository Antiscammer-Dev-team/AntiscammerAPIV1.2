# app.py
from __future__ import annotations

import asyncio
import base64
import collections
import json
import logging
import os
import re
import sys
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp
import pyotp
from dotenv import load_dotenv
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

load_dotenv()

import db

try:
    import maria_mirror  # Optional: used to mirror approved bans into a secondary MariaDB
except Exception:  # pragma: no cover
    maria_mirror = None
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import StreamingResponse

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")

# ----------------------------
# Config (SECRETS FROM ENV)
# ----------------------------
DISCORD_WEBHOOK_URL = (os.getenv("DISCORD_WEBHOOK_URL") or "").strip()
DISCORD_FALSE_POSITIVE_WEBHOOK_URL = (os.getenv("DISCORD_FALSE_POSITIVE_WEBHOOK_URL") or "").strip()

# Ticket audit (giveaway verification): session TTL and verify delay before lookup
TICKET_AUDIT_TTL_DAYS = max(1, min(365, int(os.getenv("TICKET_AUDIT_TTL_DAYS", "14"))))
TICKET_AUDIT_DELAY_SEC = float(os.getenv("TICKET_AUDIT_DELAY_SEC", "1.0"))
TICKET_AUDIT_CLAIM_RETENTION_DAYS = max(
    1, min(365, int(os.getenv("TICKET_AUDIT_CLAIM_RETENTION_DAYS", "30")))
)

# Ollama API (e.g. https://ollama.com/api for cloud, or http://localhost:11434 for local). We call /generate → .../api/generate or .../generate.
# For ollama.com cloud: OLLAMA_API_KEY is required (Bearer token); otherwise Ollama returns 401.
OLLAMA_BASE_URL = (os.getenv("OLLAMA_BASE_URL") or "https://ollama.com/api").strip().rstrip("/")
OLLAMA_API_KEY = (os.getenv("OLLAMA_API_KEY") or "").strip()
OLLAMA_MODEL = (os.getenv("OLLAMA_MODEL") or "gpt-oss:20b-cloud").strip()
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "20"))

LOG_SLOW_MS = max(0, int(os.getenv("LOG_SLOW_MS", "2000")))

# ----------------------------
# Paths / Storage (file-based storage removed; DB used)
# ----------------------------
TWOFA_ISSUER = "AntiScammer"
_admin_auth_scheme = HTTPBasic()

# Ban report proof upload — CDN expects "files" + X-Internal-Token
BAN_REPORT_UPLOAD_URL = (os.getenv("BAN_REPORT_UPLOAD_URL") or os.getenv("baseurl") or "").strip()
BAN_REPORT_UPLOAD_TOKEN = (os.getenv("BAN_REPORT_UPLOAD_TOKEN") or os.getenv("X-Internal-Token") or "").strip()
BAN_REPORT_CDN_USER = (os.getenv("CDN_USERNAME") or "").strip()
BAN_REPORT_CDN_PASS = (os.getenv("CDN_PASSWORD") or "").strip()

# Grafana reverse proxy — internal URL only (never expose Grafana's own port publicly).
# Access is gated by require_admin_auth; the authenticated admin username is forwarded via
# X-WEBAUTH-USER so Grafana can be configured with auth.proxy for single sign-on.
GRAFANA_INTERNAL_URL = (os.getenv("GRAFANA_INTERNAL_URL") or "").strip().rstrip("/")
_GRAFANA_PROXY_STRIP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-length", "content-encoding", "host", "authorization",
}

# Prometheus metrics — scraped by an internal-only Prometheus instance over
# the public domain, gated by METRICS_TOKEN (bearer-style header check).
METRICS_TOKEN = (os.getenv("METRICS_TOKEN") or "").strip()

_METRIC_REQUESTS_TOTAL = Counter(
    "antiscammer_http_requests_total",
    "Total HTTP requests handled",
    ["method", "endpoint", "status_code", "auth_kind", "api_key_label"],
)
_METRIC_REQUEST_DURATION = Histogram(
    "antiscammer_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
)
_METRIC_REQUEST_SIZE = Histogram(
    "antiscammer_http_request_size_bytes",
    "HTTP request body size in bytes",
    ["endpoint"],
    buckets=(64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, float("inf")),
)
_METRIC_RESPONSE_SIZE = Histogram(
    "antiscammer_http_response_size_bytes",
    "HTTP response body size in bytes",
    ["endpoint"],
    buckets=(64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, float("inf")),
)
_METRIC_RATE_LIMITED_TOTAL = Counter(
    "antiscammer_rate_limited_total",
    "Requests rejected by the admin rate limiter",
    ["endpoint"],
)
_METRIC_SLOW_REQUESTS_TOTAL = Counter(
    "antiscammer_slow_requests_total",
    "Requests that exceeded LOG_SLOW_MS",
    ["endpoint"],
)
_METRIC_EXCEPTIONS_TOTAL = Counter(
    "antiscammer_exceptions_total",
    "Unhandled exceptions by type",
    ["endpoint", "exception_type"],
)
_METRIC_ADMIN_ACTIONS_TOTAL = Counter(
    "antiscammer_admin_actions_total",
    "Admin audit actions performed",
    ["action"],
)
# Catch-all for dependencies that fail without surfacing as an HTTP error to
# any caller — Discord webhooks, the ban-report CDN, Ollama, the MariaDB
# mirror, and the request-log DB write. These would otherwise only show up
# as a WARNING/ERROR log line nobody is watching.
_METRIC_EXTERNAL_FAILURES_TOTAL = Counter(
    "antiscammer_external_failures_total",
    "Failures in external dependencies or secondary storage that don't surface as an HTTP error",
    ["component"],
)

# ----------------------------
# In-memory cache for scammers (loaded from DB at startup / reload)
# ----------------------------
_KNOWN_SCAMMERS: Dict[str, str] = {}  # user_id -> reason

# ----------------------------
# In-memory cache for URLs (safe / scam)
# ----------------------------
_KNOWN_SAFE_URLS: Set[str] = set()  # domains marked safe
_KNOWN_SCAM_URLS: Dict[str, str] = {}  # domain -> reason

# Request metrics for admin dashboard
_request_count: int = 0
_request_times: collections.deque = collections.deque(maxlen=100)
_startup_time: float = 0

# Admin security: rate limit (ip -> list of timestamps), login throttle (ip -> (count, lock_until))
_admin_rate_limit: Dict[str, collections.deque] = {}
_admin_login_fails: Dict[str, tuple] = {}  # ip -> (count, lock_until_timestamp)
_ADMIN_RATE_LIMIT = 60  # requests per minute
_ADMIN_LOGIN_MAX_FAILS = 5
_ADMIN_LOGIN_LOCK_SEC = 900  # 15 min

_SCAM_PROMPT_SETTING_KEY = "scam_detection_prompt_template"
_DEFAULT_SCAM_PROMPT_TEMPLATE = """You are a classifier that detects Discord scam messages.
Respond ONLY with a JSON object with:

"decision": string, one of ["scam","not_scam","uncertain"]
"confidence": string, one of ["high","medium","low"]
"reason": string

Rules:
Do NOT wrap JSON in markdown.
Output must be STRICT JSON.
If you are not completely sure, set decision="uncertain".
Anything with labled ! / . or any of that such following ban or kick or anything is not a scam
qs-fishing is a fishing plugin. Not Phishing.
Discount codes are not a scam
remote connections via tools like anydesk and teamviewer are fine if there to help fix a bug

If someone sends a "Having issues replace the file with the one i sent" And has some context of trying to assist. Then its not a scam
Any messages such as "Send your question/issue here" that does NOT redirect to a channel and instead is a url or mailto link to a discord.gg or github link is likely a scam This does not mean those links are scam look for the message too and pot a ping
If a message says "share your questions below" (or similar) and contains a link (discord.gg, github, mailto, etc.), treat as likely scam. This can cause false positives; if the link is clearly an official channel or trusted source, prefer uncertain over scam.

If ANYTHING in the message says "SQL" or "DB" or any other database and does not have other indicators thats a hard 100% not scam

User offering free food is not a scam
Saying a user needs a token is not a scam. Asking for a discord token or key is a scam
"Setting up groups" Is just someone configering a plugin or a tool. NOT A SCAM
Someone stating they have existing tickets or coins is not a scam
Support is a thing. If someone is trying to help a user and asking for lua files or remote connection. Thats not a scam. Thats support
Anything related to a admin menu is not a scam.
if someone is encouraging someone to buy anything named quazar x its safe. Quazar is a fivem addon seller.
Bot commands MUST BE IGNORED. Commands for example are -dep , !dep , !ban , --help, -Msg and more

If someone offers a "Direct link" to a support ticket that is a link to a actual site. Its a scam

URL status from our database (use this to inform your decision; you make the final classification):
{url_status_block}

Inputs Provided:
{context_block}

Current Message (RAW):
{raw_message}

Current Message (CLEANED):
{clean_message}

Reconstructed if vertical text:
{joined_message}

Obfuscation stats:
looks_vertical: {looks_vertical}
line_count: {line_count}
single_char_line_ratio: {single_char_line_ratio}
whitespace_ratio: {whitespace_ratio}
"""
_scam_prompt_template: str = _DEFAULT_SCAM_PROMPT_TEMPLATE

# ----------------------------
# General helpers
# ----------------------------
def _parse_utc_iso_z(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def _utc_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _datetime_to_iso_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def _normalize_user_id(user_id: str) -> str:
    return re.sub(r"\D+", "", user_id or "")


def _lookup_user_dict(uid: str, *, include_reason: bool) -> Dict[str, Any]:
    reason = _KNOWN_SCAMMERS.get(uid)
    out: Dict[str, Any] = {"user_id": uid, "is_flagged": reason is not None}
    if include_reason and reason is not None:
        out["reason"] = reason
    return out


def _safe_ext(filename: str) -> str:
    if not filename:
        return ""
    ext = Path(filename).suffix.lower()
    allowed = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".txt", ".log", ".json", ".pdf", ".zip"}
    return ext if ext in allowed else ""

def _mask_api_key(key: str) -> str:
    if not key or len(key) < 8:
        return "****"
    if len(key) <= 12:
        return key[:4] + "****"
    return key[:4] + "-****-****-" + key[-4:] if "-" in key else key[:4] + "****" + key[-4:]

def _generate_api_key() -> str:
    part = lambda: "".join(__import__("random").choices("0123456789ABCDEF", k=4))
    return f"ATSM-{part()}-{part()}-{part()}"

async def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    meta = await db.api_key_get(x_api_key)
    if not meta:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    expires_at = meta.get("expires_at")
    if not expires_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key has no expiry configured")

    try:
        exp = _parse_utc_iso_z(expires_at)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key expiry is malformed")

    if datetime.now(timezone.utc) >= exp:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key expired")

    return meta


async def require_master_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> str:
    """
    Dependency that ensures the caller is using the configured master API key.
    This bypasses normal per-partner restrictions and is intended only for
    fully privileged management endpoints.
    """
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    master_key = await db.master_key_get()
    if not master_key or x_api_key != master_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for master operations",
        )
    return x_api_key

def _get_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def require_admin_auth(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(_admin_auth_scheme),
) -> str:
    ip = _get_client_ip(request)
    now = time.time()
    if ip in _admin_login_fails:
        _, lock_until = _admin_login_fails[ip]
        if now < lock_until:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Too many failed logins. Try again later.",
            )
        else:
            del _admin_login_fails[ip]
    p = await db.admin_auth_get(credentials.username)
    if not p or p != credentials.password:
        request.state.admin_login_failed = True
        cnt, _ = _admin_login_fails.get(ip, (0, 0))
        cnt += 1
        lock_until = now + _ADMIN_LOGIN_LOCK_SEC if cnt >= _ADMIN_LOGIN_MAX_FAILS else 0
        _admin_login_fails[ip] = (cnt, lock_until)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin login",
            headers={"WWW-Authenticate": "Basic realm=\"Admin\""},
        )
    if ip in _admin_login_fails:
        del _admin_login_fails[ip]
    request.state.admin_user = credentials.username
    return credentials.username


async def _admin_audit(
    request: Request,
    username: str,
    action: str,
    resource: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    request.state.admin_audit_action = action
    _METRIC_ADMIN_ACTIONS_TOTAL.labels(action=action).inc()
    await db.admin_audit_log(username, action, resource, details, _get_client_ip(request))


def _render_scam_prompt(
    *,
    url_status_block: str,
    context_block: str,
    raw_message: str,
    clean_message: str,
    joined_message: str,
    looks_vertical: bool,
    line_count: int,
    single_char_line_ratio: float,
    whitespace_ratio: float,
) -> str:
    tmpl = _scam_prompt_template or _DEFAULT_SCAM_PROMPT_TEMPLATE
    try:
        return tmpl.format(
            url_status_block=url_status_block,
            context_block=context_block,
            raw_message=raw_message,
            clean_message=clean_message,
            joined_message=joined_message,
            looks_vertical=looks_vertical,
            line_count=line_count,
            single_char_line_ratio=single_char_line_ratio,
            whitespace_ratio=whitespace_ratio,
        )
    except Exception:
        log.exception("Invalid scam prompt template; falling back to default")
        return _DEFAULT_SCAM_PROMPT_TEMPLATE.format(
            url_status_block=url_status_block,
            context_block=context_block,
            raw_message=raw_message,
            clean_message=clean_message,
            joined_message=joined_message,
            looks_vertical=looks_vertical,
            line_count=line_count,
            single_char_line_ratio=single_char_line_ratio,
            whitespace_ratio=whitespace_ratio,
        )


async def _load_scam_prompt_template() -> None:
    global _scam_prompt_template
    saved = await db.app_setting_get(_SCAM_PROMPT_SETTING_KEY)
    if saved and saved.strip():
        _scam_prompt_template = saved
    else:
        _scam_prompt_template = _DEFAULT_SCAM_PROMPT_TEMPLATE

# ----------------------------
# 2FA helpers
# ----------------------------
def _b32_secret_new() -> str:
    raw = token_urlsafe(32).encode("utf-8")
    return base64.b32encode(raw).decode("utf-8").replace("=", "")

def _verify_totp(secret_b32: str, code: str) -> bool:
    totp = pyotp.TOTP(secret_b32)
    return bool(totp.verify(code.strip().replace(" ", ""), valid_window=1))

def _sanitize_twofa_user_id(user_id: str) -> str:
    uid = (user_id or "").strip()
    uid = re.sub(r"\s+", " ", uid)
    return uid[:128]

# ----------------------------
# Scammers (loaded from DB into cache)
# ----------------------------
async def load_scammers_db() -> None:
    global _KNOWN_SCAMMERS
    try:
        _KNOWN_SCAMMERS = await db.scammers_get_all()
        log.info("Loaded %d known scammers from DB", len(_KNOWN_SCAMMERS))
    except Exception:
        log.exception("Failed to load scammers from DB")
        _KNOWN_SCAMMERS = {}


async def load_urls_db() -> None:
    global _KNOWN_SAFE_URLS, _KNOWN_SCAM_URLS
    try:
        data = await db.url_list_get_all()
        safe = set()
        scam: Dict[str, str] = {}
        for domain, meta in data.items():
            t = meta.get("type", "").lower()
            reason = meta.get("reason", "") or ""
            if t == "safe":
                safe.add(domain)
            elif t == "scam":
                scam[domain] = reason
        _KNOWN_SAFE_URLS = safe
        _KNOWN_SCAM_URLS = scam
        log.info("Loaded URLs from DB: %d safe, %d scam", len(_KNOWN_SAFE_URLS), len(_KNOWN_SCAM_URLS))
    except Exception:
        log.exception("Failed to load URLs from DB")
        _KNOWN_SAFE_URLS = set()
        _KNOWN_SCAM_URLS = {}

# ----------------------------
# Discord webhook helper
# ----------------------------
async def post_banrequest_to_discord_webhook(
    *,
    case_id: str,
    uid: str,
    reason: str,
    notes: str,
    proof_bytes: bytes,
    proof_filename: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> None:
    if not DISCORD_WEBHOOK_URL:
        return

    content = f"🧾 **New ban request** — Case `{case_id}`"
    embed = {
        "title": "Ban Request Submitted",
        "fields": [
            {"name": "User ID", "value": f"`{uid}`", "inline": True},
            {"name": "Reason", "value": reason[:1024] or "(none)", "inline": False},
            {"name": "Notes", "value": (notes[:1024] if notes else "(none)"), "inline": False},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    data = aiohttp.FormData()
    data.add_field(
        "payload_json",
        json.dumps({"content": content, "embeds": [embed]}),
        content_type="application/json",
    )
    data.add_field("file", proof_bytes, filename=proof_filename, content_type="application/octet-stream")

    if session:
        async with session.post(DISCORD_WEBHOOK_URL, data=data) as resp:
            if resp.status >= 300:
                body = await resp.text()
                log.warning("Webhook post failed: %s %s", resp.status, body[:500])
                _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="discord_webhook").inc()
    else:
        async with aiohttp.ClientSession() as fallback:
            async with fallback.post(DISCORD_WEBHOOK_URL, data=data) as resp:
                if resp.status >= 300:
                    body = await resp.text()
                    log.warning("Webhook post failed: %s %s", resp.status, body[:500])
                    _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="discord_webhook").inc()


async def post_falsepositivereport_to_discord_webhook(
    *,
    case_id: str,
    uid: str,
    reason: str,
    notes: str,
    proof_bytes: bytes,
    proof_filename: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> None:
    if not DISCORD_FALSE_POSITIVE_WEBHOOK_URL:
        return

    content = f"⚠️ **New false positive report** — Case `{case_id}`"
    embed = {
        "title": "False Positive Report Submitted",
        "fields": [
            {"name": "User ID", "value": f"`{uid}`", "inline": True},
            {"name": "Reason", "value": reason[:1024] or "(none)", "inline": False},
            {"name": "Notes", "value": (notes[:1024] if notes else "(none)"), "inline": False},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    data = aiohttp.FormData()
    data.add_field(
        "payload_json",
        json.dumps({"content": content, "embeds": [embed]}),
        content_type="application/json",
    )
    data.add_field("file", proof_bytes, filename=proof_filename, content_type="application/octet-stream")

    if session:
        async with session.post(DISCORD_FALSE_POSITIVE_WEBHOOK_URL, data=data) as resp:
            if resp.status >= 300:
                body = await resp.text()
                log.warning("False positive webhook post failed: %s %s", resp.status, body[:500])
                _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="discord_fp_webhook").inc()
    else:
        async with aiohttp.ClientSession() as fallback:
            async with fallback.post(DISCORD_FALSE_POSITIVE_WEBHOOK_URL, data=data) as resp:
                if resp.status >= 300:
                    body = await resp.text()
                    log.warning("False positive webhook post failed: %s %s", resp.status, body[:500])
                    _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="discord_fp_webhook").inc()

async def upload_banreport_proof_to_interna(
    *,
    proof_bytes: bytes,
    proof_filename: str,
    case_id: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[str]:
    if not BAN_REPORT_UPLOAD_URL or not BAN_REPORT_UPLOAD_TOKEN:
        return None
    url = BAN_REPORT_UPLOAD_URL.rstrip("/")
    headers: Dict[str, str] = {"X-Internal-Token": BAN_REPORT_UPLOAD_TOKEN}
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        data = aiohttp.FormData()
        data.add_field("files", proof_bytes, filename=proof_filename, content_type="application/octet-stream")
        if BAN_REPORT_CDN_USER and BAN_REPORT_CDN_PASS:
            auth = aiohttp.BasicAuth(BAN_REPORT_CDN_USER, BAN_REPORT_CDN_PASS)
        else:
            auth = None

        async def _post(sess: aiohttp.ClientSession) -> Optional[str]:
            async with sess.post(url, headers=headers, data=data, auth=auth, timeout=timeout) as resp:
                if resp.status >= 300:
                    body = await resp.text()
                    log.warning("Ban report CDN upload failed %s: %s", resp.status, body[:500])
                    _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="ban_report_cdn").inc()
                    return None
                try:
                    result = await resp.json()
                    cdn_url = result.get("url") or result.get("cdn_url")
                    if cdn_url:
                        log.info("Ban report CDN upload ok case_id=%s url=%s", case_id, cdn_url)
                        return cdn_url
                except Exception:
                    pass
                return None

        if session:
            return await _post(session)
        async with aiohttp.ClientSession() as fallback:
            return await _post(fallback)
    except Exception as e:
        log.warning("Ban report CDN upload error: %s", e)
        _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="ban_report_cdn").inc()
        return None

# ----------------------------
# URL extraction and normalization
# ----------------------------
_URL_PATTERN = re.compile(
    r"(?:https?://)?"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)"
    r"(?::\d+)?"
    r"(?:/[/\w.\-~:%@?&+=]*)?",
    re.IGNORECASE,
)
# Short domains: discord.gg, bit.ly, goo.su, etc.
_SHORT_DOMAIN_PATTERN = re.compile(
    r"\b([a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b",
)


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text and return normalized domains (lowercase, host only).
    Handles: https://..., discord.gg/..., bare domain.tld, etc.
    """
    if not text or not isinstance(text, str):
        return []
    domains: set = set()
    # Match full URLs (http/https or scheme-relative)
    for m in _URL_PATTERN.finditer(text):
        host = m.group(1)
        if host and len(host) > 1:
            # Strip www. prefix
            if host.lower().startswith("www."):
                host = host[4:]
            domains.add(host.lower())
    # Match bare domains (e.g., discord.gg, modora.xyz)
    for m in _SHORT_DOMAIN_PATTERN.finditer(text):
        d = m.group(1).lower()
        if d and "." in d and len(d) < 64:
            domains.add(d)
    return sorted(domains)


# ----------------------------
# Scam canonicalize + detect (your existing logic)
# ----------------------------
def canonicalize_for_scam_scan(s: str) -> dict:
    raw = (s or "")
    s = raw.replace("\r", "\n").replace("\t", " ")

    s = re.sub(r'[┌┐└┘├┤┬┴┼─│╭╮╯╰═║╔╗╚╝╠╣╦╩╬]', ' ', s)
    s = re.sub(r'(?m)^\s*[*\-•]+\s*', '', s)
    s = re.sub(r':[A-Za-z0-9_]{1,32}:', ' ', s)
    s = re.sub(r'<a?:([A-Za-z0-9_]{1,32}):\d+>', r' \1 ', s)
    s = re.sub(r'[`*_~>|]', ' ', s)
    s = re.sub(r'[ \f\v]+', ' ', s)
    s = re.sub(r'\n{3,}', '\n\n', s).strip()

    lines = [ln.strip() for ln in s.split("\n") if ln.strip()]
    total_lines = len(lines)
    single_char_lines = sum(1 for ln in lines if len(ln) == 1)
    single_char_line_ratio = (single_char_lines / total_lines) if total_lines else 0.0

    ws = sum(1 for c in s if c.isspace())
    total_chars = max(1, len(s))
    whitespace_ratio = ws / total_chars

    looks_vertical = total_lines >= 6 and single_char_line_ratio >= 0.65
    joined = ""
    if looks_vertical:
        joined = "".join(ln for ln in lines if len(ln) == 1)

    return {
        "raw": raw,
        "clean": s,
        "joined": joined,
        "obfuscation": {
            "looks_vertical": looks_vertical,
            "line_count": total_lines,
            "single_char_line_ratio": round(single_char_line_ratio, 3),
            "whitespace_ratio": round(whitespace_ratio, 3),
        },
    }

async def detect_scam(
    message: str,
    context_messages: Optional[List[Dict[str, Any]]] = None,
    *,
    session: aiohttp.ClientSession,
) -> dict:
    text = (message or "").strip()

    context_block = ""
    if context_messages:
        lines = []
        for m in context_messages:
            created_at = m.get("created_at")
            author = m.get("author", "unknown")
            content = m.get("content", "")
            try:
                ts = datetime.fromisoformat(created_at).strftime("%H:%M:%S") if created_at else "??:??:??"
            except Exception:
                ts = "??:??:??"
            lines.append(f"[{ts}] {author}: {content}")
        context_block = "\n".join(lines)

    canon = canonicalize_for_scam_scan(text)
    ob = canon["obfuscation"]

    force_scam = (
        ob["looks_vertical"]
        and ob["line_count"] >= 6
        and ob["single_char_line_ratio"] >= 0.70
    )

    # Extract URLs from message and context, build status block for model
    text_to_scan = text
    if context_messages:
        for m in context_messages:
            text_to_scan += " " + (m.get("content") or "")
    extracted_domains = extract_urls_from_text(text_to_scan)
    url_status_lines: List[str] = []
    for d in extracted_domains:
        if d in _KNOWN_SCAM_URLS:
            reason = _KNOWN_SCAM_URLS.get(d, "")
            url_status_lines.append(f"- {d}: FLAGGED AS SCAM in our database. {reason} Model considers this when classifying.")
        elif d in _KNOWN_SAFE_URLS:
            url_status_lines.append(f"- {d}: WHITELISTED. It's clear. Do not flag.")
        else:
            url_status_lines.append(f"- {d}: Not in our database. Evaluate from context.")
    url_status_block = "\n".join(url_status_lines) if url_status_lines else "No URLs detected in message."

    prompt = _render_scam_prompt(
        url_status_block=url_status_block,
        context_block=context_block or "[no context]",
        raw_message=canon["raw"],
        clean_message=canon["clean"],
        joined_message=canon["joined"] or "[not detected]",
        looks_vertical=ob["looks_vertical"],
        line_count=ob["line_count"],
        single_char_line_ratio=ob["single_char_line_ratio"],
        whitespace_ratio=ob["whitespace_ratio"],
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": {
            "decision": "string",
            "confidence": "string",
            "reason": "string",
        },
    }

    headers = {
        "Authorization": f"Bearer {OLLAMA_API_KEY}",
        "Content-Type": "application/json",
    }

    # Ollama generate endpoint is /api/generate (see https://github.com/ollama/ollama/blob/main/docs/api.md)
    if OLLAMA_BASE_URL.rstrip("/").endswith("/api"):
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/generate"
    else:
        url = f"{OLLAMA_BASE_URL}/api/generate"

    try:
        async with session.post(
            url,
            headers=headers,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=OLLAMA_TIMEOUT),
        ) as resp:
            if resp.status != 200:
                raw_txt = await resp.text()
                log.warning("[OLLAMA ERROR] %s: %s", resp.status, raw_txt[:500])
                if resp.status == 401:
                    log.warning("[OLLAMA] 401 Unauthorized: set OLLAMA_API_KEY for https://ollama.com/api (cloud auth required)")
                _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="ollama").inc()
                return {
                    "is_scam": force_scam,
                    "decision": "scam" if force_scam else "uncertain",
                    "uncertain": not force_scam,
                    "confidence": None,
                    "reason": f"Ollama API error (HTTP {resp.status}). Check Ollama is running and model is loaded.",
                    "obfuscation": ob,
                }
            data = await resp.json()
    except Exception as e:
        log.warning("[OLLAMA EXCEPTION] %s", e)
        _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="ollama").inc()
        return {
            "is_scam": force_scam,
            "decision": "scam" if force_scam else "uncertain",
            "uncertain": not force_scam,
            "confidence": None,
            "reason": f"Ollama request failed: {type(e).__name__}. Check Ollama URL and connectivity.",
            "obfuscation": ob,
        }

    result = data.get("response")

    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError:
            if force_scam:
                return {
                    "is_scam": True,
                    "decision": "scam",
                    "uncertain": False,
                    "confidence": "high",
                    "reason": "Strong obfuscation detected; treated as scam bypass.",
                    "obfuscation": ob,
                }
            return {
                "is_scam": False,
                "decision": "uncertain",
                "uncertain": True,
                "confidence": None,
                "reason": "Invalid JSON",
                "obfuscation": ob,
            }

    if not isinstance(result, dict):
        if force_scam:
            return {
                "is_scam": True,
                "decision": "scam",
                "uncertain": False,
                "confidence": "high",
                "reason": "Strong obfuscation detected; treated as scam bypass.",
                "obfuscation": ob,
            }
        return {
            "is_scam": False,
            "decision": "uncertain",
            "uncertain": True,
            "confidence": None,
            "reason": "Missing JSON object",
            "obfuscation": ob,
        }

    model_decision = str(result.get("decision", "")).strip().lower()
    model_confidence = str(result.get("confidence", "")).strip().lower()
    reason = result.get("reason", "No reason provided.")

    if model_decision not in {"scam", "not_scam", "uncertain"}:
        model_decision = "uncertain"

    if force_scam:
        return {
            "is_scam": True,
            "decision": "scam",
            "uncertain": False,
            "confidence": model_confidence or "high",
            "reason": "Strong obfuscation detected (vertical/diagonal single-letter text), a common scam bypass technique.",
            "obfuscation": ob,
        }

    decision = model_decision
    uncertain = (decision == "uncertain")
    is_scam = (decision == "scam")

    return {
        "is_scam": is_scam,
        "decision": decision,
        "uncertain": uncertain,
        "confidence": model_confidence or None,
        "reason": reason,
        "obfuscation": ob,
    }

# ----------------------------
# Pydantic models
# ----------------------------
class LookupResult(BaseModel):
    user_id: str 
    is_flagged: bool
    record: Optional[Dict[str, Any]] = None

class BatchLookupRequest(BaseModel):
    user_ids: List[str] = Field(..., min_length=1, max_length=500)
    include_reason: bool = False


class UrlCheckRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=100)

class ContextItem(BaseModel):
    created_at: Optional[str] = Field(default=None, description="ISO timestamp")
    author: str = "unknown"
    content: str = ""

class DetectRequest(BaseModel):
    message: str
    context_messages: Optional[List[ContextItem]] = None

class ResolveCaseRequest(BaseModel):
    action: str
    decision_note: str = ""

class TwoFASetupRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=128)
    label: Optional[str] = Field(default=None, max_length=128)

class TwoFACodeRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=128)
    code: str = Field(..., min_length=6, max_length=10)


class TicketAuditRegisterRequest(BaseModel):
    discord_ids: List[str] = Field(..., min_length=1, max_length=100)
    store: Optional[str] = Field(default=None, max_length=256)
    server_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Discord guild snowflake; scope this giveaway to one server (call register per server).",
    )
    giveaway_key: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Your stable giveaway id/name; same user can win different giveaways (different register/audit_id per giveaway).",
    )


class TicketAuditVerifyRequest(BaseModel):
    audit_id: str = Field(..., min_length=1, max_length=128)
    discord_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Discord user snowflake; cannot be blank.",
    )
    include_reason: bool = False
    server_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Required when the session was registered with server_id; must match.",
    )

# ----------------------------
# FastAPI app + middleware
# ----------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _startup_time
    _startup_time = time.perf_counter()
    pool = await db.init_pool()
    await db.init_tables(pool)
    await db.seed_defaults(pool)
    await _load_scam_prompt_template()
    await load_scammers_db()
    await load_urls_db()
    api_keys_count = len(await db.api_key_get_all())
    log.info("LOAD PID=%s scammers_loaded=%d api_keys=%d", os.getpid(), len(_KNOWN_SCAMMERS), api_keys_count)
    if maria_mirror is None:
        log.warning("MariaDB mirror not loaded (install aiomysql?). Bans will only be written to Postgres.")
    else:
        log.info("MariaDB mirror module loaded; global_bans will be written when MARIADB_* env is set.")
    timeout = aiohttp.ClientTimeout(total=20)
    app.state.http_session = aiohttp.ClientSession(timeout=timeout)
    try:
        yield
    finally:
        await app.state.http_session.close()
        await db.close_pool()
        log.info("HTTP session closed")

app = FastAPI(title="AntiScammer Local API (Keyed)", lifespan=lifespan)

_admin_dir = Path(__file__).with_name("admin")
if _admin_dir.exists():
    app.mount("/admin/static", StaticFiles(directory=str(_admin_dir), html=True), name="admin_static")

log.info("API booting...")

# Ordered (method, path_regex, display_name) — first match wins
ROUTE_DISPLAY_NAMES: List[Tuple[Optional[str], str, str]] = [
    ("GET", r"^/$", "Root"),
    ("GET", r"^/health$", "Health check"),
    ("GET", r"^/ready$", "Ready probe"),
    ("GET", r"^/metrics$", "Prometheus metrics"),
    ("POST", r"^/detect$", "Scam detection"),
    ("POST", r"^/canonicalize$", "Message canonicalize"),
    ("POST", r"^/url-check$", "URL check"),
    ("GET", r"^/lookup/[^/]+$", "User lookup"),
    ("POST", r"^/lookup$", "Batch user lookup"),
    ("POST", r"^/banrequest$", "Submit ban request"),
    ("GET", r"^/banrequest/[^/]+$", "Get ban request"),
    ("POST", r"^/banrequest/[^/]+/resolve$", "Resolve ban request"),
    ("POST", r"^/falsepositivereport$", "Submit false positive report"),
    ("GET", r"^/falsepositivereport/[^/]+$", "Get false positive report"),
    ("POST", r"^/falsepositivereport/[^/]+/resolve$", "Resolve false positive report"),
    ("POST", r"^/ticket-audit/register$", "Ticket audit: Register"),
    ("POST", r"^/ticket-audit/verify$", "Ticket audit: Verify"),
    ("POST", r"^/2fa/setup$", "2FA: Setup"),
    ("POST", r"^/2fa/enable$", "2FA: Enable"),
    ("POST", r"^/2fa/verify$", "2FA: Verify"),
    ("GET", r"^/2fa/status$", "2FA: Status"),
    ("POST", r"^/authenticate$", "2FA: Authenticate"),
    ("GET", r"^/root/api-keys$", "Root: List API keys"),
    ("POST", r"^/root/api-keys$", "Root: Create API key"),
    ("PATCH", r"^/root/api-keys$", "Root: Update API key"),
    ("DELETE", r"^/root/api-keys$", "Root: Delete API key"),
    ("GET", r"^/root/scammers$", "Root: List scammers"),
    ("POST", r"^/root/scammers$", "Root: Add scammer"),
    ("DELETE", r"^/root/scammers$", "Root: Delete scammer (body)"),
    ("DELETE", r"^/root/scammers/[^/]+$", "Root: Delete scammer"),
    ("GET", r"^/root/urls$", "Root: List URLs"),
    ("POST", r"^/root/urls$", "Root: Add URL"),
    ("DELETE", r"^/root/urls/[^/]+$", "Root: Delete URL"),
    ("POST", r"^/staff/signal/antiscam/global-ban$", "Staff: Global ban"),
    ("GET", r"^/admin/?$", "Admin: Dashboard page"),
    ("GET", r"^/admin/admin\.js$", "Admin: Legacy JS"),
    (None, r"^/admin/static/", "Admin: Static asset"),
    (None, r"^/admin/grafana(/.*)?$", "Admin: Grafana proxy"),
    ("GET", r"^/admin/keys$", "Admin: List API keys"),
    ("GET", r"^/admin/generate-key$", "Admin: Generate API key"),
    ("POST", r"^/admin/keys$", "Admin: Add API key"),
    ("PATCH", r"^/admin/keys$", "Admin: Update API key"),
    ("DELETE", r"^/admin/keys$", "Admin: Delete API key"),
    ("POST", r"^/admin/reload-scammers$", "Admin: Reload scammers"),
    ("GET", r"^/admin/urls$", "Admin: List URLs"),
    ("POST", r"^/admin/urls$", "Admin: Add URL"),
    ("DELETE", r"^/admin/urls/[^/]+$", "Admin: Delete URL"),
    ("POST", r"^/admin/reload-urls$", "Admin: Reload URLs"),
    ("GET", r"^/admin/dashboard$", "Admin: Dashboard stats"),
    ("GET", r"^/admin/request-logs/stats$", "Admin: Request log stats"),
    ("GET", r"^/admin/request-logs/storage$", "Admin: Request log storage"),
    ("GET", r"^/admin/request-logs/export$", "Admin: Export request logs"),
    ("GET", r"^/admin/request-logs/[0-9]+$", "Admin: Request log detail"),
    ("GET", r"^/admin/request-logs$", "Admin: List request logs"),
    ("GET", r"^/admin/ban-requests$", "Admin: List ban requests"),
    ("POST", r"^/admin/ban-requests/[^/]+/resolve$", "Admin: Resolve ban request"),
    ("GET", r"^/admin/fp-reports$", "Admin: List FP reports"),
    ("POST", r"^/admin/fp-reports/[^/]+/resolve$", "Admin: Resolve FP report"),
    ("GET", r"^/admin/scammers$", "Admin: List scammers"),
    ("POST", r"^/admin/scammers$", "Admin: Add scammer"),
    ("DELETE", r"^/admin/scammers/[^/]+$", "Admin: Delete scammer"),
    ("GET", r"^/admin/users$", "Admin: List admin users"),
    ("POST", r"^/admin/users$", "Admin: Add admin user"),
    ("DELETE", r"^/admin/users/[^/]+$", "Admin: Delete admin user"),
    ("PATCH", r"^/admin/users/[^/]+/password$", "Admin: Change admin password"),
    ("GET", r"^/admin/master-key$", "Admin: Get master key"),
    ("POST", r"^/admin/master-key$", "Admin: Set master key"),
    ("GET", r"^/admin/prompt$", "Admin: Get scam prompt"),
    ("POST", r"^/admin/prompt$", "Admin: Update scam prompt"),
]
_ROUTE_DISPLAY_COMPILED: List[Tuple[Optional[str], re.Pattern[str], str]] = [
    (method, re.compile(pattern), name) for method, pattern, name in ROUTE_DISPLAY_NAMES
]


def _resolve_endpoint_name(method: str, path: str) -> str:
    for route_method, pattern, name in _ROUTE_DISPLAY_COMPILED:
        if route_method is not None and route_method != method:
            continue
        if pattern.search(path):
            return name
    return f"{method} {path}"


def _sanitize_headers_for_log(headers: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers.items():
        key = k.lower()
        if key == "authorization":
            out[k] = "[REDACTED]"
        else:
            out[k] = v
    return out


def _body_to_text(raw: bytes, content_type: Optional[str]) -> str:
    if not raw:
        return ""
    if content_type and "application/json" in content_type.lower():
        try:
            return json.dumps(json.loads(raw.decode("utf-8", errors="replace")), ensure_ascii=False)
        except Exception:
            pass
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return repr(raw[:8192])


def _extract_error_detail(response_body: str, status_code: int) -> Optional[str]:
    if status_code < 400 or not response_body:
        return None
    try:
        data = json.loads(response_body)
        if isinstance(data, dict) and data.get("detail") is not None:
            detail = data["detail"]
            if isinstance(detail, str):
                return detail[:2048]
            return json.dumps(detail, ensure_ascii=False)[:2048]
    except Exception:
        pass
    return None


async def _resolve_api_key_auth(x_api_key: str) -> Tuple[str, str, str]:
    """Returns (auth_kind, api_key, api_key_label)."""
    master_key = await db.master_key_get()
    if master_key and x_api_key == master_key:
        return "master", x_api_key, ""
    meta = await db.api_key_get(x_api_key)
    if not meta:
        return "invalid_key", x_api_key, ""
    expires_at = meta.get("expires_at")
    if expires_at:
        try:
            exp = _parse_utc_iso_z(expires_at)
            if datetime.now(timezone.utc) >= exp:
                return "expired_key", x_api_key, meta.get("label") or ""
        except Exception:
            pass
    return "api_key", x_api_key, meta.get("label") or ""


async def _persist_request_log(**kwargs: Any) -> None:
    try:
        await db.request_log_insert(**kwargs)
    except Exception:
        log.exception("request log insert failed")
        _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="request_log_db").inc()


async def _emit_request_log(
    *,
    request: Request,
    request_id: str,
    method: str,
    path: str,
    query_string: str,
    endpoint_name: str,
    status_code: int,
    elapsed_ms: int,
    auth_kind: str,
    api_key: str,
    api_key_label: str,
    request_body_bytes: bytes,
    response_body_bytes: bytes,
    response_headers: Dict[str, str],
    exception_type: Optional[str] = None,
    exception_trace: Optional[str] = None,
    rate_limited: bool = False,
) -> None:
    admin_username = getattr(request.state, "admin_user", None)
    if path.startswith("/admin") and not path.startswith("/admin/static"):
        if admin_username:
            auth_kind = "admin"
        elif getattr(request.state, "admin_login_failed", False):
            auth_kind = "admin_login_failed"

    ct_req = request.headers.get("content-type")
    ct_resp = response_headers.get("content-type") or response_headers.get("Content-Type")
    req_text = _body_to_text(request_body_bytes, ct_req)
    resp_text = _body_to_text(response_body_bytes, ct_resp)
    is_slow = LOG_SLOW_MS > 0 and elapsed_ms >= LOG_SLOW_MS
    is_error = status_code >= 400

    asyncio.create_task(
        _persist_request_log(
            request_id=request_id,
            method=method,
            path=path,
            query_string=query_string or None,
            endpoint_name=endpoint_name,
            status_code=status_code,
            time_ms=elapsed_ms,
            api_key=api_key,
            api_key_label=api_key_label,
            auth_kind=auth_kind,
            admin_username=admin_username,
            admin_audit_action=getattr(request.state, "admin_audit_action", None),
            client_ip=_get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            referer=request.headers.get("referer"),
            request_headers=_sanitize_headers_for_log(request.headers),
            response_headers=_sanitize_headers_for_log(response_headers),
            request_body=req_text,
            response_body=resp_text,
            error_detail=_extract_error_detail(resp_text, status_code),
            is_slow=is_slow,
            is_error=is_error,
            request_bytes=len(request_body_bytes),
            response_bytes=len(response_body_bytes),
            content_type_request=ct_req,
            content_type_response=ct_resp,
            exception_type=exception_type,
            exception_trace=exception_trace,
            rate_limited=rate_limited,
        )
    )


async def _caller_label(request: Request) -> str:
    key = request.headers.get("X-API-Key")
    if not key:
        return "no_key"
    meta = await db.api_key_get(key)
    if not meta:
        return "invalid_key"
    return (meta.get("label") or "unnamed")[:32]

@app.middleware("http")
async def request_id_and_timing_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    start = time.perf_counter()
    method = request.method
    path = request.url.path or "/"
    query_string = request.url.query or ""
    endpoint_name = _resolve_endpoint_name(method, path)

    auth_kind = "none"
    api_key = ""
    api_key_label = ""
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key:
        auth_kind, api_key, api_key_label = await _resolve_api_key_auth(x_api_key)

    request_body_bytes = await request.body()

    async def receive():
        return {"type": "http.request", "body": request_body_bytes, "more_body": False}

    request = Request(request.scope, receive)

    rate_limited = False
    if (
        path.startswith("/admin")
        and path not in ("/admin", "/admin/")
        and not path.startswith("/admin/static")
        and not path.startswith("/admin/grafana")
    ):
        bypass = False
        if x_api_key:
            meta = await db.api_key_get(x_api_key)
            if meta and meta.get("bypass_ratelimit"):
                bypass = True
        if not bypass:
            ip = _get_client_ip(request)
            now = time.time()
            if ip not in _admin_rate_limit:
                _admin_rate_limit[ip] = collections.deque(maxlen=_ADMIN_RATE_LIMIT + 10)
            q = _admin_rate_limit[ip]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= _ADMIN_RATE_LIMIT:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                resp_payload = {"detail": "Too many requests", "request_id": request_id}
                resp_body_bytes = json.dumps(resp_payload).encode("utf-8")
                response = JSONResponse(status_code=429, content=resp_payload)
                response.headers["X-Request-ID"] = request_id
                response.headers["X-Response-Time-Ms"] = str(elapsed_ms)
                await _emit_request_log(
                    request=request,
                    request_id=request_id,
                    method=method,
                    path=path,
                    query_string=query_string,
                    endpoint_name=endpoint_name,
                    status_code=429,
                    elapsed_ms=elapsed_ms,
                    auth_kind=auth_kind,
                    api_key=api_key,
                    api_key_label=api_key_label,
                    request_body_bytes=request_body_bytes,
                    response_body_bytes=resp_body_bytes,
                    response_headers=dict(response.headers),
                    rate_limited=True,
                )
                _METRIC_RATE_LIMITED_TOTAL.labels(endpoint=endpoint_name).inc()
                _METRIC_REQUESTS_TOTAL.labels(
                    method=method,
                    endpoint=endpoint_name,
                    status_code="429",
                    auth_kind=auth_kind,
                    api_key_label=api_key_label,
                ).inc()
                _METRIC_REQUEST_DURATION.labels(method=method, endpoint=endpoint_name).observe(elapsed_ms / 1000.0)
                _METRIC_REQUEST_SIZE.labels(endpoint=endpoint_name).observe(len(request_body_bytes))
                _METRIC_RESPONSE_SIZE.labels(endpoint=endpoint_name).observe(len(resp_body_bytes))
                log.info(
                    "call method=%s path=%s status=429 time_ms=%s auth_kind=%s is_slow=false "
                    "req_bytes=%s resp_bytes=%s request_id=%s rate_limited=true",
                    method,
                    path,
                    elapsed_ms,
                    auth_kind,
                    len(request_body_bytes),
                    len(resp_body_bytes),
                    request_id,
                )
                return response
            q.append(now)

    exception_type: Optional[str] = None
    exception_trace: Optional[str] = None
    try:
        response = await call_next(request)
    except HTTPException as e:
        response = JSONResponse(
            status_code=e.status_code,
            content={"detail": e.detail, "request_id": request_id},
        )
    except Exception as e:
        exception_type = type(e).__name__
        exception_trace = traceback.format_exc()
        log.exception("Unhandled exception: %s", e)
        response = JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    _request_times.append(elapsed_ms)
    global _request_count
    _request_count += 1

    response_body_bytes = b""
    out_headers: Dict[str, str] = {}
    if hasattr(response, "headers"):
        out_headers = dict(response.headers)

    if isinstance(response, StreamingResponse):
        chunks: List[bytes] = []
        async for chunk in response.body_iterator:
            chunks.append(chunk)
        response_body_bytes = b"".join(chunks)
        response = Response(
            content=response_body_bytes,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
    elif hasattr(response, "body") and response.body is not None:
        response_body_bytes = bytes(response.body)
    else:
        try:
            body_iter = getattr(response, "body_iterator", None)
            if body_iter is not None:
                chunks = [c async for c in body_iter]
                response_body_bytes = b"".join(chunks)
                response = Response(
                    content=response_body_bytes,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=getattr(response, "media_type", None),
                )
        except Exception:
            response_body_bytes = b""

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-Ms"] = str(elapsed_ms)

    if path.startswith("/admin") and not path.startswith("/admin/static"):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"

    status_code = getattr(response, "status_code", 0) or 0
    is_slow = LOG_SLOW_MS > 0 and elapsed_ms >= LOG_SLOW_MS

    if path != "/metrics":
        _METRIC_REQUESTS_TOTAL.labels(
            method=method,
            endpoint=endpoint_name,
            status_code=str(status_code),
            auth_kind=auth_kind,
            api_key_label=api_key_label,
        ).inc()
        _METRIC_REQUEST_DURATION.labels(method=method, endpoint=endpoint_name).observe(elapsed_ms / 1000.0)
        _METRIC_REQUEST_SIZE.labels(endpoint=endpoint_name).observe(len(request_body_bytes))
        _METRIC_RESPONSE_SIZE.labels(endpoint=endpoint_name).observe(len(response_body_bytes))
        if is_slow:
            _METRIC_SLOW_REQUESTS_TOTAL.labels(endpoint=endpoint_name).inc()
        if exception_type:
            _METRIC_EXCEPTIONS_TOTAL.labels(endpoint=endpoint_name, exception_type=exception_type).inc()

    if path != "/metrics":
        await _emit_request_log(
            request=request,
            request_id=request_id,
            method=method,
            path=path,
            query_string=query_string,
            endpoint_name=endpoint_name,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            auth_kind=auth_kind,
            api_key=api_key,
            api_key_label=api_key_label,
            request_body_bytes=request_body_bytes,
            response_body_bytes=response_body_bytes,
            response_headers=out_headers or dict(response.headers),
            exception_type=exception_type,
            exception_trace=exception_trace,
        )

    try:
        caller = await _caller_label(request)
    except Exception:
        caller = "error"
    log.info(
        "call method=%s path=%s status=%s time_ms=%s caller=%s auth_kind=%s is_slow=%s "
        "req_bytes=%s resp_bytes=%s request_id=%s",
        method,
        path,
        status_code,
        elapsed_ms,
        caller,
        auth_kind if not getattr(request.state, "admin_user", None) else "admin",
        is_slow,
        len(request_body_bytes),
        len(response_body_bytes),
        request_id,
    )
    return response

# ----------------------------
# Admin: API key management
# ----------------------------
ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AntiScammer API – Key management</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; max-width: 900px; margin: 0 auto; padding: 1rem; background: #1a1a2e; color: #eee; }
    h1 { font-size: 1.25rem; margin-bottom: 1rem; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
    th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #333; }
    th { color: #888; font-weight: 600; }
    input, button { padding: 0.5rem 0.75rem; border-radius: 4px; border: 1px solid #444; background: #2a2a3e; color: #eee; }
    button { cursor: pointer; margin-right: 0.5rem; }
    button.primary { background: #3d5a80; border-color: #3d5a80; }
    button.danger { background: #8b2635; border-color: #8b2635; }
    .form-row { margin-bottom: 0.75rem; display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
    .form-row label { min-width: 80px; }
    .msg { margin: 0.5rem 0; padding: 0.5rem; border-radius: 4px; }
    .msg.err { background: #4a2020; color: #f88; }
    .msg.ok { background: #1e3a2e; color: #8f8; }
    .key-mono { font-family: ui-monospace, monospace; font-size: 0.9em; }
    section { margin-bottom: 1.5rem; }
    #loginSection { max-width: 320px; margin: 2rem auto; border: none; }
    #loginSection h2 { margin-bottom: 1rem; }
    #mainContent { display: none; }
    #mainContent.show { display: block; }
    .logout { margin-bottom: 1rem; }
  </style>
</head>
<body>
  <form id="loginSection" onsubmit="return false">
    <h2>Admin login</h2>
    <div class="form-row"><label for="loginUser">Username</label><input type="text" id="loginUser" name="username" autocomplete="username"></div>
    <div class="form-row"><label for="loginPass">Password</label><input type="password" id="loginPass" name="password" autocomplete="current-password"></div>
    <div class="form-row"><button type="button" class="primary" id="btnLogin">Log in</button></div>
    <div id="loginMsg" class="msg"></div>
  </form>
  <div id="mainContent">
    <p class="logout"><button type="button" id="btnLogout">Log out</button></p>
  <h1>AntiScammer API – Key management</h1>
  <section>
    <h2>Add key</h2>
    <div class="form-row">
      <label>Key</label>
      <input type="text" id="newKey" placeholder="ATSM-XXXX-XXXX-XXXX" class="key-mono" size="28">
      <button type="button" id="btnGen">Generate new key</button>
    </div>
    <div class="form-row">
      <label>Label</label>
      <input type="text" id="newLabel" placeholder="e.g. Modora">
    </div>
    <div class="form-row">
      <label>Expires (UTC)</label>
      <input type="datetime-local" id="newExpires" step="1">
      <button type="button" class="primary" id="btnAdd">Add key</button>
    </div>
    <div id="addMsg"></div>
  </section>
  <section>
    <h2>Keys</h2>
    <div id="listMsg"></div>
    <table>
      <thead><tr><th>Key</th><th>Label</th><th>Expires (UTC)</th><th></th></tr></thead>
      <tbody id="keysBody"></tbody>
    </table>
  </section>
  <section>
    <h2>Master API key</h2>
    <p>Only this key will be able to call the fully privileged API endpoints.</p>
    <div class="form-row">
      <label>Current</label>
      <input type="text" id="masterKeyDisplay" class="key-mono" readonly>
    </div>
    <div class="form-row">
      <label>Set key</label>
      <input type="text" id="masterKeyInput" placeholder="Paste an existing API key" class="key-mono" size="28">
      <button type="button" class="primary" id="btnSetMaster">Save</button>
      <button type="button" class="danger" id="btnClearMaster">Clear</button>
    </div>
    <div id="masterMsg" class="msg"></div>
  </section>
  <script src="/admin/admin.js"></script>
  
</div>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
@app.get("/admin/", response_class=HTMLResponse)
async def admin_page():
    index_path = Path(__file__).with_name("admin").joinpath("index.html")
    if index_path.exists():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    return HTMLResponse(ADMIN_HTML)


@app.get("/admin/admin.js")
async def admin_js():
    """Legacy: serve admin.js from project root for fallback HTML."""
    js_path = Path(__file__).with_name("admin.js")
    return Response(content=js_path.read_text(encoding="utf-8"), media_type="application/javascript")


async def _admin_grafana_proxy(path: str, request: Request, username: str) -> Response:
    if not GRAFANA_INTERNAL_URL:
        raise HTTPException(status_code=503, detail="Grafana is not configured (set GRAFANA_INTERNAL_URL)")

    target_url = f"{GRAFANA_INTERNAL_URL}/admin/grafana/{path}"
    if request.url.query:
        target_url += "?" + request.url.query

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _GRAFANA_PROXY_STRIP_HEADERS
    }
    # Trusted proxy header for Grafana auth.proxy — safe only because Grafana's own
    # port must never be exposed publicly, so this header can only originate here.
    forward_headers["X-WEBAUTH-USER"] = username

    body = await request.body()
    session: aiohttp.ClientSession = request.app.state.http_session
    try:
        async with session.request(
            request.method,
            target_url,
            headers=forward_headers,
            data=body or None,
            allow_redirects=False,
        ) as upstream:
            content = await upstream.read()
            response = Response(content=content, status_code=upstream.status)
            for k, v in upstream.headers.items():
                if k.lower() in _GRAFANA_PROXY_STRIP_HEADERS:
                    continue
                response.headers.append(k, v)
            return response
    except aiohttp.ClientError as e:
        log.warning("Grafana proxy error: %s", e)
        raise HTTPException(status_code=502, detail="Grafana upstream unavailable")


@app.api_route("/admin/grafana", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def admin_grafana_root(request: Request, _user: str = Depends(require_admin_auth)):
    return await _admin_grafana_proxy("", request, _user)


@app.api_route("/admin/grafana/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def admin_grafana_proxy_path(path: str, request: Request, _user: str = Depends(require_admin_auth)):
    return await _admin_grafana_proxy(path, request, _user)


@app.get("/admin/keys")
async def admin_list_keys(_user: str = Depends(require_admin_auth)):
    api_keys = await db.api_key_get_all()
    keys = [
        {
            "key": k,
            "key_masked": _mask_api_key(k),
            "label": m.get("label") or "",
            "expires_at": m.get("expires_at") or "",
            "bypass_ratelimit": m.get("bypass_ratelimit", False),
        }
        for k, m in api_keys.items()
    ]
    return {"keys": keys}

@app.get("/admin/generate-key")
async def admin_generate_key(_user: str = Depends(require_admin_auth)):
    return {"key": _generate_api_key()}

class AdminAddKeyBody(BaseModel):
    key: str = Field(..., min_length=4)
    label: str = ""
    expires_at: str = "3072-12-31T23:59:59Z"
    bypass_ratelimit: bool = False

@app.post("/admin/keys")
async def admin_add_key(body: AdminAddKeyBody, _user: str = Depends(require_admin_auth)):
    key = body.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="key required")
    existing = await db.api_key_get(key)
    if existing:
        raise HTTPException(status_code=400, detail="Key already exists")
    try:
        _parse_utc_iso_z(body.expires_at)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid expires_at (use ISO UTC, e.g. 2026-12-31T23:59:59Z)")
    await db.api_key_set(
        key,
        body.expires_at.strip(),
        (body.label or "").strip(),
        bypass_ratelimit=body.bypass_ratelimit,
    )
    return {"ok": True, "key": key}

class AdminUpdateKeyBody(BaseModel):
    key: str = Field(..., min_length=4)
    label: Optional[str] = None
    expires_at: Optional[str] = None
    bypass_ratelimit: Optional[bool] = None

@app.patch("/admin/keys")
async def admin_update_key(body: AdminUpdateKeyBody, _user: str = Depends(require_admin_auth)):
    key = body.key.strip()
    meta = await db.api_key_get(key)
    if not meta:
        raise HTTPException(status_code=404, detail="Key not found")
    label = meta.get("label", "").strip() if body.label is None else body.label.strip()
    expires_at = meta.get("expires_at", "") if body.expires_at is None else body.expires_at.strip()
    bypass = meta.get("bypass_ratelimit", False) if body.bypass_ratelimit is None else body.bypass_ratelimit
    if body.expires_at is not None:
        try:
            _parse_utc_iso_z(expires_at)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid expires_at")
    await db.api_key_set(key, expires_at, label, bypass_ratelimit=bypass)
    return {"ok": True}

class AdminDeleteKeyBody(BaseModel):
    key: str = Field(..., min_length=4)

@app.delete("/admin/keys")
async def admin_delete_key(body: AdminDeleteKeyBody, _user: str = Depends(require_admin_auth)):
    key = body.key.strip()
    if not await db.api_key_get(key):
        raise HTTPException(status_code=404, detail="Key not found")
    await db.api_key_delete(key)
    return {"ok": True}

@app.post("/admin/reload-scammers")
async def admin_reload_scammers(_user: str = Depends(require_admin_auth)):
    await load_scammers_db()
    return {"ok": True, "known_scammers_count": len(_KNOWN_SCAMMERS)}


# Admin: URL list
@app.get("/admin/urls")
async def admin_list_urls(_user: str = Depends(require_admin_auth)):
    """List all safe/scam URLs."""
    data = await db.url_list_get_all()
    items = [{"domain": d, "type": m["type"], "reason": m["reason"]} for d, m in data.items()]
    return {"ok": True, "count": len(items), "items": items}


@app.post("/admin/urls")
async def admin_add_url(request: Request, _user: str = Depends(require_admin_auth)):
    """Add or update a URL."""
    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid or missing JSON body")
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="Body must be a JSON object")
    domain = (raw.get("domain") or "").strip().lower()
    url_type = raw.get("url_type") or raw.get("type") or ""
    reason = (raw.get("reason") or "").strip()[:512]
    if not domain:
        raise HTTPException(status_code=422, detail="domain required")
    if url_type not in ("safe", "scam"):
        raise HTTPException(status_code=422, detail="url_type must be 'safe' or 'scam'")
    try:
        await db.url_list_upsert(domain, url_type, reason)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await load_urls_db()
    await _admin_audit(request, _user, "url_add", domain, {"type": url_type})
    return {"ok": True, "domain": domain}


@app.delete("/admin/urls/{domain}")
async def admin_delete_url(domain: str, request: Request, _user: str = Depends(require_admin_auth)):
    """Remove a URL by domain."""
    domain = domain.lower().strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    await db.url_list_delete(domain)
    await load_urls_db()
    await _admin_audit(request, _user, "url_delete", domain)
    return {"ok": True, "domain": domain}


@app.post("/admin/reload-urls")
async def admin_reload_urls(_user: str = Depends(require_admin_auth)):
    """Reload URL cache from DB."""
    await load_urls_db()
    return {"ok": True, "safe_count": len(_KNOWN_SAFE_URLS), "scam_count": len(_KNOWN_SCAM_URLS)}


def _parse_log_datetime(value: Optional[str], field: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid {field} datetime")


@app.get("/admin/dashboard")
async def admin_dashboard(_user: str = Depends(require_admin_auth)):
    """Aggregated stats for admin overview."""
    pending_ban = await db.ban_request_list(status="pending", limit=1000)
    pending_fp = await db.fp_report_list(status="pending", limit=1000)
    admin_users = await db.admin_auth_get_all()
    api_keys = await db.api_key_get_all()
    avg_ms = int(sum(_request_times) / len(_request_times)) if _request_times else 0
    errors_24h = 0
    slow_24h = 0
    log_storage_mb = 0.0
    try:
        counts = await db.request_log_24h_counts()
        errors_24h = counts["errors_24h"]
        slow_24h = counts["slow_24h"]
        storage = await db.request_log_storage_stats()
        log_storage_mb = storage["storage_mb"]
    except Exception:
        log.exception("Failed to load request log dashboard stats")
    return {
        "ok": True,
        "known_scammers_count": len(_KNOWN_SCAMMERS),
        "safe_urls_count": len(_KNOWN_SAFE_URLS),
        "scam_urls_count": len(_KNOWN_SCAM_URLS),
        "api_keys_count": len(api_keys),
        "admin_users_count": len(admin_users),
        "pending_ban_requests": len(pending_ban),
        "pending_fp_reports": len(pending_fp),
        "requests_total": _request_count,
        "avg_response_ms": avg_ms,
        "uptime_seconds": int(time.perf_counter() - _startup_time),
        "pid": os.getpid(),
        "errors_24h": errors_24h,
        "slow_24h": slow_24h,
        "log_storage_mb": log_storage_mb,
    }


@app.get("/admin/request-logs")
async def admin_list_request_logs(
    api_key: Optional[str] = None,
    endpoint_name: Optional[str] = None,
    status: Optional[int] = None,
    method: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    q: Optional[str] = None,
    slow_only: bool = False,
    errors_only: bool = False,
    auth_kind: Optional[str] = None,
    rate_limited: Optional[bool] = None,
    min_time_ms: Optional[int] = None,
    max_time_ms: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    _user: str = Depends(require_admin_auth),
):
    result = await db.request_log_list(
        api_key=api_key,
        endpoint_name=endpoint_name,
        status=status,
        method=method,
        since=_parse_log_datetime(since, "since"),
        until=_parse_log_datetime(until, "until"),
        q=q,
        slow_only=slow_only,
        errors_only=errors_only,
        auth_kind=auth_kind,
        rate_limited=rate_limited,
        min_time_ms=min_time_ms,
        max_time_ms=max_time_ms,
        limit=limit,
        offset=offset,
    )
    return {"ok": True, **result}


@app.get("/admin/request-logs/stats")
async def admin_request_log_stats(
    since: Optional[str] = None,
    until: Optional[str] = None,
    _user: str = Depends(require_admin_auth),
):
    stats = await db.request_log_stats(
        since=_parse_log_datetime(since, "since"),
        until=_parse_log_datetime(until, "until"),
    )
    return {"ok": True, **stats}


@app.get("/admin/request-logs/storage")
async def admin_request_log_storage(_user: str = Depends(require_admin_auth)):
    storage = await db.request_log_storage_stats()
    return {"ok": True, **storage}


@app.get("/admin/request-logs/export")
async def admin_request_log_export(
    api_key: Optional[str] = None,
    endpoint_name: Optional[str] = None,
    status: Optional[int] = None,
    method: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    q: Optional[str] = None,
    slow_only: bool = False,
    errors_only: bool = False,
    auth_kind: Optional[str] = None,
    rate_limited: Optional[bool] = None,
    min_time_ms: Optional[int] = None,
    max_time_ms: Optional[int] = None,
    limit: int = 10000,
    _user: str = Depends(require_admin_auth),
):
    items = await db.request_log_export(
        api_key=api_key,
        endpoint_name=endpoint_name,
        status=status,
        method=method,
        since=_parse_log_datetime(since, "since"),
        until=_parse_log_datetime(until, "until"),
        q=q,
        slow_only=slow_only,
        errors_only=errors_only,
        auth_kind=auth_kind,
        rate_limited=rate_limited,
        min_time_ms=min_time_ms,
        max_time_ms=max_time_ms,
        limit=min(limit, 50000),
    )
    body = json.dumps({"ok": True, "count": len(items), "items": items}, ensure_ascii=False)
    filename = f"request-logs-{_utc_now_z().replace(':', '-')}.json"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/admin/request-logs/{log_id}")
async def admin_get_request_log(log_id: int, _user: str = Depends(require_admin_auth)):
    row = await db.request_log_get(log_id)
    if not row:
        raise HTTPException(status_code=404, detail="Request log not found")
    return {"ok": True, "item": row}


@app.get("/admin/ban-requests")
async def admin_list_ban_requests(
    status: Optional[str] = None,
    limit: int = 100,
    _user: str = Depends(require_admin_auth),
):
    """List ban requests with optional status filter."""
    items = await db.ban_request_list(status=status, limit=limit)
    return {"ok": True, "count": len(items), "items": items}


@app.post("/admin/ban-requests/{case_id}/resolve")
async def admin_resolve_ban_request(
    case_id: str,
    body: ResolveCaseRequest,
    _user: str = Depends(require_admin_auth),
):
    """Resolve a ban request (approve/reject)."""
    return await resolve_banrequest_case(case_id, body, {"label": _user})


@app.get("/admin/fp-reports")
async def admin_list_fp_reports(
    status: Optional[str] = None,
    limit: int = 100,
    _user: str = Depends(require_admin_auth),
):
    """List false positive reports with optional status filter."""
    items = await db.fp_report_list(status=status, limit=limit)
    return {"ok": True, "count": len(items), "items": items}


@app.post("/admin/fp-reports/{case_id}/resolve")
async def admin_resolve_fp_report(
    case_id: str,
    body: ResolveCaseRequest,
    _user: str = Depends(require_admin_auth),
):
    """Resolve a false positive report."""
    return await resolve_falsepositivereport_case(case_id, body, {"label": _user})


@app.get("/admin/scammers")
async def admin_list_scammers(_user: str = Depends(require_admin_auth)):
    """List scammers."""
    scammers = await db.scammers_get_all()
    items = [{"user_id": uid, "reason": reason} for uid, reason in scammers.items()]
    return {"ok": True, "count": len(items), "items": items}


@app.post("/admin/scammers")
async def admin_add_scammer(body: RootScammerBody, request: Request, _user: str = Depends(require_admin_auth)):
    """Add a scammer (admin auth)."""
    uid = _normalize_user_id(body.user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status_code=400, detail="reason required")
    await db.scammer_upsert(uid, reason)
    await load_scammers_db()
    if maria_mirror:
        try:
            await maria_mirror.mirror_global_ban_insert(
                user_id=uid,
                reason=reason,
                banned_by_user_id=(body.banned_by_user_id or "").strip() or _user,
                source="admin_dashboard",
                report_id=(body.report_id or "").strip(),
            )
        except Exception:
            log.exception("Failed to mirror to MariaDB")
            _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="mariadb_mirror").inc()
    await _admin_audit(request, _user, "scammer_add", uid)
    return {"ok": True, "user_id": uid}


@app.delete("/admin/scammers/{user_id}")
async def admin_delete_scammer(user_id: str, request: Request, _user: str = Depends(require_admin_auth)):
    """Remove a scammer by path."""
    uid = _normalize_user_id(user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    existing = await db.scammer_get(uid)
    if not existing:
        raise HTTPException(status_code=404, detail="Scammer not found")
    await db.scammer_delete(uid)
    await load_scammers_db()
    if maria_mirror:
        try:
            await maria_mirror.mirror_global_ban_delete(uid)
        except Exception:
            log.exception("Failed to remove from MariaDB")
            _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="mariadb_mirror").inc()
    await _admin_audit(request, _user, "scammer_delete", uid)
    return {"ok": True, "user_id": uid}


class AdminUserBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)


class AdminUserPasswordBody(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)


@app.get("/admin/users")
async def admin_list_users(_user: str = Depends(require_admin_auth)):
    """List admin users (no passwords)."""
    users = await db.admin_auth_get_all()
    return {"ok": True, "count": len(users), "items": users}


@app.post("/admin/users")
async def admin_add_user(body: AdminUserBody, _user: str = Depends(require_admin_auth)):
    """Add or update an admin user."""
    username = body.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")
    await db.admin_auth_set(username, body.password)
    return {"ok": True, "username": username}


@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str, _user: str = Depends(require_admin_auth)):
    """Remove an admin user. Cannot delete last admin."""
    username = username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Invalid username")
    users = await db.admin_auth_get_all()
    if len(users) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    await db.admin_auth_delete(username)
    return {"ok": True, "username": username}


@app.patch("/admin/users/{username}/password")
async def admin_change_password(
    username: str,
    body: AdminUserPasswordBody,
    _user: str = Depends(require_admin_auth),
):
    """Change an admin user's password."""
    username = username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Invalid username")
    existing = await db.admin_auth_get(username)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    await db.admin_auth_set(username, body.password)
    return {"ok": True, "username": username}


class AdminMasterKeyBody(BaseModel):
    key: Optional[str] = None


class AdminPromptBody(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)


@app.get("/admin/master-key")
async def admin_get_master_key(_user: str = Depends(require_admin_auth)):
    """
    Return the currently configured master API key (masked), if any.
    """
    master_key = await db.master_key_get()
    return {
        "key": master_key,
        "key_masked": _mask_api_key(master_key) if master_key else None,
    }


@app.post("/admin/master-key")
async def admin_set_master_key(body: AdminMasterKeyBody, _user: str = Depends(require_admin_auth)):
    """
    Set or clear the master API key. When setting, the key must already exist
    in the normal API keys table.
    """
    key = (body.key or "").strip()
    if key:
        meta = await db.api_key_get(key)
        if not meta:
            raise HTTPException(status_code=400, detail="API key not found")
        await db.master_key_set(key)
        return {"ok": True, "key": key}

    # Clear master key
    await db.master_key_set(None)
    return {"ok": True, "key": None}


@app.get("/admin/prompt")
async def admin_get_prompt(_user: str = Depends(require_admin_auth)):
    return {"ok": True, "prompt": _scam_prompt_template}


@app.post("/admin/prompt")
async def admin_set_prompt(body: AdminPromptBody, request: Request, _user: str = Depends(require_admin_auth)):
    global _scam_prompt_template
    prompt = body.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt required")
    _scam_prompt_template = prompt
    await db.app_setting_set(_SCAM_PROMPT_SETTING_KEY, prompt)
    await _admin_audit(
        request,
        _user,
        "prompt_update",
        "scam_detection_prompt_template",
        {"length": len(prompt)},
    )
    return {"ok": True, "updated": True, "length": len(prompt)}


# ----------------------------
# Master key full-access endpoints
# ----------------------------
class RootScammerBody(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=2048)
    report_id: Optional[str] = Field(default=None, max_length=128)  # e.g. "RPT_000000"
    banned_by_user_id: Optional[str] = Field(default=None, max_length=64)  # Discord user ID (numeric) for MariaDB integer column


class UrlListBody(BaseModel):
    """Body for adding/updating a URL in the safe/scam list."""
    domain: str = Field(..., min_length=1, max_length=256)
    url_type: str = Field(..., pattern="^(safe|scam)$")
    reason: str = Field(default="", max_length=512)


class GlobalBanBody(BaseModel):
    """Body for staff global-ban: add user to global banlist and mirror to MariaDB global_bans."""
    user_id: str = Field(..., min_length=1, max_length=128)
    reason: str = Field(..., min_length=1, max_length=2048)
    report_id: Optional[str] = Field(default=None, max_length=128)
    banned_by_user_id: Optional[str] = Field(default=None, max_length=128)
    source: Optional[str] = Field(default=None, max_length=128)


@app.get("/root/api-keys")
async def root_list_api_keys(_master: str = Depends(require_master_api_key)):
    """
    List all API keys. Requires the configured master API key.
    """
    api_keys = await db.api_key_get_all()
    keys = [
        {
            "key": k,
            "key_masked": _mask_api_key(k),
            "label": m.get("label") or "",
            "expires_at": m.get("expires_at") or "",
            "bypass_ratelimit": m.get("bypass_ratelimit", False),
        }
        for k, m in api_keys.items()
    ]
    return {"keys": keys}


@app.post("/root/api-keys")
async def root_add_api_key(body: AdminAddKeyBody, _master: str = Depends(require_master_api_key)):
    """
    Create a new API key. Requires the configured master API key.
    """
    key = body.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="key required")
    existing = await db.api_key_get(key)
    if existing:
        raise HTTPException(status_code=400, detail="Key already exists")
    try:
        _parse_utc_iso_z(body.expires_at)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid expires_at (use ISO UTC, e.g. 2026-12-31T23:59:59Z)",
        )
    await db.api_key_set(
        key,
        body.expires_at.strip(),
        (body.label or "").strip(),
        bypass_ratelimit=body.bypass_ratelimit,
    )
    return {"ok": True, "key": key}


@app.patch("/root/api-keys")
async def root_update_api_key(body: AdminUpdateKeyBody, _master: str = Depends(require_master_api_key)):
    """
    Update label and/or expiry for an existing API key. Requires the master key.
    """
    key = body.key.strip()
    meta = await db.api_key_get(key)
    if not meta:
        raise HTTPException(status_code=404, detail="Key not found")
    label = meta.get("label", "").strip() if body.label is None else body.label.strip()
    expires_at = meta.get("expires_at", "") if body.expires_at is None else body.expires_at.strip()
    bypass = meta.get("bypass_ratelimit", False) if body.bypass_ratelimit is None else body.bypass_ratelimit
    if body.expires_at is not None:
        try:
            _parse_utc_iso_z(expires_at)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid expires_at")
    await db.api_key_set(key, expires_at, label, bypass_ratelimit=bypass)
    return {"ok": True}


@app.delete("/root/api-keys")
async def root_delete_api_key(body: AdminDeleteKeyBody, _master: str = Depends(require_master_api_key)):
    """
    Delete an API key. Requires the master key.
    """
    key = body.key.strip()
    if not await db.api_key_get(key):
        raise HTTPException(status_code=404, detail="Key not found")
    await db.api_key_delete(key)
    return {"ok": True}


@app.get("/root/scammers")
async def root_list_scammers(_master: str = Depends(require_master_api_key)):
    """
    List all scammers from the global banlist. Requires the master key.
    """
    scammers = await db.scammers_get_all()
    items = [{"user_id": uid, "reason": reason} for uid, reason in scammers.items()]
    return {"count": len(items), "scammers": items}


@app.post("/root/scammers")
async def root_add_scammer(body: RootScammerBody, _master: str = Depends(require_master_api_key)):
    """
    Add or update a single scammer entry in the global banlist and mirror to MariaDB global_bans. Requires the master key.
    """
    uid = _normalize_user_id(body.user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status_code=400, detail="reason required")

    # 1) Postgres first: "Global banlist" (user_id, reason only).
    await db.scammer_upsert(uid, reason)
    await load_scammers_db()
    # Verify row is in Postgres (same DB as DATABASE_URL / DB_*)
    check = await db.scammer_get(uid)
    if not check:
        log.error("Postgres write may have failed: user_id=%s not found in Global banlist after upsert (root/scammers)", uid)
        raise HTTPException(status_code=500, detail="Failed to persist ban to Postgres Global banlist")
    log.info("Added user_id=%s to Postgres Global banlist (root/scammers)", uid)

    # 2) MariaDB: global_bans (full schema). Same ban must appear in both DBs.
    if maria_mirror is None:
        log.warning("MariaDB mirror skipped for root/scammers (module not loaded). Only Postgres was updated.")
    else:
        try:
            meta = await db.api_key_get(_master)
            label = (meta.get("label") or "root_api").strip() if meta else "root_api"
            report_id_str = (body.report_id or "").strip()
            # MariaDB banned_by_user_id is INTEGER; pass numeric string from body or label (mirror stores NULL for non-numeric)
            banned_by = (body.banned_by_user_id or "").strip() or label
            await maria_mirror.mirror_global_ban_insert(
                user_id=uid,
                reason=reason,
                banned_by_user_id=banned_by,
                source="root_scammers",
                report_id=report_id_str,
            )
            log.info("Added user_id=%s to MariaDB global_bans (root/scammers)", uid)
        except Exception:
            log.exception("Failed to add user_id=%s to MariaDB global_bans (root/scammers)", uid)
            _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="mariadb_mirror").inc()

    return {"ok": True, "user_id": uid}


class RootDeleteScammerBody(BaseModel):
    """Body for DELETE /root/scammers when user_id is not in the path."""
    user_id: str = Field(..., min_length=1, max_length=128)


async def _do_root_delete_scammer(uid: str) -> None:
    """Shared delete logic: Postgres + reload cache + MariaDB mirror. Caller validates uid."""
    existing = await db.scammer_get(uid)
    if not existing:
        raise HTTPException(status_code=404, detail="Scammer not found")
    await db.scammer_delete(uid)
    await load_scammers_db()
    if maria_mirror is not None:
        try:
            await maria_mirror.mirror_global_ban_delete(uid)
        except Exception:
            log.exception("Failed to remove user_id=%s from MariaDB global_bans", uid)
            _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="mariadb_mirror").inc()


@app.delete("/root/scammers")
async def root_delete_scammer_by_body(
    _master: str = Depends(require_master_api_key),
    user_id: Optional[str] = None,  # query param: ?user_id=...
    body: Optional[RootDeleteScammerBody] = None,  # or JSON body {"user_id": "..."}
):
    """
    Remove a scammer by user_id. Accepts user_id in query (?user_id=...) or in JSON body.
    Requires the master key.
    """
    raw = (user_id or "").strip() if user_id else (body.user_id if body else "")
    uid = _normalize_user_id(raw)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid or missing user_id (use query ?user_id=... or body)")
    await _do_root_delete_scammer(uid)
    return {"ok": True, "user_id": uid}


@app.delete("/root/scammers/{user_id}")
async def root_delete_scammer(user_id: str, _master: str = Depends(require_master_api_key)):
    """
    Remove a scammer from the global banlist by user_id (in path). Requires the master key.
    """
    uid = _normalize_user_id(user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    await _do_root_delete_scammer(uid)
    return {"ok": True, "user_id": uid}


# ----------------------------
# Root: URL list (master key)
# ----------------------------
@app.get("/root/urls")
async def root_list_urls(_master: str = Depends(require_master_api_key)):
    """List all safe/scam URLs. Requires master key."""
    data = await db.url_list_get_all()
    items = [{"domain": d, "type": m["type"], "reason": m["reason"]} for d, m in data.items()]
    return {"ok": True, "count": len(items), "items": items}


@app.post("/root/urls")
async def root_add_url(body: UrlListBody, _master: str = Depends(require_master_api_key)):
    """Add or update a URL. Requires master key."""
    domain = body.domain.lower().strip()
    if not domain:
        raise HTTPException(status_code=400, detail="domain required")
    try:
        await db.url_list_upsert(domain, body.url_type, body.reason)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    await load_urls_db()
    return {"ok": True, "domain": domain}


@app.delete("/root/urls/{domain}")
async def root_delete_url(domain: str, _master: str = Depends(require_master_api_key)):
    """Remove a URL by domain. Requires master key."""
    domain = domain.lower().strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    await db.url_list_delete(domain)
    await load_urls_db()
    return {"ok": True, "domain": domain}


@app.post("/staff/signal/antiscam/global-ban")
async def staff_global_ban(body: GlobalBanBody, _master: str = Depends(require_master_api_key)):
    """
    Add a user to Postgres "Global banlist" (user_id, reason) and to MariaDB global_bans (full schema).
    Used by the staff dashboard when dispatching a global ban. Requires master API key.
    """
    uid = _normalize_user_id(body.user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    reason = (body.reason or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="reason required")

    # Postgres: its format only (user_id, reason).
    await db.scammer_upsert(uid, reason)
    await load_scammers_db()

    # MariaDB: its format (global_bans with banned_by_user_id, source, report_id, timestamps).
    if maria_mirror is not None:
        try:
            await maria_mirror.mirror_global_ban_insert(
                user_id=uid,
                reason=reason,
                banned_by_user_id=(body.banned_by_user_id or "").strip() or "staff",
                source=(body.source or "").strip() or "staff_signal",
                report_id=(body.report_id or "").strip() or "",
            )
        except Exception:
            log.exception("Failed to mirror global ban to MariaDB for user_id=%s", uid)
            _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="mariadb_mirror").inc()

    return {"ok": True, "user_id": uid}


# ----------------------------
# 2FA endpoints
# ----------------------------
@app.post("/2fa/setup")
async def twofa_setup(
    body: TwoFASetupRequest,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    user_id = _sanitize_twofa_user_id(body.user_id)
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid user_id")

    existing = await db.twofa_get_user_entry(x_api_key, user_id)
    if existing and existing.get("enabled"):
        return {"ok": True, "enabled": True, "user_id": user_id, "detail": "2FA already enabled for this user"}

    secret = _b32_secret_new()
    partner_label = _meta.get("label") or "partner"
    label = (body.label or f"{partner_label}:{user_id}").strip()[:128]

    otpauth_url = pyotp.TOTP(secret).provisioning_uri(
        name=label,
        issuer_name=TWOFA_ISSUER,
    )

    entry = {
        "enabled": False,
        "secret_base32": secret,
        "created_at": _utc_now_z(),
        "label": label,
    }
    await db.twofa_set_user_entry(x_api_key, user_id, entry)

    return {
        "ok": True,
        "enabled": False,
        "user_id": user_id,
        "issuer": TWOFA_ISSUER,
        "account": label,
        "otpauth_url": otpauth_url,
        "secret_base32": secret,
    }

@app.post("/2fa/enable")
async def twofa_enable(
    body: TwoFACodeRequest,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    user_id = _sanitize_twofa_user_id(body.user_id)
    entry = await db.twofa_get_user_entry(x_api_key, user_id)
    if not entry:
        raise HTTPException(status_code=400, detail="2FA not set up yet. Call /2fa/setup first")

    secret = entry.get("secret_base32")
    if not secret:
        raise HTTPException(status_code=500, detail="2FA secret missing for this user")

    if not _verify_totp(secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    entry["enabled"] = True
    entry["enabled_at"] = _utc_now_z()
    await db.twofa_set_user_entry(x_api_key, user_id, entry)

    return {"ok": True, "enabled": True, "user_id": user_id}

@app.post("/2fa/verify")
async def twofa_verify(
    body: TwoFACodeRequest,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    user_id = _sanitize_twofa_user_id(body.user_id)
    entry = await db.twofa_get_user_entry(x_api_key, user_id)
    if not entry or not entry.get("enabled"):
        raise HTTPException(status_code=403, detail="2FA not enabled for this user_id under this API key")

    secret = entry.get("secret_base32")
    if not secret:
        raise HTTPException(status_code=500, detail="2FA secret missing for this user")

    if not _verify_totp(secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    return {"ok": True, "valid": True, "user_id": user_id}

@app.post("/authenticate")
async def authenticate_2fa(
    body: TwoFACodeRequest,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    user_id = _sanitize_twofa_user_id(body.user_id)
    entry = await db.twofa_get_user_entry(x_api_key, user_id)
    if not entry or not entry.get("enabled"):
        raise HTTPException(status_code=403, detail="2FA not enabled for this user_id under this API key")

    secret = entry.get("secret_base32")
    if not secret:
        raise HTTPException(status_code=500, detail="2FA secret missing for this user")

    if not _verify_totp(secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    return {"ok": True, "valid": True, "user_id": user_id}

@app.get("/2fa/status")
async def twofa_status(
    user_id: str,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    uid = _sanitize_twofa_user_id(user_id)
    entry = await db.twofa_get_user_entry(x_api_key, uid)
    return {
        "ok": True,
        "user_id": uid,
        "enabled": bool(entry and entry.get("enabled")),
        "has_secret": bool(entry and entry.get("secret_base32")),
        "label": (entry.get("label") if entry else None),
    }

# ----------------------------
# Existing API endpoints
# ----------------------------
@app.get("/ready")
async def ready():
    return {"ok": True}


@app.get("/metrics")
async def metrics(authorization: Optional[str] = Header(None)):
    """Prometheus scrape endpoint. Gated by METRICS_TOKEN (Bearer token), not public."""
    if not METRICS_TOKEN:
        raise HTTPException(status_code=503, detail="Metrics not configured (set METRICS_TOKEN)")
    expected = f"Bearer {METRICS_TOKEN}"
    if not authorization or authorization != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/health")
async def health():
    """Public health check (no API key). Use for load balancers / k8s; logs as caller=no_key."""
    twofa_data = await db.twofa_get_all_keys_users()
    total_users = sum(len((rec or {}).get("users") or {}) for rec in twofa_data.values())
    enabled_users = 0
    for rec in twofa_data.values():
        users = (rec or {}).get("users") or {}
        enabled_users += sum(1 for u in users.values() if isinstance(u, dict) and u.get("enabled"))

    return {
        "ok": True,
        "db_loaded": True,
        "known_scammers_count": len(_KNOWN_SCAMMERS),
        "twofa_keys_count": len(twofa_data),
        "twofa_users_count": total_users,
        "twofa_enabled_users_count": enabled_users,
        "utc": _utc_now_z(),
    }

@app.post("/banrequest")
async def ban_request(
    request: Request,
    user_id: str = Form(...),
    reason: str = Form(...),
    notes: str = Form(""),
    proof: UploadFile = File(...),
    _meta: dict = Depends(require_api_key),
):
    uid = _normalize_user_id(user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")

    ext = _safe_ext(proof.filename or "")
    if not ext:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    max_bytes = 10 * 1024 * 1024
    proof_chunks: List[bytes] = []
    written = 0
    while True:
        chunk = await proof.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > max_bytes:
            raise HTTPException(status_code=413, detail="File too large (max 10MB)")
        proof_chunks.append(chunk)
    proof_bytes = b"".join(proof_chunks)
    proof_filename = proof.filename or f"proof{ext}"

    case_id = uuid.uuid4().hex[:12].upper()

    proof_url = await upload_banreport_proof_to_interna(
        proof_bytes=proof_bytes,
        proof_filename=proof_filename,
        case_id=case_id,
        session=request.app.state.http_session,
    )

    record = {
        "case_id": case_id,
        "created_at": _utc_now_z(),
        "user_id": uid,
        "reason": reason.strip(),
        "notes": notes.strip(),
        "proof_original_name": proof.filename,
        "reporter_meta": _meta,  # dict -> JSONB
        "status": "pending",
    }
    if proof_url:
        record["proof_url"] = proof_url

    await db.ban_request_insert(record)

    await post_banrequest_to_discord_webhook(
        case_id=case_id,
        uid=uid,
        reason=reason.strip(),
        notes=notes.strip(),
        proof_bytes=proof_bytes,
        proof_filename=proof_filename,
        session=request.app.state.http_session,
    )

    return {"ok": True, "case_id": case_id}

@app.post("/ticket-audit/register")
async def ticket_audit_register(
    body: TicketAuditRegisterRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    _meta: dict = Depends(require_api_key),
):
    await db.ticket_audit_claim_purge_expired()

    seen: Set[str] = set()
    normalized: List[str] = []
    for raw in body.discord_ids:
        if raw is None:
            continue
        s = str(raw).strip()
        if not s:
            continue
        uid = _normalize_user_id(s)
        if uid and uid not in seen:
            seen.add(uid)
            normalized.append(uid)
    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="No valid discord_ids: all entries were blank or invalid",
        )

    audit_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=TICKET_AUDIT_TTL_DAYS)
    store_label = (body.store or "").strip() or None
    server_id = _normalize_user_id(body.server_id or "")
    server_id_val: Optional[str] = server_id if server_id else None
    giveaway_key = (body.giveaway_key or "").strip() or None

    await db.ticket_audit_insert(
        audit_id,
        x_api_key,
        store_label,
        server_id_val,
        giveaway_key,
        normalized,
        now,
        expires_at,
    )

    out_reg: Dict[str, Any] = {
        "audit_id": audit_id,
        "expires_at": _datetime_to_iso_z(expires_at),
    }
    if server_id_val is not None:
        out_reg["server_id"] = server_id_val
    if giveaway_key is not None:
        out_reg["giveaway_key"] = giveaway_key
    return out_reg


@app.post("/ticket-audit/verify")
async def ticket_audit_verify(
    body: TicketAuditVerifyRequest,
    x_api_key: str = Header(..., alias="X-API-Key"),
    _meta: dict = Depends(require_api_key),
):
    await db.ticket_audit_claim_purge_expired()

    aid = body.audit_id.strip()
    session = await db.ticket_audit_get(aid, x_api_key)
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found or expired")

    sess_server = session.get("server_id")
    if sess_server:
        verify_sid = _normalize_user_id(body.server_id or "")
        if not verify_sid or verify_sid != sess_server:
            raise HTTPException(
                status_code=400,
                detail="server_id is required and must match this audit session",
            )

    raw_discord = body.discord_id
    if raw_discord is None or not str(raw_discord).strip():
        raise HTTPException(status_code=400, detail="discord_id cannot be blank")

    uid = _normalize_user_id(str(raw_discord))
    if not uid:
        raise HTTPException(
            status_code=400,
            detail="discord_id must contain a valid numeric Discord user ID",
        )

    delay = max(0.0, TICKET_AUDIT_DELAY_SEC)
    await asyncio.sleep(delay)

    lookup = _lookup_user_dict(uid, include_reason=body.include_reason)
    allowed = set(session["discord_ids"])
    id_match = uid in allowed

    claim = await db.ticket_audit_claim_get_active(aid, x_api_key, uid)
    if claim:
        ra = claim["resolved_at"]
        rt = claim["retain_until"]
        ra_out = _datetime_to_iso_z(ra) if isinstance(ra, datetime) else None
        rt_out = _datetime_to_iso_z(rt) if isinstance(rt, datetime) else None
        ac: Dict[str, Any] = {
            "audit_id": aid,
            "id_match": id_match,
            "already_claimed": True,
            "message": "This ID has already been claimed",
            "user_id": uid,
            "lookup": lookup,
            "resolved_at": ra_out,
            "retain_until": rt_out,
        }
        if session.get("giveaway_key") is not None:
            ac["giveaway_key"] = session["giveaway_key"]
        return ac

    out: Dict[str, Any] = {
        "audit_id": aid,
        "id_match": id_match,
        "user_id": uid,
        "lookup": lookup,
    }
    if session.get("giveaway_key") is not None:
        out["giveaway_key"] = session["giveaway_key"]

    if not id_match:
        out["message"] = "Ids do not match. Checking user."
        return out

    now = datetime.now(timezone.utc)
    retain_until = now + timedelta(days=TICKET_AUDIT_CLAIM_RETENTION_DAYS)
    inserted = await db.ticket_audit_claim_try_insert(
        aid, x_api_key, uid, now, retain_until
    )
    if not inserted:
        claim2 = await db.ticket_audit_claim_get_active(aid, x_api_key, uid)
        if claim2:
            ra = claim2["resolved_at"]
            rt = claim2["retain_until"]
            ra_out = _datetime_to_iso_z(ra) if isinstance(ra, datetime) else None
            rt_out = _datetime_to_iso_z(rt) if isinstance(rt, datetime) else None
            race: Dict[str, Any] = {
                "audit_id": aid,
                "id_match": True,
                "already_claimed": True,
                "message": "This ID has already been claimed",
                "user_id": uid,
                "lookup": lookup,
                "resolved_at": ra_out,
                "retain_until": rt_out,
            }
            if session.get("giveaway_key") is not None:
                race["giveaway_key"] = session["giveaway_key"]
            return race
        return {
            "audit_id": aid,
            "id_match": True,
            "already_claimed": True,
            "message": "This ID has already been claimed",
            "user_id": uid,
            "lookup": lookup,
        }

    out["claimed"] = True
    out["resolved_at"] = _datetime_to_iso_z(now)
    out["retain_until"] = _datetime_to_iso_z(retain_until)
    return out


@app.get("/lookup/{user_id}")
async def lookup_user(
    user_id: str,
    include_reason: bool = False,
    _meta: dict = Depends(require_api_key),
):
    uid = _normalize_user_id(user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")

    return _lookup_user_dict(uid, include_reason=include_reason)

@app.post("/lookup")
async def lookup_batch(req: BatchLookupRequest, _meta: dict = Depends(require_api_key)):
    results: List[Dict[str, Any]] = []
    for raw in req.user_ids:
        uid = _normalize_user_id(raw)
        if not uid:
            results.append({"user_id": str(raw), "is_flagged": False, "error": "invalid_user_id"})
            continue
        results.append(_lookup_user_dict(uid, include_reason=req.include_reason))
    return {"count": len(results), "results": results}

@app.post("/canonicalize")
async def canonicalize(req: DetectRequest, _meta: dict = Depends(require_api_key)):
    return canonicalize_for_scam_scan(req.message)


@app.post("/url-check")
async def url_check(req: UrlCheckRequest, _meta: dict = Depends(require_api_key)):
    """Fast URL lookup against safe/scam DB. No Ollama. Returns status per URL."""
    results: List[Dict[str, Any]] = []
    for raw_url in req.urls:
        domains = extract_urls_from_text(raw_url)
        if not domains:
            results.append({"url": raw_url, "domain": None, "status": "unknown"})
            continue
        domain = domains[0]
        if domain in _KNOWN_SCAM_URLS:
            results.append({"url": raw_url, "domain": domain, "status": "scam", "reason": _KNOWN_SCAM_URLS.get(domain, "")})
        elif domain in _KNOWN_SAFE_URLS:
            results.append({"url": raw_url, "domain": domain, "status": "safe"})
        else:
            results.append({"url": raw_url, "domain": domain, "status": "unknown"})
    return {"ok": True, "count": len(results), "items": results}

@app.post("/banrequest/{case_id}/resolve")
async def resolve_banrequest_case(
    case_id: str,
    body: ResolveCaseRequest,
    _meta: dict = Depends(require_api_key),
):
    action = body.action.strip().lower()
    if action not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="action must be approve or reject")

    data = await db.ban_request_get(case_id)
    if not data:
        raise HTTPException(status_code=404, detail="Case not found")

    status_val = "approved" if action == "approve" else "rejected"
    review = {
        "reviewed_at": _utc_now_z(),
        "reviewed_by": _meta.get("label") or "unknown",
        "decision": body.decision_note.strip() or ("Approved" if action == "approve" else "Rejected"),
    }
    await db.ban_request_update_status(case_id, status_val, review)

    # When approving: add user to Global banlist so lookup returns "Flagged", and refresh in-memory cache.
    # Also mirror this approval into the external MariaDB `global_bans` table (if configured).
    if action == "approve":
        uid = _normalize_user_id(data.get("user_id") or "")
        if uid:
            base_reason = (data.get("reason") or "").strip() or f"Approved ban request {data.get('case_id', case_id)}"
            reason_text = base_reason
            if body.decision_note and body.decision_note.strip():
                reason_text = f"{base_reason} — {body.decision_note.strip()}"

            # Postgres: "Global banlist" (user_id, reason only). MariaDB: global_bans (full schema) below.
            await db.scammer_upsert(uid, reason_text)
            await load_scammers_db()
            log.info("Added user %s to Global banlist after ban request approval (case_id=%s)", uid, case_id)

            # MariaDB: global_bans (user_id, reason, banned_by_user_id, source, report_id, created_at, updated_at).
            # Best-effort; does not change Postgres.
            if maria_mirror is None:
                log.warning(
                    "MariaDB mirroring not available (maria_mirror module not loaded). "
                    "Install aiomysql and set MARIADB_* env vars to mirror bans to MariaDB."
                )
            else:
                try:
                    await maria_mirror.mirror_global_ban_insert(
                        user_id=uid,
                        reason=reason_text,
                        banned_by_user_id=str(_meta.get("label") or "unknown"),
                        source="antiscammer_banrequest",
                        report_id=str(data.get("case_id") or case_id),
                    )
                except Exception:
                    log.exception("Failed to mirror global ban to MariaDB for user_id=%s case_id=%s", uid, case_id)
                    _METRIC_EXTERNAL_FAILURES_TOTAL.labels(component="mariadb_mirror").inc()

    return {"ok": True, "case_id": data["case_id"], "status": status_val}

@app.post("/detect")
async def detect(req: DetectRequest, request: Request, _meta: dict = Depends(require_api_key)):
    session = request.app.state.http_session
    ctx = [c.model_dump() for c in req.context_messages] if req.context_messages else None
    return await detect_scam(req.message, ctx, session=session)

@app.get("/banrequest/{case_id}")
async def get_banrequest_case(case_id: str, _meta: dict = Depends(require_api_key)):
    data = await db.ban_request_get(case_id)
    if not data:
        raise HTTPException(status_code=404, detail="Case not found")
    return data

# ----------------------------
# False positive report
# ----------------------------
@app.post("/falsepositivereport")
async def false_positive_report(
    request: Request,
    user_id: str = Form(...),
    reason: str = Form(...),
    notes: str = Form(""),
    proof: UploadFile = File(...),
    _meta: dict = Depends(require_api_key),
):
    uid = _normalize_user_id(user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")

    ext = _safe_ext(proof.filename or "")
    if not ext:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    max_bytes = 10 * 1024 * 1024
    proof_chunks: List[bytes] = []
    written = 0
    while True:
        chunk = await proof.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > max_bytes:
            raise HTTPException(status_code=413, detail="File too large (max 10MB)")
        proof_chunks.append(chunk)
    proof_bytes = b"".join(proof_chunks)
    proof_filename = proof.filename or f"proof{ext}"

    case_id = uuid.uuid4().hex[:12].upper()

    proof_url = await upload_banreport_proof_to_interna(
        proof_bytes=proof_bytes,
        proof_filename=proof_filename,
        case_id=case_id,
        session=request.app.state.http_session,
    )

    record = {
        "case_id": case_id,
        "created_at": _utc_now_z(),
        "user_id": uid,
        "reason": reason.strip(),
        "notes": notes.strip(),
        "proof_original_name": proof.filename,
        "reporter_meta": _meta,  # dict -> JSONB
        "status": "pending",
    }
    if proof_url:
        record["proof_url"] = proof_url

    await db.fp_report_insert(record)

    await post_falsepositivereport_to_discord_webhook(
        case_id=case_id,
        uid=uid,
        reason=reason.strip(),
        notes=notes.strip(),
        proof_bytes=proof_bytes,
        proof_filename=proof_filename,
        session=request.app.state.http_session,
    )

    return {"ok": True, "case_id": case_id}

@app.post("/falsepositivereport/{case_id}/resolve")
async def resolve_falsepositivereport_case(
    case_id: str,
    body: ResolveCaseRequest,
    _meta: dict = Depends(require_api_key),
):
    action = body.action.strip().lower()
    if action not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="action must be approve or reject")

    data = await db.fp_report_get(case_id)
    if not data:
        raise HTTPException(status_code=404, detail="Case not found")

    status_val = "approved" if action == "approve" else "rejected"
    review = {
        "reviewed_at": _utc_now_z(),
        "reviewed_by": _meta.get("label") or "unknown",
        "decision": body.decision_note.strip() or ("Approved" if action == "approve" else "Rejected"),
    }
    await db.fp_report_update_status(case_id, status_val, review)
    return {"ok": True, "case_id": data["case_id"], "status": status_val}

@app.get("/falsepositivereport/{case_id}")
async def get_falsepositivereport_case(case_id: str, _meta: dict = Depends(require_api_key)):
    data = await db.fp_report_get(case_id)
    if not data:
        raise HTTPException(status_code=404, detail="Case not found")
    return data

@app.get("/")
def root():
    return JSONResponse(status_code=404, content={"detail": "Not found"})

@app.get("/robots.txt")
def robots_txt():
    return PlainTextResponse("User-agent: *\nDisallow: /\n")