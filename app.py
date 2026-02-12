# app.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional

import aiohttp
import pyotp
from dotenv import load_dotenv

load_dotenv()
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
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from starlette.requests import Request

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
# Config
# ----------------------------
DISCORD_WEBHOOK_URL = "https://ptb.discord.com/api/webhooks/1461018711778529438/CtIih5nJmUyHGT_BXwN-LNU4cDPbojcxkr1i7Ri28NBiQ5OE61SVPZ8pWx5vQgUZa0Yi"

OLLAMA_BASE_URL = "https://ollama.com/api"
OLLAMA_API_KEY = "f898de33fc0c4bd594308d8dcb133c4e.YMyG_NSTlypAEst3mTpQrh_f"
OLLAMA_MODEL = "gpt-oss:20b-cloud"

# ----------------------------
# Paths / Storage
# ----------------------------
SCAMMERS_DB_PATH = Path(__file__).with_name("Scammers.json")
BANREQ_DIR = Path("data") / "ban_requests"
BANREQ_DIR.mkdir(parents=True, exist_ok=True)

# 2FA (Google Authenticator/Authy/etc) JSON store
TWOFA_DB_PATH = Path(__file__).with_name("TwoFA.json")
TWOFA_ISSUER = "AntiScammer"

# API keys (managed via admin UI)
API_KEYS_PATH = Path(__file__).with_name("api_keys.json")
_API_KEYS_LOCK = asyncio.Lock()

# Admin UI login (user + pass; edit admin_auth.json to change)
ADMIN_AUTH_PATH = Path(__file__).with_name("admin_auth.json")
_ADMIN_CREDS: Dict[str, str] = {}  # username -> password (loaded at startup)
_admin_auth_scheme = HTTPBasic()

# Ban report proof upload — matches Laravel CDNUploadService (CDN expects "files" + X-Internal-Token)
BAN_REPORT_UPLOAD_URL = (os.getenv("BAN_REPORT_UPLOAD_URL") or os.getenv("baseurl") or "").strip()
BAN_REPORT_UPLOAD_TOKEN = (os.getenv("BAN_REPORT_UPLOAD_TOKEN") or os.getenv("X-Internal-Token") or "").strip()
BAN_REPORT_CDN_USER = (os.getenv("CDN_USERNAME") or "").strip()
BAN_REPORT_CDN_PASS = (os.getenv("CDN_PASSWORD") or "").strip()

# ----------------------------
# In-memory caches + locks
# ----------------------------
_SCAMMERS_RAW: Dict[str, Any] = {}
_KNOWN_SCAMMERS: Dict[str, str] = {}  # user_id -> reason
_DB_LOCK = asyncio.Lock()

_TWOFA_RAW: Dict[str, Any] = {}
# NEW SHAPE:
# _TWOFA = {
#   "<api_key>": { "users": { "<user_id>": {enabled, secret_base32, ...}, ... } }
# }
_TWOFA: Dict[str, Dict[str, Any]] = {}
_TWOFA_LOCK = asyncio.Lock()

# ----------------------------
# API Keys (with expiry) — loaded from api_keys.json
# ----------------------------
API_KEYS: Dict[str, Dict[str, Any]] = {}

def _default_api_keys() -> Dict[str, Dict[str, Any]]:
    """Default keys used when api_keys.json is missing (first run)."""
    return {
        "ATSM-GLTW-KYPE-B239": {"expires_at": "2026-05-28T23:59:59Z", "label": "Antiscammer Review team"},
        "antiscammer-internal-KEY-456": {"expires_at": "2026-06-30T23:59:59Z", "label": "internal service"},
        "ATSM-GLTW-KYPE-B96F": {"expires_at": "3072-12-31T23:59:59Z", "label": "SassGuard"},
        "ATSM-QI5H-CG8M-2065": {"expires_at": "3072-12-31T23:59:59Z", "label": "FZ vouch"},
        "ATSM-8R5H-5Z6L-151D": {"expires_at": "2026-05-28T23:59:59Z", "label": "Modora"},
        "ATSM-YJC4-CDAF-227D": {"expires_at": "3072-12-31T23:59:59Z", "label": "Modora Dev"},
        "Test-key-123-456": {"expires_at": "3072-12-31T23:59:59Z", "label": "test"},
        "ATSM-C2S4-A2S4-F5S5": {"expires_at": "2026-04-15T23:59:59Z", "label": "draakjekevin"},
    }

def load_api_keys() -> None:
    global API_KEYS
    if not API_KEYS_PATH.exists():
        API_KEYS = _default_api_keys()
        save_api_keys_sync()
        log.info("Created api_keys.json with default keys")
        return
    try:
        data = json.loads(API_KEYS_PATH.read_text(encoding="utf-8"))
        API_KEYS = data if isinstance(data, dict) else {}
        log.info("Loaded %d API keys from api_keys.json", len(API_KEYS))
    except Exception:
        log.exception("Failed to load API keys, using defaults")
        API_KEYS = _default_api_keys()

def save_api_keys_sync() -> None:
    API_KEYS_PATH.write_text(
        json.dumps(API_KEYS, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

async def save_api_keys_async() -> None:
    async with _API_KEYS_LOCK:
        save_api_keys_sync()

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

def _normalize_user_id(user_id: str) -> str:
    return re.sub(r"\D+", "", user_id or "")

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
    """Generate a new API key in ATSM-XXXX-XXXX-XXXX form."""
    part = lambda: "".join(__import__("random").choices("0123456789ABCDEF", k=4))
    return f"ATSM-{part()}-{part()}-{part()}"

async def require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    meta = API_KEYS.get(x_api_key)
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

def load_admin_auth() -> None:
    global _ADMIN_CREDS
    if not ADMIN_AUTH_PATH.exists():
        _ADMIN_CREDS = {"admin": "changeme"}
        ADMIN_AUTH_PATH.write_text(
            json.dumps({"username": "admin", "password": "changeme"}, indent=2),
            encoding="utf-8",
        )
        log.warning("Created admin_auth.json with default admin/changeme — change it!")
        return
    try:
        data = json.loads(ADMIN_AUTH_PATH.read_text(encoding="utf-8"))
        u = (data.get("username") or "admin").strip()
        p = (data.get("password") or "").strip()
        if not u or not p:
            _ADMIN_CREDS = {"admin": "changeme"}
            log.warning("admin_auth.json invalid; using admin/changeme")
        else:
            _ADMIN_CREDS = {u: p}
    except Exception:
        log.exception("Failed to load admin_auth.json")
        _ADMIN_CREDS = {"admin": "changeme"}

def require_admin_auth(credentials: HTTPBasicCredentials = Depends(_admin_auth_scheme)) -> str:
    """Validate admin username/password; raise 401 if invalid."""
    p = _ADMIN_CREDS.get(credentials.username)
    if not p or p != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin login",
            headers={"WWW-Authenticate": "Basic realm=\"Admin\""},
        )
    return credentials.username

# ----------------------------
# 2FA (Google/Authy) DB + helpers
# ----------------------------
def _b32_secret_new() -> str:
    raw = token_urlsafe(32).encode("utf-8")
    return base64.b32encode(raw).decode("utf-8").replace("=", "")

def _verify_totp(secret_b32: str, code: str) -> bool:
    # valid_window=1 allows +/- 30 seconds drift (one step)
    totp = pyotp.TOTP(secret_b32)
    return bool(totp.verify(code.strip().replace(" ", ""), valid_window=1))

def _sanitize_twofa_user_id(user_id: str) -> str:
    # Partner user IDs can be anything stable; keep safe printable + trimmed.
    # (Do NOT force digits; these are *their* internal user IDs)
    uid = (user_id or "").strip()
    uid = re.sub(r"\s+", " ", uid)
    return uid[:128]

def _twofa_get_users_for_key(api_key: str) -> Dict[str, Any]:
    key_rec = _TWOFA.get(api_key)
    if not key_rec or not isinstance(key_rec, dict):
        key_rec = {"users": {}}
        _TWOFA[api_key] = key_rec
    users = key_rec.get("users")
    if not isinstance(users, dict):
        users = {}
        key_rec["users"] = users
    return users

def _twofa_get_user_entry(api_key: str, user_id: str) -> Optional[Dict[str, Any]]:
    users = _twofa_get_users_for_key(api_key)
    return users.get(user_id)

def _twofa_set_user_entry(api_key: str, user_id: str, entry: Dict[str, Any]) -> None:
    users = _twofa_get_users_for_key(api_key)
    users[user_id] = entry

def _migrate_twofa_shape_inplace() -> bool:
    """
    Backward compat:
    Old shape per key:
      _TWOFA[api_key] = {enabled, secret_base32, label, ...}
    New shape:
      _TWOFA[api_key] = {"users": {"default": {...}}}
    Returns True if changed.
    """
    changed = False
    for api_key, rec in list(_TWOFA.items()):
        if not isinstance(rec, dict):
            _TWOFA[api_key] = {"users": {}}
            changed = True
            continue

        if "users" in rec and isinstance(rec.get("users"), dict):
            continue  # already new

        # looks like old flat entry
        if "secret_base32" in rec or "enabled" in rec:
            default_user = rec.get("user_id") or "default"
            default_user = _sanitize_twofa_user_id(str(default_user))
            _TWOFA[api_key] = {"users": {default_user: rec}}
            changed = True
        else:
            # unknown record -> normalize
            _TWOFA[api_key] = {"users": {}}
            changed = True

    return changed

def load_twofa_db() -> None:
    global _TWOFA_RAW, _TWOFA
    if not TWOFA_DB_PATH.exists():
        _TWOFA_RAW = {"keys": {}}
        _TWOFA = {}
        return
    try:
        _TWOFA_RAW = json.loads(TWOFA_DB_PATH.read_text(encoding="utf-8")) or {}
        ks = _TWOFA_RAW.get("keys", {})
        _TWOFA = ks if isinstance(ks, dict) else {}

        # migrate old shape to new on load
        if _migrate_twofa_shape_inplace():
            log.info("TwoFA.json migrated to per-user shape")
    except Exception:
        log.exception("Failed to load TwoFA DB")
        _TWOFA_RAW = {"keys": {}}
        _TWOFA = {}

def _twofa_file_write_with_lock() -> None:
    """Write TwoFA.json under a file lock so only one writer at a time (e.g. multi-process safe)."""
    lock_path = TWOFA_DB_PATH.with_suffix(TWOFA_DB_PATH.suffix + ".lock")
    import time as _time
    deadline = _time.monotonic() + 15.0
    while _time.monotonic() < deadline:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                fd = -1
                _TWOFA_RAW["keys"] = _TWOFA
                TWOFA_DB_PATH.write_text(
                    json.dumps(_TWOFA_RAW, ensure_ascii=False, indent=4, sort_keys=True),
                    encoding="utf-8",
                )
                return
            finally:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except Exception:
                        pass
                try:
                    lock_path.unlink(missing_ok=True)
                except Exception:
                    pass
            return
        except FileExistsError:
            _time.sleep(0.05)
            continue
    raise RuntimeError("Could not acquire TwoFA.json write lock within 15s")

async def save_twofa_db() -> None:
    async with _TWOFA_LOCK:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _twofa_file_write_with_lock)

# ----------------------------
# Scammers DB
# ----------------------------
def load_scammers_db() -> None:
    global _SCAMMERS_RAW, _KNOWN_SCAMMERS
    if not SCAMMERS_DB_PATH.exists():
        _SCAMMERS_RAW = {"known_scammers": {}}
        _KNOWN_SCAMMERS = {}
        return
    try:
        _SCAMMERS_RAW = json.loads(SCAMMERS_DB_PATH.read_text(encoding="utf-8")) or {}
        ks = _SCAMMERS_RAW.get("known_scammers", _SCAMMERS_RAW)
        if not isinstance(ks, dict):
            ks = {}

        clean: Dict[str, str] = {}
        for k, v in ks.items():
            nk = _normalize_user_id(str(k).strip())
            if not nk:
                continue
            clean[nk] = str(v).strip()

        _KNOWN_SCAMMERS = clean
        _SCAMMERS_RAW["known_scammers"] = _KNOWN_SCAMMERS
        log.info("Loaded %d known scammers", len(_KNOWN_SCAMMERS))
    except Exception:
        log.exception("Failed to load scammers DB")
        _SCAMMERS_RAW = {"known_scammers": {}}
        _KNOWN_SCAMMERS = {}

async def save_scammers_db() -> None:
    # Scammers.json is read-only on this server; it is updated externally and synced via secure transport.
    log.debug("save_scammers_db skipped (Scammers.json is managed externally)")

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
    else:
        async with aiohttp.ClientSession() as fallback:
            async with fallback.post(DISCORD_WEBHOOK_URL, data=data) as resp:
                if resp.status >= 300:
                    body = await resp.text()
                    log.warning("Webhook post failed: %s %s", resp.status, body[:500])

async def upload_banreport_proof_to_interna(
    *,
    proof_bytes: bytes,
    proof_filename: str,
    case_id: str,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[str]:
    """Upload ban report proof to CDN; returns proof URL if successful, else None."""
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
        return None

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

    prompt = f"""You are a classifier that detects Discord scam messages.
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

If ANYTHING in the message says "SQL" or "DB" or any other database and does not have other indicators thats a hard 100% not scam


User offering free food is not a scam

Saying a user needs a token is not a scam. Asking for a discord token or key is a scam

"Setting up groups" Is just someone configering a plugin or a tool. NOT A SCAM

Someone stating they have existing tickets or coins is not a scam

Support is a thing. If someone is trying to help a user and asking for lua files or remote connection. Thats not a scam. Thats support

Anything related to a admin menu is not a scam.

if someone is encouraging someone to buy anything named quazar x its safe. Quazar is a fivem addon seller.

If one of the links listed below is in the message @ there are no other indecators. Its not a scam
modora.xyz
sassguard.app
antiscammer.app
google.com
bing.com


Bot commands MUST BE IGNORED. Commands for example are -dep , !dep , !ban , --help, -Msg and more

Inputs Provided:
{context_block or "[no context]"}

Current Message (RAW):
{canon["raw"]}

Current Message (CLEANED):
{canon["clean"]}

Reconstructed if vertical text:
{canon["joined"] or "[not detected]"}

Obfuscation stats:
looks_vertical: {ob["looks_vertical"]}
line_count: {ob["line_count"]}
single_char_line_ratio: {ob["single_char_line_ratio"]}
whitespace_ratio: {ob["whitespace_ratio"]}
"""

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

    url = f"{OLLAMA_BASE_URL}/generate"

    try:
        async with session.post(
            url,
            headers=headers,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            if resp.status != 200:
                raw_txt = await resp.text()
                log.warning("[OLLAMA ERROR] %s: %s", resp.status, raw_txt[:500])
                return {
                    "is_scam": force_scam,
                    "decision": "scam" if force_scam else "uncertain",
                    "uncertain": not force_scam,
                    "confidence": None,
                    "reason": "API error",
                    "obfuscation": ob,
                }
            data = await resp.json()
    except Exception as e:
        log.warning("[OLLAMA EXCEPTION] %s", e)
        return {
            "is_scam": force_scam,
            "decision": "scam" if force_scam else "uncertain",
            "uncertain": not force_scam,
            "confidence": None,
            "reason": "Exception occurred",
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
    is_scam = (decision == "scam")  # your rule: uncertain does not flag

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

class ContextItem(BaseModel):
    created_at: Optional[str] = Field(default=None, description="ISO timestamp")
    author: str = "unknown"
    content: str = ""

class DetectRequest(BaseModel):
    message: str
    context_messages: Optional[List[ContextItem]] = None

class ResolveCaseRequest(BaseModel):
    action: str  # "approve" or "reject"
    decision_note: str = ""

# Multi-user 2FA requests
class TwoFASetupRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=128)
    label: Optional[str] = Field(default=None, max_length=128)

class TwoFACodeRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=128)
    code: str = Field(..., min_length=6, max_length=10)

# ----------------------------
# FastAPI app + middleware
# ----------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load API keys, admin auth, DBs, and create shared HTTP session
    load_api_keys()
    load_admin_auth()
    load_scammers_db()
    load_twofa_db()
    await save_twofa_db()
    log.info("LOAD PID=%s scammers_loaded=%d api_keys=%d", os.getpid(), len(_KNOWN_SCAMMERS), len(API_KEYS))
    log.info("2FA keys loaded=%d", len(_TWOFA))
    timeout = aiohttp.ClientTimeout(total=20)
    app.state.http_session = aiohttp.ClientSession(timeout=timeout)
    try:
        yield
    finally:
        await app.state.http_session.close()
        log.info("HTTP session closed")

app = FastAPI(title="AntiScammer Local API (Keyed)", lifespan=lifespan)
log.info("API booting...")

def _caller_label(request: Request) -> str:
    """Resolve API key to label for logging (no_key, invalid_key, or label)."""
    key = request.headers.get("X-API-Key")
    if not key:
        return "no_key"
    meta = API_KEYS.get(key)
    if not meta:
        return "invalid_key"
    return (meta.get("label") or "unnamed")[:32]

@app.middleware("http")
async def request_id_and_timing_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    start = time.perf_counter()
    caller = _caller_label(request)
    method = request.method
    path = request.url.path or "/"

    try:
        response = await call_next(request)
    except HTTPException as e:
        response = JSONResponse(status_code=e.status_code, content={"detail": e.detail, "request_id": request_id})
    except Exception as e:
        log.exception("Unhandled exception: %s", e)
        response = JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": request_id})

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time-Ms"] = str(elapsed_ms)
    status_code = getattr(response, "status_code", 0) or 0
    log.info("call method=%s path=%s status=%s time_ms=%s caller=%s request_id=%s", method, path, status_code, elapsed_ms, caller, request_id)
    return response

# ----------------------------
# Admin: API key management (protected by user/pass in admin_auth.json)
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
  <script src="/admin/admin.js"></script>
  
</div>
</body>
</html>
"""

@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    return HTMLResponse(ADMIN_HTML)

@app.get("/admin/admin.js")
async def admin_js():
    """Serve admin JS externally (CSP-friendly)."""
    js_path = Path(__file__).with_name("admin.js")
    return Response(content=js_path.read_text(encoding="utf-8"), media_type="application/javascript")

@app.get("/admin/keys")
async def admin_list_keys(_user: str = Depends(require_admin_auth)):
    keys = [
        {"key": k, "key_masked": _mask_api_key(k), "label": m.get("label") or "", "expires_at": m.get("expires_at") or ""}
        for k, m in API_KEYS.items()
    ]
    return {"keys": keys}

@app.get("/admin/generate-key")
async def admin_generate_key(_user: str = Depends(require_admin_auth)):
    return {"key": _generate_api_key()}

class AdminAddKeyBody(BaseModel):
    key: str = Field(..., min_length=4)
    label: str = ""
    expires_at: str = "3072-12-31T23:59:59Z"

@app.post("/admin/keys")
async def admin_add_key(body: AdminAddKeyBody, _user: str = Depends(require_admin_auth)):
    key = body.key.strip()
    if not key:
        raise HTTPException(status_code=400, detail="key required")
    if key in API_KEYS:
        raise HTTPException(status_code=400, detail="Key already exists")
    try:
        _parse_utc_iso_z(body.expires_at)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid expires_at (use ISO UTC, e.g. 2026-12-31T23:59:59Z)")
    API_KEYS[key] = {"expires_at": body.expires_at.strip(), "label": (body.label or "").strip()}
    await save_api_keys_async()
    return {"ok": True, "key": key}

class AdminUpdateKeyBody(BaseModel):
    key: str = Field(..., min_length=4)
    label: Optional[str] = None
    expires_at: Optional[str] = None

@app.patch("/admin/keys")
async def admin_update_key(body: AdminUpdateKeyBody, _user: str = Depends(require_admin_auth)):
    key = body.key.strip()
    if key not in API_KEYS:
        raise HTTPException(status_code=404, detail="Key not found")
    if body.label is not None:
        API_KEYS[key]["label"] = body.label.strip()
    if body.expires_at is not None:
        try:
            _parse_utc_iso_z(body.expires_at)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid expires_at")
        API_KEYS[key]["expires_at"] = body.expires_at.strip()
    await save_api_keys_async()
    return {"ok": True}

class AdminDeleteKeyBody(BaseModel):
    key: str = Field(..., min_length=4)

@app.delete("/admin/keys")
async def admin_delete_key(body: AdminDeleteKeyBody, _user: str = Depends(require_admin_auth)):
    key = body.key.strip()
    if key not in API_KEYS:
        raise HTTPException(status_code=404, detail="Key not found")
    del API_KEYS[key]
    await save_api_keys_async()
    return {"ok": True}

@app.post("/admin/reload-scammers")
async def admin_reload_scammers(_user: str = Depends(require_admin_auth)):
    load_scammers_db()
    return {"ok": True, "known_scammers_count": len(_KNOWN_SCAMMERS)}

# ----------------------------
# 2FA endpoints (Google/Authy side)
# Partner must send user_id (their internal user)
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

    existing = _twofa_get_user_entry(x_api_key, user_id)
    if existing and existing.get("enabled"):
        return {"ok": True, "enabled": True, "user_id": user_id, "detail": "2FA already enabled for this user"}

    secret = _b32_secret_new()

    partner_label = _meta.get("label") or "partner"
    # Name shown inside authenticator app
    # Recommend: "<partner_label>:<user_id>" so multiple users are easy to tell apart
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
    _twofa_set_user_entry(x_api_key, user_id, entry)
    await save_twofa_db()

    return {
        "ok": True,
        "enabled": False,
        "user_id": user_id,
        "issuer": TWOFA_ISSUER,
        "account": label,
        "otpauth_url": otpauth_url,
        "secret_base32": secret,  # remove if you don't want manual entry exposed
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
    entry = _twofa_get_user_entry(x_api_key, user_id)
    if not entry:
        raise HTTPException(status_code=400, detail="2FA not set up yet. Call /2fa/setup first")

    secret = entry.get("secret_base32")
    if not secret:
        raise HTTPException(status_code=500, detail="2FA secret missing for this user")

    if not _verify_totp(secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    entry["enabled"] = True
    entry["enabled_at"] = _utc_now_z()
    _twofa_set_user_entry(x_api_key, user_id, entry)
    await save_twofa_db()

    return {"ok": True, "enabled": True, "user_id": user_id}

# Partner calls THIS to validate a code
@app.post("/2fa/verify")
async def twofa_verify(
    body: TwoFACodeRequest,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    user_id = _sanitize_twofa_user_id(body.user_id)
    entry = _twofa_get_user_entry(x_api_key, user_id)
    if not entry or not entry.get("enabled"):
        raise HTTPException(status_code=403, detail="2FA not enabled for this user_id under this API key")

    secret = entry.get("secret_base32")
    if not secret:
        raise HTTPException(status_code=500, detail="2FA secret missing for this user")

    if not _verify_totp(secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    return {"ok": True, "valid": True, "user_id": user_id}

# Keep your old endpoint name as an alias for partner convenience
@app.post("/authenticate")
async def authenticate_2fa(
    body: TwoFACodeRequest,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    # Alias of /2fa/verify
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    user_id = _sanitize_twofa_user_id(body.user_id)
    entry = _twofa_get_user_entry(x_api_key, user_id)
    if not entry or not entry.get("enabled"):
        raise HTTPException(status_code=403, detail="2FA not enabled for this user_id under this API key")

    secret = entry.get("secret_base32")
    if not secret:
        raise HTTPException(status_code=500, detail="2FA secret missing for this user")

    if not _verify_totp(secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    return {"ok": True, "valid": True, "user_id": user_id}

# (Optional) simple status endpoint for partner UX
@app.get("/2fa/status")
async def twofa_status(
    user_id: str,
    _meta: dict = Depends(require_api_key),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    uid = _sanitize_twofa_user_id(user_id)
    entry = _twofa_get_user_entry(x_api_key, uid)
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
    """Unauthenticated readiness probe for load balancers/orchestrators."""
    return {"ok": True}

@app.get("/health")
async def health(_meta: dict = Depends(require_api_key)):
    # count total users enrolled across all keys
    total_users = 0
    enabled_users = 0
    for krec in _TWOFA.values():
        users = (krec or {}).get("users") if isinstance(krec, dict) else {}
        if isinstance(users, dict):
            total_users += len(users)
            enabled_users += sum(1 for u in users.values() if isinstance(u, dict) and u.get("enabled"))

    return {
        "ok": True,
        "db_loaded": True,
        "known_scammers_count": len(_KNOWN_SCAMMERS),
        "twofa_keys_count": len(_TWOFA),
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
    case_dir = BANREQ_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    proof_url = await upload_banreport_proof_to_interna(
        proof_bytes=proof_bytes,
        proof_filename=proof_filename,
        case_id=case_id,
        session=request.app.state.http_session,
    )

    record = {
        "case_id": case_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "user_id": uid,
        "reason": reason.strip(),
        "notes": notes.strip(),
        "proof_original_name": proof.filename,
        "reporter_meta": _meta,
        "status": "pending",
    }
    if proof_url:
        record["proof_url"] = proof_url

    (case_dir / "request.json").write_text(json.dumps(record, indent=2), encoding="utf-8")

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

@app.get("/lookup/{user_id}")
async def lookup_user(
    user_id: str,
    include_reason: bool = False,
    _meta: dict = Depends(require_api_key),
):
    uid = _normalize_user_id(user_id)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid user_id")

    reason = _KNOWN_SCAMMERS.get(uid)
    out: Dict[str, Any] = {"user_id": uid, "is_flagged": reason is not None}
    if include_reason and reason is not None:
        out["reason"] = reason
    return out

@app.post("/lookup")
async def lookup_batch(req: BatchLookupRequest, _meta: dict = Depends(require_api_key)):
    results: List[Dict[str, Any]] = []
    for raw in req.user_ids:
        uid = _normalize_user_id(raw)
        if not uid:
            results.append({"user_id": str(raw), "is_flagged": False, "error": "invalid_user_id"})
            continue
        reason = _KNOWN_SCAMMERS.get(uid)
        out = {"user_id": uid, "is_flagged": reason is not None}
        if req.include_reason and reason is not None:
            out["reason"] = reason
        results.append(out)
    return {"count": len(results), "results": results}

@app.post("/canonicalize")
async def canonicalize(req: DetectRequest, _meta: dict = Depends(require_api_key)):
    return canonicalize_for_scam_scan(req.message)

@app.post("/banrequest/{case_id}/resolve")
async def resolve_banrequest_case(
    case_id: str,
    body: ResolveCaseRequest,
    _meta: dict = Depends(require_api_key),
):
    action = body.action.strip().lower()
    if action not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="action must be approve or reject")

    case_dir = BANREQ_DIR / case_id.upper()
    data_path = case_dir / "request.json"
    if not data_path.exists():
        raise HTTPException(status_code=404, detail="Case not found")

    data = json.loads(data_path.read_text(encoding="utf-8"))
    data["status"] = "approved" if action == "approve" else "rejected"
    data["review"] = {
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "reviewed_by": _meta.get("label") or "unknown",
        "decision": body.decision_note.strip() or ("Approved" if action == "approve" else "Rejected"),
    }

    data_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return {"ok": True, "case_id": data["case_id"], "status": data["status"]}

@app.post("/detect")
async def detect(req: DetectRequest, request: Request, _meta: dict = Depends(require_api_key)):
    session = request.app.state.http_session
    ctx = [c.model_dump() for c in req.context_messages] if req.context_messages else None
    return await detect_scam(req.message, ctx, session=session)

@app.get("/banrequest/{case_id}")
async def get_banrequest_case(case_id: str, _meta: dict = Depends(require_api_key)):
    case_dir = BANREQ_DIR / case_id.upper()
    data_path = case_dir / "request.json"
    if not data_path.exists():
        raise HTTPException(status_code=404, detail="Case not found")
    return json.loads(data_path.read_text(encoding="utf-8"))

@app.get("/")
def root():
    return JSONResponse(status_code=404, content={"detail": "Not found"})
