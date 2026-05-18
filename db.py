"""
PostgreSQL database layer for AntiScammer API.
Uses asyncpg. Configure via env: DB_USERNAME, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME (or DATABASE_URL).
SSL: DB_SSLMODE = disable | allow | prefer | require | require-no-verify | verify-ca | verify-full
  (default: prefer — try TLS first, fall back to plain TCP if the server has no SSL; good for Docker Postgres).
  If unset, sslmode= on DATABASE_URL is used when present.
  Note: asyncpg treats ssl=True as verify-full; this module never passes ssl=True, only named modes.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlparse

import asyncpg

log = logging.getLogger("db")

DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()

DB_HOST = os.getenv("DB_HOST", "manage.modoralabs.com")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "antiscammer")
DB_USER = os.getenv("DB_USERNAME") or os.getenv("DB_USER", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

_pool: Optional[asyncpg.Pool] = None

_VALID_SSLMODES = frozenset(
    {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
)
_SSLMODE_ALIASES = {
    "require-no-verify": "require",
    "require_no_verify": "require",
    "no-verify": "require",
    "noverify": "require",
}


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialized")
    return _pool


def _normalize_dsn(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql://" + url[11:]
    return url


def _sslmode_from_dsn_query(dsn: str) -> Optional[str]:
    try:
        q = urlparse(dsn).query
        if not q:
            return None
        modes = parse_qs(q, keep_blank_values=True).get("sslmode")
        if not modes or not modes[0].strip():
            return None
        return modes[0].strip().lower()
    except Exception:
        return None


def _resolve_effective_sslmode(dsn_for_parse: Optional[str]) -> str:
    """
    DB_SSLMODE env overrides DATABASE_URL ?sslmode= when set (non-empty).
    Otherwise default is 'prefer' (matches asyncpg for TCP; works with plain Postgres in Docker).
    """
    raw = os.getenv("DB_SSLMODE")
    if raw is not None and raw.strip() != "":
        mode = raw.strip().lower().replace("_", "-")
    elif dsn_for_parse:
        mode = _sslmode_from_dsn_query(dsn_for_parse)
        if mode is None:
            mode = "prefer"
    else:
        mode = "prefer"
    mode = _SSLMODE_ALIASES.get(mode, mode)
    if mode not in _VALID_SSLMODES:
        raise ValueError(
            f"Invalid DB_SSLMODE / sslmode={mode!r}; expected one of "
            f"{sorted(_VALID_SSLMODES)} or alias require-no-verify"
        )
    return mode


def _ssl_for_asyncpg(mode: str) -> Union[bool, str]:
    """Return ssl connect_kw for asyncpg (never True — that maps to verify-full inside asyncpg)."""
    if mode == "disable":
        return False
    return mode


async def init_pool() -> asyncpg.Pool:
    global _pool
    if _pool is not None:
        return _pool

    if DATABASE_URL:
        dsn = _normalize_dsn(DATABASE_URL)
        ssl_mode = _resolve_effective_sslmode(dsn)
        ssl_arg = _ssl_for_asyncpg(ssl_mode)
        _pool = await asyncpg.create_pool(
            dsn=dsn,
            min_size=max(1, int(os.getenv("DB_POOL_MIN", "2"))),
            max_size=int(os.getenv("DB_POOL_MAX", "10")),
            command_timeout=30,
            ssl=ssl_arg,
        )
        log.info("Database pool created from DATABASE_URL sslmode=%s", ssl_mode)
        return _pool

    if not DB_USER or not DB_PASSWORD:
        raise RuntimeError(
            "Set DATABASE_URL or both DB_USERNAME and DB_PASSWORD in env"
        )

    ssl_mode = _resolve_effective_sslmode(None)
    ssl_arg = _ssl_for_asyncpg(ssl_mode)
    _pool = await asyncpg.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        min_size=max(1, int(os.getenv("DB_POOL_MIN", "2"))),
        max_size=int(os.getenv("DB_POOL_MAX", "10")),
        command_timeout=30,
        ssl=ssl_arg,
    )
    log.info(
        "Database pool created %s@%s:%s/%s sslmode=%s",
        DB_USER,
        DB_HOST,
        DB_PORT,
        DB_NAME,
        ssl_mode,
    )
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        log.info("Database pool closed")


async def _ensure_jsonb_columns(conn: asyncpg.Connection) -> None:
    """
    If your tables already existed with reporter_meta/review as TEXT, CREATE TABLE IF NOT EXISTS won't fix it.
    This migrates them to JSONB safely.
    """
    # Ban requests
    await conn.execute(
        """
        ALTER TABLE "Ban requests"
            ALTER COLUMN reporter_meta TYPE jsonb
            USING CASE
                WHEN reporter_meta IS NULL THEN NULL
                WHEN pg_typeof(reporter_meta)::text = 'jsonb' THEN reporter_meta
                ELSE reporter_meta::jsonb
            END
        """
    )
    await conn.execute(
        """
        ALTER TABLE "Ban requests"
            ALTER COLUMN review TYPE jsonb
            USING CASE
                WHEN review IS NULL THEN NULL
                WHEN pg_typeof(review)::text = 'jsonb' THEN review
                ELSE review::jsonb
            END
        """
    )

    # False positive reports
    await conn.execute(
        """
        ALTER TABLE "False positive reports"
            ALTER COLUMN reporter_meta TYPE jsonb
            USING CASE
                WHEN reporter_meta IS NULL THEN NULL
                WHEN pg_typeof(reporter_meta)::text = 'jsonb' THEN reporter_meta
                ELSE reporter_meta::jsonb
            END
        """
    )
    await conn.execute(
        """
        ALTER TABLE "False positive reports"
            ALTER COLUMN review TYPE jsonb
            USING CASE
                WHEN review IS NULL THEN NULL
                WHEN pg_typeof(review)::text = 'jsonb' THEN review
                ELSE review::jsonb
            END
        """
    )


async def init_tables(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "API keys" (
                key TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                bypass_ratelimit BOOLEAN NOT NULL DEFAULT FALSE
            )
        """)
        try:
            await conn.execute("""
                ALTER TABLE "API keys" ADD COLUMN IF NOT EXISTS bypass_ratelimit BOOLEAN NOT NULL DEFAULT FALSE
            """)
        except Exception:
            pass  # Column may already exist or PG < 9.6
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Admin credentials" (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Master key" (
                id INTEGER PRIMARY KEY DEFAULT 1,
                key TEXT NOT NULL
            )
        """)
        # Postgres-only schema: simple (user_id, reason). MariaDB uses a different table/schema (global_bans) via maria_mirror.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Global banlist" (
                user_id TEXT PRIMARY KEY,
                reason TEXT NOT NULL
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "2FA" (
                api_key TEXT NOT NULL,
                user_id TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                secret_base32 TEXT,
                created_at TEXT,
                label TEXT,
                enabled_at TEXT,
                PRIMARY KEY (api_key, user_id)
            )
        """)

        # These two tables might already exist from earlier versions. Keep create-if-not-exists,
        # then force reporter_meta/review to JSONB via ALTER.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Ban requests" (
                case_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                user_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                proof_original_name TEXT,
                proof_url TEXT,
                reporter_meta JSONB,
                status TEXT NOT NULL DEFAULT 'pending',
                review JSONB
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "False positive reports" (
                case_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                user_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                proof_original_name TEXT,
                proof_url TEXT,
                reporter_meta JSONB,
                status TEXT NOT NULL DEFAULT 'pending',
                review JSONB
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "URL list" (
                url_domain TEXT PRIMARY KEY,
                type TEXT NOT NULL CHECK (type IN ('safe', 'scam')),
                reason TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Admin audit log" (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT,
                details JSONB,
                ip TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "App settings" (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Ticket audit sessions" (
                audit_id TEXT PRIMARY KEY,
                api_key TEXT NOT NULL,
                store_label TEXT,
                server_id TEXT,
                giveaway_key TEXT,
                discord_ids JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            )
        """)
        try:
            await conn.execute(
                'ALTER TABLE "Ticket audit sessions" ADD COLUMN IF NOT EXISTS server_id TEXT'
            )
        except Exception:
            pass
        try:
            await conn.execute(
                'ALTER TABLE "Ticket audit sessions" ADD COLUMN IF NOT EXISTS giveaway_key TEXT'
            )
        except Exception:
            pass
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ticket_audit_sessions_api_key
            ON "Ticket audit sessions" (api_key)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ticket_audit_sessions_api_server
            ON "Ticket audit sessions" (api_key, server_id)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ticket_audit_sessions_giveaway
            ON "Ticket audit sessions" (api_key, giveaway_key)
            """
        )

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Ticket audit claims" (
                audit_id TEXT NOT NULL,
                api_key TEXT NOT NULL,
                user_id TEXT NOT NULL,
                resolved_at TIMESTAMPTZ NOT NULL,
                retain_until TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (audit_id, api_key, user_id)
            )
        """)
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ticket_audit_claims_retain
            ON "Ticket audit claims" (retain_until)
            """
        )

        # Force correct types even if table existed already
        try:
            await _ensure_jsonb_columns(conn)
        except Exception:
            # If old columns contain invalid JSON strings, the cast can fail.
            # In that case you'd need a one-time manual cleanup, but this makes the error visible.
            log.exception("Failed to migrate reporter_meta/review columns to JSONB")

        # HTTP request log (unlimited retention; disk grows over time)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "API request log" (
                id SERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                request_id TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                query_string TEXT,
                endpoint_name TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                time_ms INTEGER NOT NULL,
                api_key TEXT NOT NULL DEFAULT '',
                api_key_label TEXT NOT NULL DEFAULT '',
                auth_kind TEXT NOT NULL,
                admin_username TEXT,
                admin_audit_action TEXT,
                client_ip TEXT,
                user_agent TEXT,
                referer TEXT,
                request_headers JSONB,
                response_headers JSONB,
                request_body TEXT,
                response_body TEXT,
                error_detail TEXT,
                is_slow BOOLEAN NOT NULL DEFAULT FALSE,
                is_error BOOLEAN NOT NULL DEFAULT FALSE,
                request_bytes INTEGER NOT NULL DEFAULT 0,
                response_bytes INTEGER NOT NULL DEFAULT 0,
                content_type_request TEXT,
                content_type_response TEXT,
                exception_type TEXT,
                exception_trace TEXT,
                rate_limited BOOLEAN NOT NULL DEFAULT FALSE
            )
        """)
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_created_at
            ON "API request log" (created_at DESC)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_api_key_created
            ON "API request log" (api_key, created_at DESC)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_endpoint_created
            ON "API request log" (endpoint_name, created_at DESC)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_status_code
            ON "API request log" (status_code)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_is_error_created
            ON "API request log" (is_error, created_at DESC)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_is_slow_created
            ON "API request log" (is_slow, created_at DESC)
            """
        )
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_request_id
            ON "API request log" (request_id)
            """
        )

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "API request log hourly" (
                hour_bucket TIMESTAMPTZ NOT NULL,
                api_key TEXT NOT NULL DEFAULT '',
                endpoint_name TEXT NOT NULL DEFAULT '',
                count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                slow_count INTEGER NOT NULL DEFAULT 0,
                sum_time_ms BIGINT NOT NULL DEFAULT 0,
                max_time_ms INTEGER NOT NULL DEFAULT 0,
                sum_request_bytes BIGINT NOT NULL DEFAULT 0,
                sum_response_bytes BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (hour_bucket, api_key, endpoint_name)
            )
        """)
        await conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_api_request_log_hourly_bucket
            ON "API request log hourly" (hour_bucket DESC)
            """
        )

    log.info("Database tables initialized")


async def seed_defaults(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        n = await conn.fetchval('SELECT COUNT(*) FROM "API keys"')
        if n == 0:
            defaults = [
                ("ATSM-GLTW-KYPE-B239", "2026-05-28T23:59:59Z", "Antiscammer Review team"),
                ("antiscammer-internal-KEY-456", "2026-06-30T23:59:59Z", "internal service"),
                ("ATSM-GLTW-KYPE-B96F", "3072-12-31T23:59:59Z", "SassGuard"),
                ("ATSM-QI5H-CG8M-2065", "3072-12-31T23:59:59Z", "FZ vouch"),
                ("ATSM-8R5H-5Z6L-151D", "2026-05-28T23:59:59Z", "Modora"),
                ("ATSM-YJC4-CDAF-227D", "3072-12-31T23:59:59Z", "Modora Dev"),
                ("ATSM-4B70-A74B-9D4C", "2027-12-31T23:59:59Z", "Modora production"),
                ("Test-key-123-456", "3072-12-31T23:59:59Z", "test"),
                ("ATSM-C2S4-A2S4-F5S5", "2026-04-15T23:59:59Z", "draakjekevin"),
            ]
            for key, exp, label in defaults:
                await conn.execute(
                    'INSERT INTO "API keys" (key, expires_at, label) VALUES ($1, $2, $3)',
                    key, exp, label,
                )
            log.info("Seeded default API keys")

        # Ensure ATSM-4B70-A74B-9D4C exists (e.g. production had older seed without it)
        await conn.execute(
            """
            INSERT INTO "API keys" (key, expires_at, label) VALUES ($1, $2, $3)
            ON CONFLICT (key) DO NOTHING
            """,
            "ATSM-4B70-A74B-9D4C", "2027-12-31T23:59:59Z", "Modora production",
        )

        n = await conn.fetchval('SELECT COUNT(*) FROM "Admin credentials"')
        if n == 0:
            await conn.execute(
                'INSERT INTO "Admin credentials" (username, password) VALUES ($1, $2)',
                "admin", "changeme",
            )
            log.warning("Seeded default admin auth (admin/changeme) — change it!")

        n = await conn.fetchval('SELECT COUNT(*) FROM "URL list"')
        if n == 0:
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            default_safe = [
                "modora.xyz",
                "sassguard.app",
                "antiscammer.app",
                "google.com",
                "bing.com",
            ]
            for domain in default_safe:
                await conn.execute(
                    'INSERT INTO "URL list" (url_domain, type, reason, created_at) VALUES ($1, $2, $3, $4)',
                    domain, "safe", "", now,
                )
            log.info("Seeded default safe URLs: %s", default_safe)


# ----------------------------
# API keys
# ----------------------------
async def api_key_get(key: str) -> Optional[Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT key, expires_at, label, COALESCE(bypass_ratelimit, FALSE) AS bypass_ratelimit FROM "API keys" WHERE key = $1', key
        )
    if row is None:
        return None
    return {
        "expires_at": row["expires_at"],
        "label": row["label"] or "",
        "bypass_ratelimit": bool(row.get("bypass_ratelimit", False)),
    }


async def api_key_get_all() -> Dict[str, Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT key, expires_at, label, COALESCE(bypass_ratelimit, FALSE) AS bypass_ratelimit FROM "API keys"')
    return {
        r["key"]: {
            "expires_at": r["expires_at"],
            "label": r["label"] or "",
            "bypass_ratelimit": bool(r.get("bypass_ratelimit", False)),
        }
        for r in rows
    }


async def api_key_set(
    key: str,
    expires_at: str,
    label: str,
    bypass_ratelimit: bool = False,
) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "API keys" (key, expires_at, label, bypass_ratelimit)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (key) DO UPDATE SET expires_at = $2, label = $3, bypass_ratelimit = $4
            """,
            key, expires_at, label, bypass_ratelimit,
        )


async def api_key_delete(key: str) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM "API keys" WHERE key = $1', key)


# ----------------------------
# Admin auth
# ----------------------------
async def admin_auth_get(username: str) -> Optional[str]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT password FROM "Admin credentials" WHERE username = $1', username
        )
    return row["password"] if row else None


async def admin_auth_set(username: str, password: str) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "Admin credentials" (username, password) VALUES ($1, $2)
            ON CONFLICT (username) DO UPDATE SET password = $2
            """,
            username, password,
        )


async def admin_auth_get_all() -> List[Dict[str, Any]]:
    """List all admin usernames (no passwords)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT username FROM "Admin credentials"')
    return [{"username": r["username"]} for r in rows]


async def admin_auth_delete(username: str) -> None:
    """Remove an admin user. Caller must ensure at least one admin remains."""
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM "Admin credentials" WHERE username = $1', username)



# ----------------------------
# Master API key
# ----------------------------
async def master_key_get() -> Optional[str]:
    """
    Return the configured master API key (if any).
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow('SELECT key FROM "Master key" WHERE id = 1')
    return row["key"] if row else None


async def master_key_set(key: Optional[str]) -> None:
    """
    Set or clear the master API key. If key is None or empty, the master key is removed.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        if not key:
            await conn.execute('DELETE FROM "Master key" WHERE id = 1')
        else:
            await conn.execute(
                """
                INSERT INTO "Master key" (id, key)
                VALUES (1, $1)
                ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key
                """,
                key,
            )

# ----------------------------
# Known scammers (Postgres "Global banlist" only: user_id, reason)
# MariaDB global_bans uses a different schema and is written via maria_mirror only.
# ----------------------------
async def scammers_get_all() -> Dict[str, str]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT user_id, reason FROM "Global banlist"')
    return {r["user_id"]: r["reason"] for r in rows}


async def scammer_get(user_id: str) -> Optional[str]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT reason FROM "Global banlist" WHERE user_id = $1', user_id
        )
    return row["reason"] if row else None


async def scammers_replace_all(data: Dict[str, str]) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute('DELETE FROM "Global banlist"')
        if data:
            await conn.executemany(
                'INSERT INTO "Global banlist" (user_id, reason) VALUES ($1, $2)',
                [(uid, reason) for uid, reason in data.items()],
            )


async def scammer_upsert(user_id: str, reason: str) -> None:
    """
    Insert or update a single scammer in Postgres "Global banlist" (schema: user_id, reason only).
    Does not touch MariaDB; use maria_mirror.mirror_global_ban_insert for MariaDB global_bans.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "Global banlist" (user_id, reason)
            VALUES ($1, $2)
            ON CONFLICT (user_id) DO UPDATE SET reason = EXCLUDED.reason
            """,
            user_id,
            reason,
        )


async def scammer_delete(user_id: str) -> None:
    """
    Delete a single scammer record.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            'DELETE FROM "Global banlist" WHERE user_id = $1',
            user_id,
        )


# ----------------------------
# Ticket audit (giveaway winner verification)
# ----------------------------
async def ticket_audit_insert(
    audit_id: str,
    api_key: str,
    store_label: Optional[str],
    server_id: Optional[str],
    giveaway_key: Optional[str],
    discord_ids: List[str],
    created_at: datetime,
    expires_at: datetime,
) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "Ticket audit sessions"
                (audit_id, api_key, store_label, server_id, giveaway_key, discord_ids, created_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            audit_id,
            api_key,
            store_label,
            server_id,
            giveaway_key,
            discord_ids,
            created_at,
            expires_at,
        )


async def ticket_audit_claim_purge_expired() -> None:
    """Remove resolved claims past retain_until."""
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            'DELETE FROM "Ticket audit claims" WHERE retain_until < NOW()'
        )


async def ticket_audit_claim_get_active(
    audit_id: str, api_key: str, user_id: str
) -> Optional[Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT resolved_at, retain_until FROM "Ticket audit claims"
            WHERE audit_id = $1 AND api_key = $2 AND user_id = $3
              AND retain_until >= NOW()
            """,
            audit_id,
            api_key,
            user_id,
        )
    if row is None:
        return None
    return {
        "resolved_at": row["resolved_at"],
        "retain_until": row["retain_until"],
    }


async def ticket_audit_claim_try_insert(
    audit_id: str,
    api_key: str,
    user_id: str,
    resolved_at: datetime,
    retain_until: datetime,
) -> bool:
    """
    Insert a resolved claim. Returns True if a new row was inserted.
    Returns False if this user was already claimed for this giveaway (conflict or race).
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO "Ticket audit claims"
                (audit_id, api_key, user_id, resolved_at, retain_until)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (audit_id, api_key, user_id) DO NOTHING
            RETURNING audit_id
            """,
            audit_id,
            api_key,
            user_id,
            resolved_at,
            retain_until,
        )
    return row is not None


async def ticket_audit_get(audit_id: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Return session for this audit_id and api_key, or None if missing, wrong key, or expired.
    discord_ids is returned as a list of str.
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT audit_id, store_label, server_id, giveaway_key, discord_ids, created_at, expires_at
            FROM "Ticket audit sessions"
            WHERE audit_id = $1 AND api_key = $2
            """,
            audit_id,
            api_key,
        )
    if row is None:
        return None
    exp = row["expires_at"]
    if isinstance(exp, datetime):
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        else:
            exp = exp.astimezone(timezone.utc)
    else:
        return None
    now = datetime.now(timezone.utc)
    if now >= exp:
        return None
    raw_ids = row["discord_ids"]
    if isinstance(raw_ids, str):
        try:
            raw_ids = json.loads(raw_ids)
        except Exception:
            raw_ids = []
    if not isinstance(raw_ids, list):
        raw_ids = []
    ids_list = [str(x) for x in raw_ids]
    sid = row.get("server_id")
    if sid is not None:
        sid = str(sid).strip() or None
    gk = row.get("giveaway_key")
    if gk is not None:
        gk = str(gk).strip() or None
    return {
        "audit_id": row["audit_id"],
        "store_label": row["store_label"],
        "server_id": sid,
        "giveaway_key": gk,
        "discord_ids": ids_list,
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
    }


# ----------------------------
# URL list (safe / scam domains)
# ----------------------------
async def url_list_get_all() -> Dict[str, Dict[str, Any]]:
    """Return {domain: {type, reason}} for all URLs."""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT url_domain, type, reason FROM "URL list"')
    return {
        r["url_domain"]: {"type": r["type"], "reason": r["reason"] or ""}
        for r in rows
    }


async def url_list_get(domain: str) -> Optional[Dict[str, Any]]:
    """Get a single URL entry by domain."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT url_domain, type, reason FROM "URL list" WHERE url_domain = $1',
            domain.lower().strip(),
        )
    if row is None:
        return None
    return {"domain": row["url_domain"], "type": row["type"], "reason": row["reason"] or ""}


async def url_list_upsert(domain: str, url_type: str, reason: str = "") -> None:
    """Insert or update a URL. url_type must be 'safe' or 'scam'."""
    if url_type not in ("safe", "scam"):
        raise ValueError("type must be 'safe' or 'scam'")
    domain = domain.lower().strip()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "URL list" (url_domain, type, reason, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (url_domain) DO UPDATE SET type = $2, reason = $3
            """,
            domain, url_type, reason or "", now,
        )


async def url_list_delete(domain: str) -> None:
    """Delete a URL from the list."""
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            'DELETE FROM "URL list" WHERE url_domain = $1',
            domain.lower().strip(),
        )


async def admin_audit_log(username: str, action: str, resource: Optional[str] = None, details: Optional[Dict[str, Any]] = None, ip: Optional[str] = None) -> None:
    """Log an admin action to the audit table."""
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "Admin audit log" (username, action, resource, details, ip)
            VALUES ($1, $2, $3, $4, $5)
            """,
            username, action, resource, _jsonb_val(details) if details else None, ip,
        )


# ----------------------------
# App settings (simple key/value)
# ----------------------------
async def app_setting_get(key: str) -> Optional[str]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT value FROM "App settings" WHERE key = $1',
            key,
        )
    return row["value"] if row else None


async def app_setting_set(key: str, value: str) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "App settings" (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """,
            key,
            value,
        )


# ----------------------------
# 2FA
# ----------------------------
async def twofa_get_user_entry(api_key: str, user_id: str) -> Optional[Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT enabled, secret_base32, created_at, label, enabled_at
            FROM "2FA" WHERE api_key = $1 AND user_id = $2
            """,
            api_key, user_id,
        )
    if row is None:
        return None
    return {
        "enabled": row["enabled"],
        "secret_base32": row["secret_base32"],
        "created_at": row["created_at"],
        "label": row["label"],
        "enabled_at": row["enabled_at"],
    }


async def twofa_set_user_entry(api_key: str, user_id: str, entry: Dict[str, Any]) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "2FA" (api_key, user_id, enabled, secret_base32, created_at, label, enabled_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (api_key, user_id) DO UPDATE SET
                enabled = $3, secret_base32 = $4, created_at = $5, label = $6, enabled_at = $7
            """,
            api_key,
            user_id,
            entry.get("enabled", False),
            entry.get("secret_base32"),
            entry.get("created_at"),
            entry.get("label"),
            entry.get("enabled_at"),
        )


async def twofa_get_all_keys_users() -> Dict[str, Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            'SELECT api_key, user_id, enabled, secret_base32, created_at, label, enabled_at FROM "2FA"'
        )
    result: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        key = r["api_key"]
        if key not in result:
            result[key] = {"users": {}}
        result[key]["users"][r["user_id"]] = {
            "enabled": r["enabled"],
            "secret_base32": r["secret_base32"],
            "created_at": r["created_at"],
            "label": r["label"],
            "enabled_at": r["enabled_at"],
        }
    return result


# ----------------------------
# Ban requests
# ----------------------------
async def ban_request_insert(record: Dict[str, Any]) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "Ban requests"
            (case_id, created_at, user_id, reason, notes, proof_original_name, proof_url, reporter_meta, status, review)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
            record["case_id"],
            record["created_at"],
            record["user_id"],
            record["reason"],
            record.get("notes", ""),
            record.get("proof_original_name"),
            record.get("proof_url"),
            _jsonb_val(record.get("reporter_meta")),
            record.get("status", "pending"),
            _jsonb_val(record.get("review")),
        )


async def ban_request_get(case_id: str) -> Optional[Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT case_id, created_at, user_id, reason, notes, proof_original_name, proof_url,
                   reporter_meta, status, review
            FROM "Ban requests" WHERE UPPER(case_id) = UPPER($1)
            """,
            case_id,
        )
    if row is None:
        return None
    return _row_to_case_record(row)


async def ban_request_list(status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """List ban requests with optional status filter."""
    pool = get_pool()
    async with pool.acquire() as conn:
        if status:
            rows = await conn.fetch(
                """
                SELECT case_id, created_at, user_id, reason, notes, proof_original_name, proof_url,
                       reporter_meta, status, review
                FROM "Ban requests" WHERE LOWER(status) = LOWER($1)
                ORDER BY created_at DESC LIMIT $2
                """,
                status, limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT case_id, created_at, user_id, reason, notes, proof_original_name, proof_url,
                       reporter_meta, status, review
                FROM "Ban requests"
                ORDER BY created_at DESC LIMIT $1
                """,
                limit,
            )
    return [_row_to_case_record(r) for r in rows]


async def ban_request_update_status(case_id: str, status: str, review: Dict[str, Any]) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE "Ban requests" SET status = $1, review = $2 WHERE UPPER(case_id) = UPPER($3)
            """,
            status, _jsonb_val(review), case_id,
        )


# ----------------------------
# False positive reports
# ----------------------------
async def fp_report_insert(record: Dict[str, Any]) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "False positive reports"
            (case_id, created_at, user_id, reason, notes, proof_original_name, proof_url, reporter_meta, status, review)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """,
            record["case_id"],
            record["created_at"],
            record["user_id"],
            record["reason"],
            record.get("notes", ""),
            record.get("proof_original_name"),
            record.get("proof_url"),
            _jsonb_val(record.get("reporter_meta")),
            record.get("status", "pending"),
            _jsonb_val(record.get("review")),
        )


async def fp_report_get(case_id: str) -> Optional[Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT case_id, created_at, user_id, reason, notes, proof_original_name, proof_url,
                   reporter_meta, status, review
            FROM "False positive reports" WHERE UPPER(case_id) = UPPER($1)
            """,
            case_id,
        )
    if row is None:
        return None
    return _row_to_case_record(row)


async def fp_report_list(status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """List false positive reports with optional status filter."""
    pool = get_pool()
    async with pool.acquire() as conn:
        if status:
            rows = await conn.fetch(
                """
                SELECT case_id, created_at, user_id, reason, notes, proof_original_name, proof_url,
                       reporter_meta, status, review
                FROM "False positive reports" WHERE LOWER(status) = LOWER($1)
                ORDER BY created_at DESC LIMIT $2
                """,
                status, limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT case_id, created_at, user_id, reason, notes, proof_original_name, proof_url,
                       reporter_meta, status, review
                FROM "False positive reports"
                ORDER BY created_at DESC LIMIT $1
                """,
                limit,
            )
    return [_row_to_case_record(r) for r in rows]


async def fp_report_update_status(case_id: str, status: str, review: Dict[str, Any]) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE "False positive reports" SET status = $1, review = $2 WHERE UPPER(case_id) = UPPER($3)
            """,
            status, _jsonb_val(review), case_id,
        )


def _jsonb_val(value: Any) -> Optional[str]:
    """Serialize dict/list to JSON string for JSONB params; asyncpg may expect str not dict."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _row_to_case_record(row: asyncpg.Record) -> Dict[str, Any]:
    out = {
        "case_id": row["case_id"],
        "created_at": row["created_at"],
        "user_id": row["user_id"],
        "reason": row["reason"],
        "notes": row["notes"] or "",
        "proof_original_name": row["proof_original_name"],
        "status": row["status"],
    }
    if row.get("proof_url"):
        out["proof_url"] = row["proof_url"]

    rm = row.get("reporter_meta")
    if rm:
        out["reporter_meta"] = rm if isinstance(rm, dict) else json.loads(rm)

    rv = row.get("review")
    if rv:
        out["review"] = rv if isinstance(rv, dict) else json.loads(rv)

    return out


# ----------------------------
# API request log
# ----------------------------
def _dt_to_iso_z(dt: Any) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return str(dt)


def _request_log_row_summary(row: asyncpg.Record) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "created_at": _dt_to_iso_z(row["created_at"]),
        "request_id": row["request_id"],
        "method": row["method"],
        "path": row["path"],
        "query_string": row["query_string"],
        "endpoint_name": row["endpoint_name"],
        "status_code": row["status_code"],
        "time_ms": row["time_ms"],
        "api_key": row["api_key"] or "",
        "api_key_label": row["api_key_label"] or "",
        "auth_kind": row["auth_kind"],
        "admin_username": row["admin_username"],
        "admin_audit_action": row["admin_audit_action"],
        "client_ip": row["client_ip"],
        "user_agent": row["user_agent"],
        "referer": row["referer"],
        "error_detail": row["error_detail"],
        "is_slow": bool(row["is_slow"]),
        "is_error": bool(row["is_error"]),
        "request_bytes": row["request_bytes"] or 0,
        "response_bytes": row["response_bytes"] or 0,
        "content_type_request": row["content_type_request"],
        "content_type_response": row["content_type_response"],
        "rate_limited": bool(row["rate_limited"]),
    }


def _request_log_row_full(row: asyncpg.Record) -> Dict[str, Any]:
    out = _request_log_row_summary(row)
    rh = row.get("request_headers")
    if rh is not None and not isinstance(rh, dict):
        try:
            rh = json.loads(rh)
        except Exception:
            rh = None
    sh = row.get("response_headers")
    if sh is not None and not isinstance(sh, dict):
        try:
            sh = json.loads(sh)
        except Exception:
            sh = None
    out["request_headers"] = rh
    out["response_headers"] = sh
    out["request_body"] = row["request_body"]
    out["response_body"] = row["response_body"]
    out["exception_type"] = row["exception_type"]
    out["exception_trace"] = row["exception_trace"]
    return out


async def request_log_insert(
    *,
    request_id: str,
    method: str,
    path: str,
    query_string: Optional[str],
    endpoint_name: str,
    status_code: int,
    time_ms: int,
    api_key: str = "",
    api_key_label: str = "",
    auth_kind: str,
    admin_username: Optional[str] = None,
    admin_audit_action: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    referer: Optional[str] = None,
    request_headers: Optional[Dict[str, Any]] = None,
    response_headers: Optional[Dict[str, Any]] = None,
    request_body: Optional[str] = None,
    response_body: Optional[str] = None,
    error_detail: Optional[str] = None,
    is_slow: bool = False,
    is_error: bool = False,
    request_bytes: int = 0,
    response_bytes: int = 0,
    content_type_request: Optional[str] = None,
    content_type_response: Optional[str] = None,
    exception_type: Optional[str] = None,
    exception_trace: Optional[str] = None,
    rate_limited: bool = False,
) -> None:
    pool = get_pool()
    is_err = is_error or status_code >= 400
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "API request log" (
                request_id, method, path, query_string, endpoint_name,
                status_code, time_ms, api_key, api_key_label, auth_kind,
                admin_username, admin_audit_action, client_ip, user_agent, referer,
                request_headers, response_headers, request_body, response_body,
                error_detail, is_slow, is_error, request_bytes, response_bytes,
                content_type_request, content_type_response,
                exception_type, exception_trace, rate_limited
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19,
                $20, $21, $22, $23, $24, $25, $26, $27, $28, $29
            )
            """,
            request_id,
            method,
            path,
            query_string,
            endpoint_name,
            status_code,
            time_ms,
            api_key or "",
            api_key_label or "",
            auth_kind,
            admin_username,
            admin_audit_action,
            client_ip,
            user_agent,
            referer,
            _jsonb_val(request_headers) if request_headers else None,
            _jsonb_val(response_headers) if response_headers else None,
            request_body,
            response_body,
            error_detail,
            is_slow,
            is_err,
            request_bytes,
            response_bytes,
            content_type_request,
            content_type_response,
            exception_type,
            exception_trace,
            rate_limited,
        )
        hour_bucket = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        await conn.execute(
            """
            INSERT INTO "API request log hourly" (
                hour_bucket, api_key, endpoint_name,
                count, error_count, slow_count,
                sum_time_ms, max_time_ms, sum_request_bytes, sum_response_bytes
            ) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (hour_bucket, api_key, endpoint_name) DO UPDATE SET
                count = "API request log hourly".count + 1,
                error_count = "API request log hourly".error_count + EXCLUDED.error_count,
                slow_count = "API request log hourly".slow_count + EXCLUDED.slow_count,
                sum_time_ms = "API request log hourly".sum_time_ms + EXCLUDED.sum_time_ms,
                max_time_ms = GREATEST("API request log hourly".max_time_ms, EXCLUDED.max_time_ms),
                sum_request_bytes = "API request log hourly".sum_request_bytes + EXCLUDED.sum_request_bytes,
                sum_response_bytes = "API request log hourly".sum_response_bytes + EXCLUDED.sum_response_bytes
            """,
            hour_bucket,
            api_key or "",
            endpoint_name,
            1 if is_err else 0,
            1 if is_slow else 0,
            time_ms,
            time_ms,
            request_bytes,
            response_bytes,
        )


async def request_log_list(
    *,
    api_key: Optional[str] = None,
    endpoint_name: Optional[str] = None,
    status: Optional[int] = None,
    method: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    q: Optional[str] = None,
    slow_only: bool = False,
    errors_only: bool = False,
    auth_kind: Optional[str] = None,
    rate_limited: Optional[bool] = None,
    min_time_ms: Optional[int] = None,
    max_time_ms: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    pool = get_pool()
    conditions: List[str] = []
    params: List[Any] = []
    idx = 1

    def add(cond: str, val: Any) -> None:
        nonlocal idx
        conditions.append(cond.format(n=idx))
        params.append(val)
        idx += 1

    if api_key is not None:
        add("api_key = ${n}", api_key)
    if endpoint_name is not None:
        add("endpoint_name = ${n}", endpoint_name)
    if status is not None:
        add("status_code = ${n}", status)
    if method is not None:
        add("method = ${n}", method.upper())
    if since is not None:
        add("created_at >= ${n}", since)
    if until is not None:
        add("created_at <= ${n}", until)
    if slow_only:
        conditions.append("is_slow = TRUE")
    if errors_only:
        conditions.append("is_error = TRUE")
    if auth_kind is not None:
        add("auth_kind = ${n}", auth_kind)
    if rate_limited is not None:
        add("rate_limited = ${n}", rate_limited)
    if min_time_ms is not None:
        add("time_ms >= ${n}", min_time_ms)
    if max_time_ms is not None:
        add("time_ms <= ${n}", max_time_ms)
    if q:
        pattern = f"%{q}%"
        conditions.append(
            f"(path ILIKE ${idx} OR request_body ILIKE ${idx} OR response_body ILIKE ${idx} "
            f"OR request_id ILIKE ${idx} OR api_key ILIKE ${idx})"
        )
        params.append(pattern)
        idx += 1

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    limit = max(1, min(limit, 50000))
    offset = max(0, offset)

    async with pool.acquire() as conn:
        total = await conn.fetchval(
            f'SELECT COUNT(*) FROM "API request log"{where}',
            *params,
        )
        rows = await conn.fetch(
            f"""
            SELECT id, created_at, request_id, method, path, query_string, endpoint_name,
                   status_code, time_ms, api_key, api_key_label, auth_kind,
                   admin_username, admin_audit_action, client_ip, user_agent, referer,
                   error_detail, is_slow, is_error, request_bytes, response_bytes,
                   content_type_request, content_type_response, rate_limited
            FROM "API request log"
            {where}
            ORDER BY created_at DESC
            LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
            limit,
            offset,
        )
    return {
        "total": total or 0,
        "limit": limit,
        "offset": offset,
        "items": [_request_log_row_summary(r) for r in rows],
    }


async def request_log_get(log_id: int) -> Optional[Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT * FROM "API request log" WHERE id = $1',
            log_id,
        )
    if row is None:
        return None
    return _request_log_row_full(row)


async def request_log_storage_stats() -> Dict[str, Any]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row_count = await conn.fetchval('SELECT COUNT(*) FROM "API request log"')
        raw_bytes = await conn.fetchval(
            """
            SELECT COALESCE(
                pg_total_relation_size('"API request log"'::regclass)
                + pg_total_relation_size('"API request log hourly"'::regclass),
                0
            )
            """
        )
        hourly_rows = await conn.fetchval('SELECT COUNT(*) FROM "API request log hourly"')
    return {
        "row_count": row_count or 0,
        "hourly_row_count": hourly_rows or 0,
        "storage_bytes": raw_bytes or 0,
        "storage_mb": round((raw_bytes or 0) / (1024 * 1024), 2),
    }


async def request_log_24h_counts() -> Dict[str, int]:
    """Error and slow counts in the last 24 hours."""
    pool = get_pool()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE is_error) AS errors_24h,
                COUNT(*) FILTER (WHERE is_slow) AS slow_24h
            FROM "API request log"
            WHERE created_at >= $1
            """,
            since,
        )
    if row is None:
        return {"errors_24h": 0, "slow_24h": 0}
    return {
        "errors_24h": int(row["errors_24h"] or 0),
        "slow_24h": int(row["slow_24h"] or 0),
    }


async def request_log_stats(
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
) -> Dict[str, Any]:
    pool = get_pool()
    now = datetime.now(timezone.utc)
    if since is None:
        since = now - timedelta(hours=24)
    if until is None:
        until = now

    async with pool.acquire() as conn:
        totals = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_count,
                COUNT(*) FILTER (WHERE is_error) AS error_count,
                COUNT(*) FILTER (WHERE is_slow) AS slow_count,
                COALESCE(SUM(request_bytes), 0) AS sum_request_bytes,
                COALESCE(SUM(response_bytes), 0) AS sum_response_bytes,
                COALESCE(
                    percentile_cont(0.5) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p50_ms,
                COALESCE(
                    percentile_cont(0.95) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p95_ms,
                COALESCE(
                    percentile_cont(0.99) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p99_ms
            FROM "API request log"
            WHERE created_at >= $1 AND created_at <= $2
            """,
            since,
            until,
        )

        per_key = await conn.fetch(
            """
            SELECT
                api_key,
                MAX(api_key_label) AS api_key_label,
                COUNT(*) AS count,
                COUNT(*) FILTER (WHERE is_error) AS error_count,
                COUNT(*) FILTER (WHERE is_slow) AS slow_count,
                COALESCE(SUM(request_bytes), 0) AS sum_request_bytes,
                COALESCE(SUM(response_bytes), 0) AS sum_response_bytes,
                COALESCE(
                    percentile_cont(0.5) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p50_ms,
                COALESCE(
                    percentile_cont(0.95) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p95_ms,
                COALESCE(
                    percentile_cont(0.99) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p99_ms
            FROM "API request log"
            WHERE created_at >= $1 AND created_at <= $2
            GROUP BY api_key
            ORDER BY count DESC
            """,
            since,
            until,
        )

        per_endpoint = await conn.fetch(
            """
            SELECT
                endpoint_name,
                COUNT(*) AS count,
                COUNT(*) FILTER (WHERE is_error) AS error_count,
                COUNT(*) FILTER (WHERE is_slow) AS slow_count,
                COALESCE(
                    percentile_cont(0.5) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p50_ms,
                COALESCE(
                    percentile_cont(0.95) WITHIN GROUP (ORDER BY time_ms),
                    0
                )::int AS p95_ms
            FROM "API request log"
            WHERE created_at >= $1 AND created_at <= $2
            GROUP BY endpoint_name
            ORDER BY count DESC
            """,
            since,
            until,
        )

        hour_since = now - timedelta(hours=24)
        hourly = await conn.fetch(
            """
            SELECT
                hour_bucket,
                SUM(count) AS count,
                SUM(error_count) AS error_count,
                SUM(slow_count) AS slow_count,
                SUM(sum_time_ms) AS sum_time_ms
            FROM "API request log hourly"
            WHERE hour_bucket >= $1
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            """,
            hour_since,
        )

        errors_24h_row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE is_error) AS errors_24h,
                COUNT(*) FILTER (WHERE is_slow) AS slow_24h
            FROM "API request log"
            WHERE created_at >= $1
            """,
            hour_since,
        )

    total_count = int(totals["total_count"] or 0) if totals else 0
    error_count = int(totals["error_count"] or 0) if totals else 0
    slow_count = int(totals["slow_count"] or 0) if totals else 0

    def _pct(num: int, den: int) -> float:
        return round(100.0 * num / den, 2) if den else 0.0

    def _agg_row(r: asyncpg.Record) -> Dict[str, Any]:
        c = int(r["count"] or 0)
        ec = int(r["error_count"] or 0)
        sc = int(r["slow_count"] or 0)
        out: Dict[str, Any] = {
            "count": c,
            "error_count": ec,
            "slow_count": sc,
            "error_pct": _pct(ec, c),
            "slow_pct": _pct(sc, c),
            "p50_ms": int(r.get("p50_ms") or 0),
            "p95_ms": int(r.get("p95_ms") or 0),
        }
        if "p99_ms" in r:
            out["p99_ms"] = int(r.get("p99_ms") or 0)
        if "api_key" in r:
            out["api_key"] = r["api_key"] or ""
            out["api_key_label"] = r.get("api_key_label") or ""
        if "endpoint_name" in r:
            out["endpoint_name"] = r["endpoint_name"]
        if "sum_request_bytes" in r:
            out["sum_request_bytes"] = int(r["sum_request_bytes"] or 0)
            out["sum_response_bytes"] = int(r["sum_response_bytes"] or 0)
        return out

    return {
        "since": _dt_to_iso_z(since),
        "until": _dt_to_iso_z(until),
        "total_count": total_count,
        "error_count": error_count,
        "slow_count": slow_count,
        "error_pct": _pct(error_count, total_count),
        "slow_pct": _pct(slow_count, total_count),
        "p50_ms": int(totals["p50_ms"] or 0) if totals else 0,
        "p95_ms": int(totals["p95_ms"] or 0) if totals else 0,
        "p99_ms": int(totals["p99_ms"] or 0) if totals else 0,
        "sum_request_bytes": int(totals["sum_request_bytes"] or 0) if totals else 0,
        "sum_response_bytes": int(totals["sum_response_bytes"] or 0) if totals else 0,
        "errors_24h": int(errors_24h_row["errors_24h"] or 0) if errors_24h_row else 0,
        "slow_24h": int(errors_24h_row["slow_24h"] or 0) if errors_24h_row else 0,
        "per_key": [_agg_row(r) for r in per_key],
        "per_endpoint": [_agg_row(r) for r in per_endpoint],
        "hourly_series": [
            {
                "hour_bucket": _dt_to_iso_z(r["hour_bucket"]),
                "count": int(r["count"] or 0),
                "error_count": int(r["error_count"] or 0),
                "slow_count": int(r["slow_count"] or 0),
                "avg_time_ms": (
                    int(r["sum_time_ms"] or 0) // int(r["count"] or 1)
                    if int(r["count"] or 0) > 0
                    else 0
                ),
            }
            for r in hourly
        ],
    }


async def request_log_export(
    *,
    api_key: Optional[str] = None,
    endpoint_name: Optional[str] = None,
    status: Optional[int] = None,
    method: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    q: Optional[str] = None,
    slow_only: bool = False,
    errors_only: bool = False,
    auth_kind: Optional[str] = None,
    rate_limited: Optional[bool] = None,
    min_time_ms: Optional[int] = None,
    max_time_ms: Optional[int] = None,
    limit: int = 10000,
) -> List[Dict[str, Any]]:
    result = await request_log_list(
        api_key=api_key,
        endpoint_name=endpoint_name,
        status=status,
        method=method,
        since=since,
        until=until,
        q=q,
        slow_only=slow_only,
        errors_only=errors_only,
        auth_kind=auth_kind,
        rate_limited=rate_limited,
        min_time_ms=min_time_ms,
        max_time_ms=max_time_ms,
        limit=limit,
        offset=0,
    )
    return result["items"]