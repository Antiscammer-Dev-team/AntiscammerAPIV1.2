"""
PostgreSQL database layer for AntiScammer API.
Uses asyncpg. Configure via env: DB_USERNAME, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME (or DATABASE_URL).
SSL: DB_SSLMODE = disable | require | require-no-verify (default: require).
  require-no-verify = use SSL but do not verify server cert (for self-signed/internal).
"""
from __future__ import annotations

import json
import logging
import os
import ssl
from typing import Any, Dict, Optional, Union

import asyncpg

log = logging.getLogger("db")

DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()

DB_HOST = os.getenv("DB_HOST", "manage.modoralabs.com")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "antiscammer")
DB_USER = os.getenv("DB_USERNAME") or os.getenv("DB_USER", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

# SSL: disable | require | require-no-verify (SSL without cert verification)
DB_SSLMODE = (os.getenv("DB_SSLMODE") or "require").strip().lower()

_pool: Optional[asyncpg.Pool] = None


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("Database pool not initialized")
    return _pool


def _ssl_for_asyncpg() -> Union[bool, ssl.SSLContext]:
    """Return ssl argument for asyncpg: False, True, or context that skips verification."""
    if DB_SSLMODE == "disable":
        return False
    if DB_SSLMODE == "require-no-verify":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return True


def _normalize_dsn(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql://" + url[11:]
    return url


async def init_pool() -> asyncpg.Pool:
    global _pool
    if _pool is not None:
        return _pool

    ssl_ctx = _ssl_for_asyncpg()

    if DATABASE_URL:
        dsn = _normalize_dsn(DATABASE_URL)
        _pool = await asyncpg.create_pool(
            dsn=dsn,
            min_size=1,
            max_size=10,
            command_timeout=30,
            ssl=ssl_ctx,
        )
        log.info("Database pool created from DATABASE_URL")
        return _pool

    if not DB_USER or not DB_PASSWORD:
        raise RuntimeError(
            "Set DATABASE_URL or both DB_USERNAME and DB_PASSWORD in env"
        )

    _pool = await asyncpg.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        min_size=1,
        max_size=10,
        command_timeout=30,
        ssl=ssl_ctx,
    )
    log.info(
        "Database pool created %s@%s:%s/%s ssl=%s",
        DB_USER,
        DB_HOST,
        DB_PORT,
        DB_NAME,
        DB_SSLMODE,
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
                label TEXT NOT NULL DEFAULT ''
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS "Admin credentials" (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
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

        # Force correct types even if table existed already
        try:
            await _ensure_jsonb_columns(conn)
        except Exception:
            # If old columns contain invalid JSON strings, the cast can fail.
            # In that case you'd need a one-time manual cleanup, but this makes the error visible.
            log.exception("Failed to migrate reporter_meta/review columns to JSONB")

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


# ----------------------------
# API keys
# ----------------------------
async def api_key_get(key: str) -> Optional[Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            'SELECT key, expires_at, label FROM "API keys" WHERE key = $1', key
        )
    if row is None:
        return None
    return {"expires_at": row["expires_at"], "label": row["label"] or ""}


async def api_key_get_all() -> Dict[str, Dict[str, Any]]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch('SELECT key, expires_at, label FROM "API keys"')
    return {r["key"]: {"expires_at": r["expires_at"], "label": r["label"] or ""} for r in rows}


async def api_key_set(key: str, expires_at: str, label: str) -> None:
    pool = get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO "API keys" (key, expires_at, label)
            VALUES ($1, $2, $3)
            ON CONFLICT (key) DO UPDATE SET expires_at = $2, label = $3
            """,
            key, expires_at, label,
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


# ----------------------------
# Known scammers
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