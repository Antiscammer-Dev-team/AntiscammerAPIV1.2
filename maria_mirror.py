from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Optional

import aiomysql

log = logging.getLogger("app")

MARIADB_HOST = os.getenv("MARIADB_HOST", "").strip()
MARIADB_PORT = int(os.getenv("MARIADB_PORT", "3306"))
MARIADB_USER = os.getenv("MARIADB_USER", "").strip() or os.getenv("MARIADB_USERNAME", "").strip()
MARIADB_PASSWORD = os.getenv("MARIADB_PASSWORD", "").strip()
MARIADB_DB = os.getenv("MARIADB_DB", "").strip()

_pool: Optional[aiomysql.Pool] = None
_lock = asyncio.Lock()


def _as_int_or_none(value: Optional[str]) -> Optional[int]:
  """If value is a string of digits (e.g. Discord user ID), return int; else None. For integer columns."""
  if value is None:
      return None
  s = (value or "").strip()
  if not s or not s.isdigit():
      return None
  try:
      return int(s)
  except ValueError:
      return None


def _enabled() -> bool:
  """Return True if we have enough configuration to talk to the secondary MariaDB."""
  return bool(MARIADB_HOST and MARIADB_USER and MARIADB_PASSWORD and MARIADB_DB)


async def _get_pool() -> Optional[aiomysql.Pool]:
  """
  Lazily create and return a MariaDB connection pool.
  Returns None if MariaDB mirroring is not configured.
  """
  global _pool
  if not _enabled():
      return None

  if _pool is not None:
      return _pool

  async with _lock:
      if _pool is not None:
          return _pool
      try:
          _pool = await aiomysql.create_pool(
              host=MARIADB_HOST,
              port=MARIADB_PORT,
              user=MARIADB_USER,
              password=MARIADB_PASSWORD,
              db=MARIADB_DB,
              minsize=1,
              maxsize=5,
              autocommit=True,
          )
          log.info(
              "MariaDB mirror pool created host=%s port=%s db=%s",
              MARIADB_HOST,
              MARIADB_PORT,
              MARIADB_DB,
          )
      except Exception:
          log.exception("Failed to create MariaDB mirror pool")
          _pool = None
      return _pool


async def mirror_global_ban_insert(
    *,
    user_id: str,
    reason: str,
    banned_by_user_id: str,
    source: str,
    report_id: str,  # string e.g. "RPT_000000" or "" for none
) -> None:
  """
  Insert into MariaDB global_bans only (MariaDB-specific schema).
  Postgres uses a different table/schema ("Global banlist": user_id, reason only) in db.py.
  This function does not touch Postgres.

  report_id: str, e.g. "RPT-00006" or "RPT_000000"; stored as VARCHAR. Use "" for NULL.

  MariaDB global_bans schema (already created on the MariaDB side):

      global_bans(
          id                BIGINT AUTO_INCREMENT PRIMARY KEY,
          user_id           VARCHAR(...) NOT NULL,
          reason            TEXT NOT NULL,
          banned_by_user_id INT/BIGINT NULL,
          source            VARCHAR(...) NULL,
          report_id         VARCHAR(...) NULL,
          created_at        DATETIME NOT NULL,
          updated_at        DATETIME NOT NULL
      )
  """
  if not _enabled():
      log.warning(
          "MariaDB mirroring skipped: set MARIADB_HOST, MARIADB_USER, MARIADB_PASSWORD, MARIADB_DB to enable"
      )
      return

  pool = await _get_pool()
  if pool is None:
      log.warning("MariaDB mirroring skipped: could not create connection pool")
      return

  try:
      async with pool.acquire() as conn:
          async with conn.cursor() as cur:
              # banned_by_user_id is INTEGER in DB; report_id is VARCHAR (string)
              banned_by_int = _as_int_or_none(banned_by_user_id)
              report_id_val = (report_id or "").strip() or None  # empty string -> NULL
              await cur.execute(
                  """
                  INSERT INTO global_bans (
                      user_id,
                      reason,
                      banned_by_user_id,
                      source,
                      report_id,
                      created_at,
                      updated_at
                  )
                  VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                  """,
                  (user_id, reason, banned_by_int, source, report_id_val),
              )
      log.info(
          "Mirrored global ban to MariaDB: user_id=%s report_id=%s source=%s",
          user_id, report_id or "(none)", source,
      )
  except Exception:
      log.exception(
          "MariaDB global_bans insert failed: user_id=%s report_id=%s",
          user_id, report_id,
      )


async def fetch_all_global_bans() -> dict[str, str]:
  """
  Return {user_id: reason} for every row in MariaDB global_bans.
  Empty dict if mirroring isn't configured or the query fails.
  """
  if not _enabled():
      return {}

  pool = await _get_pool()
  if pool is None:
      return {}

  try:
      async with pool.acquire() as conn:
          async with conn.cursor() as cur:
              await cur.execute("SELECT user_id, reason FROM global_bans")
              rows = await cur.fetchall()
      return {str(user_id): reason for user_id, reason in rows}
  except Exception:
      log.exception("MariaDB global_bans fetch failed")
      return {}


async def mirror_global_ban_delete(user_id: str) -> None:
  """Remove the global_bans row for this user_id (mirror of Postgres delete)."""
  if not _enabled():
      return
  pool = await _get_pool()
  if pool is None:
      return
  try:
      async with pool.acquire() as conn:
          async with conn.cursor() as cur:
              await cur.execute("DELETE FROM global_bans WHERE user_id = %s", (user_id,))
      log.info("Removed user_id=%s from MariaDB global_bans", user_id)
  except Exception:
      log.exception("MariaDB global_bans delete failed: user_id=%s", user_id)


# A host label chain like evil.example.com (or an IPv4 address); no scheme/path/port.
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")


def _scam_url_host(value: str) -> Optional[str]:
  """
  Reduce a scam_urls value to a bare host, or None if it isn't host-only.

  The API's "URL list" is keyed by domain, so a value with a path (e.g. a phishing page
  hosted on docs.google.com) must NOT be collapsed to its host - that would flag the
  whole shared domain as a scam.
  """
  v = (value or "").strip().lower()
  v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
  v = v.rstrip("/")
  if any(c in v for c in "/?#"):
      return None
  v = v.rsplit("@", 1)[-1].split(":", 1)[0]
  if v.startswith("www."):
      v = v[4:]
  if len(v) > 253 or not _HOST_RE.match(v):
      return None
  return v


async def fetch_host_only_scam_urls() -> Optional[dict[str, str]]:
  """
  Return {host: source} for every host-only row in MariaDB scam_urls (entries with a
  path are skipped, see _scam_url_host). Returns None if mirroring isn't configured or
  the query fails, so callers can tell "no rows" apart from "couldn't read".
  """
  if not _enabled():
      return None

  pool = await _get_pool()
  if pool is None:
      return None

  try:
      async with pool.acquire() as conn:
          async with conn.cursor() as cur:
              # Pre-filter in SQL so path-bearing feed URLs (the bulk of the table)
              # never leave MariaDB; _scam_url_host re-checks each row.
              await cur.execute(
                  "SELECT value, source FROM scam_urls "
                  "WHERE value NOT LIKE %s OR value REGEXP %s",
                  ("%/%", "^[a-z][a-z0-9+.-]*://[^/?#]+/?$"),
              )
              rows = await cur.fetchall()
  except Exception:
      log.exception("MariaDB scam_urls fetch failed")
      return None

  out: dict[str, str] = {}
  for value, source in rows:
      host = _scam_url_host(str(value))
      if host:
          out.setdefault(host, str(source or "manual"))
  return out
