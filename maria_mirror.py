from __future__ import annotations

import asyncio
import logging
import os
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

  report_id: str, e.g. "RPT_000000" or "" (stored as NULL when empty).

  MariaDB global_bans schema (already created on the MariaDB side):

      global_bans(
          id                BIGINT AUTO_INCREMENT PRIMARY KEY,
          user_id           VARCHAR(...) NOT NULL,
          reason            TEXT NOT NULL,
          banned_by_user_id VARCHAR(...) NULL,
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
                  (user_id, reason, banned_by_user_id, source, report_id or None),
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

