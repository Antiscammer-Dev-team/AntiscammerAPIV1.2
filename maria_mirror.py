from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import aiomysql

log = logging.getLogger("maria_mirror")

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
    report_id: str,
) -> None:
  """
  Insert a global ban row into the existing `global_bans` table in the secondary MariaDB.

  Expected schema (already created on the MariaDB side, not touched here):

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
  pool = await _get_pool()
  if pool is None:
      return

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
              (user_id, reason, banned_by_user_id, source, report_id),
          )

