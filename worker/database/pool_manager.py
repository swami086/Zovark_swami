"""Tiered database connection pool manager using psycopg2.

Pools:
  - critical: alert ingestion (min=10, max=20)
  - normal: investigations (min=5, max=15)
  - background: analytics/retention (min=2, max=5)

Usage:
    from database.pool_manager import pooled_connection

    with pooled_connection("critical") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT ...")
"""
import os
import logging
from contextlib import contextmanager

import psycopg2
from psycopg2.pool import ThreadedConnectionPool

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
)

POOL_CONFIGS = {
    "critical": {"minconn": 10, "maxconn": 20},
    "normal": {"minconn": 5, "maxconn": 15},
    "background": {"minconn": 2, "maxconn": 5},
}

# Module-level pool storage
_pools: dict[str, ThreadedConnectionPool] = {}


def initialize_pools(database_url: str = None):
    """Create connection pools for each tier. Call once at worker startup."""
    global _pools
    dsn = database_url or DATABASE_URL

    for tier, config in POOL_CONFIGS.items():
        try:
            pool = ThreadedConnectionPool(
                config["minconn"],
                config["maxconn"],
                dsn,
                options=f"-c jit=off -c application_name=hydra-{tier}",
            )
            _pools[tier] = pool
            logger.info(f"Pool '{tier}' initialized: min={config['minconn']}, max={config['maxconn']}")
        except Exception as e:
            logger.error(f"Failed to create pool '{tier}': {e}")


def close_pools():
    """Gracefully close all pools. Call at worker shutdown."""
    global _pools
    for tier, pool in _pools.items():
        try:
            pool.closeall()
            logger.info(f"Pool '{tier}' closed")
        except Exception as e:
            logger.warning(f"Error closing pool '{tier}': {e}")
    _pools.clear()


@contextmanager
def pooled_connection(tier: str = "normal"):
    """Context manager that borrows a connection from the specified tier's pool.

    Auto-returns the connection when the block exits. Commits on success,
    rolls back on exception.

    Falls back to 'normal' tier if requested tier unavailable.
    Falls back to a fresh psycopg2.connect() if no pools are initialized.

    Usage:
        with pooled_connection("critical") as conn:
            with conn.cursor() as cur:
                cur.execute(...)
    """
    pool = _pools.get(tier) or _pools.get("normal")

    if pool is None:
        # Fallback: no pool initialized (e.g., during tests or startup race)
        logger.warning(f"No pool available for tier '{tier}', using direct connection")
        conn = psycopg2.connect(DATABASE_URL)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return

    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)
