"""Tiered database connection pool manager using asyncpg.

Pools:
  - critical: alert ingestion (min=10, max=20, timeout=5s)
  - normal: investigations (min=5, max=15, timeout=30s)
  - background: analytics/retention (min=2, max=5, timeout=60s)
"""
import os
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
)

POOL_CONFIGS = {
    "critical": {"min_size": 10, "max_size": 20, "command_timeout": 5},
    "normal": {"min_size": 5, "max_size": 15, "command_timeout": 30},
    "background": {"min_size": 2, "max_size": 5, "command_timeout": 60},
}


class ConnectionPoolManager:
    """Manages tiered asyncpg connection pools."""

    def __init__(self, database_url: str = None):
        self.database_url = database_url or DATABASE_URL
        self._pools = {}

    async def initialize(self):
        """Create connection pools for each tier."""
        try:
            import asyncpg
        except ImportError:
            logger.warning("asyncpg not installed — pool manager unavailable")
            return

        for tier, config in POOL_CONFIGS.items():
            try:
                pool = await asyncpg.create_pool(
                    self.database_url,
                    min_size=config["min_size"],
                    max_size=config["max_size"],
                    command_timeout=config["command_timeout"],
                    server_settings={"jit": "off", "application_name": f"hydra-{tier}"},
                )
                self._pools[tier] = pool
                logger.info(f"Pool '{tier}' initialized: min={config['min_size']}, max={config['max_size']}")
            except Exception as e:
                logger.error(f"Failed to create pool '{tier}': {e}")

    async def acquire(self, tier: str = "normal"):
        """Acquire a connection from the specified tier's pool.

        Falls back to 'normal' tier if requested tier unavailable.
        """
        pool = self._pools.get(tier) or self._pools.get("normal")
        if pool is None:
            raise RuntimeError(f"No connection pool available (requested: {tier})")
        return pool.acquire()

    async def execute(self, query: str, *args, tier: str = "normal"):
        """Execute a query using the specified tier's pool."""
        pool = self._pools.get(tier) or self._pools.get("normal")
        if pool is None:
            raise RuntimeError(f"No connection pool available (requested: {tier})")
        async with pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetch(self, query: str, *args, tier: str = "normal"):
        """Fetch rows using the specified tier's pool."""
        pool = self._pools.get(tier) or self._pools.get("normal")
        if pool is None:
            raise RuntimeError(f"No connection pool available (requested: {tier})")
        async with pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args, tier: str = "normal"):
        """Fetch a single row."""
        pool = self._pools.get(tier) or self._pools.get("normal")
        if pool is None:
            raise RuntimeError(f"No connection pool available (requested: {tier})")
        async with pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def close(self):
        """Gracefully close all pools."""
        for tier, pool in self._pools.items():
            try:
                await pool.close()
                logger.info(f"Pool '{tier}' closed")
            except Exception as e:
                logger.warning(f"Error closing pool '{tier}': {e}")
        self._pools.clear()

    @property
    def is_initialized(self):
        return len(self._pools) > 0


# Module-level singleton
_pool_manager = None


async def get_pool_manager(database_url: str = None) -> ConnectionPoolManager:
    global _pool_manager
    if _pool_manager is None:
        _pool_manager = ConnectionPoolManager(database_url)
        await _pool_manager.initialize()
    return _pool_manager
