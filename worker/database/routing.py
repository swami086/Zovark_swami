"""Read/write routing with replica lag tracking.

Routes reads to healthy replicas, writes to primary.
Falls back to primary when no healthy replicas are available.
Works with zero replicas (single-DB deployment).
"""
import os
import random
import logging
from contextvars import ContextVar
from functools import wraps

logger = logging.getLogger(__name__)

# Context variable for read/write routing
operation_context: ContextVar[str] = ContextVar("operation_context", default="write")

REPLICA_LAG_THRESHOLD = 5.0  # seconds


class DatabaseRouter:
    """Routes queries to primary or replica based on operation context."""

    def __init__(self, primary_url: str = None, replica_urls: list = None):
        self.primary_url = primary_url or os.environ.get(
            "DATABASE_URL",
            "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
        )
        replica_str = os.environ.get("DATABASE_REPLICA_URLS", "")
        self.replica_urls = replica_urls or [u.strip() for u in replica_str.split(",") if u.strip()]
        self._replica_health = {url: {"lag": 0.0, "healthy": True} for url in self.replica_urls}

    def get_url(self) -> str:
        """Get the appropriate database URL based on current operation context."""
        ctx = operation_context.get()

        if ctx == "read" and self.replica_urls:
            healthy = [url for url, health in self._replica_health.items()
                       if health["healthy"] and health["lag"] < REPLICA_LAG_THRESHOLD]
            if healthy:
                return random.choice(healthy)
            logger.warning("No healthy replicas, falling back to primary for read")

        return self.primary_url

    async def update_replica_health(self):
        """Check replica lag and update health status."""
        try:
            import asyncpg
        except ImportError:
            return

        for url in self.replica_urls:
            try:
                conn = await asyncpg.connect(url, timeout=5)
                try:
                    row = await conn.fetchrow(
                        "SELECT CASE WHEN pg_is_in_recovery() "
                        "THEN EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp())) "
                        "ELSE 0 END AS lag"
                    )
                    lag = float(row["lag"]) if row else 0.0
                    was_healthy = self._replica_health[url]["healthy"]
                    self._replica_health[url] = {"lag": lag, "healthy": lag < REPLICA_LAG_THRESHOLD}
                    if was_healthy and not self._replica_health[url]["healthy"]:
                        logger.warning(f"Replica {url} unhealthy: lag={lag:.1f}s")
                    elif not was_healthy and self._replica_health[url]["healthy"]:
                        logger.info(f"Replica {url} recovered: lag={lag:.1f}s")
                finally:
                    await conn.close()
            except Exception as e:
                self._replica_health[url] = {"lag": 999.0, "healthy": False}
                logger.warning(f"Replica {url} unreachable: {e}")

    @property
    def has_replicas(self) -> bool:
        return len(self.replica_urls) > 0

    @property
    def healthy_replica_count(self) -> int:
        return sum(1 for h in self._replica_health.values() if h["healthy"])


def read_operation(func):
    """Decorator to mark a function as a read operation."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        token = operation_context.set("read")
        try:
            return await func(*args, **kwargs)
        finally:
            operation_context.reset(token)
    return wrapper


def write_operation(func):
    """Decorator to mark a function as a write operation."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        token = operation_context.set("write")
        try:
            return await func(*args, **kwargs)
        finally:
            operation_context.reset(token)
    return wrapper


# Module-level singleton
_router = None


def get_router() -> DatabaseRouter:
    global _router
    if _router is None:
        _router = DatabaseRouter()
    return _router
