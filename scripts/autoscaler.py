#!/usr/bin/env python3
"""ZOVARC Docker Compose Autoscaler — queue-depth-based worker scaling.

Polls Temporal queue depth (via SDK or DB fallback) every POLL_INTERVAL seconds.
Scales worker containers up when pending tasks exceed threshold, and down after
a cooldown period of zero pending tasks.

Usage:
    python scripts/autoscaler.py

Environment variables:
    AUTOSCALE_MIN=1             Minimum workers (default 1)
    AUTOSCALE_MAX=10            Maximum workers (default 10)
    AUTOSCALE_THRESHOLD=5       Pending tasks before scale-up (default 5)
    AUTOSCALE_COOLDOWN=300      Seconds of zero pending before scale-down (default 300)
    AUTOSCALE_STEP_UP=2         Workers to add per scale-up (default 2)
    TEMPORAL_ADDRESS=localhost:7233  Temporal gRPC address
    POLL_INTERVAL=15            Seconds between checks (default 15)
    COMPOSE_PROJECT_DIR=.       Docker compose project directory
    DATABASE_URL=               PostgreSQL URL for fallback queue depth query
"""

import os
import sys
import time
import json
import asyncio
import logging
import subprocess
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [autoscaler] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("autoscaler")

# Temporal SDK is optional — fall back to DB if not available
try:
    from temporalio.client import Client as TemporalClient
    HAS_TEMPORAL_SDK = True
except ImportError:
    HAS_TEMPORAL_SDK = False
    log.warning("temporalio SDK not installed, using DB fallback for queue depth")

# Configuration
AUTOSCALE_MIN = int(os.environ.get("AUTOSCALE_MIN", "1"))
AUTOSCALE_MAX = int(os.environ.get("AUTOSCALE_MAX", "10"))
AUTOSCALE_THRESHOLD = int(os.environ.get("AUTOSCALE_THRESHOLD", "5"))
AUTOSCALE_COOLDOWN = int(os.environ.get("AUTOSCALE_COOLDOWN", "300"))
AUTOSCALE_STEP_UP = int(os.environ.get("AUTOSCALE_STEP_UP", "2"))
TEMPORAL_ADDRESS = os.environ.get("TEMPORAL_ADDRESS", "localhost:7233")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))
COMPOSE_PROJECT_DIR = os.environ.get("COMPOSE_PROJECT_DIR", ".")
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@localhost:5432/zovarc"
)

# State
_temporal_client = None
_last_zero_pending = None  # timestamp when pending first hit zero
_scale_events = []  # for metrics


async def _get_temporal_client():
    """Get or create Temporal client (cached)."""
    global _temporal_client
    if _temporal_client is None and HAS_TEMPORAL_SDK:
        try:
            _temporal_client = await TemporalClient.connect(TEMPORAL_ADDRESS)
            log.info("Connected to Temporal at %s", TEMPORAL_ADDRESS)
        except Exception as e:
            log.warning("Temporal connection failed: %s", e)
    return _temporal_client


async def get_queue_depth_sdk() -> dict:
    """Get pending + running workflow counts via Temporal SDK.

    Returns: {pending: int, running: int}
    """
    client = await _get_temporal_client()
    if client is None:
        raise RuntimeError("No Temporal client")

    running = await client.count_workflows("ExecutionStatus='Running'")
    # Temporal doesn't expose task queue backlog directly via SDK,
    # so count Running as a proxy for active work
    return {"pending": 0, "running": running.count}


def get_queue_depth_db() -> dict:
    """Get pending + running task counts from PostgreSQL.

    Returns: {pending: int, running: int}
    """
    try:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status, COUNT(*) FROM agent_tasks "
                    "WHERE status IN ('pending', 'running') GROUP BY status"
                )
                counts = {"pending": 0, "running": 0}
                for row in cur.fetchall():
                    counts[row[0]] = row[1]
                return counts
        finally:
            conn.close()
    except Exception as e:
        log.warning("DB queue depth query failed: %s", e)
        return {"pending": 0, "running": 0}


def get_queue_depth_docker() -> dict:
    """Fallback: count tasks via docker exec into postgres."""
    try:
        result = subprocess.run(
            [
                "docker", "exec", "zovarc-postgres", "psql", "-U", "zovarc",
                "-d", "zovarc", "-t", "-c",
                "SELECT status, COUNT(*) FROM agent_tasks "
                "WHERE status IN ('pending', 'running') GROUP BY status",
            ],
            capture_output=True, text=True, timeout=10,
        )
        counts = {"pending": 0, "running": 0}
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.strip().split("|")
                if len(parts) == 2:
                    status = parts[0].strip()
                    count = int(parts[1].strip())
                    if status in counts:
                        counts[status] = count
        return counts
    except Exception as e:
        log.warning("Docker queue depth fallback failed: %s", e)
        return {"pending": 0, "running": 0}


async def get_queue_depth() -> dict:
    """Get queue depth using best available method.

    Returns: {pending: int, running: int}
    """
    # Try Temporal SDK first
    if HAS_TEMPORAL_SDK:
        try:
            return await get_queue_depth_sdk()
        except Exception:
            pass

    # Try direct DB connection
    try:
        import psycopg2  # noqa: F401
        return get_queue_depth_db()
    except ImportError:
        pass

    # Fall back to docker exec
    return get_queue_depth_docker()


def get_current_workers() -> int:
    """Get current worker replica count."""
    try:
        result = subprocess.run(
            [
                "docker", "compose", "-f",
                f"{COMPOSE_PROJECT_DIR}/docker-compose.yml",
                "ps", "--format", "json", "worker",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            entries = [
                json.loads(line)
                for line in result.stdout.strip().split("\n")
                if line.strip()
            ]
            # Only count running containers
            running = [e for e in entries if e.get("State") == "running"]
            return len(running) if running else len(entries)
    except Exception as e:
        log.warning("Failed to get worker count: %s", e)
    return 1


def scale_workers(target: int) -> bool:
    """Scale workers to target count. Returns True if successful."""
    target = max(AUTOSCALE_MIN, min(AUTOSCALE_MAX, target))
    log.info("Scaling workers to %d", target)
    try:
        result = subprocess.run(
            [
                "docker", "compose", "-f",
                f"{COMPOSE_PROJECT_DIR}/docker-compose.yml",
                "up", "-d", "--scale", f"worker={target}", "--no-recreate",
            ],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            log.info("Scale to %d successful", target)
            return True
        else:
            log.error("Scale failed: %s", result.stderr[:200])
            return False
    except Exception as e:
        log.error("Scale command failed: %s", e)
        return False


async def run_loop():
    """Main autoscaling loop with cooldown logic."""
    global _last_zero_pending

    log.info(
        "ZOVARC Autoscaler started: min=%d max=%d threshold=%d cooldown=%ds step=%d poll=%ds",
        AUTOSCALE_MIN, AUTOSCALE_MAX, AUTOSCALE_THRESHOLD,
        AUTOSCALE_COOLDOWN, AUTOSCALE_STEP_UP, POLL_INTERVAL,
    )

    while True:
        try:
            depth = await get_queue_depth()
            pending = depth["pending"] + depth["running"]
            current = get_current_workers()

            # Compute desired worker count
            if pending > AUTOSCALE_THRESHOLD:
                # Scale up: add STEP_UP workers, capped at MAX
                desired = min(AUTOSCALE_MAX, current + AUTOSCALE_STEP_UP)
                _last_zero_pending = None
            elif pending == 0:
                # Track cooldown for scale-down
                now = time.time()
                if _last_zero_pending is None:
                    _last_zero_pending = now
                elapsed_zero = now - _last_zero_pending

                if elapsed_zero >= AUTOSCALE_COOLDOWN and current > AUTOSCALE_MIN:
                    # Scale down after cooldown
                    desired = AUTOSCALE_MIN
                    log.info(
                        "Zero pending for %ds (cooldown=%ds), scaling down",
                        int(elapsed_zero), AUTOSCALE_COOLDOWN,
                    )
                else:
                    desired = current
            else:
                # Some tasks but under threshold — maintain current
                _last_zero_pending = None
                desired = current

            log.info(
                "pending=%d running=%d workers=%d desired=%d",
                depth["pending"], depth["running"], current, desired,
            )

            if desired != current:
                action = "scale_up" if desired > current else "scale_down"
                success = scale_workers(desired)
                _scale_events.append({
                    "time": datetime.utcnow().isoformat(),
                    "action": action,
                    "from": current,
                    "to": desired,
                    "success": success,
                })

        except Exception as e:
            log.error("Autoscale loop error: %s", e)

        await asyncio.sleep(POLL_INTERVAL)


def print_status():
    """Print current autoscaler status (for --status flag)."""
    current = get_current_workers()
    print(f"Current workers: {current}")
    print(f"Config: min={AUTOSCALE_MIN} max={AUTOSCALE_MAX} threshold={AUTOSCALE_THRESHOLD}")
    print(f"Temporal: {TEMPORAL_ADDRESS}")
    print(f"Compose dir: {COMPOSE_PROJECT_DIR}")


if __name__ == "__main__":
    if "--status" in sys.argv:
        print_status()
    else:
        asyncio.run(run_loop())
