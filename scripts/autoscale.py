#!/usr/bin/env python3
"""Docker Compose autoscaler — polls Temporal queue depth and scales workers.

Usage (host):
    python3 scripts/autoscale.py

Usage (container):
    docker compose -f docker-compose.yml -f docker-compose.autoscaler.yml up autoscaler

Environment variables:
    AUTOSCALE_MIN=1         Minimum workers (default 1)
    AUTOSCALE_MAX=10        Maximum workers (default 10)
    AUTOSCALE_THRESHOLD=5   Pending tasks per worker before scale-up (default 5)
    TEMPORAL_ADDRESS=temporal:7233  Temporal server address
    POLL_INTERVAL=15        Seconds between checks (default 15)
"""

import os
import sys
import time
import asyncio
import subprocess

# Temporal SDK is optional — fall back to HTTP if not available
try:
    from temporalio.client import Client as TemporalClient
    HAS_TEMPORAL_SDK = True
except ImportError:
    HAS_TEMPORAL_SDK = False

AUTOSCALE_MIN = int(os.environ.get("AUTOSCALE_MIN", "1"))
AUTOSCALE_MAX = int(os.environ.get("AUTOSCALE_MAX", "10"))
AUTOSCALE_THRESHOLD = int(os.environ.get("AUTOSCALE_THRESHOLD", "5"))
TEMPORAL_ADDRESS = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))
COMPOSE_PROJECT = os.environ.get("COMPOSE_PROJECT_DIR", ".")


async def get_queue_depth_sdk() -> int:
    """Get pending task count via Temporal SDK."""
    client = await TemporalClient.connect(TEMPORAL_ADDRESS)
    desc = await client.get_workflow_handle("__system").describe()
    # Use workflow count as proxy (SDK doesn't expose queue depth directly)
    count_result = await client.count_workflows("ExecutionStatus='Running'")
    return count_result.count


def get_queue_depth_fallback() -> int:
    """Fallback: count running workflows via docker exec."""
    try:
        result = subprocess.run(
            ["docker", "exec", "hydra-postgres", "psql", "-U", "hydra", "-d", "hydra",
             "-t", "-c", "SELECT COUNT(*) FROM agent_tasks WHERE status IN ('pending', 'running')"],
            capture_output=True, text=True, timeout=10
        )
        return int(result.stdout.strip()) if result.returncode == 0 else 0
    except Exception as e:
        print(f"Queue depth fallback failed: {e}")
        return 0


def get_current_workers() -> int:
    """Get current worker replica count."""
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", f"{COMPOSE_PROJECT}/docker-compose.yml",
             "ps", "--format", "json", "worker"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            import json
            entries = [json.loads(line) for line in result.stdout.strip().split('\n') if line.strip()]
            return len(entries)
    except Exception:
        pass
    return 1


def scale_workers(target: int) -> None:
    """Scale workers to target count."""
    target = max(AUTOSCALE_MIN, min(AUTOSCALE_MAX, target))
    print(f"Scaling workers to {target}")
    subprocess.run(
        ["docker", "compose", "-f", f"{COMPOSE_PROJECT}/docker-compose.yml",
         "up", "-d", "--scale", f"worker={target}", "--no-recreate"],
        timeout=60
    )


async def run_loop():
    """Main autoscaling loop."""
    print(f"HYDRA Autoscaler started: min={AUTOSCALE_MIN}, max={AUTOSCALE_MAX}, "
          f"threshold={AUTOSCALE_THRESHOLD}, poll={POLL_INTERVAL}s")

    while True:
        try:
            pending = get_queue_depth_fallback()
            current = get_current_workers()
            desired = max(AUTOSCALE_MIN, min(AUTOSCALE_MAX, pending // AUTOSCALE_THRESHOLD + 1))

            print(f"[autoscale] pending={pending} current={current} desired={desired}")

            if desired != current:
                scale_workers(desired)
        except Exception as e:
            print(f"[autoscale] error: {e}")

        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    asyncio.run(run_loop())
