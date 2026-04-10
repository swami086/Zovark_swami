"""
DEPRECATED — NATS is no longer used for task dispatch.

Ingest and queued tasks are published to Redpanda (`tasks.new.{tenant_id}`).
See `redpanda_consumer.py`.
"""


def create_nats_consumer(worker_id: str = "unknown"):  # noqa: ARG001
    """No-op stub; NATS pipeline removed."""
    return None
