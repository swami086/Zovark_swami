"""Model flywheel: publish finetuning artifact events to Redpanda (Kafka API).

Downstream MLOps / quantization jobs can subscribe to
``platform.finetuning.data_ready.{tenant_id}`` when export completes.
Mirrors the pattern in ``workflows/feedback_aggregation.emit_feedback_summary``.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger(__name__)

FINETUNING_DATA_READY_SCHEMA = "zovark.platform.finetuning.data_ready.v1"


def finetuning_data_ready_topic(tenant_id: str) -> str:
    tid = (tenant_id or "").strip() or "global"
    return f"platform.finetuning.data_ready.{tid}"


def build_finetuning_data_ready_envelope(
    tenant_id: str,
    *,
    job_id: str,
    training_path: str,
    dpo_path: str,
    examples_count: int,
    dpo_rows: int,
) -> Dict[str, Any]:
    return {
        "schema": FINETUNING_DATA_READY_SCHEMA,
        "tenant_id": tenant_id,
        "job_id": job_id,
        "training_path": training_path,
        "dpo_path": dpo_path or "",
        "examples_count": int(examples_count),
        "dpo_rows": int(dpo_rows),
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }


def emit_finetuning_data_ready_sync(tenant_id: str, envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Blocking Kafka publish. Call via ``asyncio.to_thread`` from activities."""
    brokers = os.environ.get("ZOVARK_REDPANDA_BROKERS", "").strip()
    if not brokers:
        return {"emitted": False, "reason": "redpanda not configured"}

    topic = finetuning_data_ready_topic(tenant_id)
    key = (envelope.get("job_id") or "").encode("utf-8")

    def _send() -> None:
        from kafka import KafkaProducer

        hosts = [b.strip() for b in brokers.split(",") if b.strip()]
        producer = KafkaProducer(
            bootstrap_servers=hosts,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        try:
            producer.send(topic, key=key or None, value=envelope)
            producer.flush(timeout=10)
        finally:
            producer.close()

    try:
        _send()
        return {"emitted": True, "topic": topic}
    except Exception as e:
        logger.warning("emit_finetuning_data_ready_sync failed: %s", e)
        return {"emitted": False, "reason": str(e)[:500]}
