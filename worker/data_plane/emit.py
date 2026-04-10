"""
Fire-and-forget projections after PostgreSQL commit: stream + graph + analytics file.
"""
from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

try:
    from settings import settings
except ImportError:  # pragma: no cover
    settings = None  # type: ignore

_kafka_producer = None
_kafka_lock = threading.Lock()
_surreal_schema_ready = False


def _settings():
    if settings is None:
        raise RuntimeError("settings unavailable")
    return settings


def reset_data_plane_state_for_tests() -> None:
    """Clear module caches (unit tests only)."""
    global _kafka_producer, _surreal_schema_ready
    with _kafka_lock:
        if _kafka_producer is not None:
            try:
                _kafka_producer.flush(timeout=2)
                _kafka_producer.close()
            except Exception:
                pass
            _kafka_producer = None
    _surreal_schema_ready = False


def _kafka_producer_sync(brokers: str):
    global _kafka_producer
    from kafka import KafkaProducer

    with _kafka_lock:
        if _kafka_producer is None:
            hosts = [h.strip() for h in brokers.split(",") if h.strip()]
            _kafka_producer = KafkaProducer(
                bootstrap_servers=hosts,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k is not None else None,
                linger_ms=5,
                retries=2,
            )
        return _kafka_producer


def _emit_redpanda(payload: dict, topic: str, key: str) -> None:
    s = _settings()
    prod = _kafka_producer_sync(s.redpanda_brokers)
    prod.send(topic, key=key, value=payload)
    prod.flush(timeout=5)


async def _emit_surreal(record: dict) -> None:
    global _surreal_schema_ready
    s = _settings()
    base = s.surreal_http_url.rstrip("/")
    user = s.surreal_user
    pwd = s.surreal_password.get_secret_value()
    headers = {
        "Accept": "application/json",
        "Surreal-NS": s.surreal_ns,
        "Surreal-DB": s.surreal_db,
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        if not _surreal_schema_ready:
            r = await client.post(
                f"{base}/sql",
                headers=headers,
                auth=(user, pwd),
                content="DEFINE TABLE IF NOT EXISTS investigation SCHEMALESS;",
            )
            r.raise_for_status()
            _surreal_schema_ready = True
        r2 = await client.post(
            f"{base}/key/investigation",
            headers=headers,
            auth=(user, pwd),
            json=record,
        )
        r2.raise_for_status()


def _emit_duckdb_row(row: dict) -> None:
    import duckdb

    s = _settings()
    path = s.duckdb_path
    con = duckdb.connect(path)
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_completed (
                stored_at TIMESTAMPTZ,
                task_id VARCHAR,
                tenant_id VARCHAR,
                verdict VARCHAR,
                risk_score INTEGER,
                task_type VARCHAR,
                trace_id VARCHAR,
                investigation_id VARCHAR
            )
            """
        )
        con.execute(
            """
            INSERT INTO investigation_completed VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            [
                row["stored_at"],
                row["task_id"],
                row["tenant_id"],
                row["verdict"],
                row["risk_score"],
                row["task_type"],
                row["trace_id"],
                row["investigation_id"],
            ],
        )
    finally:
        con.close()


async def emit_after_investigation_stored(
    *,
    task_id: str,
    tenant_id: str,
    verdict: str,
    risk_score: int,
    task_type: str,
    trace_id: str,
    investigation_id: Optional[str],
    status: str,
) -> None:
    """
    Called after agent_tasks commit. Each backend is optional and isolated; errors are swallowed by caller.
    """
    if settings is None:
        return

    s = settings
    now = datetime.now(timezone.utc)
    stored_at = now.isoformat()
    base_payload: dict[str, Any] = {
        "schema": "zovark.investigation.completed.v1",
        "stored_at": stored_at,
        "task_id": task_id,
        "tenant_id": tenant_id,
        "verdict": verdict,
        "risk_score": int(risk_score),
        "task_type": task_type,
        "trace_id": trace_id or "",
        "investigation_id": investigation_id or "",
        "status": status,
    }

    if s.redpanda_enabled:
        await asyncio.to_thread(
            _emit_redpanda,
            base_payload,
            s.redpanda_topic_investigations,
            task_id,
        )

    if s.surreal_enabled:
        surreal_record = {k: v for k, v in base_payload.items() if k != "schema"}
        await _emit_surreal(surreal_record)

    if s.duckdb_enabled:
        row = {
            "stored_at": now,
            "task_id": task_id,
            "tenant_id": tenant_id,
            "verdict": verdict,
            "risk_score": int(risk_score),
            "task_type": task_type,
            "trace_id": trace_id or "",
            "investigation_id": investigation_id or "",
        }
        await asyncio.to_thread(_emit_duckdb_row, row)
