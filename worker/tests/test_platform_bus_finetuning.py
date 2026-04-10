"""Ticket 5 — finetuning flywheel Redpanda envelope (no broker required)."""

from finetuning.platform_bus import (
    FINETUNING_DATA_READY_SCHEMA,
    build_finetuning_data_ready_envelope,
    finetuning_data_ready_topic,
)


def test_finetuning_data_ready_topic():
    assert finetuning_data_ready_topic("e1c1bc5d-0000-0000-0000-000000000000") == (
        "platform.finetuning.data_ready.e1c1bc5d-0000-0000-0000-000000000000"
    )
    assert finetuning_data_ready_topic("") == "platform.finetuning.data_ready.global"
    assert finetuning_data_ready_topic("   ") == "platform.finetuning.data_ready.global"


def test_build_envelope_schema_and_counts():
    env = build_finetuning_data_ready_envelope(
        "00000000-0000-0000-0000-000000000001",
        job_id="ft-1",
        training_path="/tmp/a.jsonl",
        dpo_path="/tmp/b.jsonl",
        examples_count=42,
        dpo_rows=7,
    )
    assert env["schema"] == FINETUNING_DATA_READY_SCHEMA
    assert env["tenant_id"] == "00000000-0000-0000-0000-000000000001"
    assert env["job_id"] == "ft-1"
    assert env["training_path"] == "/tmp/a.jsonl"
    assert env["dpo_path"] == "/tmp/b.jsonl"
    assert env["examples_count"] == 42
    assert env["dpo_rows"] == 7
    assert "occurred_at" in env
