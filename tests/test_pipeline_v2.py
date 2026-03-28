"""
Integration tests for V2 pipeline stages.
Uses ZOVARK_FAST_FILL=true — no LLM dependency.
Tests pass without llama-server running.
"""
import os
import json
import asyncio
import pytest

# Force FAST_FILL mode for all tests
os.environ["ZOVARK_FAST_FILL"] = "true"
os.environ["DEDUP_ENABLED"] = "false"  # Skip Redis dependency in tests

# Add worker to path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))


SAMPLE_TASK = {
    "task_id": "test-001",
    "tenant_id": "tenant-001",
    "task_type": "brute_force_investigation",
    "input": {
        "prompt": "Analyze SSH brute force attack",
        "severity": "high",
        "siem_event": {
            "title": "SSH Brute Force",
            "source_ip": "10.0.0.99",
            "destination_ip": "10.0.0.5",
            "hostname": "WEB-SERVER-01",
            "username": "admin",
            "rule_name": "SSH_Brute_Force",
            "raw_log": "Failed password for admin from 10.0.0.99 port 54321 ssh2\nAccepted password for admin from 10.0.0.99 port 54324 ssh2",
        },
    },
}


class TestStage1Ingest:
    def test_ingest_returns_required_fields(self):
        from stages.ingest import ingest_alert
        result = asyncio.run(ingest_alert(SAMPLE_TASK))
        assert result["task_id"] == "test-001"
        assert result["tenant_id"] == "tenant-001"
        assert result["task_type"] == "brute_force_investigation"
        assert "siem_event" in result
        assert isinstance(result["is_duplicate"], bool)

    def test_ingest_not_duplicate_when_dedup_disabled(self):
        from stages.ingest import ingest_alert
        result = asyncio.run(ingest_alert(SAMPLE_TASK))
        assert result["is_duplicate"] is False

    def test_ingest_preserves_siem_event(self):
        from stages.ingest import ingest_alert
        result = asyncio.run(ingest_alert(SAMPLE_TASK))
        assert result["siem_event"]["source_ip"] == "10.0.0.99"
        assert "raw_log" in result["siem_event"]


class TestStage2Analyze:
    def test_fast_fill_returns_code(self):
        from stages.analyze import analyze_alert
        from stages import IngestOutput
        ingest = IngestOutput(
            task_id="test-001", tenant_id="tenant-001",
            task_type="brute_force_investigation",
            siem_event=SAMPLE_TASK["input"]["siem_event"],
            prompt="Analyze SSH brute force",
        )
        result = asyncio.run(analyze_alert(ingest))
        assert result["code"] != ""
        assert result["source"] == "fast_fill"
        assert "import re" in result["code"]
        assert "json.dumps" in result["code"]

    def test_fast_fill_code_is_valid_python(self):
        from stages.analyze import analyze_alert
        from stages import IngestOutput
        import ast
        ingest = IngestOutput(
            task_id="test-001", tenant_id="tenant-001",
            task_type="brute_force",
            siem_event=SAMPLE_TASK["input"]["siem_event"],
        )
        result = asyncio.run(analyze_alert(ingest))
        # Should parse without SyntaxError
        ast.parse(result["code"])

    def test_fast_fill_no_llm_calls(self):
        from stages.analyze import analyze_alert
        from stages import IngestOutput
        ingest = IngestOutput(
            task_id="test-001", tenant_id="tenant-001",
            task_type="brute_force",
            siem_event=SAMPLE_TASK["input"]["siem_event"],
        )
        result = asyncio.run(analyze_alert(ingest))
        assert result["tokens_in"] == 0
        assert result["tokens_out"] == 0
        assert result["generation_ms"] == 0


class TestStage3Execute:
    def test_execute_fast_fill_returns_result(self):
        from stages.execute import execute_investigation
        # Generate stub code first
        code = 'import json\nprint(json.dumps({"findings": ["test"], "iocs": [], "risk_score": 50}))'
        result = asyncio.run(execute_investigation({"code": code, "task_type": "test"}))
        assert result["status"] == "completed"
        assert result["exit_code"] == 0

    def test_execute_parses_json_output(self):
        from stages.execute import execute_investigation
        code = 'import json\nprint(json.dumps({"findings": [{"title": "Test"}], "iocs": [{"type": "ipv4", "value": "1.2.3.4"}], "risk_score": 75}))'
        result = asyncio.run(execute_investigation({"code": code, "task_type": "test"}))
        assert result["risk_score"] == 75
        assert len(result["iocs"]) == 1
        assert result["iocs"][0]["value"] == "1.2.3.4"

    def test_execute_blocks_forbidden_imports(self):
        from stages.execute import execute_investigation
        code = 'import os\nos.system("whoami")'
        result = asyncio.run(execute_investigation({"code": code, "task_type": "test"}))
        assert result["status"] == "failed"
        assert "Forbidden import" in result["stderr"]

    def test_execute_empty_code_fails(self):
        from stages.execute import execute_investigation
        result = asyncio.run(execute_investigation({"code": "", "task_type": "test"}))
        assert result["status"] == "failed"


class TestStage4Assess:
    def test_assess_fast_fill_returns_verdict(self):
        from stages.assess import assess_results
        result = asyncio.run(assess_results({
            "task_id": "test-001", "tenant_id": "tenant-001",
            "stdout": '{"findings": ["test"], "iocs": [], "risk_score": 50}',
            "iocs": [{"type": "ipv4", "value": "1.2.3.4"}],
            "findings": [{"title": "Test"}],
            "risk_score": 75,
            "task_type": "brute_force",
        }))
        assert result["verdict"] in ("true_positive", "suspicious", "benign", "inconclusive")
        assert result["risk_score"] == 75
        assert result["memory_summary"] != ""

    def test_assess_high_risk_is_suspicious(self):
        from stages.assess import assess_results
        result = asyncio.run(assess_results({
            "iocs": [{"type": "ipv4", "value": "1.2.3.4"}, {"type": "hash", "value": "abc123"}],
            "findings": [{"title": "Attack"}],
            "risk_score": 85,
            "task_type": "lateral_movement",
        }))
        assert result["verdict"] in ("true_positive", "suspicious")

    def test_assess_no_iocs_is_benign(self):
        from stages.assess import assess_results
        result = asyncio.run(assess_results({
            "iocs": [], "findings": [], "risk_score": 10, "task_type": "test",
        }))
        assert result["verdict"] == "benign"


class TestStage5Store:
    """Store tests require DB — skip if not available."""

    def test_store_output_has_required_fields(self):
        from stages import StoreOutput
        s = StoreOutput(task_id="test-001", status="completed")
        assert s.task_id == "test-001"
        assert s.status == "completed"
        assert s.investigation_id is None


class TestFullPipeline:
    def test_fast_fill_pipeline_end_to_end(self):
        """Run all 5 stages in sequence with FAST_FILL=true."""
        from stages.ingest import ingest_alert
        from stages.analyze import analyze_alert
        from stages.execute import execute_investigation
        from stages.assess import assess_results
        from stages import IngestOutput

        # Stage 1: Ingest
        ingested = asyncio.run(ingest_alert(SAMPLE_TASK))
        assert not ingested["is_duplicate"]

        # Stage 2: Analyze
        ingest_obj = IngestOutput(**{
            k: ingested[k] for k in IngestOutput.__dataclass_fields__
            if k in ingested
        })
        analyzed = asyncio.run(analyze_alert(ingest_obj))
        assert analyzed["code"] != ""
        assert analyzed["source"] == "fast_fill"

        # Stage 3: Execute
        executed = asyncio.run(execute_investigation({
            "code": analyzed["code"],
            "task_type": ingested["task_type"],
        }))
        assert executed["status"] == "completed"
        assert executed["exit_code"] == 0

        # Stage 4: Assess
        assessed = asyncio.run(assess_results({
            **executed,
            "task_id": ingested["task_id"],
            "tenant_id": ingested["tenant_id"],
            "task_type": ingested["task_type"],
        }))
        assert assessed["verdict"] in ("true_positive", "suspicious", "benign", "inconclusive")
        assert assessed["memory_summary"] != ""

        # Stage 5: Store (skip DB, just verify contract)
        # In a real test with DB, would call store_investigation()
        assert assessed["risk_score"] >= 0
