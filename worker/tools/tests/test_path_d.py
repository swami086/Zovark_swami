"""Tests for Path D: per-investigation fallback from v3 tool runner to v2 sandbox."""
import json
import pytest
from unittest.mock import patch, MagicMock
from dataclasses import asdict

from stages.execute import _execute_v3_tools, execute_investigation
from stages import ExecuteOutput


class TestNormalV3Execution:
    """Normal v3 execution should set path_d_fallback=False."""

    def test_successful_v3(self):
        data = {
            "plan": [{"tool": "extract_ipv4", "args": {"text": "$raw_log"}}],
            "siem_event": {"raw_log": "Attack from 10.0.0.1"},
            "execution_mode": "tools",
        }
        result = _execute_v3_tools(data)
        assert result["path_d_fallback"] is False
        assert result["execution_mode"] == "tools"
        assert result["status"] == "completed"

    def test_successful_v3_with_detection(self):
        data = {
            "plan": [{"tool": "detect_kerberoasting", "args": {"siem_event": "$siem_event"}}],
            "siem_event": {
                "title": "TGS", "source_ip": "10.0.1.50", "username": "svc_sql",
                "rule_name": "Kerb",
                "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433",
            },
            "execution_mode": "tools",
        }
        result = _execute_v3_tools(data)
        assert result["path_d_fallback"] is False
        assert result["risk_score"] >= 50


class TestV3FailureTriggersPathD:
    """When v3 tool runner fails, Path D should fall back to v2 sandbox."""

    def test_empty_plan_raises(self):
        """Empty plan raises ValueError in _execute_v3_tools."""
        data = {
            "plan": [],
            "siem_event": {"raw_log": "test"},
            "execution_mode": "tools",
        }
        with pytest.raises(ValueError, match="No tool plan"):
            _execute_v3_tools(data)

    @patch("stages.execute._execute_v3_tools")
    @patch("stages.execute._execute_v2_sandbox")
    def test_path_d_fallback_on_v3_exception(self, mock_v2, mock_v3):
        """V3 exception triggers Path D fallback to v2."""
        import asyncio

        mock_v3.side_effect = RuntimeError("Tool catalog corrupted")
        mock_v2.return_value = asdict(ExecuteOutput(
            status="completed", risk_score=75,
            findings=[{"title": "Attack detected"}],
            iocs=[{"type": "ipv4", "value": "10.0.0.1"}],
            execution_mode="sandbox",
        ))

        data = {
            "plan": [{"tool": "broken_tool", "args": {}}],
            "siem_event": {"raw_log": "test"},
            "execution_mode": "tools",
        }
        # execute_investigation is an async Temporal activity — run it directly
        result = asyncio.run(
            execute_investigation(data)
        )

        assert result["path_d_fallback"] is True
        assert result["execution_mode"] == "sandbox_fallback"
        assert "Tool catalog corrupted" in result["path_d_reason"]
        assert result["status"] == "completed"

    @patch("stages.execute._execute_v3_tools")
    @patch("stages.execute._execute_v2_sandbox")
    def test_path_d_preserves_v2_results(self, mock_v2, mock_v3):
        """Path D fallback should preserve the v2 execution results."""
        import asyncio

        mock_v3.side_effect = ValueError("Invalid plan")
        mock_v2.return_value = asdict(ExecuteOutput(
            status="completed", risk_score=85,
            findings=[{"title": "Brute force"}],
            iocs=[{"type": "ipv4", "value": "185.220.101.45"}],
            execution_mode="sandbox",
        ))

        data = {
            "plan": [{"tool": "bad", "args": {}}],
            "siem_event": {"raw_log": "test"},
            "execution_mode": "tools",
        }
        result = asyncio.run(
            execute_investigation(data)
        )

        assert result["risk_score"] == 85
        assert result["findings"][0]["title"] == "Brute force"
        assert result["path_d_fallback"] is True


class TestBothV3AndV2Fail:
    """When both v3 and v2 fail, return error verdict."""

    @patch("stages.execute._execute_v3_tools")
    @patch("stages.execute._execute_v2_sandbox")
    def test_both_fail(self, mock_v2, mock_v3):
        import asyncio

        mock_v3.side_effect = RuntimeError("v3 broken")
        mock_v2.side_effect = RuntimeError("v2 also broken")

        data = {
            "plan": [{"tool": "x", "args": {}}],
            "siem_event": {"raw_log": "test"},
            "execution_mode": "tools",
        }
        result = asyncio.run(
            execute_investigation(data)
        )

        assert result["path_d_fallback"] is True
        assert result["execution_mode"] == "failed"
        assert result["risk_score"] == 0
        assert result["status"] == "failed"
        assert "v3" in result["path_d_reason"]
        assert "v2" in result["path_d_reason"]

    @patch("stages.execute._execute_v3_tools")
    @patch("stages.execute._execute_v2_sandbox")
    def test_both_fail_has_findings(self, mock_v2, mock_v3):
        import asyncio

        mock_v3.side_effect = TimeoutError("v3 timeout")
        mock_v2.side_effect = ConnectionError("Docker unreachable")

        data = {
            "plan": [{"tool": "x", "args": {}}],
            "siem_event": {"raw_log": "test"},
            "execution_mode": "tools",
        }
        result = asyncio.run(
            execute_investigation(data)
        )

        assert len(result["findings"]) >= 1
        assert "failed" in result["findings"][0]["title"].lower()


class TestGlobalSandboxMode:
    """Global ZOVARK_EXECUTION_MODE=sandbox bypasses v3 entirely."""

    @patch("stages.execute._execute_v2_sandbox")
    def test_sandbox_mode_no_path_d(self, mock_v2):
        import asyncio

        mock_v2.return_value = asdict(ExecuteOutput(
            status="completed", risk_score=50,
            execution_mode="sandbox",
        ))

        data = {
            "plan": [{"tool": "extract_ipv4", "args": {"text": "$raw_log"}}],
            "siem_event": {"raw_log": "test"},
            "execution_mode": "sandbox",
            "code": "print('test')",
        }
        result = asyncio.run(
            execute_investigation(data)
        )

        assert result["path_d_fallback"] is False
        assert result["execution_mode"] == "sandbox"
