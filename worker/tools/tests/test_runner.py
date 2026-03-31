"""Tests for the tool runner — plan execution, variable resolution, conditional branching."""
import json
import time
import pytest
from pathlib import Path

from tools.runner import execute_plan, _resolve_ref, _evaluate_condition


class TestVariableResolution:
    def test_raw_log(self):
        result = _resolve_ref("$raw_log", {}, {}, "test log", {}, {})
        assert result == "test log"

    def test_siem_event(self):
        event = {"source_ip": "10.0.0.1"}
        result = _resolve_ref("$siem_event", {}, event, "", {}, {})
        assert result == event

    def test_siem_event_field(self):
        result = _resolve_ref("$siem_event.source_ip", {}, {"source_ip": "10.0.0.1"}, "", {}, {})
        assert result == "10.0.0.1"

    def test_step_result(self):
        result = _resolve_ref("$step1", {1: [{"value": "10.0.0.1"}]}, {}, "", {}, {})
        assert result == [{"value": "10.0.0.1"}]

    def test_step_field(self):
        result = _resolve_ref("$step1.risk_score", {1: {"risk_score": 85}}, {}, "", {}, {})
        assert result == 85

    def test_step_count(self):
        result = _resolve_ref("$step1.count", {1: [1, 2, 3]}, {}, "", {}, {})
        assert result == 3

    def test_step_count_int(self):
        result = _resolve_ref("$step1.count", {1: 42}, {}, "", {}, {})
        assert result == 42

    def test_missing_step(self):
        result = _resolve_ref("$step99", {}, {}, "", {}, {})
        assert result is None

    def test_non_variable(self):
        result = _resolve_ref("plain text", {}, {}, "", {}, {})
        assert result == "plain text"

    def test_correlation_context(self):
        ctx = {"investigations": []}
        result = _resolve_ref("$correlation_context", {}, {}, "", ctx, {})
        assert result == ctx


class TestConditionEvaluation:
    def test_greater_than_true(self):
        assert _evaluate_condition("$step1 > 50", {1: 100}, {}, "", {}, {}) is True

    def test_greater_than_false(self):
        assert _evaluate_condition("$step1 > 50", {1: 30}, {}, "", {}, {}) is False

    def test_gte(self):
        assert _evaluate_condition("$step1 >= 50", {1: 50}, {}, "", {}, {}) is True

    def test_less_than(self):
        assert _evaluate_condition("$step1 < 10", {1: 5}, {}, "", {}, {}) is True

    def test_equality(self):
        assert _evaluate_condition("$step1.action == failure", {1: {"action": "failure"}}, {}, "", {}, {}) is True

    def test_null_check(self):
        assert _evaluate_condition("$step1.field == null", {1: {"field": None}}, {}, "", {}, {}) is True

    def test_boolean_check_true(self):
        assert _evaluate_condition("$step1.escalation_recommended", {1: {"escalation_recommended": True}}, {}, "", {}, {}) is True

    def test_boolean_check_false(self):
        assert _evaluate_condition("$step1.escalation_recommended", {1: {"escalation_recommended": False}}, {}, "", {}, {}) is False

    def test_missing_step_is_false(self):
        assert _evaluate_condition("$step99 > 0", {}, {}, "", {}, {}) is False


class TestBasicPlanExecution:
    def test_simple_extraction(self):
        plan = [
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
        ]
        result = execute_plan(plan, {"raw_log": "Attack from 10.0.0.5"})
        assert result["tools_executed"] == 1
        assert len(result["iocs"]) >= 1
        assert result["verdict"] in ("benign", "inconclusive")

    def test_multi_step_plan(self):
        plan = [
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
            {"tool": "extract_usernames", "args": {"text": "$raw_log"}},
            {"tool": "parse_auth_log", "args": {"raw_log": "$raw_log"}},
            {"tool": "count_pattern", "args": {"text": "$raw_log", "pattern": "failed"}},
            {"tool": "score_brute_force", "args": {"failed_count": "$step4", "unique_sources": "$step1.count", "timespan_minutes": 60}},
        ]
        result = execute_plan(plan, {
            "raw_log": "Failed password for root from 10.0.0.1 failed failed failed",
        })
        assert result["tools_executed"] == 5
        assert result["risk_score"] >= 0

    def test_detection_tool(self):
        plan = [
            {"tool": "detect_kerberoasting", "args": {"siem_event": "$siem_event"}},
            {"tool": "map_mitre", "args": {"technique_ids": ["T1558.003"]}},
        ]
        result = execute_plan(plan, {
            "title": "TGS Request", "source_ip": "10.0.1.50", "username": "svc_sql",
            "rule_name": "Kerberoasting",
            "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433",
        })
        assert result["risk_score"] >= 50
        assert result["verdict"] in ("suspicious", "true_positive")


class TestConditionalBranching:
    def test_true_branch(self):
        plan = [
            {"tool": "count_pattern", "args": {"text": "$raw_log", "pattern": "failed"}},
            {
                "condition": "$step1 > 3",
                "if_true": {"tool": "score_brute_force", "args": {"failed_count": "$step1", "unique_sources": 1, "timespan_minutes": 5}},
                "if_false": {"tool": "score_generic", "args": {"indicators_found": "$step1", "high_severity_count": 0, "medium_severity_count": 0}},
            },
        ]
        result = execute_plan(plan, {"raw_log": "failed " * 10})
        assert result["risk_score"] >= 20  # brute force scoring with 10 failures in 5 min

    def test_false_branch(self):
        plan = [
            {"tool": "count_pattern", "args": {"text": "$raw_log", "pattern": "failed"}},
            {
                "condition": "$step1 > 100",
                "if_true": {"tool": "score_brute_force", "args": {"failed_count": "$step1", "unique_sources": 1, "timespan_minutes": 5}},
                "if_false": {"tool": "score_generic", "args": {"indicators_found": "$step1", "high_severity_count": 0, "medium_severity_count": 0}},
            },
        ]
        result = execute_plan(plan, {"raw_log": "failed failed"})
        assert result["tools_executed"] == 2
        # Generic scoring with 2 indicators, 0 severity = low score
        assert result["risk_score"] <= 30

    def test_boolean_condition(self):
        plan = [
            {"tool": "correlate_with_history", "args": {
                "ioc_values": ["10.0.0.5"],
                "lookback_hours": 24,
                "history_context": "$correlation_context",
            }},
            {
                "condition": "$step1.escalation_recommended",
                "if_true": {"tool": "map_mitre", "args": {"technique_ids": ["T1110", "T1110.001"]}},
                "if_false": {"tool": "map_mitre", "args": {"technique_ids": ["T1110"]}},
            },
        ]
        # With correlation data that triggers escalation
        result = execute_plan(plan, {"raw_log": "test"}, history_context={
            "investigations": [
                {"source_ip": "10.0.0.5", "task_type": "brute_force", "risk_score": 85, "timestamp": "2026-03-30"},
                {"source_ip": "10.0.0.5", "task_type": "lateral_movement", "risk_score": 75, "timestamp": "2026-03-30"},
            ],
        })
        assert result["tools_executed"] == 2


class TestErrorIsolation:
    def test_unknown_tool_continues(self):
        plan = [
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
            {"tool": "nonexistent_tool", "args": {}},
            {"tool": "score_generic", "args": {"indicators_found": 0, "high_severity_count": 0, "medium_severity_count": 0}},
        ]
        result = execute_plan(plan, {"raw_log": "10.0.0.1"})
        assert result["tools_executed"] == 2  # first and third
        assert len(result["errors"]) == 1

    def test_bad_args_continues(self):
        plan = [
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
            {"tool": "count_pattern", "args": {"text": "$raw_log"}},  # missing 'pattern' arg
            {"tool": "score_generic", "args": {"indicators_found": 0, "high_severity_count": 0, "medium_severity_count": 0}},
        ]
        result = execute_plan(plan, {"raw_log": "test"})
        # Should run first and third even if second fails
        assert result["tools_executed"] >= 2


class TestIOCDeduplication:
    def test_dedup_by_value(self):
        plan = [
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
        ]
        result = execute_plan(plan, {"raw_log": "Attack from 10.0.0.5 and 10.0.0.5"})
        values = [ioc["value"] for ioc in result["iocs"]]
        assert values.count("10.0.0.5") == 1


class TestVerdictDerivation:
    def test_true_positive(self):
        plan = [
            {"tool": "detect_kerberoasting", "args": {"siem_event": "$siem_event"}},
        ]
        result = execute_plan(plan, {
            "title": "TGS", "source_ip": "10.0.1.50", "username": "svc_sql",
            "rule_name": "Kerb",
            "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433 TargetUserName=svc_sql ClientAddress=10.0.1.50",
        })
        assert result["verdict"] == "true_positive"

    def test_benign(self):
        plan = [
            {"tool": "extract_ipv4", "args": {"text": "$raw_log"}},
            {"tool": "score_generic", "args": {"indicators_found": 1, "high_severity_count": 0, "medium_severity_count": 0}},
        ]
        result = execute_plan(plan, {"raw_log": "Normal activity from 10.0.0.1"})
        assert result["risk_score"] <= 35
        assert result["verdict"] == "benign"


class TestPlanExecution:
    """Test that each attack type plan produces reasonable output."""

    @pytest.fixture
    def plans(self):
        plans_path = Path(__file__).parent.parent / "investigation_plans.json"
        with open(plans_path) as f:
            return json.load(f)

    def test_all_plans_execute(self, plans):
        for task_type, plan_data in plans.items():
            event = {
                "title": f"Test {task_type}",
                "source_ip": "10.0.0.1",
                "username": "testuser",
                "rule_name": "Test",
                "raw_log": f"Test for {task_type} EventID=4625 Failed password from 10.0.0.1 User=testuser 500 attempts",
            }
            result = execute_plan(
                plan_data["plan"], event,
                history_context={"investigations": []},
                institutional_knowledge={},
            )
            assert isinstance(result, dict), f"{task_type}: result is not a dict"
            assert "risk_score" in result, f"{task_type}: missing risk_score"
            assert "verdict" in result, f"{task_type}: missing verdict"
            assert "findings" in result, f"{task_type}: missing findings"
            assert "iocs" in result, f"{task_type}: missing iocs"
            assert result["tools_executed"] >= 1, f"{task_type}: no tools executed"

    def test_benign_plan_low_risk(self, plans):
        event = {
            "title": "Password Changed",
            "username": "j.smith",
            "rule_name": "PasswordChange",
            "raw_log": "EventID=4724 Status=Success User=j.smith",
        }
        result = execute_plan(
            plans["benign_system_event"]["plan"], event,
            history_context={"investigations": []},
            institutional_knowledge={},
        )
        assert result["risk_score"] <= 25
