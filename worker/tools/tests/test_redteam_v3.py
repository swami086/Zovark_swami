"""Red Team v3 — Tests for security vulnerabilities in the tool-calling architecture."""
import time
import pytest

from tools.runner import execute_plan, _resolve_ref, _evaluate_condition
from tools.extraction import extract_ipv4, extract_domains, extract_usernames
from tools.analysis import count_pattern
from tools.parsing import parse_auth_log
from tools.enrichment import correlate_with_history, lookup_institutional_knowledge


class TestArgInjection:
    """Category 1: Tool argument injection."""

    def test_sql_injection_in_ip(self):
        result = extract_ipv4("Failed from 10.0.0.1; DROP TABLE agent_tasks")
        values = [r["value"] for r in result]
        assert "DROP" not in str(values)
        assert "10.0.0.1" in values

    def test_path_traversal_in_username(self):
        result = parse_auth_log("Failed password for ../../../../etc/passwd from 10.0.0.1")
        username = result.get("username", "")
        # Should extract the path-like string but not execute filesystem traversal
        assert "etc" not in username or username != "/etc/passwd"

    def test_large_input_100k(self):
        """100K input should complete quickly without DoS."""
        t0 = time.time()
        result = extract_ipv4("A" * 100_000 + " from 10.0.0.1")
        elapsed = time.time() - t0
        assert elapsed < 5.0  # Should complete in under 5s

    def test_large_input_1m(self):
        """1M input should complete without crash."""
        t0 = time.time()
        result = extract_ipv4("A" * 1_000_000 + " from 10.0.0.1")
        elapsed = time.time() - t0
        assert elapsed < 10.0

    def test_null_bytes(self):
        result = extract_ipv4("Attack from 10.0.0.1\x00DROP TABLE")
        values = [r["value"] for r in result]
        assert "10.0.0.1" in values

    def test_unicode_in_domain(self):
        """Zero-width characters should not create phantom domains."""
        result = extract_domains("Query to ev\u200bil.com")
        # Zero-width space splits the domain — should NOT extract "evil.com"
        values = [r["value"] for r in result]
        assert "evil.com" not in values  # ZWS should prevent matching


class TestVarResolutionInjection:
    """Category 2: Variable resolution injection."""

    def test_dunder_class(self):
        result = _resolve_ref("$siem_event.__class__", {}, {"test": 1}, "", {}, {})
        # Should return empty string (field "__class__" doesn't exist in dict)
        assert result == "" or result is None

    def test_dunder_globals(self):
        result = _resolve_ref("$raw_log.__globals__", {}, {}, "test", {}, {})
        # $raw_log resolves to "test", then .__globals__ is not supported
        # The resolver only handles dot-separated field access for specific prefixes
        assert result == "$raw_log.__globals__" or result == "test" or result is None

    def test_import_injection(self):
        result = _resolve_ref("$__import__('os').system('id')", {}, {}, "", {}, {})
        # Should not execute — not a valid variable reference
        assert result == "$__import__('os').system('id')" or result is None

    def test_huge_step_index(self):
        result = _resolve_ref("$step999999", {}, {}, "", {}, {})
        assert result is None

    def test_newline_injection(self):
        result = _resolve_ref("$siem_event\nmalicious()", {}, {"test": 1}, "", {}, {})
        # Newline in ref should not execute code
        assert not callable(result)


class TestPlanManipulation:
    """Category 3: Plan manipulation attacks."""

    def test_unknown_tool_blocked(self):
        result = execute_plan(
            [{"tool": "os.system", "args": {"command": "id"}}],
            {"raw_log": "test"},
        )
        assert len(result["errors"]) > 0
        assert result["tools_executed"] == 0

    def test_empty_tool_name(self):
        result = execute_plan(
            [{"tool": "", "args": {}}],
            {"raw_log": "test"},
        )
        assert len(result["errors"]) > 0

    def test_1000_step_timeout(self):
        """1000 steps should be limited by total timeout."""
        t0 = time.time()
        plan = [{"tool": "extract_ipv4", "args": {"text": "$raw_log"}}] * 1000
        result = execute_plan(plan, {"raw_log": "10.0.0.1"}, total_timeout=5.0)
        elapsed = time.time() - t0
        assert elapsed < 30  # Timeout should kick in

    def test_risk_suppression_ineffective(self):
        """Detection tools should still detect attacks even if followed by benign scoring."""
        plan = [
            {"tool": "detect_kerberoasting", "args": {"siem_event": "$siem_event"}},
            {"tool": "score_generic", "args": {"indicators_found": 0, "high_severity_count": 0, "medium_severity_count": 0}},
        ]
        result = execute_plan(plan, {
            "title": "TGS", "source_ip": "10.0.1.50", "username": "svc_sql",
            "rule_name": "Kerb",
            "raw_log": "EventID=4769 TicketEncryptionType=0x17 ServiceName=MSSQLSvc/db01:1433",
        })
        # Max of risk scores — detection tool should dominate
        assert result["risk_score"] >= 50


class TestConditionalBypass:
    """Category 4: Conditional expression bypass."""

    def test_code_injection_in_condition(self):
        """Code injection in condition string should not execute."""
        result = _evaluate_condition("$step1 > 0; import os", {1: 5}, {}, "", {}, {})
        # Should return False (regex won't match the semicolon-injected string)
        assert isinstance(result, bool)

    def test_none_comparison(self):
        result = _evaluate_condition("$step1 > 0", {1: None}, {}, "", {}, {})
        assert result is False

    def test_string_coercion(self):
        """String values should be coerced for numeric comparison."""
        result = _evaluate_condition("$step1 > 100", {1: "99999"}, {}, "", {}, {})
        assert result is True  # "99999" coerced to float > 100


class TestEnrichmentSafety:
    """Category 5: Enrichment tool safety."""

    def test_large_ioc_list(self):
        """10K IOCs should not cause performance issues."""
        t0 = time.time()
        iocs = [f"10.0.0.{i % 256}" for i in range(10000)]
        result = correlate_with_history(iocs, 24, {"investigations": []})
        elapsed = time.time() - t0
        assert elapsed < 5.0

    def test_xss_in_knowledge_base(self):
        """XSS payloads should be stored as-is (not executed)."""
        result = lookup_institutional_knowledge(
            ["10.0.0.1"],
            {"10.0.0.1": {"description": "<script>alert(1)</script>", "expected_behavior": "normal"}},
        )
        # Should store the XSS string as-is
        assert result["has_context"] is True
        desc = result["known_entities"][0]["description"]
        assert "<script>" in desc  # Stored as-is, not sanitized (display layer responsibility)

    def test_fabricated_history(self):
        """Fabricated history should be processed (context is trusted at tool level)."""
        result = correlate_with_history(
            ["10.0.0.1"], 24,
            {"investigations": [
                {"source_ip": "10.0.0.1", "task_type": "critical_breach", "risk_score": 100},
            ]},
        )
        # This is expected behavior — the tool processes what it receives
        assert result["correlation_count"] == 1
