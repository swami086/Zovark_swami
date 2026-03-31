"""Tests for enrichment tools."""
import pytest
from tools.enrichment import (
    map_mitre, lookup_known_bad, correlate_with_history,
    lookup_institutional_knowledge,
)


class TestMapMitre:
    def test_single_technique(self):
        result = map_mitre(["T1110"])
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1110"

    def test_multiple_techniques(self):
        result = map_mitre(["T1110", "T1558.003"])
        assert len(result) == 2

    def test_empty_list(self):
        assert map_mitre([]) == []

    def test_unknown_technique(self):
        result = map_mitre(["T9999"])
        assert len(result) == 1
        assert result[0]["name"] == "Unknown"


class TestLookupKnownBad:
    def test_clean_ip(self):
        result = lookup_known_bad("10.0.0.1", "ipv4")
        assert result["is_known_bad"] is False

    def test_has_required_keys(self):
        result = lookup_known_bad("test", "filename")
        assert "is_known_bad" in result


class TestCorrelateWithHistory:
    def test_correlated(self):
        result = correlate_with_history(
            ["10.0.0.5"], 24,
            {"investigations": [
                {"source_ip": "10.0.0.5", "task_type": "brute_force", "risk_score": 85, "timestamp": "2026-03-30T10:00:00Z"},
                {"source_ip": "10.0.0.5", "task_type": "lateral_movement", "risk_score": 75, "timestamp": "2026-03-30T10:30:00Z"},
            ]},
        )
        assert result["escalation_recommended"] is True
        assert "related_investigations" in result
        assert "kill_chain_stage" in result
        assert result["correlation_count"] >= 2

    def test_no_correlation(self):
        result = correlate_with_history(
            ["192.168.1.1"], 24,
            {"investigations": []},
        )
        assert result["escalation_recommended"] is False
        assert result["correlation_count"] == 0

    def test_empty_iocs(self):
        result = correlate_with_history([], 24, {})
        assert result["correlation_count"] == 0


class TestLookupInstitutionalKnowledge:
    def test_known_entities(self):
        result = lookup_institutional_knowledge(
            ["10.0.1.50", "svc_sql"],
            {
                "10.0.1.50": {"description": "Oracle batch server", "expected_behavior": "Kerberos TGS requests between 2-4 AM", "hours_active": "2-4"},
                "svc_sql": {"description": "SQL service account", "expected_behavior": "MSSQLSvc SPN requests"},
            },
        )
        assert result["has_context"] is True
        assert len(result["known_entities"]) == 2
        assert len(result["baselines"]) >= 1

    def test_unknown_entities(self):
        result = lookup_institutional_knowledge(["unknown_ip"], {})
        assert result["has_context"] is False

    def test_empty(self):
        result = lookup_institutional_knowledge([], {})
        assert result["has_context"] is False
