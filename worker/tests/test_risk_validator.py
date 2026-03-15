"""Tests for independent heuristic risk score validation.

Covers:
  - compute_heuristic_risk: severity baseline, keyword indicators, MITRE
    technique boosting, entity threat-score bonuses, 100-cap
  - validate_risk_score: override logic (threshold=30), no-override path,
    final_severity mapping, return-dict shape
"""
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
for _p in (_WORKER,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from security.risk_validator import validate_risk_score, compute_heuristic_risk
import pytest


# ---------------------------------------------------------------------------
# compute_heuristic_risk — direct unit tests
# ---------------------------------------------------------------------------

class TestComputeHeuristicRisk:
    """Unit tests for the heuristic scoring engine."""

    # Severity baselines (critical=40, high=30, medium=15, low=5, unknown=10)
    @pytest.mark.parametrize("severity,expected_min", [
        ("critical", 40),
        ("high",     30),
        ("medium",   15),
        ("low",       5),
        ("",         10),  # unknown/missing → default 10
    ])
    def test_severity_baseline(self, severity, expected_min):
        score = compute_heuristic_risk({"severity": severity}, [], "", [])
        assert score >= expected_min, (
            f"severity={severity!r} should yield score >= {expected_min}, got {score}"
        )

    def test_cobalt_strike_adds_points(self):
        base = compute_heuristic_risk({"severity": "medium"}, [], "", [])
        boosted = compute_heuristic_risk(
            {"severity": "medium"}, [], "cobalt strike c2 beacon detected", []
        )
        assert boosted > base

    def test_mimikatz_adds_points(self):
        base = compute_heuristic_risk({"severity": "medium"}, [], "", [])
        boosted = compute_heuristic_risk(
            {"severity": "medium"}, [], "mimikatz credential dump", []
        )
        assert boosted > base

    def test_ransomware_adds_points(self):
        base = compute_heuristic_risk({"severity": "medium"}, [], "", [])
        boosted = compute_heuristic_risk(
            {"severity": "medium"}, [], "ransomware encryption detected", []
        )
        assert boosted > base

    def test_mitre_technique_boost(self):
        without = compute_heuristic_risk({"severity": "medium"}, [], "test", [])
        with_tech = compute_heuristic_risk(
            {"severity": "medium"}, [], "test", ["T1059.001", "T1003"]
        )
        # Each HIGH_RISK_TECHNIQUES hit adds 15 pts
        assert with_tech >= without + 30

    def test_non_high_risk_technique_no_boost(self):
        without = compute_heuristic_risk({"severity": "medium"}, [], "", [])
        with_other = compute_heuristic_risk(
            {"severity": "medium"}, [], "", ["T9999.999"]
        )
        assert with_other == without

    def test_high_threat_entity_boost(self):
        without = compute_heuristic_risk({"severity": "medium"}, [], "", [])
        entities = [{"type": "ip", "threat_score": 85}]
        with_entity = compute_heuristic_risk(
            {"severity": "medium"}, entities, "", []
        )
        # threat_score > 70 → +15
        assert with_entity == without + 15

    def test_medium_threat_entity_small_boost(self):
        without = compute_heuristic_risk({"severity": "medium"}, [], "", [])
        entities = [{"type": "ip", "threat_score": 50}]
        with_entity = compute_heuristic_risk(
            {"severity": "medium"}, entities, "", []
        )
        # threat_score > 40 → +5
        assert with_entity == without + 5

    def test_two_file_hashes_add_bonus(self):
        without = compute_heuristic_risk(
            {"severity": "low"}, [], "", []
        )
        entities = [
            {"type": "file_hash", "threat_score": 0},
            {"type": "file_hash", "threat_score": 0},
        ]
        with_hashes = compute_heuristic_risk(
            {"severity": "low"}, entities, "", []
        )
        # >= 2 file_hash entities → +10
        assert with_hashes == without + 10

    def test_three_ips_add_bonus(self):
        without = compute_heuristic_risk({"severity": "low"}, [], "", [])
        entities = [
            {"type": "ip", "threat_score": 0},
            {"type": "ip", "threat_score": 0},
            {"type": "ip", "threat_score": 0},
        ]
        with_ips = compute_heuristic_risk(
            {"severity": "low"}, entities, "", []
        )
        # >= 3 ip entities → +10
        assert with_ips == without + 10

    def test_alert_name_contributes_to_text(self):
        """alert_name field is included in the text scan."""
        without = compute_heuristic_risk({"severity": "low"}, [], "", [])
        with_name = compute_heuristic_risk(
            {"severity": "low", "alert_name": "Cobalt Strike beacon"}, [], "", []
        )
        assert with_name > without

    def test_description_contributes_to_text(self):
        without = compute_heuristic_risk({"severity": "low"}, [], "", [])
        with_desc = compute_heuristic_risk(
            {"severity": "low", "description": "mimikatz lateral movement"},
            [], "", [],
        )
        assert with_desc > without

    def test_capped_at_100(self):
        """Score must never exceed 100 no matter how many signals fire."""
        entities = [{"type": "ip", "threat_score": 90}] * 20
        score = compute_heuristic_risk(
            {"severity": "critical", "alert_name": "cobalt strike mimikatz ransomware"},
            entities,
            "cobalt strike mimikatz metasploit reverse shell c2 beacon credential dump "
            "ransomware lateral movement privilege escalation data exfil psexec",
            ["T1059.001", "T1003", "T1078", "T1021", "T1053",
             "T1047", "T1569", "T1548", "T1134", "T1055"],
        )
        assert score == 100

    def test_case_insensitive_keyword_match(self):
        """Keyword matching is case-insensitive (re.I)."""
        upper = compute_heuristic_risk({"severity": "low"}, [], "MIMIKATZ", [])
        lower = compute_heuristic_risk({"severity": "low"}, [], "mimikatz", [])
        assert upper == lower


# ---------------------------------------------------------------------------
# validate_risk_score — override and no-override logic
# ---------------------------------------------------------------------------

class TestValidateRiskScoreOverride:
    """Tests for the LLM suppression override (heuristic - llm_score > 30)."""

    def test_high_risk_cobalt_strike_overrides(self):
        result = validate_risk_score(
            llm_score=10,
            alert_data={"severity": "critical", "alert_name": "Cobalt Strike beacon detected"},
            entities=[],
            output="cobalt strike C2 beacon communicating with evil.com",
            techniques=[],
        )
        assert result["heuristic_score"] > 50
        assert result["score_overridden"] is True
        assert result["final_risk_score"] > 10
        assert result["final_risk_score"] == result["heuristic_score"]

    def test_mimikatz_overrides_low_llm_score(self):
        result = validate_risk_score(
            llm_score=5,
            alert_data={"severity": "critical", "alert_name": "Mimikatz detected"},
            entities=[],
            output="mimikatz credential dump lateral movement",
            techniques=["T1003"],
        )
        assert result["score_overridden"] is True
        assert result["final_risk_score"] > result["llm_score"]

    def test_override_reason_populated(self):
        result = validate_risk_score(
            llm_score=5,
            alert_data={"severity": "critical"},
            entities=[],
            output="cobalt strike c2 beacon",
            techniques=[],
        )
        assert result["score_overridden"] is True
        assert result["override_reason"] is not None
        assert "5" in result["override_reason"]  # mentions original llm_score


class TestValidateRiskScoreNoOverride:
    """Tests for cases where the LLM score is trusted (no override)."""

    def test_llm_agrees_with_heuristic(self):
        """When llm_score is close to heuristic, no override."""
        result = validate_risk_score(
            llm_score=50,
            alert_data={"severity": "medium"},
            entities=[],
            output="Suspicious activity",
            techniques=[],
        )
        assert result["score_overridden"] is False
        assert result["final_risk_score"] == 50
        assert result["override_reason"] is None

    def test_benign_alert_not_overridden(self):
        result = validate_risk_score(
            llm_score=10,
            alert_data={"severity": "low", "alert_name": "User login"},
            entities=[],
            output="Normal login event from known IP",
            techniques=[],
        )
        # heuristic = 5 (low) + no keywords = 5; diff = 5 - 10 = -5 → no override
        assert result["score_overridden"] is False
        assert result["final_risk_score"] == 10

    def test_exact_threshold_not_overridden(self):
        """heuristic - llm == 30 does NOT trigger override (strictly >)."""
        # severity=critical → baseline 40; llm=10 → diff = 30 → no override
        result = validate_risk_score(
            llm_score=10,
            alert_data={"severity": "critical"},
            entities=[],
            output="",
            techniques=[],
        )
        # heuristic = 40; diff = 30; threshold is > 30, so no override
        assert result["score_overridden"] is False


class TestValidateRiskScoreReturnShape:
    """Validate the structure of every validate_risk_score result."""

    def _call(self, **kwargs):
        defaults = dict(
            llm_score=30,
            alert_data={"severity": "medium"},
            entities=[],
            output="test",
            techniques=[],
        )
        defaults.update(kwargs)
        return validate_risk_score(**defaults)

    def test_required_keys_present(self):
        result = self._call()
        for key in ("final_risk_score", "final_severity", "llm_score",
                    "heuristic_score", "score_overridden", "override_reason"):
            assert key in result, f"Missing key: {key}"

    def test_final_risk_score_is_int_or_float(self):
        result = self._call()
        assert isinstance(result["final_risk_score"], (int, float))

    def test_final_risk_score_never_exceeds_100(self):
        result = validate_risk_score(
            llm_score=50,
            alert_data={"severity": "critical",
                        "alert_name": "cobalt strike mimikatz ransomware"},
            entities=[{"type": "ip", "threat_score": 90}] * 10,
            output=(
                "cobalt strike mimikatz metasploit reverse shell c2 beacon "
                "credential dump ransomware lateral movement privilege escalation "
                "data exfil"
            ),
            techniques=["T1059.001", "T1003", "T1078", "T1021", "T1053"],
        )
        assert result["final_risk_score"] <= 100


class TestFinalSeverityMapping:
    """final_severity must follow the score→label mapping in the source."""

    @pytest.mark.parametrize("score,expected_severity", [
        (80,  "critical"),
        (99,  "critical"),
        (60,  "high"),
        (79,  "high"),
        (40,  "medium"),
        (59,  "medium"),
        (20,  "low"),
        (39,  "low"),
        (0,   "informational"),
        (19,  "informational"),
    ])
    def test_severity_label(self, score, expected_severity):
        result = validate_risk_score(
            llm_score=score,
            alert_data={"severity": "low"},
            entities=[],
            output="",
            techniques=[],
        )
        assert result["final_severity"] == expected_severity, (
            f"score={score} should map to {expected_severity!r}, "
            f"got {result['final_severity']!r}"
        )
