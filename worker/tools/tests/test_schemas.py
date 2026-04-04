"""Tests for Pydantic LLM output validation schemas."""
import pytest
from pydantic import ValidationError
from schemas import VerdictOutput, IOCItem, ToolSelectionOutput


class TestVerdictOutput:
    def test_valid_verdict_passes(self):
        v = VerdictOutput(
            verdict="true_positive", risk_score=78, severity="high",
            summary="Brute force detected", mitre_techniques=["T1110.001"],
        )
        assert v.verdict == "true_positive"
        assert v.risk_score == 78

    def test_invalid_risk_score_rejected(self):
        with pytest.raises(ValidationError):
            VerdictOutput(
                verdict="benign", risk_score=150, severity="low",
                summary="Should fail",
            )

    def test_negative_risk_rejected(self):
        with pytest.raises(ValidationError):
            VerdictOutput(
                verdict="benign", risk_score=-5, severity="low",
                summary="Should fail",
            )

    def test_hallucinated_mitre_dropped(self):
        v = VerdictOutput(
            verdict="suspicious", risk_score=50, severity="medium",
            summary="Test", mitre_techniques=["T1110.001", "ATTACK-FAKE", "T1078"],
        )
        assert v.mitre_techniques == ["T1110.001", "T1078"]

    def test_empty_summary_rejected(self):
        with pytest.raises(ValidationError):
            VerdictOutput(
                verdict="benign", risk_score=0, severity="info", summary="",
            )

    def test_all_verdicts_accepted(self):
        for v in ["true_positive", "suspicious", "benign", "inconclusive", "error"]:
            result = VerdictOutput(
                verdict=v, risk_score=50, severity="medium", summary="Test",
            )
            assert result.verdict == v

    def test_malicious_rejected(self):
        with pytest.raises(ValidationError):
            VerdictOutput(
                verdict="malicious", risk_score=90, severity="critical",
                summary="Should not accept malicious",
            )


class TestIOCItem:
    def test_valid_ioc_passes(self):
        ioc = IOCItem(ioc_type="ip", value="192.168.1.1", context="source")
        assert ioc.value == "192.168.1.1"

    def test_invalid_hash_length_rejected(self):
        with pytest.raises(ValidationError):
            IOCItem(ioc_type="hash_md5", value="tooshort")

    def test_valid_md5(self):
        ioc = IOCItem(ioc_type="hash_md5", value="d41d8cd98f00b204e9800998ecf8427e")
        assert len(ioc.value) == 32

    def test_valid_sha256(self):
        ioc = IOCItem(
            ioc_type="hash_sha256",
            value="a948904f2f0f479b8f8564e9e27f63e0f4c8d2d0abc44f1c71d262036c2f5e54",
        )
        assert len(ioc.value) == 64

    def test_invalid_cve_format(self):
        with pytest.raises(ValidationError):
            IOCItem(ioc_type="cve", value="not-a-cve")

    def test_valid_cve(self):
        ioc = IOCItem(ioc_type="cve", value="CVE-2024-1234")
        assert ioc.value == "CVE-2024-1234"

    def test_domain_no_spaces(self):
        with pytest.raises(ValidationError):
            IOCItem(ioc_type="domain", value="evil domain.com")

    def test_empty_value_rejected(self):
        with pytest.raises(ValidationError):
            IOCItem(ioc_type="ip", value="")


class TestToolSelectionOutput:
    def test_valid_tools(self):
        ts = ToolSelectionOutput(tools=["extract_ipv4", "score_brute_force"])
        assert len(ts.tools) == 2

    def test_empty_tools_rejected(self):
        with pytest.raises(ValidationError):
            ToolSelectionOutput(tools=[])
