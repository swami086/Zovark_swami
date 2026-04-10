"""Ticket 3 — Python pipeline quality (subset of unit checks, no DB)."""

from governance.cmmc import evaluate_cmmc_for_techniques
from governance.hipaa import evaluate_hipaa_for_techniques
from governance.suppression import validate_suppression_rule_syntax
from finetuning.evaluator import load_reference_cases


def test_compliance_yaml_loads():
    c = evaluate_cmmc_for_techniques(["T1110"])
    assert "IR.L2-3.6.1" in c.get("control_ids", [])
    h = evaluate_hipaa_for_techniques(["T1486"])
    assert any("164." in x for x in h.get("section_refs", []))


def test_suppression_regex_validates():
    ok, _ = validate_suppression_rule_syntax(r"(?i)scheduled.test")
    assert ok is True
    bad, msg = validate_suppression_rule_syntax("((unclosed")
    assert bad is False
    assert "regex" in msg.lower()


def test_reference_cases_from_plans():
    cases = load_reference_cases(50)
    assert len(cases) == 50
    assert all("siem_event" in c for c in cases)

