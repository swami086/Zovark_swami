"""Tests for tool_subsets.py — ensures subsets stay in sync with investigation plans."""
import json
import os
import pytest

from tools.tool_subsets import TOOL_SUBSETS, ALIASES, get_tool_subset


PLANS_PATH = os.path.join(os.path.dirname(__file__), "..", "investigation_plans.json")


@pytest.fixture(scope="module")
def investigation_plans():
    with open(PLANS_PATH) as f:
        return json.load(f)


class TestSubsetPlanParity:
    """Every tool referenced in an investigation plan must appear in that plan's TOOL_SUBSETS entry."""

    def _tools_in_plan(self, plan_data: dict) -> set:
        tools = set()
        for step in plan_data.get("plan", []):
            if "tool" in step:
                tools.add(step["tool"])
            for branch in ("if_true", "if_false"):
                if branch in step and "tool" in step[branch]:
                    tools.add(step[branch]["tool"])
        return tools

    def test_all_plan_tools_in_subset(self, investigation_plans):
        """For every plan that has a matching TOOL_SUBSETS entry, verify
        all tools used in the plan are present in the subset."""
        failures = []
        for plan_key, plan_data in investigation_plans.items():
            subset = TOOL_SUBSETS.get(plan_key)
            if subset is None:
                continue
            plan_tools = self._tools_in_plan(plan_data)
            subset_set = set(subset)
            missing = plan_tools - subset_set
            if missing:
                failures.append(f"{plan_key}: plan uses {missing} but subset omits them")

        assert not failures, "Subset-vs-plan drift detected:\n" + "\n".join(failures)

    def test_insider_threat_includes_correlate(self):
        subset = TOOL_SUBSETS["insider_threat_detection"]
        assert "correlate_with_history" in subset

    def test_aliases_resolve_to_known_subsets(self):
        for alias, canonical in ALIASES.items():
            assert canonical in TOOL_SUBSETS, (
                f"Alias '{alias}' → '{canonical}' has no TOOL_SUBSETS entry"
            )

    def test_get_tool_subset_returns_none_for_unknown(self):
        assert get_tool_subset("completely_unknown_type_xyz") is None

    def test_get_tool_subset_resolves_alias(self):
        result = get_tool_subset("phishing")
        assert result is not None
        assert "detect_phishing" in result
