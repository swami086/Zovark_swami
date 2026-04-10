"""Ticket 4: ActivityEnvironment-backed behavior checks for pipeline stages."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

try:
    from temporalio.testing import ActivityEnvironment
except ImportError:  # pragma: no cover
    ActivityEnvironment = None  # type: ignore[misc, assignment]


def test_test_database_url_required_for_worker_ci():
    """Fail loudly in CI when TEST_DATABASE_URL is missing (operator must set explicitly)."""
    if os.environ.get("CI") or os.environ.get("REQUIRE_TEST_DATABASE_URL"):
        assert os.environ.get(
            "TEST_DATABASE_URL", ""
        ).strip(), "TEST_DATABASE_URL must be set for worker tests in CI"


@pytest.mark.skipif(ActivityEnvironment is None, reason="temporalio not installed")
def test_activity_environment_executes_simple_callable():
    env = ActivityEnvironment()

    def double(x: int) -> int:
        return x * 2

    assert env.run(double, 11) == 22


# --- Stage behavior (mocked IO; exercises real activity logic paths) ---


@pytest.mark.skipif(ActivityEnvironment is None, reason="temporalio not installed")
def test_ingest_alert_masks_pii_and_returns_output():
    from stages.ingest import ingest_alert

    task = {
        "task_id": "t1",
        "tenant_id": "e1c1bc5d-0000-0000-0000-000000000001",
        "task_type": "brute_force",
        "input": {
            "prompt": "Contact user@example.com for details",
            "siem_event": {"raw_log": "ssh fail", "source_ip": "10.0.0.1"},
        },
    }

    async def run():
        with patch("stages.ingest.redis") as mock_redis:
            mock_redis.from_url.side_effect = RuntimeError("no redis")
            with patch("stages.ingest._get_db", side_effect=RuntimeError("no db")):
                env = ActivityEnvironment()
                return await env.run(ingest_alert, task)

    import asyncio

    out = asyncio.run(run())
    assert out["task_id"] == "t1"
    assert out["tenant_id"] == task["tenant_id"]
    assert out.get("pii_masked") is True
    assert "user@example.com" not in (out.get("prompt") or "")


@pytest.mark.skipif(ActivityEnvironment is None, reason="temporalio not installed")
def test_analyze_alert_v3_returns_plan_from_mocked_branch():
    import stages.analyze as analyze_mod
    from stages import AnalyzeOutput
    from stages.analyze import analyze_alert

    ingest_dict = {
        "task_id": "t2",
        "tenant_id": "e1c1bc5d-0000-0000-0000-000000000001",
        "task_type": "brute_force",
        "siem_event": {"raw_log": "test"},
        "prompt": "",
    }

    async def fake_v3(_ingest):
        return AnalyzeOutput(
            plan=[{"tool": "extract_ipv4", "args": {"field": "raw_log"}}],
            source="saved_plan",
            path_taken="A",
            execution_mode="tools",
            generation_ms=1,
        )

    async def run():
        with patch.object(analyze_mod, "EXECUTION_MODE", "tools"):
            with patch.object(analyze_mod, "_analyze_v3_tools", new=fake_v3):
                env = ActivityEnvironment()
                return await env.run(analyze_alert, ingest_dict)

    import asyncio

    out = asyncio.run(run())
    assert out["execution_mode"] == "tools"
    assert len(out.get("plan", [])) == 1
    assert out["plan"][0]["tool"] == "extract_ipv4"


@pytest.mark.skipif(ActivityEnvironment is None, reason="temporalio not installed")
def test_execute_investigation_v3_tools_uses_runner():
    from stages.execute import execute_investigation

    payload = {
        "task_id": "t3",
        "tenant_id": "e1c1bc5d-0000-0000-0000-000000000001",
        "task_type": "brute_force",
        "execution_mode": "tools",
        "plan": [{"tool": "count_pattern", "args": {"text": "$raw_log", "pattern": "a"}}],
        "siem_event": {"raw_log": "aaa"},
        "trace_id": "",
    }

    fake_result = {
        "risk_score": 12,
        "findings": ["three a's"],
        "iocs": [],
        "errors": [],
    }

    async def run():
        with patch("stages.execute._load_correlation_context", return_value={"investigations": []}):
            with patch("stages.execute._load_institutional_knowledge", return_value={}):
                with patch("stages.execute.execute_plan", return_value=fake_result):
                    env = ActivityEnvironment()
                    return await env.run(execute_investigation, payload)

    import asyncio

    out = asyncio.run(run())
    assert out["execution_mode"] == "tools"
    assert out["risk_score"] == 12
    assert "three" in out["stdout"].lower()


@pytest.mark.skipif(ActivityEnvironment is None, reason="temporalio not installed")
def test_assess_results_llm_down_path_fail_closed():
    from stages.assess import assess_results

    payload = {
        "task_id": "t4",
        "tenant_id": "e1c1bc5d-0000-0000-0000-000000000001",
        "path_taken": "error_llm_down",
        "task_type": "brute_force",
    }

    async def run():
        env = ActivityEnvironment()
        return await env.run(assess_results, payload)

    import asyncio

    out = asyncio.run(run())
    assert out["verdict"] == "needs_manual_review"
    assert out.get("needs_human_review") is True


@pytest.mark.skipif(ActivityEnvironment is None, reason="temporalio not installed")
def test_apply_governance_assist_benign_no_review():
    from stages.govern import apply_governance

    async def run():
        with patch(
            "stages.govern._get_governance_config",
            return_value={
                "autonomy_level": "assist",
                "consecutive_correct": 0,
                "upgrade_threshold": 20,
            },
        ):
            env = ActivityEnvironment()
            return await env.run(
                apply_governance,
                {
                    "tenant_id": "e1c1bc5d-0000-0000-0000-000000000001",
                    "task_type": "brute_force",
                    "verdict": "benign",
                },
            )

    import asyncio

    out = asyncio.run(run())
    assert out["autonomy_level"] == "assist"
    assert out["needs_human_review"] is False


@pytest.mark.skipif(ActivityEnvironment is None, reason="temporalio not installed")
def test_store_investigation_marks_failed_when_db_write_errors():
    from stages.store import store_investigation

    payload = {
        "task_id": "t5",
        "tenant_id": "e1c1bc5d-0000-0000-0000-000000000001",
        "status": "completed",
        "verdict": "benign",
        "risk_score": 10,
        "task_type": "log_analysis",
    }

    mock_cur = MagicMock()
    mock_cur.__enter__ = lambda s: mock_cur
    mock_cur.__exit__ = lambda *a: False
    mock_cur.execute.side_effect = RuntimeError("db write failed")

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cur

    async def run():
        with patch("stages.store._get_db", return_value=mock_conn):
            env = ActivityEnvironment()
            return await env.run(store_investigation, payload)

    import asyncio

    out = asyncio.run(run())
    assert out.get("status") == "failed"
