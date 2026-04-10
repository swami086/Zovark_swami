"""Optional data-plane emit (Redpanda / Surreal / DuckDB)."""
import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

from pydantic import SecretStr

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _mock_settings(**overrides):
    m = MagicMock()
    m.redpanda_enabled = False
    m.surreal_enabled = False
    m.duckdb_enabled = False
    m.redpanda_brokers = "redpanda:9092"
    m.redpanda_topic_investigations = "zovark.investigations.completed"
    m.surreal_http_url = "http://surrealdb:8000"
    m.surreal_user = "root"
    m.surreal_password = SecretStr("change-me-surreal")
    m.surreal_ns = "zovark"
    m.surreal_db = "core"
    m.duckdb_path = "/tmp/zovark_test_analytics.duckdb"
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


def test_emit_skips_when_settings_unavailable():
    from data_plane import emit as emit_mod

    async def run():
        with patch.object(emit_mod, "settings", None):
            await emit_mod.emit_after_investigation_stored(
                task_id="t1",
                tenant_id="ten1",
                verdict="benign",
                risk_score=10,
                task_type="test",
                trace_id="tr",
                investigation_id=None,
                status="completed",
            )

    asyncio.run(run())


def test_emit_redpanda_when_enabled():
    from data_plane import emit as emit_mod

    emit_mod.reset_data_plane_state_for_tests()
    mock_s = _mock_settings(redpanda_enabled=True)
    mock_prod = MagicMock()

    async def run():
        with patch.object(emit_mod, "settings", mock_s):
            with patch.object(emit_mod, "_kafka_producer_sync", return_value=mock_prod):
                await emit_mod.emit_after_investigation_stored(
                    task_id="t1",
                    tenant_id="ten1",
                    verdict="true_positive",
                    risk_score=80,
                    task_type="brute_force",
                    trace_id="tr",
                    investigation_id="inv1",
                    status="completed",
                )

    try:
        asyncio.run(run())
        mock_prod.send.assert_called_once()
        mock_prod.flush.assert_called_once()
    finally:
        emit_mod.reset_data_plane_state_for_tests()


def test_emit_surreal_when_enabled():
    from data_plane import emit as emit_mod

    emit_mod.reset_data_plane_state_for_tests()
    mock_s = _mock_settings(surreal_enabled=True)

    async def run():
        with patch.object(emit_mod, "settings", mock_s):
            with patch("httpx.AsyncClient") as client_cls:
                inst = AsyncMock()
                inst.__aenter__.return_value = inst
                inst.__aexit__.return_value = None
                ok = MagicMock()
                ok.raise_for_status = MagicMock()
                inst.post = AsyncMock(side_effect=[ok, ok])
                client_cls.return_value = inst

                await emit_mod.emit_after_investigation_stored(
                    task_id="t1",
                    tenant_id="ten1",
                    verdict="benign",
                    risk_score=5,
                    task_type="health_check",
                    trace_id="tr",
                    investigation_id=None,
                    status="completed",
                )

                assert inst.post.await_count == 2
                paths = [str(c.args[0]) for c in inst.post.await_args_list if c.args]
                assert any(p.endswith("/sql") for p in paths)
                assert any("/key/investigation" in p for p in paths)

    try:
        asyncio.run(run())
    finally:
        emit_mod.reset_data_plane_state_for_tests()


def test_emit_duckdb_when_enabled(tmp_path):
    from data_plane import emit as emit_mod

    dbfile = tmp_path / "a.duckdb"
    mock_s = _mock_settings(duckdb_enabled=True, duckdb_path=str(dbfile))

    async def run():
        with patch.object(emit_mod, "settings", mock_s):
            await emit_mod.emit_after_investigation_stored(
                task_id="t1",
                tenant_id="ten1",
                verdict="benign",
                risk_score=1,
                task_type="x",
                trace_id="",
                investigation_id=None,
                status="completed",
            )

    asyncio.run(run())
    assert dbfile.is_file()
