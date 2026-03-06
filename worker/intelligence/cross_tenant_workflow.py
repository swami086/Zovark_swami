"""Cross-tenant refresh workflow — refreshes materialized view and recomputes threat scores."""

import os
from datetime import timedelta
from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    from intelligence.cross_tenant import refresh_cross_tenant_intel, compute_threat_score
    import psycopg2


@activity.defn
async def _list_multi_tenant_entities(data: dict) -> list:
    """List entity IDs that appear across multiple tenants."""
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT e.id::text
                FROM entities e
                JOIN cross_tenant_intel cti ON e.entity_hash = cti.entity_hash
                ORDER BY e.id::text
            """)
            return [row[0] for row in cur.fetchall()]
    except Exception as e:
        print(f"_list_multi_tenant_entities error: {e}")
        return []
    finally:
        conn.close()


@workflow.defn
class CrossTenantRefreshWorkflow:
    @workflow.run
    async def run(self, params: dict) -> dict:
        # 1. Refresh materialized view
        refresh_result = await workflow.execute_activity(
            refresh_cross_tenant_intel,
            {},
            schedule_to_close_timeout=timedelta(minutes=5),
        )

        workflow.logger.info(
            f"Refresh done: {refresh_result.get('entities_correlated', 0)} correlated, "
            f"{refresh_result.get('multi_tenant_entities', 0)} multi-tenant"
        )

        # 2. Get all multi-tenant entity IDs and recompute threat scores
        entity_ids = await workflow.execute_activity(
            _list_multi_tenant_entities,
            {},
            schedule_to_close_timeout=timedelta(minutes=2),
        )

        scores_updated = 0
        for eid in entity_ids:
            try:
                await workflow.execute_activity(
                    compute_threat_score,
                    {"entity_id": eid, "tenant_id": None},
                    schedule_to_close_timeout=timedelta(seconds=30),
                )
                scores_updated += 1
            except Exception as e:
                workflow.logger.info(f"Threat score computation failed for {eid}: {e}")

        refresh_result["scores_updated"] = scores_updated
        return refresh_result
