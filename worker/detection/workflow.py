"""Detection generation workflow — orchestrates pattern mining, Sigma generation, and validation."""

import os
from datetime import timedelta
from temporalio import workflow, activity

with workflow.unsafe.imports_passed_through():
    from detection.pattern_miner import mine_attack_patterns
    from detection.sigma_generator import generate_sigma_rule
    from detection.rule_validator import validate_sigma_rule
    import psycopg2
    from psycopg2.extras import RealDictCursor


@activity.defn
async def _list_candidates_for_generation(data: dict) -> list:
    """List detection candidates that need Sigma rule generation."""
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id::text, technique_id, pattern_description,
                       entity_types, edge_patterns
                FROM detection_candidates
                WHERE status = 'candidate'
                ORDER BY investigation_count DESC
                LIMIT 50
            """)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@workflow.defn
class DetectionGenerationWorkflow:
    @workflow.run
    async def run(self, params: dict) -> dict:
        min_investigations = params.get("min_investigations", 2)

        # 1. Mine attack patterns
        mine_result = await workflow.execute_activity(
            mine_attack_patterns,
            {"min_investigations": min_investigations},
            schedule_to_close_timeout=timedelta(minutes=5),
        )

        workflow.logger.info(
            f"Mining done: {mine_result['candidates_found']} patterns, "
            f"{mine_result['candidates_created']} new candidates"
        )

        # 2. Get all candidates that need Sigma rules
        candidates = await workflow.execute_activity(
            _list_candidates_for_generation,
            {},
            schedule_to_close_timeout=timedelta(minutes=1),
        )

        rules_generated = 0
        rules_validated = 0
        rules_approved = 0

        # 3. Generate and validate Sigma rules for each candidate
        for candidate in candidates:
            try:
                # Generate
                gen_result = await workflow.execute_activity(
                    generate_sigma_rule,
                    {
                        "candidate_id": candidate["id"],
                        "technique_id": candidate["technique_id"],
                        "pattern_description": candidate["pattern_description"],
                        "entity_types": candidate["entity_types"],
                        "edge_patterns": candidate["edge_patterns"],
                    },
                    schedule_to_close_timeout=timedelta(minutes=3),
                )

                if gen_result.get("valid"):
                    rules_generated += 1

                    # Validate
                    val_result = await workflow.execute_activity(
                        validate_sigma_rule,
                        {
                            "candidate_id": candidate["id"],
                            "technique_id": candidate["technique_id"],
                            "sigma_yaml": gen_result["sigma_yaml"],
                        },
                        schedule_to_close_timeout=timedelta(minutes=1),
                    )

                    rules_validated += 1
                    if val_result.get("status") == "approved":
                        rules_approved += 1

            except Exception as e:
                workflow.logger.info(f"Failed to process candidate {candidate['technique_id']}: {e}")

        result = {
            "candidates_found": mine_result["candidates_found"],
            "candidates_created": mine_result["candidates_created"],
            "rules_generated": rules_generated,
            "rules_validated": rules_validated,
            "rules_approved": rules_approved,
        }
        workflow.logger.info(f"Detection generation complete: {result}")
        return result
