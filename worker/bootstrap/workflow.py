"""Bootstrap Corpus Temporal Workflow.

Loads MITRE ATT&CK + CISA KEV, generates synthetic investigations,
extracts entities to seed the entity graph.
"""

from datetime import timedelta
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from bootstrap.activities import (
        load_mitre_techniques,
        load_cisa_kev,
        generate_synthetic_investigation,
        process_bootstrap_entity,
        list_techniques,
    )


@workflow.defn
class BootstrapCorpusWorkflow:

    @workflow.run
    async def run(self, params: dict) -> dict:
        """Run the full bootstrap pipeline.

        params: {
            tenant_id: str (required),
            max_techniques: int (default 50),
            batch_size: int (default 10),
            skip_mitre_load: bool (default False),
            skip_cisa_load: bool (default False),
        }
        """
        tenant_id = params.get("tenant_id")
        max_techniques = params.get("max_techniques", 50)

        stats = {
            "mitre_loaded": 0,
            "cisa_loaded": 0,
            "investigations_generated": 0,
            "investigations_failed": 0,
            "entities_processed": 0,
            "total_entities": 0,
            "total_edges": 0,
        }

        # Step 1: Load MITRE techniques
        if not params.get("skip_mitre_load", False):
            workflow.logger.info("Step 1: Loading MITRE ATT&CK techniques...")
            mitre_result = await workflow.execute_activity(
                load_mitre_techniques,
                {
                    "stix_path": "/app/bootstrap_data/mitre/enterprise-attack.json",
                    "embedding_batch_size": 32,
                },
                schedule_to_close_timeout=timedelta(minutes=30),
                heartbeat_timeout=timedelta(minutes=5),
            )
            stats["mitre_loaded"] = mitre_result.get("techniques_loaded", 0)
            workflow.logger.info(
                f"MITRE loaded: {stats['mitre_loaded']} techniques, "
                f"{mitre_result.get('embeddings_created', 0)} embeddings"
            )

        # Step 2: Load CISA KEV
        if not params.get("skip_cisa_load", False):
            workflow.logger.info("Step 2: Loading CISA KEV catalog...")
            cisa_result = await workflow.execute_activity(
                load_cisa_kev,
                {"kev_path": "/app/bootstrap_data/cisa/known_exploited_vulnerabilities.json"},
                schedule_to_close_timeout=timedelta(minutes=10),
            )
            stats["cisa_loaded"] = cisa_result.get("vulnerabilities_loaded", 0)
            workflow.logger.info(f"CISA loaded: {stats['cisa_loaded']} vulnerabilities")

        # Step 3+4: Generate synthetic investigations + extract entities
        if max_techniques > 0:
            workflow.logger.info(f"Step 3: Generating investigations for {max_techniques} techniques...")

            technique_list = await workflow.execute_activity(
                list_techniques,
                {"limit": max_techniques},
                schedule_to_close_timeout=timedelta(seconds=30),
            )

            for i, tech in enumerate(technique_list):
                workflow.logger.info(
                    f"Processing technique {i + 1}/{len(technique_list)}: "
                    f"{tech['technique_id']} {tech['name']}"
                )

                # Generate synthetic investigation
                try:
                    gen_result = await workflow.execute_activity(
                        generate_synthetic_investigation,
                        {
                            "source": "mitre",
                            "source_id": tech["technique_id"],
                            "title": tech["name"],
                            "description": tech.get("description", ""),
                        },
                        schedule_to_close_timeout=timedelta(minutes=3),
                    )
                    if gen_result.get("investigation_length", 0) > 0:
                        stats["investigations_generated"] += 1
                    else:
                        stats["investigations_failed"] += 1
                        continue
                except Exception as e:
                    workflow.logger.info(f"Generation failed for {tech['technique_id']}: {e}")
                    stats["investigations_failed"] += 1
                    continue

                # Extract entities from the generated investigation
                try:
                    entity_result = await workflow.execute_activity(
                        process_bootstrap_entity,
                        {
                            "source_id": tech["technique_id"],
                            "source": "mitre",
                            "tenant_id": tenant_id,
                        },
                        schedule_to_close_timeout=timedelta(minutes=3),
                    )
                    stats["entities_processed"] += 1
                    stats["total_entities"] += entity_result.get("entities", 0)
                    stats["total_edges"] += entity_result.get("edges", 0)
                except Exception as e:
                    workflow.logger.info(f"Entity processing failed for {tech['technique_id']}: {e}")

        workflow.logger.info(f"Bootstrap complete: {stats}")
        return stats
