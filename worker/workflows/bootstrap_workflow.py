"""Bootstrap Pipeline Workflow — orchestrates MITRE ATT&CK + CISA KEV ingestion.

Temporal workflow that downloads, parses, and stores threat intelligence data
for the entity graph cold-start. Supports air-gapped deployments by checking
for bundled files before attempting downloads.

Activities:
    sync_mitre_attack   — download + parse + store MITRE ATT&CK techniques
    sync_cisa_kev       — download + parse + store CISA KEV catalog
    compute_bootstrap_stats — count entities, edges, investigations created
"""

import os
import logging
from datetime import timedelta

from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    from bootstrap.mitre_attack import (
        resolve_stix_path,
        parse_stix_bundle,
        store_techniques,
    )
    from bootstrap.cisa_kev import (
        resolve_kev_path,
        parse_kev_catalog,
        store_kev_catalog,
        store_to_bootstrap_corpus,
    )
    import psycopg2

logger = logging.getLogger(__name__)


DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark"
)


@activity.defn
async def sync_mitre_attack(params: dict) -> dict:
    """Download + parse + store MITRE ATT&CK Enterprise techniques.

    Params:
        force_download: bool — skip bundled file, always download (default False)

    Returns:
        {techniques_stored, software_count, groups_count, relationships_count, source}
    """
    force_download = params.get("force_download", False)

    try:
        if force_download:
            from bootstrap.mitre_attack import download_stix
            stix_path = download_stix()
            source = "download"
        else:
            stix_path = resolve_stix_path()
            source = "bundled" if "/bootstrap_data/" in stix_path else "download"
    except Exception as e:
        logger.error("Failed to resolve MITRE STIX: %s", e)
        return {"techniques_stored": 0, "error": str(e)}

    parsed = parse_stix_bundle(stix_path)
    techniques = parsed.get("techniques", [])

    stored = store_techniques(techniques, DATABASE_URL)

    return {
        "techniques_stored": stored,
        "software_count": len(parsed.get("software", [])),
        "groups_count": len(parsed.get("groups", [])),
        "relationships_count": len(parsed.get("relationships", [])),
        "source": source,
    }


@activity.defn
async def sync_cisa_kev(params: dict) -> dict:
    """Download + parse + store CISA KEV catalog.

    Params:
        force_download: bool — skip bundled file, always download (default False)

    Returns:
        {kev_stored, corpus_inserted, source}
    """
    force_download = params.get("force_download", False)

    try:
        if force_download:
            from bootstrap.cisa_kev import download_kev
            kev_path = download_kev()
            source = "download"
        else:
            kev_path = resolve_kev_path()
            source = "bundled" if "/bootstrap_data/" in kev_path else "download"
    except Exception as e:
        logger.error("Failed to resolve CISA KEV: %s", e)
        return {"kev_stored": 0, "error": str(e)}

    vulns = parse_kev_catalog(kev_path)
    kev_stored = store_kev_catalog(vulns, DATABASE_URL)
    corpus_inserted = store_to_bootstrap_corpus(vulns, DATABASE_URL)

    return {
        "kev_stored": kev_stored,
        "corpus_inserted": corpus_inserted,
        "source": source,
    }


@activity.defn
async def compute_bootstrap_stats(params: dict) -> dict:
    """Compute counts of bootstrap data across tables.

    Returns:
        {mitre_techniques, kev_entries, bootstrap_investigations,
         bootstrap_entities, bootstrap_completed}
    """
    stats = {
        "mitre_techniques": 0,
        "kev_entries": 0,
        "bootstrap_investigations": 0,
        "bootstrap_entities": 0,
        "bootstrap_completed": 0,
    }

    try:
        conn = psycopg2.connect(DATABASE_URL)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM mitre_techniques")
                stats["mitre_techniques"] = cur.fetchone()[0]

                # kev_catalog may not exist yet in older deployments
                try:
                    cur.execute("SELECT COUNT(*) FROM kev_catalog")
                    stats["kev_entries"] = cur.fetchone()[0]
                except Exception:
                    conn.rollback()

                cur.execute("SELECT COUNT(*) FROM investigations WHERE source = 'bootstrap'")
                stats["bootstrap_investigations"] = cur.fetchone()[0]

                try:
                    cur.execute("SELECT COUNT(*) FROM entities WHERE tenant_id IS NULL")
                    stats["bootstrap_entities"] = cur.fetchone()[0]
                except Exception:
                    conn.rollback()

                cur.execute(
                    "SELECT COUNT(*) FROM bootstrap_corpus WHERE status = 'completed'"
                )
                stats["bootstrap_completed"] = cur.fetchone()[0]
        finally:
            conn.close()
    except Exception as e:
        logger.error("Failed to compute bootstrap stats: %s", e)
        stats["error"] = str(e)

    return stats


@workflow.defn
class BootstrapPipelineWorkflow:
    """Orchestrates MITRE ATT&CK + CISA KEV ingestion.

    Params:
        skip_mitre: bool — skip MITRE sync (default False)
        skip_cisa: bool — skip CISA sync (default False)
        force_download: bool — always download, ignore bundled (default False)
    """

    @workflow.run
    async def run(self, params: dict) -> dict:
        results = {
            "mitre": {},
            "cisa": {},
            "stats": {},
        }

        # Step 1: Sync MITRE ATT&CK
        if not params.get("skip_mitre", False):
            workflow.logger.info("Step 1: Syncing MITRE ATT&CK techniques...")
            results["mitre"] = await workflow.execute_activity(
                sync_mitre_attack,
                {"force_download": params.get("force_download", False)},
                start_to_close_timeout=timedelta(minutes=30),
                heartbeat_timeout=timedelta(minutes=10),
            )
            workflow.logger.info(
                "MITRE sync complete: %d techniques stored (source=%s)",
                results["mitre"].get("techniques_stored", 0),
                results["mitre"].get("source", "unknown"),
            )

        # Step 2: Sync CISA KEV
        if not params.get("skip_cisa", False):
            workflow.logger.info("Step 2: Syncing CISA KEV catalog...")
            results["cisa"] = await workflow.execute_activity(
                sync_cisa_kev,
                {"force_download": params.get("force_download", False)},
                start_to_close_timeout=timedelta(minutes=15),
                heartbeat_timeout=timedelta(minutes=5),
            )
            workflow.logger.info(
                "CISA sync complete: %d KEV entries stored (source=%s)",
                results["cisa"].get("kev_stored", 0),
                results["cisa"].get("source", "unknown"),
            )

        # Step 3: Compute stats
        workflow.logger.info("Step 3: Computing bootstrap stats...")
        results["stats"] = await workflow.execute_activity(
            compute_bootstrap_stats,
            {},
            start_to_close_timeout=timedelta(seconds=30),
        )

        workflow.logger.info("Bootstrap pipeline complete: %s", results["stats"])
        return results
