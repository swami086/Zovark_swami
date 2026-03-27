"""New Temporal workflows for v0.13.0 features.

Orchestrates: Zeek ingestion, DeepLog analysis, sandbox analysis,
and investigation enrichment.
"""
from datetime import timedelta
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from activities.network_analysis import ingest_zeek_logs
    from investigation.deeplog_analyzer import analyze_alert_sequence
    from threat_intel.attack_surface import enrich_alert_with_attack_surface

# Import sandbox activity if available
try:
    with workflow.unsafe.imports_passed_through():
        from sandbox.string_analyzer import analyze_binary_strings
    _HAS_STRING_ANALYZER = True
except ImportError:
    _HAS_STRING_ANALYZER = False


@workflow.defn
class ZeekIngestionWorkflow:
    """Ingest Zeek logs, then enrich extracted IOCs with attack surface data."""

    @workflow.run
    async def run(self, params: dict) -> dict:
        tenant_id = params.get("tenant_id")

        # Step 1: Ingest and analyze Zeek logs
        ingest_result = await workflow.execute_activity(
            ingest_zeek_logs,
            params,
            schedule_to_close_timeout=timedelta(minutes=10),
            retry_policy=workflow.RetryPolicy(maximum_attempts=3),
        )

        # Step 2: Enrich top IOCs with attack surface data
        enrichments = []
        iocs = ingest_result.get("iocs_extracted", [])[:10]
        for ioc in iocs:
            try:
                result = await workflow.execute_activity(
                    enrich_alert_with_attack_surface,
                    {"alert_id": "", "tenant_id": tenant_id, "ioc": ioc},
                    schedule_to_close_timeout=timedelta(minutes=2),
                )
                enrichments.append(result)
            except Exception:
                pass

        return {
            "ingest": ingest_result,
            "enrichments": enrichments,
        }


@workflow.defn
class DeepLogAnalysisWorkflow:
    """Run DeepLog anomaly detection on alert sequences."""

    @workflow.run
    async def run(self, params: dict) -> dict:
        result = await workflow.execute_activity(
            analyze_alert_sequence,
            params,
            schedule_to_close_timeout=timedelta(minutes=5),
            retry_policy=workflow.RetryPolicy(maximum_attempts=2),
        )
        return result


@workflow.defn
class SandboxAnalysisWorkflow:
    """Analyze binary strings, then enrich high-risk IOCs."""

    @workflow.run
    async def run(self, params: dict) -> dict:
        if not _HAS_STRING_ANALYZER:
            return {"error": "StringSifter analyzer not available"}

        analysis = await workflow.execute_activity(
            analyze_binary_strings,
            params,
            schedule_to_close_timeout=timedelta(minutes=3),
        )

        # If high risk, enrich IOCs
        enrichments = []
        if analysis.get("risk_score", 0) > 0.7:
            iocs = analysis.get("iocs", {})
            for ip in (iocs.get("ips", []) or [])[:5]:
                try:
                    result = await workflow.execute_activity(
                        enrich_alert_with_attack_surface,
                        {"alert_id": "", "tenant_id": params.get("tenant_id"), "ioc": ip},
                        schedule_to_close_timeout=timedelta(minutes=2),
                    )
                    enrichments.append(result)
                except Exception:
                    pass

        return {
            "analysis": analysis,
            "enrichments": enrichments,
        }


@workflow.defn
class InvestigationEnrichmentWorkflow:
    """Parallel DeepLog + attack surface enrichment on top alerts."""

    @workflow.run
    async def run(self, params: dict) -> dict:
        tenant_id = params.get("tenant_id")
        alert_ids = params.get("alert_ids", [])

        # Run DeepLog and enrichment in parallel
        deeplog_handle = workflow.start_activity(
            analyze_alert_sequence,
            {"alert_ids": alert_ids, "tenant_id": tenant_id},
            schedule_to_close_timeout=timedelta(minutes=5),
        )

        # Enrich top 5 alerts
        enrichment_handles = []
        for alert_id in alert_ids[:5]:
            handle = workflow.start_activity(
                enrich_alert_with_attack_surface,
                {"alert_id": alert_id, "tenant_id": tenant_id},
                schedule_to_close_timeout=timedelta(minutes=2),
            )
            enrichment_handles.append(handle)

        # Await all
        deeplog_result = await deeplog_handle
        enrichment_results = []
        for h in enrichment_handles:
            try:
                enrichment_results.append(await h)
            except Exception:
                pass

        return {
            "deeplog": deeplog_result,
            "enrichments": enrichment_results,
        }
