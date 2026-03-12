"""Alert correlation workflow — orchestrates alert grouping and incident creation (Issue #53)."""

from datetime import timedelta
from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from correlation.engine import correlate_alerts, create_incident


@workflow.defn
class AlertCorrelationWorkflow:
    """Orchestrate alert correlation: group related alerts, then create incidents."""

    @workflow.run
    async def run(self, params: dict) -> dict:
        tenant_id = params.get("tenant_id")
        lookback_minutes = params.get("lookback_minutes", 30)

        if not tenant_id:
            return {"status": "error", "message": "tenant_id required"}

        # 1. Correlate alerts
        correlation_result = await workflow.execute_activity(
            correlate_alerts,
            {"tenant_id": tenant_id, "lookback_minutes": lookback_minutes},
            schedule_to_close_timeout=timedelta(minutes=2),
        )

        groups = correlation_result.get("correlation_groups", [])
        workflow.logger.info(
            f"Correlation: {correlation_result['total_alerts_processed']} alerts, "
            f"{correlation_result['groups_found']} groups"
        )

        if not groups:
            return {
                "status": "completed",
                "alerts_processed": correlation_result["total_alerts_processed"],
                "incidents_created": 0,
            }

        # 2. Create incidents for each correlation group
        incidents_created = 0
        incident_ids = []

        for group in groups:
            try:
                incident = await workflow.execute_activity(
                    create_incident,
                    {
                        "tenant_id": tenant_id,
                        "title": group["title"],
                        "severity": group["severity"],
                        "alert_ids": group["alert_ids"],
                        "correlation_rule": group["rule"],
                        "source_ips": [group["key"]] if group["rule"] == "same_source_ip" else [],
                        "target_users": [group["key"]] if group["rule"] == "same_target_user" else [],
                        "mitre_techniques": [group["key"]] if group["rule"] == "same_mitre_technique" else [],
                    },
                    schedule_to_close_timeout=timedelta(seconds=30),
                )

                if incident.get("incident_id"):
                    incidents_created += 1
                    incident_ids.append(incident["incident_id"])

            except Exception as e:
                workflow.logger.info(f"Incident creation failed for group '{group['title']}': {e}")

        result = {
            "status": "completed",
            "alerts_processed": correlation_result["total_alerts_processed"],
            "groups_found": len(groups),
            "incidents_created": incidents_created,
            "incident_ids": incident_ids,
        }
        workflow.logger.info(f"Correlation workflow complete: {incidents_created} incidents created")
        return result
