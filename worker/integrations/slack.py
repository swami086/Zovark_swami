"""
HYDRA Slack Integration — Temporal Activity
Posts investigation results to Slack via incoming webhooks.
Supports: investigation_complete, approval_needed, sla_breach events.
"""
import os
import json
import httpx
from temporalio import activity
from datetime import datetime, timezone


SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}


def _build_investigation_complete_blocks(data: dict) -> list:
    """Build Slack blocks for investigation_complete event."""
    severity = data.get("severity", "medium").lower()
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    verdict = data.get("verdict", "unknown")
    investigation_id = data.get("investigation_id", "N/A")
    title = data.get("title", "Investigation Complete")
    summary = data.get("summary", "No summary available.")
    entities = data.get("entities", [])
    mitre = data.get("mitre_techniques", [])
    duration = data.get("duration_seconds", 0)

    entity_text = ", ".join(entities[:10]) if entities else "None identified"
    mitre_text = ", ".join(mitre[:5]) if mitre else "None mapped"

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Investigation Complete: {verdict.upper()}", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Investigation ID:*\n`{investigation_id}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Verdict:*\n{verdict}"},
                {"type": "mrkdwn", "text": f"*Duration:*\n{duration}s"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Summary:*\n{summary[:500]}"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Entities:*\n{entity_text}"},
                {"type": "mrkdwn", "text": f"*MITRE:*\n{mitre_text}"},
            ]
        },
        {"type": "divider"},
    ]


def _build_approval_needed_blocks(data: dict) -> list:
    """Build Slack blocks for approval_needed event."""
    action = data.get("action", "unknown")
    investigation_id = data.get("investigation_id", "N/A")
    reason = data.get("reason", "Manual approval required")
    requester = data.get("requester", "system")

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Approval Required", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Action:*\n{action}"},
                {"type": "mrkdwn", "text": f"*Investigation:*\n`{investigation_id}`"},
                {"type": "mrkdwn", "text": f"*Requester:*\n{requester}"},
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Reason:*\n{reason}"}
        },
        {"type": "divider"},
    ]


def _build_sla_breach_blocks(data: dict) -> list:
    """Build Slack blocks for sla_breach event."""
    investigation_id = data.get("investigation_id", "N/A")
    sla_target = data.get("sla_target_minutes", 0)
    elapsed = data.get("elapsed_minutes", 0)
    severity = data.get("severity", "high")

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "SLA Breach Alert", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Investigation:*\n`{investigation_id}`"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*SLA Target:*\n{sla_target} min"},
                {"type": "mrkdwn", "text": f"*Elapsed:*\n{elapsed} min"},
            ]
        },
        {"type": "divider"},
    ]


BLOCK_BUILDERS = {
    "investigation_complete": _build_investigation_complete_blocks,
    "approval_needed": _build_approval_needed_blocks,
    "sla_breach": _build_sla_breach_blocks,
}


@activity.defn
async def send_slack_notification(data: dict) -> dict:
    """
    Send a Slack notification via incoming webhook.

    Args:
        data: {
            "event_type": "investigation_complete" | "approval_needed" | "sla_breach",
            "webhook_url": optional override,
            "channel": optional channel override,
            ...event-specific fields
        }

    Returns:
        {"status": "sent" | "skipped" | "error", "event_type": str}
    """
    event_type = data.get("event_type", "investigation_complete")
    webhook_url = data.get("webhook_url") or SLACK_WEBHOOK_URL

    if not webhook_url:
        activity.logger.warning("No Slack webhook URL configured — skipping notification")
        return {"status": "skipped", "event_type": event_type, "reason": "no_webhook_url"}

    builder = BLOCK_BUILDERS.get(event_type)
    if not builder:
        return {"status": "error", "event_type": event_type, "reason": f"unknown event type: {event_type}"}

    blocks = builder(data)
    payload = {
        "blocks": blocks,
        "text": f"HYDRA: {event_type.replace('_', ' ').title()}",
    }

    if data.get("channel"):
        payload["channel"] = data["channel"]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 200:
                activity.logger.info("Slack notification sent", event_type=event_type)
                return {"status": "sent", "event_type": event_type, "http_status": resp.status_code}
            else:
                activity.logger.error("Slack webhook failed", status=resp.status_code, body=resp.text[:200])
                return {"status": "error", "event_type": event_type, "http_status": resp.status_code, "body": resp.text[:200]}
    except Exception as e:
        activity.logger.error("Slack notification error", error=str(e))
        return {"status": "error", "event_type": event_type, "error": str(e)}
