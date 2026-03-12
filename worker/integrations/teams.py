"""
HYDRA Microsoft Teams Integration — Temporal Activity
Posts adaptive cards to Teams via incoming webhook.
"""
import os
import httpx
from temporalio import activity


TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")

SEVERITY_COLORS = {
    "critical": "attention",
    "high": "warning",
    "medium": "accent",
    "low": "good",
    "info": "default",
}

# Hex colors for the card accent
SEVERITY_HEX = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}


def _build_adaptive_card(data: dict) -> dict:
    """Build a Teams adaptive card payload."""
    event_type = data.get("event_type", "investigation_complete")
    severity = data.get("severity", "medium").lower()
    investigation_id = data.get("investigation_id", "N/A")
    verdict = data.get("verdict", "unknown")
    title = data.get("title", f"HYDRA: {event_type.replace('_', ' ').title()}")
    summary = data.get("summary", "No summary available.")
    entities = data.get("entities", [])
    mitre = data.get("mitre_techniques", [])

    entity_text = ", ".join(entities[:10]) if entities else "None identified"
    mitre_text = ", ".join(mitre[:5]) if mitre else "None mapped"
    color_style = SEVERITY_COLORS.get(severity, "default")

    body_items = [
        {
            "type": "TextBlock",
            "text": title,
            "weight": "bolder",
            "size": "large",
            "color": color_style,
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "auto",
                    "items": [
                        {"type": "TextBlock", "text": "Severity", "weight": "bolder", "isSubtle": True},
                        {"type": "TextBlock", "text": severity.upper(), "color": color_style, "weight": "bolder"},
                    ]
                },
                {
                    "type": "Column",
                    "width": "auto",
                    "items": [
                        {"type": "TextBlock", "text": "Verdict", "weight": "bolder", "isSubtle": True},
                        {"type": "TextBlock", "text": verdict.upper()},
                    ]
                },
                {
                    "type": "Column",
                    "width": "auto",
                    "items": [
                        {"type": "TextBlock", "text": "Investigation", "weight": "bolder", "isSubtle": True},
                        {"type": "TextBlock", "text": investigation_id[:12]},
                    ]
                },
            ]
        },
        {
            "type": "TextBlock",
            "text": summary[:500],
            "wrap": True,
        },
    ]

    # Add entities and MITRE sections
    if event_type == "investigation_complete":
        body_items.extend([
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Entities", "value": entity_text},
                    {"title": "MITRE", "value": mitre_text},
                ]
            },
        ])

    if event_type == "sla_breach":
        sla_target = data.get("sla_target_minutes", 0)
        elapsed = data.get("elapsed_minutes", 0)
        body_items.append({
            "type": "FactSet",
            "facts": [
                {"title": "SLA Target", "value": f"{sla_target} min"},
                {"title": "Elapsed", "value": f"{elapsed} min"},
            ]
        })

    if event_type == "approval_needed":
        action = data.get("action", "unknown")
        reason = data.get("reason", "Manual approval required")
        body_items.append({
            "type": "FactSet",
            "facts": [
                {"title": "Action", "value": action},
                {"title": "Reason", "value": reason},
            ]
        })

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body_items,
                }
            }
        ]
    }

    return card


@activity.defn
async def send_teams_notification(data: dict) -> dict:
    """
    Send a Microsoft Teams notification via incoming webhook.

    Args:
        data: {
            "event_type": "investigation_complete" | "approval_needed" | "sla_breach",
            "webhook_url": optional override,
            "severity": str,
            "investigation_id": str,
            ...event-specific fields
        }

    Returns:
        {"status": "sent"|"skipped"|"error", "event_type": str}
    """
    event_type = data.get("event_type", "investigation_complete")
    webhook_url = data.get("webhook_url") or TEAMS_WEBHOOK_URL

    if not webhook_url:
        activity.logger.warning("No Teams webhook URL configured — skipping notification")
        return {"status": "skipped", "event_type": event_type, "reason": "no_webhook_url"}

    card = _build_adaptive_card(data)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=card)
            if resp.status_code in (200, 202):
                activity.logger.info("Teams notification sent", event_type=event_type)
                return {"status": "sent", "event_type": event_type, "http_status": resp.status_code}
            else:
                activity.logger.error("Teams webhook failed", status=resp.status_code, body=resp.text[:200])
                return {"status": "error", "event_type": event_type, "http_status": resp.status_code, "body": resp.text[:200]}
    except Exception as e:
        activity.logger.error("Teams notification error", error=str(e))
        return {"status": "error", "event_type": event_type, "error": str(e)}
