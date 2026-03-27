"""
ZOVARC Jira Integration — Temporal Activity
Creates Jira issues from investigation results via REST API v3.
Maps investigation verdict/severity to Jira priority.
"""
import os
import base64
import httpx
from temporalio import activity


JIRA_URL = os.environ.get("JIRA_URL", "")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SEC")

# Map ZOVARC severity to Jira priority names
SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


def _build_description(data: dict) -> dict:
    """Build Jira ADF (Atlassian Document Format) description."""
    summary = data.get("summary", "No summary available.")
    entities = data.get("entities", [])
    mitre = data.get("mitre_techniques", [])
    investigation_id = data.get("investigation_id", "N/A")
    verdict = data.get("verdict", "unknown")
    severity = data.get("severity", "medium")

    entity_text = ", ".join(entities[:20]) if entities else "None identified"
    mitre_text = ", ".join(mitre[:10]) if mitre else "None mapped"

    # Atlassian Document Format v1
    return {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "heading",
                "attrs": {"level": 2},
                "content": [{"type": "text", "text": "Investigation Summary"}]
            },
            {
                "type": "table",
                "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                "content": [
                    {
                        "type": "tableRow",
                        "content": [
                            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Field"}]}]},
                            {"type": "tableHeader", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Value"}]}]},
                        ]
                    },
                    _table_row("Investigation ID", investigation_id),
                    _table_row("Verdict", verdict.upper()),
                    _table_row("Severity", severity.upper()),
                    _table_row("Entities", entity_text),
                    _table_row("MITRE Techniques", mitre_text),
                ]
            },
            {
                "type": "heading",
                "attrs": {"level": 3},
                "content": [{"type": "text", "text": "Details"}]
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": summary[:2000]}]
            },
        ]
    }


def _table_row(key: str, value: str) -> dict:
    return {
        "type": "tableRow",
        "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": key, "marks": [{"type": "strong"}]}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": value}]}]},
        ]
    }


@activity.defn
async def create_jira_ticket(data: dict) -> dict:
    """
    Create a Jira issue from investigation data.

    Args:
        data: {
            "investigation_id": str,
            "title": str,
            "summary": str,
            "verdict": str,
            "severity": str,
            "entities": list[str],
            "mitre_techniques": list[str],
            "project_key": optional str,
            "issue_type": optional str (default "Task"),
            "labels": optional list[str],
        }

    Returns:
        {"status": "created"|"skipped"|"error", "issue_key": str, "issue_url": str}
    """
    jira_url = data.get("jira_url") or JIRA_URL
    jira_email = data.get("jira_email") or JIRA_EMAIL
    jira_token = data.get("jira_api_token") or JIRA_API_TOKEN
    project_key = data.get("project_key") or JIRA_PROJECT_KEY

    if not jira_url or not jira_email or not jira_token:
        activity.logger.warning("Jira not configured — skipping ticket creation")
        return {"status": "skipped", "reason": "jira_not_configured"}

    severity = data.get("severity", "medium").lower()
    priority_name = SEVERITY_TO_PRIORITY.get(severity, "Medium")
    issue_type = data.get("issue_type", "Task")
    title = data.get("title", f"ZOVARC Investigation: {data.get('investigation_id', 'N/A')}")

    labels = data.get("labels", ["zovarc", "security-investigation"])
    if data.get("verdict"):
        labels.append(f"verdict-{data['verdict']}")

    description_adf = _build_description(data)

    issue_payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": title[:255],
            "description": description_adf,
            "issuetype": {"name": issue_type},
            "priority": {"name": priority_name},
            "labels": labels,
        }
    }

    # Basic auth: email:api_token
    auth_str = base64.b64encode(f"{jira_email}:{jira_token}".encode()).decode()

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{jira_url.rstrip('/')}/rest/api/3/issue",
                headers={
                    "Authorization": f"Basic {auth_str}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json=issue_payload,
            )

            if resp.status_code in (200, 201):
                result = resp.json()
                issue_key = result.get("key", "")
                issue_url = f"{jira_url.rstrip('/')}/browse/{issue_key}"
                activity.logger.info("Jira ticket created", issue_key=issue_key)
                return {
                    "status": "created",
                    "issue_key": issue_key,
                    "issue_id": result.get("id", ""),
                    "issue_url": issue_url,
                }
            else:
                activity.logger.error("Jira API error", status=resp.status_code, body=resp.text[:300])
                return {
                    "status": "error",
                    "http_status": resp.status_code,
                    "error": resp.text[:300],
                }
    except Exception as e:
        activity.logger.error("Jira integration error", error=str(e))
        return {"status": "error", "error": str(e)}
