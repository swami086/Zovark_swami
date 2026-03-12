"""
HYDRA ServiceNow Integration — Temporal Activity
Creates ServiceNow incidents from investigation results via REST API.
Maps HYDRA severity to ServiceNow impact/urgency matrix.
"""
import os
import httpx
from temporalio import activity


SNOW_INSTANCE = os.environ.get("SNOW_INSTANCE", "")  # e.g. "mycompany.service-now.com"
SNOW_USER = os.environ.get("SNOW_USER", "")
SNOW_PASSWORD = os.environ.get("SNOW_PASSWORD", "")
SNOW_ASSIGNMENT_GROUP = os.environ.get("SNOW_ASSIGNMENT_GROUP", "Security Operations")

# ServiceNow impact/urgency: 1=High, 2=Medium, 3=Low
SEVERITY_MAP = {
    "critical": {"impact": "1", "urgency": "1"},  # P1
    "high":     {"impact": "1", "urgency": "2"},   # P2
    "medium":   {"impact": "2", "urgency": "2"},   # P3
    "low":      {"impact": "2", "urgency": "3"},   # P4
    "info":     {"impact": "3", "urgency": "3"},   # P5
}


def _build_work_notes(data: dict) -> str:
    """Build ServiceNow work notes from investigation data."""
    parts = []
    parts.append(f"=== HYDRA Investigation Report ===")
    parts.append(f"Investigation ID: {data.get('investigation_id', 'N/A')}")
    parts.append(f"Verdict: {data.get('verdict', 'unknown').upper()}")
    parts.append(f"Severity: {data.get('severity', 'medium').upper()}")
    parts.append("")

    if data.get("summary"):
        parts.append(f"Summary:\n{data['summary'][:2000]}")
        parts.append("")

    entities = data.get("entities", [])
    if entities:
        parts.append(f"Entities ({len(entities)}):")
        for e in entities[:20]:
            parts.append(f"  - {e}")
        parts.append("")

    mitre = data.get("mitre_techniques", [])
    if mitre:
        parts.append(f"MITRE ATT&CK Techniques:")
        for t in mitre[:10]:
            parts.append(f"  - {t}")
        parts.append("")

    steps = data.get("investigation_steps", [])
    if steps:
        parts.append(f"Investigation Steps ({len(steps)}):")
        for i, step in enumerate(steps[:10], 1):
            parts.append(f"  {i}. {step}")

    return "\n".join(parts)


@activity.defn
async def create_snow_incident(data: dict) -> dict:
    """
    Create a ServiceNow incident from investigation data.

    Args:
        data: {
            "investigation_id": str,
            "title": str,
            "summary": str,
            "verdict": str,
            "severity": str,
            "entities": list[str],
            "mitre_techniques": list[str],
            "investigation_steps": list[str],
            "assignment_group": optional str,
            "category": optional str,
            "caller_id": optional str,
        }

    Returns:
        {"status": "created"|"skipped"|"error", "incident_number": str, "sys_id": str}
    """
    snow_instance = data.get("snow_instance") or SNOW_INSTANCE
    snow_user = data.get("snow_user") or SNOW_USER
    snow_password = data.get("snow_password") or SNOW_PASSWORD

    if not snow_instance or not snow_user or not snow_password:
        activity.logger.warning("ServiceNow not configured — skipping incident creation")
        return {"status": "skipped", "reason": "servicenow_not_configured"}

    severity = data.get("severity", "medium").lower()
    impact_urgency = SEVERITY_MAP.get(severity, {"impact": "2", "urgency": "2"})
    investigation_id = data.get("investigation_id", "N/A")
    title = data.get("title", f"HYDRA Security Investigation: {investigation_id}")

    work_notes = _build_work_notes(data)

    incident_payload = {
        "short_description": title[:160],
        "description": data.get("summary", "Automated investigation by HYDRA SOC platform.")[:4000],
        "impact": impact_urgency["impact"],
        "urgency": impact_urgency["urgency"],
        "category": data.get("category", "Security"),
        "subcategory": "Investigation",
        "assignment_group": data.get("assignment_group") or SNOW_ASSIGNMENT_GROUP,
        "work_notes": work_notes,
        "caller_id": data.get("caller_id", ""),
        "u_investigation_id": investigation_id,
    }

    # Ensure scheme in instance URL
    base_url = snow_instance
    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{base_url.rstrip('/')}/api/now/table/incident",
                auth=(snow_user, snow_password),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json=incident_payload,
            )

            if resp.status_code in (200, 201):
                result = resp.json().get("result", {})
                incident_number = result.get("number", "")
                sys_id = result.get("sys_id", "")
                activity.logger.info("ServiceNow incident created",
                                     incident_number=incident_number, sys_id=sys_id)
                return {
                    "status": "created",
                    "incident_number": incident_number,
                    "sys_id": sys_id,
                    "incident_url": f"{base_url}/nav_to.do?uri=incident.do?sys_id={sys_id}",
                }
            else:
                activity.logger.error("ServiceNow API error",
                                      status=resp.status_code, body=resp.text[:300])
                return {
                    "status": "error",
                    "http_status": resp.status_code,
                    "error": resp.text[:300],
                }
    except Exception as e:
        activity.logger.error("ServiceNow integration error", error=str(e))
        return {"status": "error", "error": str(e)}
