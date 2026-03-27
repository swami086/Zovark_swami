"""Alert correlation engine — activities (Issue #53).

Groups related alerts by IP, user, timewindow (5 min), and MITRE technique.
Creates merged incidents from correlated alert groups.
"""

import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
    return psycopg2.connect(db_url)


# Correlation window in minutes
CORRELATION_WINDOW_MINUTES = 5


@activity.defn
async def correlate_alerts(data: dict) -> dict:
    """Group related alerts by IP, user, timewindow, and MITRE technique.

    Input: {tenant_id, lookback_minutes: 30}
    Returns: {
        correlation_groups: [{rule, key, alert_ids, severity, title}],
        total_alerts_processed: int,
        groups_found: int,
    }
    """
    tenant_id = data.get("tenant_id")
    lookback_minutes = data.get("lookback_minutes", 30)

    if not tenant_id:
        return {"correlation_groups": [], "total_alerts_processed": 0, "groups_found": 0}

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Fetch recent alerts that are not yet part of an incident
            cur.execute("""
                SELECT id::text, tenant_id::text, alert_type,
                       raw_sample, created_at
                FROM alert_fingerprints
                WHERE tenant_id = %s
                  AND created_at > NOW() - make_interval(mins => %s)
                ORDER BY created_at
            """, (tenant_id, lookback_minutes))
            alerts = [dict(r) for r in cur.fetchall()]

        if not alerts:
            return {"correlation_groups": [], "total_alerts_processed": 0, "groups_found": 0}

        groups = []

        # Rule 1: Same source IP within correlation window
        ip_groups = _group_by_field(alerts, "source_ip", CORRELATION_WINDOW_MINUTES)
        for key, alert_ids in ip_groups.items():
            if len(alert_ids) >= 2:
                groups.append({
                    "rule": "same_source_ip",
                    "key": key,
                    "alert_ids": alert_ids,
                    "severity": _escalate_severity(len(alert_ids)),
                    "title": f"Correlated alerts from source IP {key}",
                })

        # Rule 2: Same target user within correlation window
        user_groups = _group_by_field(alerts, "target_user", CORRELATION_WINDOW_MINUTES)
        for key, alert_ids in user_groups.items():
            if len(alert_ids) >= 2:
                groups.append({
                    "rule": "same_target_user",
                    "key": key,
                    "alert_ids": alert_ids,
                    "severity": _escalate_severity(len(alert_ids)),
                    "title": f"Correlated alerts targeting user {key}",
                })

        # Rule 3: Same MITRE technique within correlation window
        technique_groups = _group_by_field(alerts, "mitre_technique", CORRELATION_WINDOW_MINUTES)
        for key, alert_ids in technique_groups.items():
            if len(alert_ids) >= 2:
                groups.append({
                    "rule": "same_mitre_technique",
                    "key": key,
                    "alert_ids": alert_ids,
                    "severity": _escalate_severity(len(alert_ids)),
                    "title": f"Correlated alerts using technique {key}",
                })

        return {
            "correlation_groups": groups,
            "total_alerts_processed": len(alerts),
            "groups_found": len(groups),
        }

    finally:
        conn.close()


def _group_by_field(alerts, field_name, window_minutes):
    """Group alerts by a field extracted from raw_sample within time window.

    Returns: {field_value: [alert_id, ...]}
    """
    field_map = {}  # field_value -> [(alert_id, created_at)]

    for alert in alerts:
        raw = alert.get("raw_sample")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        if not isinstance(raw, dict):
            raw = {}

        value = raw.get(field_name, "")
        if not value:
            continue

        created_at = alert.get("created_at")
        alert_id = alert.get("id")
        if value not in field_map:
            field_map[value] = []
        field_map[value].append((alert_id, created_at))

    # Filter groups within time window
    result = {}
    for value, entries in field_map.items():
        if len(entries) < 2:
            continue

        entries.sort(key=lambda x: x[1])
        # Check if first and last are within window
        first_time = entries[0][1]
        last_time = entries[-1][1]

        if hasattr(first_time, 'timestamp') and hasattr(last_time, 'timestamp'):
            diff_minutes = (last_time - first_time).total_seconds() / 60
            if diff_minutes <= window_minutes:
                result[value] = [e[0] for e in entries]
        else:
            # If timestamps aren't datetime objects, include all
            result[value] = [e[0] for e in entries]

    return result


def _escalate_severity(alert_count):
    """Escalate severity based on number of correlated alerts."""
    if alert_count >= 10:
        return "critical"
    elif alert_count >= 5:
        return "high"
    elif alert_count >= 3:
        return "medium"
    return "low"


@activity.defn
async def create_incident(data: dict) -> dict:
    """Create an incident from correlated alerts.

    Input: {
        tenant_id, title, severity, alert_ids: [],
        correlation_rule, mitre_techniques: [], source_ips: [], target_users: []
    }
    Returns: {incident_id, title, severity, alert_count}
    """
    tenant_id = data.get("tenant_id")
    title = data.get("title", "Correlated incident")
    severity = data.get("severity", "medium")
    alert_ids = data.get("alert_ids", [])
    correlation_rule = data.get("correlation_rule", "")
    mitre_techniques = data.get("mitre_techniques", [])
    source_ips = data.get("source_ips", [])
    target_users = data.get("target_users", [])

    if not tenant_id or not alert_ids:
        return {"incident_id": None, "error": "Missing tenant_id or alert_ids"}

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO incidents
                (tenant_id, title, severity, alert_ids, alert_count,
                 correlation_rule, mitre_techniques, source_ips, target_users)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id::text
            """, (
                tenant_id,
                title[:500],
                severity,
                alert_ids,
                len(alert_ids),
                correlation_rule,
                mitre_techniques,
                source_ips,
                target_users,
            ))
            row = cur.fetchone()
            incident_id = row[0] if row else None
        conn.commit()

        return {
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "alert_count": len(alert_ids),
        }
    finally:
        conn.close()
