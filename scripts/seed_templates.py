"""Seed agent_skills code_template + parameters from investigation_plans.json (V3 runner).

Every seeded template delegates to tools.runner.execute_plan with embedded plan steps.
No custom regex/mock detection blocks — single source of truth with investigation_plans.json.
"""
import json
import os
import psycopg2

DB_URL = os.getenv("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")

_V3_RUNNER_TEMPLATE = """import json, sys

SIEM_EVENT_JSON = '''{{siem_event_json}}'''
LOG_DATA = '''{{log_data}}'''

try:
    siem_event = json.loads(SIEM_EVENT_JSON)
except (json.JSONDecodeError, TypeError):
    siem_event = {"raw_log": LOG_DATA}
if not siem_event.get("raw_log"):
    siem_event["raw_log"] = LOG_DATA or ""

from tools.runner import execute_plan

PLAN = __PLAN_PLACEHOLDER__

result = execute_plan(PLAN, siem_event)

output = {
    "findings": result.get("findings", []),
    "iocs": result.get("iocs", []),
    "recommendations": [],
    "risk_score": result.get("risk_score", 0),
    "verdict": result.get("verdict", "needs_review"),
    "tools_executed": result.get("tools_executed", 0),
    "follow_up_needed": result.get("risk_score", 0) >= 50,
    "follow_up_prompt": "Review investigation results." if result.get("risk_score", 0) >= 50 else "",
}
print(json.dumps(output, indent=2))
"""

_plans_path = os.path.join(os.path.dirname(__file__), "..", "worker", "tools", "investigation_plans.json")
try:
    with open(_plans_path) as _f:
        _ALL_PLANS = json.load(_f)
except Exception:
    _ALL_PLANS = {}


def _make_v3_template(plan_key: str) -> str:
    plan_data = _ALL_PLANS.get(plan_key, {})
    plan_steps = plan_data.get("plan", [])
    return _V3_RUNNER_TEMPLATE.replace("__PLAN_PLACEHOLDER__", json.dumps(plan_steps))


# agent_skills.skill_slug → investigation_plans.json top-level key
SKILL_SLUG_TO_PLAN_KEY = {
    "brute-force-investigation": "brute_force",
    "ransomware-triage": "ransomware_triage",
    "lateral-movement-detection": "lateral_movement_detection",
    "c2-communication-hunt": "c2_communication_hunt",
    "phishing-investigation": "phishing_investigation",
    "privilege-escalation-hunt": "privilege_escalation_hunt",
    "data-exfiltration-detection": "data_exfiltration_detection",
    "insider-threat-detection": "insider_threat_detection",
    "supply-chain-compromise": "supply_chain_compromise",
    "cloud-infrastructure-attack": "cloud_infrastructure_attack",
    "network-beaconing": "network_beaconing",
}

skeleton_params = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "siem_event_json", "type": "string", "default": "{}"},
]

UPDATES = [
    (slug, _make_v3_template(plan_key), skeleton_params)
    for slug, plan_key in SKILL_SLUG_TO_PLAN_KEY.items()
]


def main():
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        print("Connected to PostgreSQL successfully.")
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    for slug, template, params in UPDATES:
        try:
            cur.execute(
                """
                UPDATE agent_skills
                SET code_template = %s, parameters = %s::jsonb
                WHERE skill_slug = %s;
                """,
                (template, json.dumps(params), slug),
            )
            print(f"Updated skill: {slug}")
        except Exception as e:
            print(f"Error updating {slug}: {e}")
            conn.rollback()
            continue

    conn.commit()
    print("All template updates completed.")
    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
