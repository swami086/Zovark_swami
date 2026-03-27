"""Seed 5 default SOAR response playbooks for ZOVARC."""

import os
import json
import psycopg2

DB_URL = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@localhost:5432/zovarc")

PLAYBOOKS = [
    {
        "name": "Brute Force Response",
        "description": "Auto-respond to brute force attacks: block attacker IP, disable compromised user, create ticket.",
        "trigger_conditions": {"verdict": "true_positive", "risk_score_gte": 60},
        "actions": [
            {"type": "block_ip", "context": {"ip": "{{attacker_ip}}"}},
            {"type": "disable_user", "context": {"username": "{{target_user}}"}},
            {"type": "send_notification", "context": {"channel": "security", "message": "Brute force attack detected and contained"}},
            {"type": "create_ticket", "context": {"title": "Brute Force Attack Response", "priority": "high"}},
        ],
        "requires_approval": True,
    },
    {
        "name": "Ransomware Containment",
        "description": "Isolate endpoint, quarantine files, rotate credentials, notify SOC.",
        "trigger_conditions": {"verdict": "true_positive", "risk_score_gte": 80},
        "actions": [
            {"type": "isolate_endpoint", "context": {"hostname": "{{affected_host}}"}},
            {"type": "quarantine_file", "context": {"file_hash": "{{malware_hash}}"}},
            {"type": "rotate_credentials", "context": {"username": "{{affected_user}}"}},
            {"type": "send_notification", "context": {"channel": "security-critical", "message": "RANSOMWARE DETECTED — containment initiated"}},
            {"type": "create_ticket", "context": {"title": "Ransomware Incident", "priority": "critical"}},
        ],
        "requires_approval": True,
    },
    {
        "name": "C2 Beacon Response",
        "description": "Block C2 IP/domain, isolate beaconing endpoint, alert SOC.",
        "trigger_conditions": {"verdict": "true_positive", "risk_score_gte": 70},
        "actions": [
            {"type": "block_ip", "context": {"ip": "{{c2_ip}}"}},
            {"type": "isolate_endpoint", "context": {"hostname": "{{beaconing_host}}"}},
            {"type": "send_notification", "context": {"channel": "security", "message": "C2 beacon detected — endpoint isolated"}},
            {"type": "create_ticket", "context": {"title": "C2 Communication Detected", "priority": "high"}},
        ],
        "requires_approval": True,
    },
    {
        "name": "Lateral Movement Alert",
        "description": "Disable compromised account, notify SOC, create investigation ticket.",
        "trigger_conditions": {"verdict": "true_positive", "risk_score_gte": 60},
        "actions": [
            {"type": "disable_user", "context": {"username": "{{compromised_user}}"}},
            {"type": "send_notification", "context": {"channel": "security", "message": "Lateral movement detected — account disabled"}},
            {"type": "create_ticket", "context": {"title": "Lateral Movement Investigation", "priority": "high"}},
        ],
        "requires_approval": True,
    },
    {
        "name": "Phishing Auto-Response",
        "description": "Block sender domain, quarantine attachment, notify affected users.",
        "trigger_conditions": {"verdict": "suspicious", "risk_score_gte": 40},
        "actions": [
            {"type": "block_ip", "context": {"ip": "{{sender_ip}}"}},
            {"type": "quarantine_file", "context": {"file_hash": "{{attachment_hash}}"}},
            {"type": "send_notification", "context": {"channel": "security", "message": "Phishing campaign detected — sender blocked"}},
            {"type": "create_ticket", "context": {"title": "Phishing Campaign Response", "priority": "medium"}},
        ],
        "requires_approval": False,
    },
]


def seed():
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            # Get the default tenant
            cur.execute("SELECT id FROM tenants WHERE slug = 'zovarc-dev' LIMIT 1")
            row = cur.fetchone()
            if not row:
                print("ERROR: No tenant found with slug 'zovarc-dev'")
                return
            tenant_id = row[0]

            for pb in PLAYBOOKS:
                cur.execute("""
                    INSERT INTO response_playbooks (name, description, trigger_conditions, actions, requires_approval, tenant_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    RETURNING id
                """, (
                    pb["name"],
                    pb["description"],
                    json.dumps(pb["trigger_conditions"]),
                    json.dumps(pb["actions"]),
                    pb["requires_approval"],
                    str(tenant_id),
                ))
                result = cur.fetchone()
                if result:
                    print(f"  Seeded: {pb['name']} (id={result[0]})")
                else:
                    print(f"  Skipped (already exists): {pb['name']}")

        conn.commit()
        print(f"\nDone — {len(PLAYBOOKS)} playbooks seeded for tenant {tenant_id}")
    finally:
        conn.close()


if __name__ == "__main__":
    seed()
