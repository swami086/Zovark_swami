#!/usr/bin/env python3
"""
Simulated SIEM webhook test — sends 3 alerts in different formats.
Run inside zovarc-worker container:
  docker exec zovarc-worker python /app/simulate_siem.py
"""
import json
import time
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
import os

API_BASE = "http://zovarc-api:8090/api/v1"
DB_URL = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")

def get_tenant_id():
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM tenants LIMIT 1")
            row = cur.fetchone()
            return str(row[0]) if row else None
    finally:
        conn.close()

def register_and_login(tenant_id):
    """Register a test user (or login if exists) and return JWT token."""
    client = httpx.Client(timeout=10)

    # Try register
    try:
        resp = client.post(f"{API_BASE}/auth/register", json={
            "email": "siem-test@testcorp.com",
            "password": "password123",
            "display_name": "SIEM Test",
            "tenant_id": tenant_id,
        })
    except Exception:
        pass

    # Login
    resp = client.post(f"{API_BASE}/auth/login", json={
        "email": "siem-test@testcorp.com",
        "password": "password123",
    })
    if resp.status_code != 200:
        # Try with admin
        resp = client.post(f"{API_BASE}/auth/login", json={
            "email": "admin@testcorp.com",
            "password": "password123",
        })
    data = resp.json()
    return data.get("token", ""), client

def main():
    print("=" * 60)
    print("ZOVARC SIEM WEBHOOK SIMULATION")
    print("=" * 60)

    tenant_id = get_tenant_id()
    if not tenant_id:
        print("ERROR: No tenant found in database.")
        return

    print(f"Tenant ID: {tenant_id}")

    token, client = register_and_login(tenant_id)
    if not token:
        print("ERROR: Failed to get JWT token.")
        return
    print(f"JWT token acquired.")

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Step 1: Create a log source with auto_investigate=true
    print("\n--- Step 1: Creating log source ---")
    resp = client.post(f"{API_BASE}/log-sources", headers=headers, json={
        "name": "Test Splunk Instance",
        "source_type": "splunk",
        "connection_config": {
            "auto_investigate": True,
            "default_task_type": "threat_hunt",
        },
    })
    if resp.status_code not in (200, 201):
        print(f"ERROR: Failed to create log source: {resp.text}")
        return

    source = resp.json()
    source_id = source["id"]
    webhook_url = f"http://zovarc-api:8090/api/v1/webhooks/{source_id}/alert"
    print(f"Log source created: {source_id}")
    print(f"Webhook URL: {webhook_url}")

    # Step 2: Send 3 simulated alerts
    alerts = [
        {
            "name": "Splunk - Brute Force",
            "payload": {
                "search_name": "Failed Login Alert",
                "result": {
                    "src_ip": "10.0.0.55",
                    "dest_ip": "192.168.1.100",
                    "event_count": 47,
                    "severity": "high",
                    "rule": "Multiple Failed Logins from Single IP"
                }
            }
        },
        {
            "name": "Elastic - Malware",
            "payload": {
                "rule": {
                    "id": "rule-001",
                    "name": "Suspicious Process Execution",
                    "severity": "critical"
                },
                "kibana": {
                    "alert": {
                        "original_event": {
                            "source_ip": "172.16.0.200",
                            "process_name": "mimikatz.exe"
                        }
                    }
                }
            }
        },
        {
            "name": "Generic - Data Exfil",
            "payload": {
                "alert_name": "Large Outbound Transfer Detected",
                "severity": "medium",
                "source_ip": "192.168.1.50",
                "dest_ip": "45.33.32.156",
                "bytes_transferred": 524288000,
                "destination_country": "RU"
            }
        }
    ]

    results = []
    for i, alert in enumerate(alerts, 1):
        print(f"\n--- Step 2.{i}: Sending {alert['name']} alert ---")
        resp = client.post(webhook_url, json=alert["payload"])
        print(f"  Status: {resp.status_code}")
        data = resp.json()
        print(f"  Alert ID: {data.get('alert_id')}")
        print(f"  Investigation ID: {data.get('investigation_id')}")
        results.append(data)
        time.sleep(2)

    # Step 3: Verify
    print("\n--- Step 3: Verification ---")
    print("Waiting 5 seconds for workflows to start...")
    time.sleep(5)

    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check siem_alerts
            cur.execute("SELECT COUNT(*) as cnt FROM siem_alerts WHERE log_source_id = %s", (source_id,))
            alert_count = cur.fetchone()["cnt"]
            print(f"\n  siem_alerts rows: {alert_count} (expected: 3)")

            # Check agent_tasks created
            cur.execute("""
                SELECT COUNT(*) as cnt FROM agent_tasks
                WHERE id IN (SELECT task_id FROM siem_alerts WHERE log_source_id = %s AND task_id IS NOT NULL)
            """, (source_id,))
            task_count = cur.fetchone()["cnt"]
            print(f"  auto-created investigations: {task_count} (expected: 3)")

            # Check log_source event_count
            cur.execute("SELECT event_count FROM log_sources WHERE id = %s", (source_id,))
            ev = cur.fetchone()["event_count"]
            print(f"  log_source event_count: {ev} (expected: 3)")

            # List the alerts
            cur.execute("SELECT alert_name, severity, source_ip, status, task_id FROM siem_alerts WHERE log_source_id = %s ORDER BY created_at", (source_id,))
            print("\n  Alerts detail:")
            for row in cur.fetchall():
                print(f"    {row['alert_name']} | severity={row['severity']} | src={row['source_ip']} | status={row['status']} | task={str(row['task_id'])[:8] if row['task_id'] else 'none'}...")

    finally:
        conn.close()

    # Summary
    print("\n" + "=" * 60)
    all_ok = alert_count == 3 and task_count == 3
    if all_ok:
        print("✅ ALL CHECKS PASSED")
    else:
        print("⚠️  SOME CHECKS FAILED")
    print("=" * 60)

if __name__ == "__main__":
    main()
