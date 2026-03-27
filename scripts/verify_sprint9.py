#!/usr/bin/env python3
"""Sprint 9 verification: search, filters, pagination, stats."""
import json, httpx, sys

API = "http://zovarc-api:8090"

# Login
r = httpx.post(f"{API}/api/v1/auth/login", json={"email": "siem-test@testcorp.com", "password": "test1234"})
if r.status_code != 200:
    # Try register
    import psycopg2
    conn = psycopg2.connect("postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
    cur = conn.cursor()
    cur.execute("SELECT id FROM tenants LIMIT 1")
    tid = str(cur.fetchone()[0])
    conn.close()
    r2 = httpx.post(f"{API}/api/v1/auth/register", json={"email": "test9@testcorp.com", "password": "test1234", "display_name": "Tester", "tenant_id": tid})
    if r2.status_code not in (200, 201):
        print(f"Register failed: {r2.text}")
    # Set admin role
    conn = psycopg2.connect("postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
    cur = conn.cursor()
    cur.execute("UPDATE users SET role='admin' WHERE email='test9@testcorp.com'")
    conn.commit()
    conn.close()
    r = httpx.post(f"{API}/api/v1/auth/login", json={"email": "test9@testcorp.com", "password": "test1234"})

token = r.json()["token"]
headers = {"Authorization": f"Bearer {token}"}
print(f"Logged in. Token: {token[:20]}...")

print("\n--- Test 1: List tasks (page=1, limit=2) ---")
r = httpx.get(f"{API}/api/v1/tasks?page=1&limit=2", headers=headers)
d = r.json()
print(f"  Status: {r.status_code}")
print(f"  Total: {d.get('total')}, Page: {d.get('page')}, Pages: {d.get('pages')}")
print(f"  Tasks returned: {len(d.get('tasks', []))}")
for t in d.get("tasks", []):
    print(f"    {t['id'][:8]}... | {t.get('task_type')} | {t.get('status')} | prompt: {(t.get('prompt') or '-')[:50]}")

print("\n--- Test 2: Search for 'brute' ---")
r = httpx.get(f"{API}/api/v1/tasks?search=brute", headers=headers)
d = r.json()
print(f"  Total matching: {d.get('total')}")
for t in d.get("tasks", []):
    print(f"    {t['id'][:8]}... | {(t.get('prompt') or '')[:60]}")

print("\n--- Test 3: Filter by status=pending ---")
r = httpx.get(f"{API}/api/v1/tasks?status=pending", headers=headers)
d = r.json()
print(f"  Total pending: {d.get('total')}")

print("\n--- Test 4: Sort by status asc ---")
r = httpx.get(f"{API}/api/v1/tasks?sort=status&order=asc", headers=headers)
d = r.json()
for t in d.get("tasks", []):
    print(f"    {t['id'][:8]}... | {t.get('status')}")

print("\n--- Test 5: Enhanced stats ---")
r = httpx.get(f"{API}/api/v1/stats", headers=headers)
d = r.json()
print(f"  Total tasks: {d.get('total_tasks')}")
print(f"  Completed: {d.get('completed')}, Failed: {d.get('failed')}, Pending: {d.get('pending')}, Executing: {d.get('executing')}")
print(f"  SIEM alerts: total={d.get('siem_alerts_total')}, new={d.get('siem_alerts_new')}, investigating={d.get('siem_alerts_investigating')}")
print(f"  Type distribution: {d.get('type_distribution')}")
print(f"  Recent activity: {len(d.get('recent_activity', []))} items")

print("\n--- Test 6: Health endpoint ---")
r = httpx.get(f"{API}/health")
d = r.json()
print(f"  Mode: {d.get('mode')}, LLM: {d.get('llm_model')}, DB: {d['services'].get('db')}")

print("\n============================================================")
print("✅ ALL VERIFICATION TESTS COMPLETE")
print("============================================================")
