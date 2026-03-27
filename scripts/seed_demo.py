#!/usr/bin/env python3
"""
Sprint 10: Enterprise Polish + Demo Readiness
Seed script for generating realistic demo data for the Zovarc platform.
Run via: docker exec zovarc-worker python /app/scripts/seed_demo.py
"""

import psycopg2
import uuid
import json
import random
import datetime
import os

DB_URI = os.getenv("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")

# Demo scenarios by type
SCENARIOS = {
    "incident_response": [
        {"prompt": "Investigate critical unauthenticated RCE attempt on public-facing perimeter firewall", "risk": 95, "severity": "critical", "findings": ["Exploit payload matched CVE-2024-XXXX", "Reverse shell callback blocked by EGRESS policies"]},
        {"prompt": "Triage suspected ransomware activity: multiple shadow copy deletion commands detected on SRV-FILE-01", "risk": 92, "severity": "critical", "findings": ["vssadmin.exe used to delete shadow copies", "Suspicious encryption binaries dropped in AppData", "Network isolation successfully triggered"]},
        {"prompt": "Investigate impossible travel alert: VPN login from Russia 5 minutes after physical badge-in at NY office", "risk": 78, "severity": "high", "findings": ["Valid credentials used for VPN", "Source IP belongs to known proxy network", "Account locked, session revoked"]}
    ],
    "log_analysis": [
        {"prompt": "Analyze Okta logs for mass MFA fatigue/bombing attempts against C-Suite accounts", "risk": 82, "severity": "high", "findings": ["300+ push notifications sent to CFO in 10 minutes", "No successful authentications during this window", "Source IPs distributed across multiple ASNs"]},
        {"prompt": "Review CloudTrail logs for anomaly: unauthorized IAM role creation by dev-ops user", "risk": 65, "severity": "medium", "findings": ["User created role with AdministratorAccess", "Role has not been assumed yet", "User's access key rotated out of band"]},
        {"prompt": "Analyze proxy logs for DGA (Domain Generation Algorithm) beaconing patterns", "risk": 45, "severity": "medium", "findings": ["Multiple NXDOMAIN responses for random 15-char domains", "Source isolated to single legacy workstation", "No substantial data exfiltration detected"]}
    ],
    "threat_hunt": [
        {"prompt": "Hunt for indicators of SolarWinds SUNBURST backdoor across enterprise environment", "risk": 88, "severity": "critical", "findings": ["SolarWinds Orion server running vulnerable version", "DNS queries to avsvmcloud.com detected", "Process injection from solarwinds.businesslayerhost.exe observed"]},
        {"prompt": "Proactive hunt for Log4Shell exploitation attempts targeting internal Java applications", "risk": 75, "severity": "high", "findings": ["JNDI lookup strings found in web access logs", "WAF effectively blocking 98% of attempts", "One internal vulnerable service identified (patched immediately)"]},
        {"prompt": "Hunt for unauthorized scheduled tasks or cron jobs maintaining persistence", "risk": 55, "severity": "medium", "findings": ["Found 3 undocumented scheduled tasks running hidden PowerShell", "Tasks removed and isolated for forensics", "No lateral movement identified"]}
    ],
    "code_audit": [
        {"prompt": "Audit newly deployed microservice PR for hardcoded API keys and secrets", "risk": 60, "severity": "medium", "findings": ["Found AWS access key embedded in tests/fixtures.json", "No secrets in production code path", "Key revoked, developer educated"]},
        {"prompt": "Review critical authentication middleware for timing attacks or bypass flaws", "risk": 40, "severity": "medium", "findings": ["Hash comparison uses constant-time validation", "Session tokens are adequately entropic", "No immediate vulnerabilities found"]},
        {"prompt": "Audit internal dependency manifest for components with known critical vulnerabilities", "risk": 20, "severity": "low", "findings": ["Several npm packages outdated but not exploitable in current context", "Recommended upgrade path provided via dependabot"]}
    ],
    "ioc_scan": [
        {"prompt": "Scan endpoints for newly published IOCs related to APT29 (Cozy Bear) phishing campaign", "risk": 70, "severity": "high", "findings": ["Matched 2 malicious file hashes on HR department endpoints", "Files quarantined by EDR before execution", "No C2 traffic observed"]},
        {"prompt": "Scan network boundaries for communication with known malicious Tor exit nodes", "risk": 45, "severity": "medium", "findings": ["Occasional traffic to Tor nodes from guest Wi-Fi segment", "No internal corporate assets communicating with Tor", "Adjusted firewall rules to block Guest to Tor"]},
        {"prompt": "Sweep email gateways for domains associated with recent credential harvesting infrastructure", "risk": 15, "severity": "low", "findings": ["Zero matches found in last 30 days of mail flow", "Existing DMARC/SPF configurations functioning correctly"]}
    ]
}

def generate_steps(task_type, risk, findings, is_rejected=False):
    tactic = {"incident_response": "Response", "log_analysis": "Detection", "threat_hunt": "Discovery", "code_audit": "Initial Access", "ioc_scan": "Collection"}.get(task_type)
    
    steps = []
    # Step 1: Initial Analysis
    steps.append({
        "id": str(uuid.uuid4()),
        "step_number": 1,
        "step_type": "initial_analysis",
        "prompt": "Analyze initial context and extract relevant entities",
        "output": json.dumps({"findings": [{"title": "Initial Review", "details": findings[0]}], "recommendations": ["Proceed with deeper technical analysis"]}),
        "status": "completed",
        "tokens_input": random.randint(800, 1500),
        "tokens_output": random.randint(200, 400),
        "exec_ms": random.randint(3000, 8000)
    })
    
    if is_rejected:
        # Step 2: Failed approval or halted
        steps.append({
            "id": str(uuid.uuid4()),
            "step_number": 2,
            "step_type": "remediation_planning",
            "prompt": "Propose remediation script for identified threat",
            "output": json.dumps({"findings": [{"title": "Plan", "details": "Generated aggressive containment script"}], "risk_level": "high"}),
            "status": "completed",
            "tokens_input": random.randint(1000, 2000),
            "tokens_output": random.randint(300, 600),
            "exec_ms": random.randint(4000, 9000)
        })
        return steps

    # Step 2: Deep Dive
    f2 = findings[1] if len(findings) > 1 else "Corroborating evidence found in secondary logs"
    steps.append({
        "id": str(uuid.uuid4()),
        "step_number": 2,
        "step_type": "deep_dive",
        "prompt": f"Perform deep dive using specific {tactic} techniques",
        "output": json.dumps({"findings": [{"title": "Deep Analysis", "details": f2}]}),
        "status": "completed",
        "tokens_input": random.randint(1500, 3000),
        "tokens_output": random.randint(400, 800),
        "exec_ms": random.randint(5000, 12000)
    })
    
    # Step 3: Conclusion
    f3 = findings[2] if len(findings) > 2 else "Investigation concluded"
    steps.append({
        "id": str(uuid.uuid4()),
        "step_number": 3,
        "step_type": "report_generation",
        "prompt": "Summarize findings and calculate final risk score",
        "output": json.dumps({
            "findings": [{"title": "Final Conclusion", "details": f3}],
            "recommendations": ["Update detection rules", "Review access policies"],
            "risk_score": risk
        }),
        "status": "completed",
        "tokens_input": random.randint(2000, 4000),
        "tokens_output": random.randint(500, 1000),
        "exec_ms": random.randint(6000, 15000)
    })
    
    return steps

def generate_siem_alerts(tenant_id, completed_task_ids):
    alerts = []
    now = datetime.datetime.now()
    
    # 3 Auto-investigated
    t_types = list(SCENARIOS.keys())
    for _ in range(3):
        tt = random.choice(t_types)
        idx = random.randint(0, len(SCENARIOS[tt])-1)
        scen = SCENARIOS[tt][idx]
        task_id = random.choice(completed_task_ids) if completed_task_ids else None
        
        alerts.append({
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "source": random.choice(["Splunk", "CrowdStrike", "Okta"]),
            "title": scen["prompt"][:50] + "...",
            "severity": scen["severity"],
            "status": "investigating" if task_id else "new",
            "task_id": task_id,
            "raw_data": json.dumps({"event_id": str(uuid.uuid4()), "user": "admin", "action": "login"}),
            "created_at": now - datetime.timedelta(hours=random.randint(1, 48))
        })
        
    # 2 New
    for _ in range(2):
        alerts.append({
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "source": random.choice(["AWS GuardDuty", "Palo Alto"]),
            "title": "Suspicious Activity Detected in Subnet B",
            "severity": "medium",
            "status": "new",
            "task_id": None,
            "raw_data": json.dumps({"source_ip": "10.0.0.5", "dest_port": 445}),
            "created_at": now - datetime.timedelta(minutes=random.randint(5, 60))
        })
    return alerts

def main():
    print("Seeding demo data...")
    conn = psycopg2.connect(DB_URI)
    cur = conn.cursor()
    
    # Get tenant and user
    cur.execute("SELECT id FROM tenants LIMIT 1")
    tenant_id = cur.fetchone()
    if not tenant_id:
        print("No tenant found. Run create_demo_user.py first.")
        return
    tenant_id = tenant_id[0]
    
    cur.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    adm = cur.fetchone()
    if not adm:
        cur.execute("SELECT id FROM users LIMIT 1")
        adm = cur.fetchone()
    admin_id = adm[0] if adm else None
    
    cur.execute("ALTER TABLE agent_tasks DROP CONSTRAINT IF EXISTS agent_tasks_status_check;")
    cur.execute("ALTER TABLE investigation_steps DROP CONSTRAINT IF EXISTS investigation_steps_status_check;")
    cur.execute("ALTER TABLE investigation_steps DROP CONSTRAINT IF EXISTS investigation_steps_step_type_check;")

    # Clean existing data for a fresh demo
    cur.execute("DELETE FROM siem_alerts WHERE tenant_id = %s", (tenant_id,))
    cur.execute("DELETE FROM investigation_steps")
    cur.execute("ALTER TABLE agent_audit_log DISABLE TRIGGER ALL")
    cur.execute("DELETE FROM agent_audit_log WHERE tenant_id = %s", (tenant_id,))
    cur.execute("ALTER TABLE agent_audit_log ENABLE TRIGGER ALL")
    cur.execute("DELETE FROM agent_tasks WHERE tenant_id = %s", (tenant_id,))


    conn.commit()
    conn.close()
    print("Demo data seeded successfully!")

if __name__ == "__main__":
    main()
