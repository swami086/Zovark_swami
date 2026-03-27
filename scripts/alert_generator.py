#!/usr/bin/env python3
"""
ZOVARC Alert Generator — continuous alert submission for demos.

Usage:
    python scripts/alert_generator.py                          # 2/min, unlimited
    python scripts/alert_generator.py --rate 1 --total 10      # 1/min, 10 alerts
    python scripts/alert_generator.py --severity-dist "critical:10,high:30,medium:40,low:20"
"""
import argparse
import json
import os
import random
import signal
import sys
import time
import urllib.request
from datetime import datetime

API_URL = os.environ.get("ZOVARC_API_URL", "http://localhost:8090")

# Randomization pools
SOURCE_IPS = [f"10.0.0.{i}" for i in range(10, 100)]
DEST_IPS = ["203.0.113.50", "185.220.101.42", "45.33.32.156", "198.51.100.23", "192.0.2.99",
            "91.234.99.1", "104.20.0.85", "172.217.14.206"]
HOSTNAMES = [f"WS-{dept}-{n:02d}" for dept in ["ANALYST", "FINANCE", "DEV", "HR", "EXEC", "IT"] for n in range(1, 6)]
USERNAMES = ["jsmith", "alice", "bob.jones", "m.chen", "s.patel", "k.williams", "j.garcia",
             "a.rodriguez", "t.wilson", "l.martinez", "r.taylor", "d.anderson"]


def login(api_url: str) -> str:
    email = os.environ.get("ZOVARC_TEST_EMAIL", "admin@test.local")
    password = os.environ.get("ZOVARC_TEST_PASSWORD", "TestPass2026")
    payload = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/auth/login", data=payload,
                                 headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())["token"]


def submit_alert(api_url: str, token: str, alert: dict) -> dict:
    payload = json.dumps({
        "task_type": alert["task_type"],
        "input": {
            "prompt": alert.get("prompt", f"Investigate {alert['task_type']}"),
            "severity": alert["severity"],
            "siem_event": alert["siem_event"],
        }
    }).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/tasks", data=payload,
                                 headers={"Authorization": f"Bearer {token}",
                                           "Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())


def randomize_alert(template: dict, severity: str = None) -> dict:
    """Create a randomized version of a template alert."""
    alert = json.loads(json.dumps(template))  # deep copy
    siem = alert["siem_event"]
    siem["source_ip"] = random.choice(SOURCE_IPS)
    siem["destination_ip"] = random.choice(DEST_IPS)
    siem["hostname"] = random.choice(HOSTNAMES)
    siem["username"] = random.choice(USERNAMES)
    if severity:
        alert["severity"] = severity
    # Randomize raw_log IPs
    if siem.get("raw_log"):
        siem["raw_log"] = siem["raw_log"].replace("10.0.0.99", siem["source_ip"])
    return alert


def pick_severity(dist: dict) -> str:
    """Pick severity based on distribution percentages."""
    r = random.randint(1, 100)
    cumulative = 0
    for sev, pct in dist.items():
        cumulative += pct
        if r <= cumulative:
            return sev
    return "medium"


def main():
    parser = argparse.ArgumentParser(description="ZOVARC Alert Generator")
    parser.add_argument("--rate", type=float, default=2, help="Alerts per minute (default: 2)")
    parser.add_argument("--total", type=int, default=0, help="Max alerts to generate (0=unlimited)")
    parser.add_argument("--api-url", default=API_URL, help="ZOVARC API URL")
    parser.add_argument("--severity-dist", default="critical:10,high:30,medium:40,low:20",
                        help="Severity distribution (e.g., 'critical:10,high:30,medium:40,low:20')")
    args = parser.parse_args()

    # Parse severity distribution
    sev_dist = {}
    for pair in args.severity_dist.split(","):
        k, v = pair.strip().split(":")
        sev_dist[k.strip()] = int(v.strip())

    # Load corpus
    corpus_path = os.path.join(os.path.dirname(__file__), "alert_corpus_100.json")
    if os.path.exists(corpus_path):
        with open(corpus_path) as f:
            templates = json.load(f)
    else:
        # Fallback: built-in templates
        templates = ALERT_TEMPLATES

    interval = 60.0 / args.rate if args.rate > 0 else 30
    generated = 0
    results = {"completed": 0, "running": 0, "pending": 0, "failed": 0, "error": 0}

    # Graceful shutdown
    running = True
    def handle_signal(sig, frame):
        nonlocal running
        running = False
        print("\n\nShutting down...")
    signal.signal(signal.SIGINT, handle_signal)

    print(f"ZOVARC Alert Generator")
    print(f"  API:      {args.api_url}")
    print(f"  Rate:     {args.rate}/min (interval: {interval:.1f}s)")
    print(f"  Total:    {'unlimited' if args.total == 0 else args.total}")
    print(f"  Severity: {args.severity_dist}")
    print()

    # Auth
    try:
        token = login(args.api_url)
        print("Authenticated successfully.\n")
    except Exception as e:
        print(f"Login failed: {e}")
        sys.exit(1)

    token_refresh_counter = 0

    while running:
        if args.total > 0 and generated >= args.total:
            break

        severity = pick_severity(sev_dist)
        template = random.choice(templates)
        alert = randomize_alert(template, severity)

        timestamp = datetime.now().strftime("%H:%M:%S")
        task_type = alert["task_type"]
        src = alert["siem_event"].get("source_ip", "?")
        dst = alert["siem_event"].get("destination_ip", "?")

        try:
            resp = submit_alert(args.api_url, token, alert)
            task_id = resp.get("task_id", "?")[:8]
            status = resp.get("status", "submitted")
            print(f"[{timestamp}] >> {task_type:30s} | {src} -> {dst} | {severity.upper():8s} | Task: {task_id}")
            generated += 1
            results[status] = results.get(status, 0) + 1
        except Exception as e:
            print(f"[{timestamp}] !! ERROR: {e}")
            results["error"] += 1

        # Refresh token every 10 alerts
        token_refresh_counter += 1
        if token_refresh_counter >= 10:
            try:
                token = login(args.api_url)
                token_refresh_counter = 0
            except Exception:
                pass

        if running and (args.total == 0 or generated < args.total):
            time.sleep(interval)

    # Summary
    elapsed = generated * interval / 60 if generated > 0 else 0
    print(f"\n{'='*60}")
    print(f"Generated {generated} alerts in ~{elapsed:.1f} minutes.")
    for k, v in results.items():
        if v > 0:
            print(f"  {k}: {v}")
    print(f"{'='*60}")


# Inline templates (used if corpus file not found)
ALERT_TEMPLATES = [
    {"task_type": "brute_force", "prompt": "Analyze SSH brute force attack", "severity": "high",
     "siem_event": {"title": "SSH Brute Force", "source_ip": "10.0.0.99", "destination_ip": "10.0.0.5",
                    "hostname": "WEB-SERVER-01", "username": "admin", "rule_name": "SSH_Brute_Force",
                    "raw_log": "Failed password for admin from 10.0.0.99 port 54321 ssh2"}},
    {"task_type": "phishing", "prompt": "Investigate phishing email", "severity": "high",
     "siem_event": {"title": "Phishing Email Detected", "source_ip": "10.0.0.42", "destination_ip": "203.0.113.50",
                    "hostname": "MAIL-SERVER", "username": "alice", "rule_name": "Phishing_URL",
                    "raw_log": "From: attacker@evil.com Subject: Urgent Invoice URL: http://phish.evil.com/steal"}},
    {"task_type": "c2_communication_hunt", "prompt": "Investigate C2 beacon", "severity": "high",
     "siem_event": {"title": "C2 Beacon Detected", "source_ip": "10.0.0.15", "destination_ip": "185.220.101.42",
                    "hostname": "WORKSTATION-07", "username": "jsmith", "rule_name": "C2_Beacon",
                    "raw_log": "DNS query: evil-c2.xyz HTTP POST http://185.220.101.42/beacon interval=60s"}},
    {"task_type": "lateral_movement", "prompt": "Investigate pass-the-hash", "severity": "critical",
     "siem_event": {"title": "Pass the Hash Detected", "source_ip": "10.0.0.50", "destination_ip": "10.0.0.200",
                    "hostname": "WS-FINANCE-03", "username": "svc_backup", "rule_name": "PtH_Detected",
                    "raw_log": "EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY User=svc_backup"}},
    {"task_type": "ransomware", "prompt": "Investigate ransomware activity", "severity": "critical",
     "siem_event": {"title": "Ransomware File Encryption", "source_ip": "10.0.0.75", "destination_ip": "10.0.0.100",
                    "hostname": "FILE-SERVER-01", "username": "bob.jones", "rule_name": "Ransomware_Detected",
                    "raw_log": "FileRename: documents.docx -> documents.docx.locked Process=cryptor.exe"}},
    {"task_type": "data_exfiltration", "prompt": "Investigate data exfiltration", "severity": "high",
     "siem_event": {"title": "Large Outbound Transfer", "source_ip": "10.0.0.30", "destination_ip": "203.0.113.99",
                    "hostname": "DB-SERVER-01", "username": "db_admin", "rule_name": "Data_Exfil",
                    "raw_log": "Outbound transfer: 10.0.0.30 -> 203.0.113.99 size=4.2GB protocol=HTTPS"}},
    {"task_type": "privilege_escalation", "prompt": "Investigate privilege escalation", "severity": "critical",
     "siem_event": {"title": "Privilege Escalation Detected", "source_ip": "10.0.0.22", "destination_ip": "10.0.0.1",
                    "hostname": "WORKSTATION-12", "username": "temp_user", "rule_name": "PrivEsc_Detected",
                    "raw_log": "EventID=4672 PrivilegesAssigned=SeDebugPrivilege User=temp_user Process=psexec.exe"}},
    {"task_type": "insider_threat", "prompt": "Investigate insider threat", "severity": "medium",
     "siem_event": {"title": "Unusual After-Hours Access", "source_ip": "10.0.0.88", "destination_ip": "10.0.0.200",
                    "hostname": "WS-HR-02", "username": "j.garcia", "rule_name": "After_Hours_Access",
                    "raw_log": "Login at 03:42 UTC User=j.garcia AccessedFiles=employee_compensation.xlsx,org_chart.pdf"}},
    {"task_type": "network_beaconing", "prompt": "Investigate network beaconing", "severity": "medium",
     "siem_event": {"title": "Periodic DNS Beaconing", "source_ip": "10.0.0.33", "destination_ip": "91.234.99.1",
                    "hostname": "WS-DEV-04", "username": "m.chen", "rule_name": "DNS_Beacon",
                    "raw_log": "DNS query: update.suspic.io interval=120s consistent_size=64bytes count=47"}},
    {"task_type": "supply_chain_compromise", "prompt": "Investigate supply chain compromise", "severity": "critical",
     "siem_event": {"title": "Suspicious Package Update", "source_ip": "10.0.0.60", "destination_ip": "104.20.0.85",
                    "hostname": "BUILD-SERVER-01", "username": "ci_runner", "rule_name": "Supply_Chain",
                    "raw_log": "npm install: lodash-utils@2.0.1 (unpublished 10min ago, re-published with new maintainer)"}},
    {"task_type": "cloud_infrastructure", "prompt": "Investigate cloud misconfig", "severity": "high",
     "siem_event": {"title": "S3 Bucket Public Access", "source_ip": "10.0.0.45", "destination_ip": "52.219.128.1",
                    "hostname": "CLOUD-ADMIN", "username": "devops_lead", "rule_name": "Cloud_Misconfig",
                    "raw_log": "PutBucketPolicy: Bucket=prod-customer-data Principal=* Action=s3:GetObject"}},
    {"task_type": "brute_force", "prompt": "Investigate RDP brute force", "severity": "high",
     "siem_event": {"title": "RDP Brute Force", "source_ip": "10.0.0.77", "destination_ip": "10.0.0.10",
                    "hostname": "TERMINAL-SRV-01", "username": "admin", "rule_name": "RDP_Brute_Force",
                    "raw_log": "EventID=4625 LogonType=10 Status=0xC000006D Count=47 Source=10.0.0.77"}},
    {"task_type": "phishing", "prompt": "Investigate credential harvesting", "severity": "high",
     "siem_event": {"title": "Credential Harvesting Page", "source_ip": "10.0.0.55", "destination_ip": "45.33.32.156",
                    "hostname": "WS-EXEC-01", "username": "cfo", "rule_name": "Phishing_Cred_Harvest",
                    "raw_log": "POST https://m1cros0ft-365.com/login?redirect=outlook.office.com User-Agent: Chrome/120"}},
    {"task_type": "data_exfiltration", "prompt": "Investigate DNS tunneling", "severity": "high",
     "siem_event": {"title": "DNS Tunneling Detected", "source_ip": "10.0.0.19", "destination_ip": "198.51.100.23",
                    "hostname": "WS-DEV-08", "username": "s.patel", "rule_name": "DNS_Tunnel",
                    "raw_log": "DNS TXT queries: avg_len=180bytes domain=t.exfil.net count=2400/hour"}},
    {"task_type": "lateral_movement", "prompt": "Investigate WMI lateral movement", "severity": "high",
     "siem_event": {"title": "WMI Remote Execution", "source_ip": "10.0.0.40", "destination_ip": "10.0.0.201",
                    "hostname": "WS-IT-03", "username": "admin_svc", "rule_name": "WMI_Lateral",
                    "raw_log": "WMI Process Create: Target=10.0.0.201 User=admin_svc Cmd=powershell -enc aWVYIChO"}},
    {"task_type": "ransomware", "prompt": "Investigate ransomware indicator", "severity": "critical",
     "siem_event": {"title": "Shadow Copy Deletion", "source_ip": "10.0.0.82", "destination_ip": "10.0.0.82",
                    "hostname": "FILE-SERVER-02", "username": "SYSTEM", "rule_name": "Shadow_Copy_Del",
                    "raw_log": "vssadmin.exe Delete Shadows /All /Quiet followed by bcdedit /set recoveryenabled No"}},
    {"task_type": "privilege_escalation", "prompt": "Investigate kernel exploit", "severity": "critical",
     "siem_event": {"title": "Kernel Exploit Attempt", "source_ip": "10.0.0.91", "destination_ip": "10.0.0.1",
                    "hostname": "WS-DEV-12", "username": "intern_dev", "rule_name": "Kernel_Exploit",
                    "raw_log": "EventID=4688 Process=exploit.exe ParentProcess=cmd.exe Elevation=True NewProcessSID=S-1-5-18"}},
    {"task_type": "c2_communication_hunt", "prompt": "Investigate encrypted C2", "severity": "high",
     "siem_event": {"title": "Encrypted C2 Traffic", "source_ip": "10.0.0.28", "destination_ip": "192.0.2.99",
                    "hostname": "WS-ANALYST-02", "username": "k.williams", "rule_name": "Encrypted_C2",
                    "raw_log": "TLS SNI=cdn-static.com JA3=a0e9f5d64349fb13 entropy=7.9 bytes_out=512 interval=30s"}},
    {"task_type": "insider_threat", "prompt": "Investigate mass download", "severity": "medium",
     "siem_event": {"title": "Mass File Download", "source_ip": "10.0.0.66", "destination_ip": "10.0.0.200",
                    "hostname": "WS-HR-05", "username": "l.martinez", "rule_name": "Mass_Download",
                    "raw_log": "SharePoint download: 847 files in 12 minutes User=l.martinez Location=HR-Confidential"}},
    {"task_type": "network_beaconing", "prompt": "Investigate HTTP beaconing", "severity": "medium",
     "siem_event": {"title": "HTTP Beacon Pattern", "source_ip": "10.0.0.44", "destination_ip": "91.234.99.1",
                    "hostname": "WS-FINANCE-01", "username": "r.taylor", "rule_name": "HTTP_Beacon",
                    "raw_log": "POST http://91.234.99.1/api/check interval=60s±5s size=256b UA=curl/7.88.1"}},
]


if __name__ == "__main__":
    main()
