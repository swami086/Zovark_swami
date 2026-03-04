import json, re, sys
from collections import defaultdict, Counter
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
MAX_FAILURES = {{max_failures}}
TIME_WINDOW = {{time_window}}
WATCH_IPS = {{watch_ips}}
HIGH_VALUE_ACCOUNTS = {{high_value_accounts}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = """
2026-03-01T10:00:01Z host sshd[123]: Failed password for invalid user admin from 192.168.1.100 port 22
2026-03-01T10:00:02Z host sshd[123]: Failed password for invalid user root from 192.168.1.100 port 22
2026-03-01T10:00:03Z host sshd[123]: Failed password for invalid user oracle from 192.168.1.100 port 22
2026-03-01T10:00:04Z host sshd[123]: Failed password for invalid user test from 192.168.1.100 port 22
2026-03-01T10:00:05Z host sshd[123]: Failed password for invalid user admin from 192.168.1.100 port 22
2026-03-01T10:00:06Z host sshd[123]: Failed password for invalid user root from 192.168.1.100 port 22
2026-03-01T10:00:07Z host sshd[123]: Failed password for invalid user postgres from 192.168.1.100 port 22
2026-03-01T10:00:08Z host sshd[123]: Failed password for invalid user admin from 192.168.1.100 port 22
2026-03-01T10:00:09Z host sshd[123]: Failed password for invalid user admin from 192.168.1.100 port 22
2026-03-01T10:00:10Z host sshd[123]: Failed password for invalid user admin from 192.168.1.100 port 22
2026-03-01T10:00:11Z host sshd[123]: Failed password for invalid user admin from 192.168.1.100 port 22
2026-03-01T10:00:20Z host sshd[124]: Accepted password for admin from 192.168.1.100 port 22
    """

# === DETECTION ENGINE ===
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_PATTERN = re.compile(r'(?:user|for) ([a-zA-Z0-9_-]+)')
FAIL_PATTERNS = ["Failed password", "4625", "authentication failure", "invalid credentials", "FAILED LOGIN", "logon failure"]
SUCCESS_PATTERNS = ["Accepted password", "4624", "session opened"]

failed_ips = defaultdict(list)
success_ips = defaultdict(list)
targeted_users = set()
high_value_targets_hit = set()

lines = LOG_DATA.strip().split('\n')
for line in lines:
    ip_match = IP_PATTERN.search(line)
    if not ip_match:
        continue
    ip = ip_match.group()
    
    user_match = USER_PATTERN.search(line)
    user = user_match.group(1) if user_match else "unknown"
    
    is_fail = any(p.lower() in line.lower() for p in FAIL_PATTERNS)
    is_success = any(p.lower() in line.lower() for p in SUCCESS_PATTERNS)
    
    if is_fail:
        failed_ips[ip].append(user)
        targeted_users.add(user)
        if user in HIGH_VALUE_ACCOUNTS:
            high_value_targets_hit.add(user)
    elif is_success:
        success_ips[ip].append(user)

brute_force_ips = []
cred_stuffing_ips = []
password_spray_users = defaultdict(set)
compromised_ips = []

for ip, users in failed_ips.items():
    if len(users) > MAX_FAILURES:
        brute_force_ips.append(ip)
    if len(set(users)) > 5:
        cred_stuffing_ips.append(ip)
    for u in users:
        password_spray_users[u].add(ip)
    if ip in success_ips:
        compromised_ips.append(ip)

findings = []
risk_score = 0
recommendations = []
iocs = {"ips": list(set(brute_force_ips + cred_stuffing_ips + compromised_ips)), "domains": [], "hashes": []}

if brute_force_ips:
    findings.append({"title": "Brute Force Attack Detected", "details": f"IPs exceeding failure threshold: {', '.join(brute_force_ips)}"})
    risk_score += 40
    recommendations.append("Block attacker IPs at the perimeter firewall.")
if cred_stuffing_ips:
    findings.append({"title": "Credential Stuffing Detected", "details": f"IPs attempting multiple distinct users: {', '.join(cred_stuffing_ips)}"})
    risk_score += 30
if compromised_ips:
    findings.append({"title": "Account Compromise Detected", "details": f"Successful login from IP after multiple failures: {', '.join(compromised_ips)}"})
    risk_score += 50
    recommendations.append("Immediately revoke active sessions and enforce password reset for affected accounts.")

if not findings:
    findings.append({"title": "No Brute Force Activity", "details": "No significant authentication failures detected within thresholds."})

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 60,
    "follow_up_prompt": "Please review the compromised accounts and provide isolation instructions if needed." if compromised_ips else ""
}
print(json.dumps(output, indent=2))
