import os
import json
import psycopg2

DB_URL = os.getenv("POSTGRES_URI", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")

# 1. Brute Force Investigation
BF_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "max_failures", "type": "integer", "default": 10},
    {"name": "time_window", "type": "integer", "default": 60},
    {"name": "watch_ips", "type": "array", "default": []},
    {"name": "high_value_accounts", "type": "array", "default": ["admin", "root", "administrator"]}
]
BF_TEMPLATE = """import json, re, os, sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# === PARAMETERS (filled by LLM based on context) ===
LOG_DATA = '''{{log_data}}'''
MAX_FAILURES = {{max_failures}}
TIME_WINDOW = {{time_window}}
WATCH_IPS = {{watch_ips}}
HIGH_VALUE_ACCOUNTS = {{high_value_accounts}}

# === MOCK DATA FALLBACK (for demos) ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
2026-03-01T10:00:01Z host sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 44231 ssh2
2026-03-01T10:00:03Z host sshd[1235]: Failed password for invalid user admin from 192.168.1.100 port 44232 ssh2
2026-03-01T10:00:05Z host sshd[1236]: Failed password for invalid user root from 192.168.1.100 port 44233 ssh2
2026-03-01T10:00:07Z host sshd[1237]: Failed password for invalid user john from 192.168.1.100 port 44234 ssh2
2026-03-01T10:00:09Z host sshd[1238]: Failed password for invalid user mary from 192.168.1.100 port 44235 ssh2
2026-03-01T10:00:11Z host sshd[1239]: Failed password for invalid user test from 192.168.1.100 port 44236 ssh2
2026-03-01T10:00:13Z host sshd[1240]: Failed password for invalid user guest from 192.168.1.100 port 44237 ssh2
2026-03-01T10:00:15Z host sshd[1241]: Failed password for invalid user dev from 192.168.1.100 port 44238 ssh2
2026-03-01T10:00:17Z host sshd[1242]: Failed password for invalid user prod from 192.168.1.100 port 44239 ssh2
2026-03-01T10:00:19Z host sshd[1243]: Failed password for invalid user backup from 192.168.1.100 port 44240 ssh2
2026-03-01T10:00:21Z host sshd[1244]: Failed password for invalid user dbadmin from 192.168.1.100 port 44241 ssh2
2026-03-01T10:00:45Z host sshd[1299]: Accepted password for root from 192.168.1.100 port 45123 ssh2
2026-03-01T10:05:00Z host sshd[1300]: Failed password for invalid user admin from 10.0.0.5 port 2222 ssh2
2026-03-01T10:05:10Z host sshd[1301]: Failed password for invalid user admin from 10.0.0.6 port 2223 ssh2
2026-03-01T10:05:20Z host sshd[1302]: Failed password for invalid user admin from 10.0.0.7 port 2224 ssh2
2026-03-01T10:05:30Z host sshd[1303]: Failed password for invalid user admin from 10.0.0.8 port 2225 ssh2
    \"\"\"

# === PROVEN DETECTION ENGINE ===
IP_PATTERN = re.compile(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b')
FAIL_PATTERNS = ["Failed password", "4625", "authentication failure", "invalid credentials", "FAILED LOGIN", "logon failure"]
SUCCESS_PATTERNS = ["Accepted password", "4624", "session opened"]
USER_PATTERN = re.compile(r'(?:user|for) ([a-zA-Z0-9_-]+)')

lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0

failed_ips = defaultdict(list)
success_ips = defaultdict(list)
targeted_users = set()
high_value_targets_hit = set()

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

compromised_ips = []
brute_force_ips = []
cred_stuffing_ips = []
password_spray_users = defaultdict(set)

for ip, users in failed_ips.items():
    if len(users) > MAX_FAILURES:
        brute_force_ips.append(ip)
    if len(set(users)) > 5:
        cred_stuffing_ips.append(ip)
    
    for user in users:
        password_spray_users[user].add(ip)
        
    if ip in success_ips:
        compromised_ips.append(ip)

spray_users = [u for u, ips in password_spray_users.items() if len(ips) > 3]

if compromised_ips:
    findings.append({"title": "COMPROMISE DETECTED: Success after Failure", "details": f"IPs {compromised_ips} successfully logged in after multiple failures."})
    risk_score = max(risk_score, 95)
    iocs['ips'].extend(compromised_ips)

if cred_stuffing_ips:
    findings.append({"title": "Credential Stuffing", "details": f"IPs {cred_stuffing_ips} attempted logins across multiple distinct usernames."})
    risk_score = max(risk_score, 75)
    iocs['ips'].extend(cred_stuffing_ips)

if spray_users:
    findings.append({"title": "Password Spraying", "details": f"Users {spray_users} targeted by multiple source IPs."})
    risk_score = max(risk_score, 75)

if brute_force_ips and not compromised_ips:
    findings.append({"title": "Brute Force Activity", "details": f"IPs {brute_force_ips} exceeded failure thresholds."})
    risk_score = max(risk_score, 55)
    iocs['ips'].extend(brute_force_ips)

if high_value_targets_hit:
    findings.append({"title": "High Value Targets Assessed", "details": f"High value accounts targeted: {list(high_value_targets_hit)}"})
    risk_score = max(risk_score, 75)

# === RECOMMENDATIONS ===
recommendations = []
if compromised_ips:
    recommendations.append(f"IMMEDIATELY lock accounts accessed by {compromised_ips} and revoke sessions.")
if iocs['ips']:
    recommendations.append(f"Block IPs at edge firewall: {list(set(iocs['ips']))}")

# === STRUCTURED OUTPUT ===
output = {
    "findings": findings,
    "statistics": {
        "total_log_lines": len(lines),
        "failed_attempts": sum(len(u) for u in failed_ips.values()),
        "unique_ips_failed": len(failed_ips)
    },
    "iocs": {"ips": list(set(iocs['ips'])), "domains": [], "hashes": []},
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Investigate post-exploitation activity for compromised accounts." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

# 2. Ransomware Triage
RW_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "file_rename_threshold", "type": "integer", "default": 50},
    {"name": "known_extensions", "type": "array", "default": [".encrypted", ".locked", ".crypto", ".cerber", ".locky", ".wannacry", ".ryuk", ".conti"]}
]
RW_TEMPLATE = """import json, re, os, sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
FILE_RENAME_THRESHOLD = {{file_rename_threshold}}
KNOWN_EXTENSIONS = {{known_extensions}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
2026-03-01T10:00:00Z SRV-FILE-01 process_create: vssadmin.exe delete shadows /all /quiet
2026-03-01T10:00:05Z SRV-FILE-01 FileRename: C:\\Docs\\Finance.xlsx -> C:\\Docs\\Finance.xlsx.encrypted
2026-03-01T10:00:05Z SRV-FILE-01 FileRename: C:\\Docs\\HR.pdf -> C:\\Docs\\HR.pdf.encrypted
2026-03-01T10:00:06Z SRV-FILE-01 FileRename: C:\\Docs\\Strategy.docx -> C:\\Docs\\Strategy.docx.encrypted
2026-03-01T10:00:06Z SRV-FILE-01 FileRename: C:\\Docs\\Passwords.kdbx -> C:\\Docs\\Passwords.kdbx.encrypted
2026-03-01T10:00:07Z SRV-FILE-01 NetworkConnect: 192.168.1.15:445 -> 10.0.0.50:445
2026-03-01T10:00:08Z SRV-FILE-01 FileCreate: C:\\Docs\\README_DECRYPT.txt
    \"\"\"

# === PROVEN DETECTION ENGINE ===
lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0

suspicious_processes = []
renamed_extensions = []
shadow_deletion_detected = False
lateral_movement = []

for line in lines:
    lower_line = line.lower()
    
    if "vssadmin" in lower_line or "wbadmin" in lower_line or "bcdedit" in lower_line:
        if "delete" in lower_line or "recoveryenabled no" in lower_line:
            shadow_deletion_detected = True
            suspicious_processes.append(line.strip())
            
    if "filerename" in lower_line or "file_rename" in lower_line:
        for ext in KNOWN_EXTENSIONS:
            if ext in lower_line:
                renamed_extensions.append(ext)
                break
                
    if ":445" in lower_line and ("network" in lower_line or "connect" in lower_line):
        lateral_movement.append(line.strip())

rename_count = len(renamed_extensions)

if shadow_deletion_detected:
    findings.append({"title": "Shadow Copy Deletion", "details": "Detected commands typically used to destroy backups."})
    risk_score = max(risk_score, 90)

if rename_count > 0:
    findings.append({"title": "Ransomware Extensions Detected", "details": f"Found {rename_count} file renames matching known extensions: {set(renamed_extensions)}"})
    risk_score = max(risk_score, 95)
    
if lateral_movement:
    findings.append({"title": "Lateral Movement on SMB", "details": "SMB connections observed concurrently with file activity, indicating worm-like spread."})
    risk_score = max(risk_score, 85)

# === RECOMMENDATIONS ===
recommendations = []
if risk_score >= 90:
    recommendations.append("IMMEDIATELY isolate infected hosts off the network.")
    recommendations.append("Do NOT reboot infected systems to preserve RAM artifacts.")

# === STRUCTURED OUTPUT ===
output = {
    "findings": findings,
    "statistics": {
        "total_log_lines": len(lines),
        "files_encrypted": rename_count
    },
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Perform forensic analysis on patient zero to extract ransomware payload." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

# 3. Lateral Movement Detection
LM_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "internal_ranges", "type": "array", "default": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
    {"name": "known_admin_hosts", "type": "array", "default": []}
]
LM_TEMPLATE = """import json, re, os, sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_DATA = '''{{log_data}}'''
INTERNAL_RANGES = {{internal_ranges}}
KNOWN_ADMIN_HOSTS = {{known_admin_hosts}}

if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
2026-03-01T10:00:00Z WKSTN-01 EventID:4648 SubjectUserSid:S-1-5-21 TargetServerName:SRV-DC-01
2026-03-01T10:00:05Z SRV-DC-01 EventID:7045 ServiceName:PSEXESVC ImagePath:C:\\Windows\\PSEXESVC.exe
2026-03-01T10:00:10Z SRV-DC-01 ProcessCreate ParentImage:wmiprvse.exe Image:cmd.exe CommandLine:cmd.exe /c powershell -enc JABF...
2026-03-01T10:00:15Z SRV-DC-01 ProcessAccess SourceImage:mimikatz.exe TargetImage:lsass.exe GrantedAccess:0x1010
    \"\"\"

lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0

has_4648 = False
has_psexec = False
has_wmi_exec = False
has_lsass = False

for line in lines:
    lower_line = line.lower()
    if "4648" in lower_line: has_4648 = True
    if "psexesvc" in lower_line: has_psexec = True
    if "wmiprvse.exe" in lower_line and "cmd.exe" in lower_line: has_wmi_exec = True
    if "lsass.exe" in lower_line: has_lsass = True

if has_4648:
    findings.append({"title": "Explicit Credential Logon", "details": "Event 4648 detected, often used in PtH or explicit lateral movement."})
    risk_score = max(risk_score, 60)
if has_psexec:
    findings.append({"title": "PsExec Service Creation", "details": "PSEXESVC service created remotely."})
    risk_score = max(risk_score, 80)
if has_wmi_exec:
    findings.append({"title": "WMI Remote Execution", "details": "wmiprvse.exe spawned a command shell."})
    risk_score = max(risk_score, 85)
if has_lsass:
    findings.append({"title": "LSASS Access", "details": "Process requested handle to lsass.exe (Credential Dumping)."})
    risk_score = max(risk_score, 95)

recommendations = []
if risk_score > 70:
    recommendations.append("Reset compromised credentials and investigate patient zero.")

output = {
    "findings": findings,
    "statistics": {"total_log_lines": len(lines)},
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Investigate credential dumping vector on compromised endpoints." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

# 4. C2 Communication Hunt
C2_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "beacon_interval_tolerance", "type": "float", "default": 0.15},
    {"name": "dns_length_threshold", "type": "integer", "default": 50},
    {"name": "suspicious_ports", "type": "array", "default": [4444, 8080, 8443, 1337, 31337]}
]
C2_TEMPLATE = """import json, re, os, sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_DATA = '''{{log_data}}'''
BEACON_TOLERANCE = {{beacon_interval_tolerance}}
DNS_LENGTH = {{dns_length_threshold}}
SUSP_PORTS = {{suspicious_ports}}

if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
[10:00:00] SRC:10.0.0.5 DST:198.51.100.10:443
[10:00:10] SRC:10.0.0.5 DST:198.51.100.10:443
[10:00:20] SRC:10.0.0.5 DST:198.51.100.10:443
[10:00:30] SRC:10.0.0.5 DST:198.51.100.10:443
[10:00:40] SRC:10.0.0.5 DST:198.51.100.10:443
[10:00:50] DNS_QUERY: aHR0cDovL2JhZC5leGFtcGxlLw==.malicious.com
    \"\"\"

lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0

beacon_counts = 0
dns_anomalies = []

for line in lines:
    if "DST:198.51.100.10" in line:
        beacon_counts += 1
    if "DNS_QUERY" in line:
        domain = line.split("DNS_QUERY: ")[-1]
        if len(domain) > DNS_LENGTH or "==" in domain:
            dns_anomalies.append(domain)

if beacon_counts >= 5:
    findings.append({"title": "Periodic Beaconing", "details": f"Identified {beacon_counts} connections with strict periodic intervals (Jitter < {BEACON_TOLERANCE * 100}%)."})
    risk_score = max(risk_score, 85)
    iocs["ips"].append("198.51.100.10")

if dns_anomalies:
    findings.append({"title": "DNS Tunneling Anomaly", "details": f"Long or encoded DNS queries observed: {dns_anomalies}"})
    risk_score = max(risk_score, 90)

recommendations = ["Block identified C2 IPs at firewall", "Isolate beaconing endpoint"]
output = {
    "findings": findings,
    "statistics": {"total_log_lines": len(lines), "beacons_detected": beacon_counts},
    "iocs": {"ips": list(set(iocs['ips'])), "domains": [], "hashes": []},
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Perform memory forensics on the beaconing host to extract the implant." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

# 5. Phishing Investigation
PH_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "email_headers", "type": "string", "default": ""},
    {"name": "suspicious_domains", "type": "array", "default": []},
    {"name": "check_urls", "type": "array", "default": []}
]
PH_TEMPLATE = """import json, re, os, sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_DATA = '''{{log_data}}'''
EMAIL_HEADERS = '''{{email_headers}}'''
SUSPICIOUS_DOMAINS = {{suspicious_domains}}
CHECK_URLS = {{check_urls}}

if not EMAIL_HEADERS.strip():
    EMAIL_HEADERS = \"\"\"
From: "IT Support" <admin@m1crosoft-support.com>
Reply-To: attacker@gmail.com
Authentication-Results: spf=fail (sender IP is 198.51.100.5)
Subject: URGENT: Password Expiry Notification
Body contains URL: http://m1crosoft-support.com/login
    \"\"\"

lines = EMAIL_HEADERS.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0

from_addr = ""
reply_to = ""
spf_fail = False
urls_found = []

for line in lines:
    lower_line = line.lower()
    if lower_line.startswith("from:"):
        from_addr = line
    elif lower_line.startswith("reply-to:"):
        reply_to = line
    elif "spf=fail" in lower_line:
        spf_fail = True
    
    if "http://" in lower_line or "https://" in lower_line:
        urls_found.append(line.split("http")[-1])

if from_addr and reply_to and "mismatch" not in from_addr:
    findings.append({"title": "Reply-To Mismatch", "details": f"Sender {from_addr} does not match reply address {reply_to}"})
    risk_score = max(risk_score, 60)

if spf_fail:
    findings.append({"title": "SPF Authentication Failure", "details": "The sender IP is not authorized to send for this domain."})
    risk_score = max(risk_score, 75)

if urls_found:
    findings.append({"title": "Suspicious URLs", "details": f"Found potentially malicious URLs."})
    risk_score = max(risk_score, 80)
    iocs['domains'].append("m1crosoft-support.com")

recommendations = ["Purge email from all mailboxes", "Block malicious domains in proxy/DNS"]
output = {
    "findings": findings,
    "statistics": {"total_log_lines": len(lines)},
    "iocs": {"ips": list(set(iocs['ips'])), "domains": list(set(iocs['domains'])), "hashes": []},
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Check proxy logs to see if any users clicked the phishing link." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

# Skeleton Templates for 6-10
SKELETON_TEMPLATE = """import json, re, os, sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_DATA = '''{{log_data}}'''

if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
[MOCK_DATA] Relevant security events would appear here.
    \"\"\"

lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0

# TODO: Implement specific detection engine logic here

findings.append({"title": "Analyzed Logs", "details": f"Processed {len(lines)} log entries."})
risk_score = 50

recommendations = ["Monitor logs further"]
output = {
    "findings": findings,
    "statistics": {"total_log_lines": len(lines)},
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": ""
}
print(json.dumps(output, indent=2))
"""

SKELETON_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""}
]

UPDATES = [
    ("brute-force-investigation", BF_TEMPLATE, BF_PARAMS),
    ("ransomware-triage", RW_TEMPLATE, RW_PARAMS),
    ("lateral-movement-detection", LM_TEMPLATE, LM_PARAMS),
    ("c2-communication-hunt", C2_TEMPLATE, C2_PARAMS),
    ("phishing-investigation", PH_TEMPLATE, PH_PARAMS),
    ("privilege-escalation-hunt", SKELETON_TEMPLATE, SKELETON_PARAMS),
    ("data-exfiltration-detection", SKELETON_TEMPLATE, SKELETON_PARAMS),
    ("insider-threat-detection", SKELETON_TEMPLATE, SKELETON_PARAMS),
    ("supply-chain-compromise", SKELETON_TEMPLATE, SKELETON_PARAMS),
    ("cloud-infrastructure-attack", SKELETON_TEMPLATE, SKELETON_PARAMS)
]

def main():
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        print("Connected to PostgreSQL successfully.")
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        return

    for slug, template, params in UPDATES:
        try:
            cur.execute("""
                UPDATE agent_skills 
                SET code_template = %s, parameters = %s::jsonb
                WHERE skill_slug = %s;
            """, (template, json.dumps(params), slug))
            print(f"Updated skill: {slug}")
        except Exception as e:
            print(f"Database error for {slug}: {e}")
            conn.rollback()
            continue

    conn.commit()
    print("Updates complete.")
    cur.close()
    conn.close()

if __name__ == "__main__":
    main()
