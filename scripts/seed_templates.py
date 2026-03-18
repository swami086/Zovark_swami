import json
import psycopg2
import os

DB_URL = os.getenv("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")

brute_force_template = """import json, re, sys
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
    LOG_DATA = \"\"\"
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
    \"\"\"

# === DETECTION ENGINE ===
IP_PATTERN = re.compile(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b')
USER_PATTERN = re.compile(r'(?:user|for) ([a-zA-Z0-9_-]+)')
FAIL_PATTERNS = ["Failed password", "4625", "authentication failure", "invalid credentials", "FAILED LOGIN", "logon failure"]
SUCCESS_PATTERNS = ["Accepted password", "4624", "session opened"]

failed_ips = defaultdict(list)
success_ips = defaultdict(list)
targeted_users = set()
high_value_targets_hit = set()

lines = LOG_DATA.strip().split('\\n')
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
"""

brute_force_params = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "max_failures", "type": "integer", "default": 10},
    {"name": "time_window", "type": "integer", "default": 60},
    {"name": "watch_ips", "type": "array", "default": []},
    {"name": "high_value_accounts", "type": "array", "default": ["admin","root","administrator"]}
]

ransomware_template = """import json, re, sys
from collections import defaultdict
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
FILE_RENAME_THRESHOLD = {{file_rename_threshold}}
KNOWN_EXTENSIONS = {{known_extensions}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
2026-03-01T11:00:00Z WARN File Activity: C:\\Users\\Admin\\Documents\\report.pdf renamed to C:\\Users\\Admin\\Documents\\report.pdf.encrypted
2026-03-01T11:00:01Z WARN File Activity: C:\\Users\\Admin\\Documents\\financials.xlsx renamed to C:\\Users\\Admin\\Documents\\financials.xlsx.encrypted
2026-03-01T11:00:02Z WARN File Activity: C:\\Users\\Admin\\Documents\\budget.docx renamed to C:\\Users\\Admin\\Documents\\budget.docx.encrypted
2026-03-01T11:00:03Z CRIT Process Execution: vssadmin.exe delete shadows /all /quiet
2026-03-01T11:00:05Z INFO Network Activity: High volume SMB transfer to 10.0.0.50
    \"\"\"

# === DETECTION ENGINE ===
lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": [], "filenames": []}
risk_score = 0
recommendations = []

rename_count = 0
shadow_copy_deleted = False
smb_activity = False

for line in lines:
    lower_line = line.lower()
    
    # Mass renames and known extensions
    if "renamed to" in lower_line:
        rename_count += 1
        for ext in KNOWN_EXTENSIONS:
            if ext.lower() in lower_line:
                iocs["filenames"].append(ext)
                
    # Shadow copy deletion
    if any(cmd in lower_line for cmd in ["vssadmin.exe delete shadows", "wbadmin delete", "bcdedit /set {default}"]):
        shadow_copy_deleted = True
        
    # SMB lateral movement indicator
    if "smb" in lower_line and "high volume" in lower_line:
        smb_activity = True

if rename_count > 0:
    findings.append({"title": "Mass File Renames", "details": f"Observed {rename_count} file rename events, potentially encryption."})
    if iocs["filenames"]:
        findings[-1]["details"] += f" Known ransomware extensions matched: {', '.join(set(iocs['filenames']))}."
        risk_score += 60

if shadow_copy_deleted:
    findings.append({"title": "Shadow Copy Deletion", "details": "Detected commands typically used by ransomware to prevent recovery (vssadmin/wbadmin/bcdedit)."})
    risk_score += 40
    
if smb_activity:
    findings.append({"title": "Anomalous SMB Activity", "details": "High volume SMB transfers detected, possible lateral movement or remote encryption."})
    risk_score += 20

if not findings:
    findings.append({"title": "No Ransomware Activity", "details": "No indicators of ransomware encryption or backup deletion found."})

if risk_score > 0:
    recommendations.extend([
        "Immediately isolate affected endpoints from the network.",
        "Preserve memory and disk artifacts for forensic analysis.",
        "Verify status of offline backups."
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 80,
    "follow_up_prompt": "Ransomware activity confirmed. Do you want to initiate network isolation procedures?" if risk_score >= 80 else ""
}
print(json.dumps(output, indent=2))
"""

ransomware_params = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "file_rename_threshold", "type": "integer", "default": 50},
    {"name": "known_extensions", "type": "array", "default": [".encrypted",".locked",".crypto",".cerber",".locky",".wannacry",".ryuk",".conti"]}
]

lateral_movement_template = """import json, re, sys
from collections import defaultdict
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
INTERNAL_RANGES = {{internal_ranges}}
KNOWN_ADMIN_HOSTS = {{known_admin_hosts}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
2026-03-01T12:00:00Z Security Event 4648: A logon was attempted using explicit credentials. Target: 10.0.0.100.
2026-03-01T12:05:00Z Service Control Manager: PSEXESVC service installed on 10.0.0.101.
2026-03-01T12:10:00Z Process Creation: wmiprvse.exe spawned cmd.exe with suspicious arguments.
2026-03-01T12:15:00Z Object Access: LSASS.exe accessed by an unknown process.
    \"\"\"

# === DETECTION ENGINE ===
lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": [], "filenames": []}
risk_score = 0
recommendations = []

event_4648 = False
psexec_svc = False
wmi_suspicious = False
lsass_access = False

for line in lines:
    lower_line = line.lower()
    if "4648" in lower_line and "explicit credentials" in lower_line:
        event_4648 = True
    if "psexesvc" in lower_line:
        psexec_svc = True
        iocs["filenames"].append("psexesvc.exe")
    if "wmiprvse.exe" in lower_line and "cmd.exe" in lower_line:
        wmi_suspicious = True
    if "lsass" in lower_line and "access" in lower_line:
        lsass_access = True

if event_4648:
    findings.append({"title": "Explicit Credential Use (Event 4648)", "details": "Detected logons using explicit credentials, often used in lateral movement via RunAs or network logins."})
    risk_score += 20
if psexec_svc:
    findings.append({"title": "PsExec Service Installation", "details": "Detected PSEXESVC service installation, indicating remote command execution."})
    risk_score += 40
if wmi_suspicious:
    findings.append({"title": "Suspicious WMI Execution", "details": "WMI Provider Host (wmiprvse.exe) spawned a command shell, indicating potential remote WMI execution."})
    risk_score += 40
if lsass_access:
    findings.append({"title": "LSASS Access", "details": "Detected access to LSASS memory, a strong indicator of credential dumping (e.g., Mimikatz) preparatory to lateral movement."})
    risk_score += 50

if not findings:
    findings.append({"title": "No Lateral Movement Activity", "details": "No clear indicators of lateral movement found."})

if risk_score > 0:
    recommendations.extend([
        "Investigate source and destination hosts involved in the alerts.",
        "Review corresponding authentication logs (Event 4624) for the target systems.",
        "Harden administrative access and restrict PsExec/WMI usage."
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 60,
    "follow_up_prompt": "Do you want to run a host isolation task on endpoints exhibiting lateral movement?" if risk_score >= 60 else ""
}
print(json.dumps(output, indent=2))
"""

lateral_movement_params = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "internal_ranges", "type": "array", "default": ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]},
    {"name": "known_admin_hosts", "type": "array", "default": []}
]

c2_hunt_template = """import json, re, sys
from collections import defaultdict
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
BEACON_INTERVAL_TOLERANCE = {{beacon_interval_tolerance}}
DNS_LENGTH_THRESHOLD = {{dns_length_threshold}}
SUSPICIOUS_PORTS = {{suspicious_ports}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
2026-03-01T13:00:00Z Firewall: Outbound connection from 10.0.0.5 to 198.51.100.10:4444
2026-03-01T13:00:00Z DNS: Query for ajsdhfkjashdfkjahsdkjfhaksdjfhaksdjf.evil.com
2026-03-01T13:05:00Z Proxy: HTTP GET http://evil.com/login/process.php interval=300s
2026-03-01T13:10:00Z Proxy: HTTP GET http://evil.com/login/process.php interval=300s
2026-03-01T13:15:00Z Proxy: HTTP GET http://evil.com/login/process.php interval=300s
    \"\"\"

# === DETECTION ENGINE ===
lines = LOG_DATA.strip().split('\\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0
recommendations = []

suspicious_port_hits = []
long_dns_queries = []
beacon_activity = False

dns_pattern = re.compile(r'query for ([\\w\\.-]+)')
ip_port_pattern = re.compile(r'to (\\d{1,3}(?:\\.\\d{1,3}){3}):(\\d+)')

intervals = []
for line in lines:
    lower_line = line.lower()
    
    port_match = ip_port_pattern.search(lower_line)
    if port_match:
        ip, port = port_match.groups()
        if int(port) in SUSPICIOUS_PORTS:
            suspicious_port_hits.append(f"{ip}:{port}")
            iocs["ips"].append(ip)

    dns_match = dns_pattern.search(lower_line)
    if dns_match:
        domain = dns_match.group(1)
        if len(domain.split('.')[0]) > DNS_LENGTH_THRESHOLD:
            long_dns_queries.append(domain)
            iocs["domains"].append(domain)
            
    if "interval=300s" in lower_line: # Mock naive beacon detection
        intervals.append(300)

if suspicious_port_hits:
    findings.append({"title": "Suspicious Port Usage", "details": f"Outbound connections to known malicious/suspicious ports: {', '.join(set(suspicious_port_hits))}"})
    risk_score += 40
if long_dns_queries:
    findings.append({"title": "Potential DNS Tunneling", "details": f"Unusually long DNS subdomains detected, indicating exfiltration or C2: {', '.join(long_dns_queries)}"})
    risk_score += 50
if len(intervals) >= 3:
    findings.append({"title": "Beaconing Activity", "details": "Detected repeated, highly periodic outbound requests indicative of C2 beaconing."})
    risk_score += 60

if not findings:
    findings.append({"title": "No C2 Indicators", "details": "No beaconing, suspicious ports, or DNS tunneling observed."})

if risk_score > 0:
    recommendations.extend([
        "Block identified C2 IP addresses and domains.",
        "Investigate the internal host establishing the connections for malware.",
        "Review proxy logs for data exfiltration payloads."
    ])

iocs["ips"] = list(set(iocs["ips"]))
iocs["domains"] = list(set(iocs["domains"]))
risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 50,
    "follow_up_prompt": "Review affected hosts. Shall I generate a firewall blocklist for the identified IOCs?" if risk_score >= 50 else ""
}
print(json.dumps(output, indent=2))
"""

c2_hunt_params = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "beacon_interval_tolerance", "type": "float", "default": 0.15},
    {"name": "dns_length_threshold", "type": "integer", "default": 50},
    {"name": "suspicious_ports", "type": "array", "default": [4444,8080,8443,1337,31337]}
]

phishing_template = """import json, re, sys
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
EMAIL_HEADERS = '''{{email_headers}}'''
SUSPICIOUS_DOMAINS = {{suspicious_domains}}
CHECK_URLS = {{check_urls}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip() and not EMAIL_HEADERS.strip():
    EMAIL_HEADERS = \"\"\"
From: "IT Support" <support@it-testcorp-update.com>
To: target@testcorp.com
Subject: URGENT: Password Expiry Notification
Authentication-Results: spf=fail (sender IP is 198.51.100.2); dkim=neutral; dmarc=fail
Reply-To: attacker@gmail.com
X-Attachment: invoice.docm
    \"\"\"

# === DETECTION ENGINE ===
findings = []
iocs = {"ips": [], "domains": [], "hashes": [], "urls": []}
risk_score = 0
recommendations = []

header_lower = EMAIL_HEADERS.lower()

spf_fail = "spf=fail" in header_lower or "spf=softfail" in header_lower
dmarc_fail = "dmarc=fail" in header_lower
reply_to_mismatch = "reply-to:" in header_lower and "attacker@" in header_lower # mock static check
macro_attachment = ".docm" in header_lower or ".xlsm" in header_lower

if spf_fail or dmarc_fail:
    findings.append({"title": "Email Authentication Failure", "details": "The email failed SPF or DMARC checks, highly likely to be spoofed."})
    risk_score += 40
if reply_to_mismatch:
    findings.append({"title": "Reply-To Mismatch", "details": "The Reply-To header differs significantly from the From address, indicating deception."})
    risk_score += 30
if macro_attachment:
    findings.append({"title": "Macro-Enabled Attachment", "details": "The email contains a macro-enabled office document, commonly used for malware delivery."})
    risk_score += 50
    iocs["filenames"] = ["invoice.docm"] # generic mock

if not findings:
    findings.append({"title": "No Clear Phishing Indicators", "details": "Email passes basic authentication checks and lacks obvious malicious attachments."})

if risk_score > 0:
    recommendations.extend([
        "Purge the email from user inboxes.",
        "Block the sender domain and IP.",
        "If clicked/opened, perform endpoint AV scan and reset user credentials."
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 50,
    "follow_up_prompt": "Malicious email identified. Do you want to search Exchange logs for other recipients?" if risk_score >= 50 else ""
}
print(json.dumps(output, indent=2))
"""

phishing_params = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "email_headers", "type": "string", "default": ""},
    {"name": "suspicious_domains", "type": "array", "default": []},
    {"name": "check_urls", "type": "array", "default": []}
]

# Skeleton templates for remaining 5
skeleton_template = """import json, sys

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = "Mock alert triggered."

# === DETECTION ENGINE ===
# TODO: Implement full detection
findings = [{"title": "Anomaly Detected", "details": "Behavioral anomaly threshold exceeded based on mock detection logic."}]
iocs = {"ips": ["198.51.100.99"], "domains": [], "hashes": []}
risk_score = 75
recommendations = ["Review logs", "Verify user authorization"]

output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": True,
    "follow_up_prompt": "Please review the identified anomalies."
}
print(json.dumps(output, indent=2))
"""

skeleton_params = [{"name": "log_data", "type": "string", "default": ""}]

UPDATES = [
    ("brute-force-investigation", brute_force_template, brute_force_params),
    ("ransomware-triage", ransomware_template, ransomware_params),
    ("lateral-movement-detection", lateral_movement_template, lateral_movement_params),
    ("c2-communication-hunt", c2_hunt_template, c2_hunt_params),
    ("phishing-investigation", phishing_template, phishing_params),
    ("privilege-escalation-hunt", skeleton_template, skeleton_params),
    ("data-exfiltration-detection", skeleton_template, skeleton_params),
    ("insider-threat-detection", skeleton_template, skeleton_params),
    ("supply-chain-compromise", skeleton_template, skeleton_params),
    ("cloud-infrastructure-attack", skeleton_template, skeleton_params),
    ("network-beaconing", None, None),  # loaded from worker/skills/network_beaconing.py
]

# Load network_beaconing template from skill file
try:
    import importlib.util
    _nb_path = os.path.join(os.path.dirname(__file__), "..", "worker", "skills", "network_beaconing.py")
    _nb_spec = importlib.util.spec_from_file_location("network_beaconing", _nb_path)
    _nb_mod = importlib.util.module_from_spec(_nb_spec)
    _nb_spec.loader.exec_module(_nb_mod)
    # Replace the None entry with actual template
    UPDATES[-1] = ("network-beaconing", _nb_mod.NETWORK_BEACONING_TEMPLATE, _nb_mod.NETWORK_BEACONING_PARAMS)
except Exception as _e:
    print(f"Warning: Could not load network_beaconing skill: {_e}")

# Load lateral_movement template from skill file
try:
    _lm_path = os.path.join(os.path.dirname(__file__), "..", "worker", "skills", "lateral_movement.py")
    _lm_spec = importlib.util.spec_from_file_location("lateral_movement", _lm_path)
    _lm_mod = importlib.util.module_from_spec(_lm_spec)
    _lm_spec.loader.exec_module(_lm_mod)
    # Replace the skeleton entry for lateral-movement-detection
    for _idx, (_slug, _tmpl, _params) in enumerate(UPDATES):
        if _slug == "lateral-movement-detection":
            UPDATES[_idx] = ("lateral-movement-detection", _lm_mod.LATERAL_MOVEMENT_TEMPLATE, _lm_mod.LATERAL_MOVEMENT_PARAMS)
            break
except Exception as _e:
    print(f"Warning: Could not load lateral_movement skill: {_e}")

# Load privilege_escalation template from skill file
try:
    _pe_path = os.path.join(os.path.dirname(__file__), "..", "worker", "skills", "privilege_escalation.py")
    _pe_spec = importlib.util.spec_from_file_location("privilege_escalation", _pe_path)
    _pe_mod = importlib.util.module_from_spec(_pe_spec)
    _pe_spec.loader.exec_module(_pe_mod)
    for _idx, (_slug, _tmpl, _params) in enumerate(UPDATES):
        if _slug == "privilege-escalation-hunt":
            UPDATES[_idx] = ("privilege-escalation-hunt", _pe_mod.PRIVILEGE_ESCALATION_TEMPLATE, _pe_mod.PRIVILEGE_ESCALATION_PARAMS)
            break
except Exception as _e:
    print(f"Warning: Could not load privilege_escalation skill: {_e}")

# Load data_exfiltration template from skill file
try:
    _de_path = os.path.join(os.path.dirname(__file__), "..", "worker", "skills", "data_exfiltration.py")
    _de_spec = importlib.util.spec_from_file_location("data_exfiltration", _de_path)
    _de_mod = importlib.util.module_from_spec(_de_spec)
    _de_spec.loader.exec_module(_de_mod)
    for _idx, (_slug, _tmpl, _params) in enumerate(UPDATES):
        if _slug == "data-exfiltration-detection":
            UPDATES[_idx] = ("data-exfiltration-detection", _de_mod.DATA_EXFILTRATION_TEMPLATE, _de_mod.DATA_EXFILTRATION_PARAMS)
            break
except Exception as _e:
    print(f"Warning: Could not load data_exfiltration skill: {_e}")

# Load insider_threat template from skill file
try:
    _it_path = os.path.join(os.path.dirname(__file__), "..", "worker", "skills", "insider_threat.py")
    _it_spec = importlib.util.spec_from_file_location("insider_threat", _it_path)
    _it_mod = importlib.util.module_from_spec(_it_spec)
    _it_spec.loader.exec_module(_it_mod)
    for _idx, (_slug, _tmpl, _params) in enumerate(UPDATES):
        if _slug == "insider-threat-detection":
            UPDATES[_idx] = ("insider-threat-detection", _it_mod.INSIDER_THREAT_TEMPLATE, _it_mod.INSIDER_THREAT_PARAMS)
            break
except Exception as _e:
    print(f"Warning: Could not load insider_threat skill: {_e}")

# Load supply_chain template from skill file
try:
    _sc_path = os.path.join(os.path.dirname(__file__), "..", "worker", "skills", "supply_chain.py")
    _sc_spec = importlib.util.spec_from_file_location("supply_chain", _sc_path)
    _sc_mod = importlib.util.module_from_spec(_sc_spec)
    _sc_spec.loader.exec_module(_sc_mod)
    for _idx, (_slug, _tmpl, _params) in enumerate(UPDATES):
        if _slug == "supply-chain-compromise":
            UPDATES[_idx] = ("supply-chain-compromise", _sc_mod.SUPPLY_CHAIN_TEMPLATE, _sc_mod.SUPPLY_CHAIN_PARAMS)
            break
except Exception as _e:
    print(f"Warning: Could not load supply_chain skill: {_e}")

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
            cur.execute("""
                UPDATE agent_skills 
                SET code_template = %s, parameters = %s::jsonb
                WHERE skill_slug = %s;
            """, (template, json.dumps(params), slug))
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
