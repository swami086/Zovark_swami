import json, re, sys
from collections import defaultdict
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
INTERNAL_RANGES = {{internal_ranges}}
KNOWN_ADMIN_HOSTS = {{known_admin_hosts}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = """
2026-03-01T12:00:00Z Security Event 4648: A logon was attempted using explicit credentials. Target: 10.0.0.100.
2026-03-01T12:05:00Z Service Control Manager: PSEXESVC service installed on 10.0.0.101.
2026-03-01T12:10:00Z Process Creation: wmiprvse.exe spawned cmd.exe with suspicious arguments.
2026-03-01T12:15:00Z Object Access: LSASS.exe accessed by an unknown process.
    """

# === DETECTION ENGINE ===
lines = LOG_DATA.strip().split('\n')
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
