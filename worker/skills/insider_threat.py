"""
Insider Threat Skill — Off-hours access, bulk file download, USB, email forwarding.

Analyzes endpoint/identity logs for:
  - Off-hours logins (22:00-06:00)
  - Bulk file access/download patterns
  - USB/removable media events
  - Print jobs for sensitive documents
  - Email forwarding rules to external addresses
  - Access to out-of-role directories

Skill slug: insider-threat-detection
MITRE: T1074 (Data Staged), T1052 (Exfil Over Physical Medium),
       T1114 (Email Collection), T1078 (Valid Accounts)
"""

INSIDER_THREAT_TEMPLATE = """import json, re
from collections import defaultdict

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
WATCH_ACCOUNTS = {{watch_accounts}}
SENSITIVE_DIRS = {{sensitive_dirs}}
OFF_HOURS_START = {{off_hours_start}}
OFF_HOURS_END = {{off_hours_end}}

# === IOC EXTRACTION ===
IP_PATTERN = re.compile(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b')
USER_PAT = re.compile(r'(?:User|user|username|SubjectUser)[:= ]+([a-zA-Z0-9_.\\\\-]+)')
HOST_PAT = re.compile(r'(?:Host|Hostname|Computer)[:= ]+([a-zA-Z0-9_.-]+)')
EMAIL_PAT = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}')
PATH_PAT = re.compile(r'[A-Z]:\\\\(?:[\\w .-]+\\\\)*[\\w .-]+')
TIME_PAT = re.compile(r'(\\d{2}:\\d{2}(?::\\d{2})?)')

def extract_iocs(text):
    iocs = []
    seen = set()
    def add(t, v, c="medium"):
        k = (t, v.lower())
        if k not in seen:
            seen.add(k)
            iocs.append({"type": t, "value": v, "confidence": c})
    for m in IP_PATTERN.finditer(text): add("ipv4", m.group())
    for m in USER_PAT.finditer(text): add("username", m.group(1))
    for m in HOST_PAT.finditer(text): add("hostname", m.group(1))
    for m in EMAIL_PAT.finditer(text): add("email", m.group(), "high")
    for m in PATH_PAT.finditer(text): add("file_path", m.group())
    return iocs

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
# SIEM Alert: Insider Threat - Bulk File Access
# Source IP: 10.0.0.88
# Hostname: HR-PC-04
# Username: rthompson
login time=23:45 user=rthompson src_ip=10.0.0.88 Hostname=HR-PC-04
FileAccess count=847 path=C:\\\\Finance\\\\Payroll\\\\ user=rthompson duration_minutes=12
USB EventID=6416 DeviceName=SanDisk_Cruzer DriveLetter=E: user=rthompson
PrintJob EventID=307 Document=Q4_Compensation_Report.xlsx Printer=HR-PRINTER-01 user=rthompson
EmailRule action=forward to=rthompson.personal@gmail.com user=rthompson
    \"\"\"

# === DETECTION ENGINE ===
lines = [l.strip() for l in LOG_DATA.strip().split('\\n') if l.strip() and not l.strip().startswith('#')]
findings = []
iocs_list = []
recommendations = []
risk_score = 0
statistics = {"total_events": len(lines), "off_hours_logins": 0, "bulk_access": 0,
              "usb_events": 0, "print_events": 0, "email_forwards": 0, "sensitive_access": 0}

# --- Phase 1: Off-hours login detection ---
for line in lines:
    if 'login' in line.lower() or 'logon' in line.lower():
        tm = TIME_PAT.search(line)
        if tm:
            parts = tm.group(1).split(':')
            hour = int(parts[0])
            if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
                findings.append({
                    "title": "OFF-HOURS LOGIN DETECTED",
                    "details": f"Login at {tm.group(1)} (off-hours: {OFF_HOURS_START}:00-{OFF_HOURS_END}:00). Line: {line[:120]}"
                })
                risk_score = max(risk_score, 60)
                statistics["off_hours_logins"] += 1

# --- Phase 2: Bulk file access ---
count_pat = re.compile(r'count[=:]\\s*(\\d+)', re.IGNORECASE)
for line in lines:
    if 'fileaccess' in line.lower() or 'file_access' in line.lower() or 'accessed' in line.lower():
        cm = count_pat.search(line)
        if cm:
            count = int(cm.group(1))
            if count > 50:
                findings.append({
                    "title": f"BULK FILE ACCESS: {count} files",
                    "details": f"{count} files accessed in a short window. This exceeds normal usage patterns. Line: {line[:120]}"
                })
                risk_score = max(risk_score, 80)
                statistics["bulk_access"] += 1

# --- Phase 3: USB/removable media ---
for line in lines:
    lower = line.lower()
    if 'usb' in lower or 'removable' in lower or '6416' in lower or 'driveletter' in lower:
        findings.append({
            "title": "USB/REMOVABLE MEDIA DETECTED",
            "details": f"Removable media event detected. Data may have been copied to external device. Line: {line[:120]}"
        })
        risk_score = max(risk_score, 75)
        statistics["usb_events"] += 1

# --- Phase 4: Print job detection ---
for line in lines:
    lower = line.lower()
    if 'printjob' in lower or 'print' in lower and '307' in lower:
        findings.append({
            "title": "SENSITIVE DOCUMENT PRINTED",
            "details": f"Print job detected for potentially sensitive document. Line: {line[:120]}"
        })
        risk_score = max(risk_score, 55)
        statistics["print_events"] += 1

# --- Phase 5: Email forwarding rules ---
for line in lines:
    lower = line.lower()
    if 'forward' in lower and ('email' in lower or 'rule' in lower or '@' in line):
        email = EMAIL_PAT.search(line)
        if email:
            addr = email.group()
            findings.append({
                "title": f"EMAIL FORWARDING TO EXTERNAL: {addr}",
                "details": f"Email forwarding rule to external address {addr}. Data exfiltration via email."
            })
            risk_score = max(risk_score, 85)
            statistics["email_forwards"] += 1
            iocs_list.append({"type": "email", "value": addr, "confidence": "high"})

# --- Phase 6: Sensitive directory access ---
for line in lines:
    for sens_dir in SENSITIVE_DIRS:
        if sens_dir.lower() in line.lower():
            findings.append({
                "title": f"SENSITIVE DIRECTORY ACCESS: {sens_dir}",
                "details": f"Access to sensitive directory '{sens_dir}' detected. Line: {line[:120]}"
            })
            risk_score = max(risk_score, 70)
            statistics["sensitive_access"] += 1
            break

# --- Phase 7: Extract all IOCs from raw text ---
text_iocs = extract_iocs(LOG_DATA)
seen_values = {(i["type"], i["value"].lower()) for i in iocs_list}
for ti in text_iocs:
    key = (ti["type"], ti["value"].lower())
    if key not in seen_values:
        seen_values.add(key)
        iocs_list.append(ti)

# --- Final output ---
if not findings:
    findings.append({"title": "No Insider Threat Indicators", "details": "No off-hours access, bulk downloads, USB, or email forwarding detected."})

if risk_score > 0:
    recommendations.extend([
        "Interview the employee with HR and Legal present.",
        "Preserve forensic image of the workstation.",
        "Review DLP logs for the past 30 days.",
        "Disable email forwarding rules to external addresses.",
        "Check USB device serial number against asset inventory.",
        "Revoke access to sensitive directories pending investigation.",
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs_list,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "statistics": statistics,
    "follow_up_needed": risk_score >= 60,
    "follow_up_prompt": "Correlate user activity across all systems. Check for data exfiltration to cloud storage." if risk_score >= 60 else ""
}
print(json.dumps(output, indent=2))
"""

INSIDER_THREAT_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "watch_accounts", "type": "array", "default": ["admin", "root", "svc_"]},
    {"name": "sensitive_dirs", "type": "array", "default": ["Finance", "Payroll", "HR", "Legal", "Executive", "Confidential"]},
    {"name": "off_hours_start", "type": "integer", "default": 22},
    {"name": "off_hours_end", "type": "integer", "default": 6},
]
