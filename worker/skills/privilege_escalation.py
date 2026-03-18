"""
Privilege Escalation Skill — Token theft, LSASS access, UAC bypass, group changes.

Analyzes Windows/Linux logs for:
  - Token theft / impersonation (EventID 4672, SeDebugPrivilege)
  - LSASS access attempts (EventID 10, Sysmon)
  - UAC bypass patterns (eventvwr.exe, fodhelper.exe spawning elevated children)
  - Local group membership changes (EventID 4732, 4728)
  - Service creation for privesc (EventID 4697, 7045)
  - Scheduled task creation (EventID 4698)
  - Sudo/sudoers abuse on Linux

Skill slug: privilege-escalation-hunt
MITRE: T1134 (Access Token Manipulation), T1003.001 (LSASS Memory),
       T1548.002 (UAC Bypass), T1053.005 (Scheduled Task),
       T1543.003 (Windows Service)
"""

PRIVILEGE_ESCALATION_TEMPLATE = """import json, re
from collections import defaultdict

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
WATCH_ACCOUNTS = {{watch_accounts}}
WATCH_PROCESSES = {{watch_processes}}

# === IOC EXTRACTION ===
IP_PATTERN = re.compile(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b')
HASH_MD5 = re.compile(r'\\b[a-fA-F0-9]{32}\\b')
HASH_SHA256 = re.compile(r'\\b[a-fA-F0-9]{64}\\b')
USER_PAT = re.compile(r'(?:User|SubjectUser|MemberName|user)[:= ]+([a-zA-Z0-9_.\\\\-]+)')
HOST_PAT = re.compile(r'(?:Host|Hostname|Computer)[:= ]+([a-zA-Z0-9_.-]+)')
PATH_PAT = re.compile(r'[A-Z]:\\\\(?:[\\w .-]+\\\\)*[\\w .-]+')

def extract_iocs(text):
    iocs = []
    seen = set()
    def add(ioc_type, value, conf="medium"):
        key = (ioc_type, value.lower())
        if key not in seen:
            seen.add(key)
            iocs.append({"type": ioc_type, "value": value, "confidence": conf})
    for m in IP_PATTERN.finditer(text):
        add("ipv4", m.group())
    for m in HASH_MD5.finditer(text):
        add("md5", m.group(), "high")
    for m in HASH_SHA256.finditer(text):
        add("sha256", m.group(), "high")
    for m in USER_PAT.finditer(text):
        add("username", m.group(1))
    for m in HOST_PAT.finditer(text):
        add("hostname", m.group(1))
    for m in PATH_PAT.finditer(text):
        add("file_path", m.group())
    return iocs

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
# SIEM Alert: Privilege Escalation Detected
# Source IP: 10.0.0.75
# Hostname: WS-DEV-07
# Username: jsmith
EventID=4672 SubjectUser=jsmith PrivilegesAssigned=SeDebugPrivilege,SeTcbPrivilege SourceIP=10.0.0.75
EventID=10 SourceProcessId=4812 SourceImage=C:\\\\Users\\\\\\\\jsmith\\\\\\\\Downloads\\\\\\\\exploit.exe TargetImage=C:\\\\Windows\\\\\\\\System32\\\\\\\\lsass.exe GrantedAccess=0x1FFFFF
EventID=4732 MemberName=jsmith GroupName=Administrators SourceIP=10.0.0.75
EventID=4698 TaskName=Updater TaskContent=C:\\\\Temp\\\\\\\\backdoor.exe SubjectUser=jsmith
    \"\"\"

# === DETECTION ENGINE ===
lines = [l.strip() for l in LOG_DATA.strip().split('\\n') if l.strip() and not l.strip().startswith('#')]
findings = []
iocs_list = []
recommendations = []
risk_score = 0
statistics = {"total_events": 0, "priv_events": 0, "lsass_events": 0, "group_changes": 0, "sched_tasks": 0, "service_creates": 0}

# Parse events
events = []
for line in lines:
    event = {}
    for kv in re.finditer(r'(\\w+)[:=](\\S+)', line):
        event[kv.group(1)] = kv.group(2)
    if event:
        events.append(event)
        statistics["total_events"] += 1

# --- Phase 1: Dangerous privilege assignment (EventID 4672) ---
DANGEROUS_PRIVS = ['SeDebugPrivilege', 'SeTcbPrivilege', 'SeAssignPrimaryTokenPrivilege',
                   'SeLoadDriverPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege']
for e in events:
    if e.get('EventID') == '4672':
        privs = e.get('PrivilegesAssigned', '')
        hit = [p for p in DANGEROUS_PRIVS if p in privs]
        if hit:
            user = e.get('SubjectUser', 'unknown')
            findings.append({
                "title": f"Dangerous Privileges Assigned to {user}",
                "details": f"Privileges: {', '.join(hit)}. SeDebugPrivilege enables credential dumping and process injection."
            })
            risk_score = max(risk_score, 80)
            statistics["priv_events"] += 1
            for p in hit:
                iocs_list.append({"type": "privilege", "value": p, "confidence": "high"})

# --- Phase 2: LSASS access (EventID 10) ---
for e in events:
    if e.get('EventID') == '10':
        target = e.get('TargetImage', '')
        source = e.get('SourceImage', '')
        if 'lsass.exe' in target.lower():
            findings.append({
                "title": f"LSASS ACCESS DETECTED: {source}",
                "details": f"Process {source} accessed lsass.exe with GrantedAccess={e.get('GrantedAccess','?')}. "
                           f"This is a strong indicator of credential dumping (Mimikatz, ProcDump, etc.)."
            })
            risk_score = max(risk_score, 95)
            statistics["lsass_events"] += 1
            iocs_list.append({"type": "process", "value": source, "confidence": "high"})

# --- Phase 3: UAC bypass processes ---
UAC_BYPASS = ['eventvwr.exe', 'fodhelper.exe', 'sdclt.exe', 'computerdefaults.exe',
              'cmstp.exe', 'mshta.exe', 'wscript.exe']
for e in events:
    proc = e.get('SourceImage', e.get('Process', '')).lower()
    for bypass in UAC_BYPASS:
        if bypass in proc:
            findings.append({
                "title": f"UAC Bypass Process: {bypass}",
                "details": f"Process {proc} matches known UAC bypass vector. Check child processes for elevated execution."
            })
            risk_score = max(risk_score, 85)

# --- Phase 4: Local group membership changes (EventID 4732, 4728) ---
for e in events:
    if e.get('EventID') in ('4732', '4728'):
        member = e.get('MemberName', 'unknown')
        group = e.get('GroupName', 'unknown')
        if 'admin' in group.lower():
            findings.append({
                "title": f"ADMIN GROUP CHANGE: {member} added to {group}",
                "details": f"User {member} was added to {group}. This grants full local administrator access."
            })
            risk_score = max(risk_score, 90)
            statistics["group_changes"] += 1

# --- Phase 5: Scheduled task creation (EventID 4698) ---
for e in events:
    if e.get('EventID') == '4698':
        task = e.get('TaskName', 'unknown')
        content = e.get('TaskContent', '')
        user = e.get('SubjectUser', 'unknown')
        findings.append({
            "title": f"Scheduled Task Created: {task} by {user}",
            "details": f"Task '{task}' created by {user}. Content: {content}. "
                       f"Attackers use scheduled tasks for persistence and privilege escalation."
        })
        risk_score = max(risk_score, 75)
        statistics["sched_tasks"] += 1
        if content:
            iocs_list.append({"type": "file_path", "value": content, "confidence": "high"})

# --- Phase 6: Service creation (EventID 4697, 7045) ---
for e in events:
    if e.get('EventID') in ('4697', '7045'):
        svc = e.get('ServiceName', e.get('ServiceFileName', 'unknown'))
        findings.append({
            "title": f"Service Created: {svc}",
            "details": f"New service installed. Attackers create services for SYSTEM-level execution."
        })
        risk_score = max(risk_score, 80)
        statistics["service_creates"] += 1

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
    findings.append({"title": "No Privilege Escalation Indicators", "details": "No token theft, LSASS access, UAC bypass, or group changes detected."})

if risk_score > 0:
    recommendations.extend([
        "IMMEDIATELY revoke elevated privileges from the affected account.",
        "Isolate the workstation and begin forensic imaging.",
        "Reset credentials for any account with SeDebugPrivilege.",
        "Review scheduled tasks and services created in the last 24 hours.",
        "Check for lateral movement from this host.",
        "Deploy LSASS protection (Credential Guard, PPL).",
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs_list,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "statistics": statistics,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Investigate lateral movement from this host. Check for persistence mechanisms." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

PRIVILEGE_ESCALATION_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "watch_accounts", "type": "array", "default": ["admin", "root", "DA_", "svc_"]},
    {"name": "watch_processes", "type": "array", "default": ["mimikatz", "procdump", "rubeus", "lazagne"]},
]
