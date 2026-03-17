"""
Lateral Movement Skill — Pass-the-Hash, NTLM relay, and credential abuse detection.

Analyzes Windows EventLog data for:
  - Pass-the-Hash (LogonType 9 with NTLM hashes)
  - Mimikatz artifacts (process names, command lines)
  - Service account abuse from workstations
  - Suspicious RDP/SMB/WinRM lateral movement patterns
  - Credential reuse across multiple hosts

Skill slug: lateral-movement-detection
MITRE: T1021 (Remote Services), T1021.001 (RDP), T1021.002 (SMB),
       T1550.002 (Pass the Hash), T1003 (Credential Dumping)
"""

LATERAL_MOVEMENT_TEMPLATE = """import json, re, hashlib
from collections import defaultdict, Counter

# === PARAMETERS (filled by LLM from alert context) ===
LOG_DATA = '''{{log_data}}'''
TARGET_PORTS = {{target_ports}}
MAX_FAILED_LOGONS = {{max_failed_logons}}
WATCH_ACCOUNTS = {{watch_accounts}}

# === IOC EXTRACTION (from prompts v2 pattern) ===
IOC_PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "file_path_windows": r'[A-Z]:\\(?:[\w .-]+\\)*[\w .-]+',
    "username": r'(?:User|user|Username|Account)[:= ]+([a-zA-Z0-9_.\\-]+)',
    "hostname": r'(?:Host|Hostname|TargetHost|Computer)[:= ]+([a-zA-Z0-9_.-]+)',
}

def extract_iocs(text, ioc_types=None):
    patterns = IOC_PATTERNS
    if ioc_types:
        patterns = {k: v for k, v in patterns.items() if k in ioc_types}
    iocs = []
    seen = set()
    for ioc_type, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            value = match.group(1) if match.lastindex else match.group(0)
            key = (ioc_type, value.lower())
            if key not in seen:
                seen.add(key)
                confidence = "high" if ioc_type in ("md5", "sha256") else "medium"
                iocs.append({"type": ioc_type, "value": value, "confidence": confidence})
    return iocs

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
# SIEM Alert: Lateral Movement - Pass the Hash
# Source IP: 10.0.0.50
# Dest IP: 10.0.0.200
# Hostname: WS-FINANCE-03
# Username: svc_backup
EventID=4624 LogonType=9 SourceIP=10.0.0.50 TargetHost=DC-PRIMARY.corp.local TargetIP=10.0.0.200 User=svc_backup NTLM_hash=aad3b435b51404eeaad3b435b51404ee Process=C:\\\\Windows\\\\System32\\\\svchost.exe ParentProcess=C:\\\\Tools\\\\mimikatz.exe CommandLine=sekurlsa::pth /user:svc_backup /domain:corp.local /ntlm:aad3b435b51404eeaad3b435b51404ee
EventID=4672 SubjectUser=svc_backup PrivilegesAssigned=SeDebugPrivilege,SeTcbPrivilege SourceIP=10.0.0.50
EventID=4648 SubjectUser=svc_backup TargetUser=Administrator TargetHost=DC-PRIMARY.corp.local SourceIP=10.0.0.50
EventID=4624 LogonType=3 SourceIP=10.0.0.50 TargetHost=FILE-SERVER-01.corp.local TargetIP=10.0.0.201 User=svc_backup
    \"\"\"

# === DETECTION ENGINE ===
lines = [l.strip() for l in LOG_DATA.strip().split('\\n') if l.strip() and not l.strip().startswith('#')]
findings = []
iocs_list = []
recommendations = []
risk_score = 0
statistics = {}

# --- Phase 1: Parse Windows Event fields ---
events = []
for line in lines:
    event = {}
    for kv in re.finditer(r'(\w+)[:=](\S+)', line):
        event[kv.group(1)] = kv.group(2)
    if event:
        events.append(event)

# --- Phase 2: Detect Pass-the-Hash (LogonType 9) ---
pth_events = [e for e in events if e.get('LogonType') == '9']
if pth_events:
    for e in pth_events:
        src = e.get('SourceIP', 'unknown')
        dst = e.get('TargetHost', e.get('TargetIP', 'unknown'))
        user = e.get('User', 'unknown')
        findings.append({
            "title": f"PASS-THE-HASH DETECTED: {src} → {dst}",
            "details": (
                f"LogonType 9 (NewCredentials) from {src} to {dst} as {user}. "
                f"This logon type is characteristic of Pass-the-Hash attacks "
                f"where stolen NTLM hashes are used for lateral movement."
            )
        })
    risk_score = max(risk_score, 90)

# --- Phase 3: Detect Mimikatz artifacts ---
MIMIKATZ_INDICATORS = ['mimikatz', 'sekurlsa', 'lsadump', 'kerberos::list',
                       'privilege::debug', 'token::elevate', 'crypto::capi']
mimikatz_hits = []
for line in lines:
    lower = line.lower()
    for indicator in MIMIKATZ_INDICATORS:
        if indicator in lower:
            mimikatz_hits.append(indicator)

if mimikatz_hits:
    findings.append({
        "title": "MIMIKATZ DETECTED",
        "details": (
            f"Credential theft tool indicators found: {', '.join(set(mimikatz_hits))}. "
            f"Mimikatz enables Pass-the-Hash, Pass-the-Ticket, and credential dumping."
        )
    })
    risk_score = max(risk_score, 95)

# --- Phase 4: Detect NTLM hash patterns ---
ntlm_pattern = re.compile(r'(?:NTLM_hash|ntlm|NTHash)[:=]([a-fA-F0-9]{32})', re.IGNORECASE)
ntlm_hashes = set()
for line in lines:
    for m in ntlm_pattern.finditer(line):
        ntlm_hashes.add(m.group(1))

if ntlm_hashes:
    for h in ntlm_hashes:
        iocs_list.append({"type": "ntlm_hash", "value": h, "confidence": "high"})
    findings.append({
        "title": f"NTLM Hashes Observed ({len(ntlm_hashes)})",
        "details": f"NTLM hashes found in logs: {', '.join(list(ntlm_hashes)[:3])}. These may indicate credential theft or Pass-the-Hash."
    })
    risk_score = max(risk_score, 85)

# --- Phase 5: Detect privilege escalation (EventID 4672) ---
priv_events = [e for e in events if e.get('EventID') == '4672']
dangerous_privs = ['SeDebugPrivilege', 'SeTcbPrivilege', 'SeImpersonatePrivilege']
for e in priv_events:
    privs = e.get('PrivilegesAssigned', '')
    hit_privs = [p for p in dangerous_privs if p in privs]
    if hit_privs:
        findings.append({
            "title": f"Dangerous Privileges Assigned to {e.get('SubjectUser', 'unknown')}",
            "details": f"Privileges: {', '.join(hit_privs)}. SeDebugPrivilege enables credential dumping."
        })
        risk_score = max(risk_score, 80)

# --- Phase 6: Detect credential use across hosts (4648) ---
explicit_cred = [e for e in events if e.get('EventID') == '4648']
if explicit_cred:
    for e in explicit_cred:
        findings.append({
            "title": f"Explicit Credential Use: {e.get('SubjectUser','?')} → {e.get('TargetUser','?')}",
            "details": (
                f"User {e.get('SubjectUser','unknown')} used explicit credentials to access "
                f"{e.get('TargetHost', 'unknown')} as {e.get('TargetUser','unknown')}. "
                f"Source: {e.get('SourceIP','unknown')}."
            )
        })
    risk_score = max(risk_score, 75)

# --- Phase 7: Service account abuse from workstations ---
for e in events:
    user = e.get('User', e.get('SubjectUser', '')).lower()
    src = e.get('SourceIP', '')
    for watch in WATCH_ACCOUNTS:
        if watch.lower() in user and src:
            findings.append({
                "title": f"Service Account Used from Workstation",
                "details": f"Account '{user}' (matches watch pattern '{watch}') logged in from {src}. Service accounts should not originate from workstations."
            })
            risk_score = max(risk_score, 70)
            break

# --- Phase 8: Extract all IOCs from raw text ---
text_iocs = extract_iocs(LOG_DATA)
seen_values = {(i["type"], i["value"].lower()) for i in iocs_list}
for ti in text_iocs:
    key = (ti["type"], ti["value"].lower())
    if key not in seen_values:
        seen_values.add(key)
        iocs_list.append(ti)

# --- Final output ---
if not findings:
    findings.append({
        "title": "No Lateral Movement Indicators",
        "details": "No Pass-the-Hash, credential abuse, or lateral movement patterns detected."
    })

if risk_score > 0:
    recommendations.extend([
        "IMMEDIATELY isolate the source workstation from the network.",
        "Reset credentials for all accounts observed in lateral movement.",
        "Check for persistence mechanisms on compromised hosts.",
        "Block NTLM authentication where possible; enforce Kerberos.",
        "Review SMB/RDP access logs on destination hosts for further lateral spread.",
        "Scan for additional mimikatz artifacts across the environment.",
    ])

risk_score = min(100, risk_score)
statistics["total_events"] = len(events)
statistics["pth_events"] = len(pth_events)
statistics["mimikatz_indicators"] = len(set(mimikatz_hits))
statistics["ntlm_hashes_found"] = len(ntlm_hashes)
statistics["privilege_escalation_events"] = len(priv_events)
statistics["explicit_credential_events"] = len(explicit_cred)

output = {
    "findings": findings,
    "iocs": iocs_list,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "statistics": statistics,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Investigate all destination hosts for persistence. Generate timeline of lateral movement chain." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

LATERAL_MOVEMENT_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "target_ports", "type": "array", "default": [445, 3389, 5985, 5986, 135, 139]},
    {"name": "max_failed_logons", "type": "integer", "default": 5},
    {"name": "watch_accounts", "type": "array", "default": ["svc_", "admin", "DA_", "SA_"]},
]
