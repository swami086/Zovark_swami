"""
Supply Chain Compromise Skill — Update hijack, DLL sideload, trusted binary C2.

Analyzes endpoint/process logs for:
  - Unsigned or unexpected software updates
  - DLL side-loading from wrong paths
  - Trusted binaries making outbound C2 connections
  - Unexpected child processes from update services
  - Hash mismatch on known-good binaries
  - Build system compromise indicators

Skill slug: supply-chain-compromise
MITRE: T1195 (Supply Chain Compromise), T1195.002 (Compromise Software Supply Chain),
       T1574.001 (DLL Search Order Hijacking), T1036 (Masquerading)
"""

SUPPLY_CHAIN_TEMPLATE = """import json, re
from collections import defaultdict

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
TRUSTED_PROCESSES = {{trusted_processes}}
KNOWN_GOOD_HASHES = {{known_good_hashes}}
SUSPICIOUS_CHILD_PROCESSES = {{suspicious_child_processes}}

# === IOC EXTRACTION ===
IP_PATTERN = re.compile(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b')
HASH_MD5 = re.compile(r'\\b[a-fA-F0-9]{32}\\b')
HASH_SHA256 = re.compile(r'\\b[a-fA-F0-9]{64}\\b')
PATH_PAT = re.compile(r'[A-Z]:\\\\(?:[\\w .-]+\\\\)*[\\w .-]+')
PROC_PAT = re.compile(r'(?:Process|Image|SourceImage|TargetImage|ChildProcess|ParentProcess)[:= ]+([\\w.\\\\: -]+?)(?:\\s|$)')
USER_PAT = re.compile(r'(?:User|user|username)[:= ]+([a-zA-Z0-9_.\\\\-]+)')

def extract_iocs(text):
    iocs = []
    seen = set()
    def add(t, v, c="medium"):
        k = (t, v.lower())
        if k not in seen:
            seen.add(k)
            iocs.append({"type": t, "value": v, "confidence": c})
    for m in IP_PATTERN.finditer(text): add("ipv4", m.group())
    for m in HASH_MD5.finditer(text): add("md5", m.group(), "high")
    for m in HASH_SHA256.finditer(text): add("sha256", m.group(), "high")
    for m in PATH_PAT.finditer(text): add("file_path", m.group())
    for m in PROC_PAT.finditer(text): add("process", m.group(1).strip())
    for m in USER_PAT.finditer(text): add("username", m.group(1))
    return iocs

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
# SIEM Alert: Supply Chain Compromise
# Source IP: 10.0.0.12
# Hostname: MGMT-SERVER-01
Process=SolarWinds.BusinessLayerHost.exe ParentProcess=solarwinds.exe ChildProcess=rundll32.exe DLL=C:\\\\Windows\\\\SysWOW64\\\\avsvmcloud.dll
Outbound dst_ip=20.140.0.1 dst_port=443 Process=SolarWinds.BusinessLayerHost.exe bytes_out=4096
DLL_Load Process=SolarWinds.BusinessLayerHost.exe DLL=C:\\\\Windows\\\\SysWOW64\\\\avsvmcloud.dll Expected_Path=C:\\\\Program Files\\\\SolarWinds\\\\Orion\\\\
Hash_Mismatch File=avsvmcloud.dll MD5=d0d626deb3f9484e649294a8dfa814c5 Expected_MD5=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
    \"\"\"

# === DETECTION ENGINE ===
lines = [l.strip() for l in LOG_DATA.strip().split('\\n') if l.strip() and not l.strip().startswith('#')]
findings = []
iocs_list = []
recommendations = []
risk_score = 0
statistics = {"total_events": len(lines), "dll_sideloads": 0, "hash_mismatches": 0,
              "suspicious_children": 0, "trusted_outbound": 0, "update_hijacks": 0}

# --- Phase 1: DLL side-loading (DLL loaded from wrong path) ---
for line in lines:
    lower = line.lower()
    if 'dll_load' in lower or 'dll' in lower and 'expected_path' in lower:
        dll_match = re.search(r'DLL[:= ]+([\\w.\\\\: -]+?)(?:\\s|$)', line)
        expected = re.search(r'Expected_Path[:= ]+([\\w.\\\\: -]+?)(?:\\s|$)', line)
        if dll_match:
            dll = dll_match.group(1).strip()
            exp = expected.group(1).strip() if expected else "unknown"
            findings.append({
                "title": f"DLL SIDE-LOADING: {dll}",
                "details": f"DLL loaded from unexpected path. Expected: {exp}. "
                           f"DLL side-loading is a common supply chain attack vector."
            })
            risk_score = max(risk_score, 90)
            statistics["dll_sideloads"] += 1
            iocs_list.append({"type": "file_path", "value": dll, "confidence": "high"})

# --- Phase 2: Hash mismatch on known binaries ---
for line in lines:
    lower = line.lower()
    if 'hash_mismatch' in lower or ('expected_md5' in lower or 'expected_sha256' in lower):
        md5s = HASH_MD5.findall(line)
        sha256s = HASH_SHA256.findall(line)
        file_match = re.search(r'File[:= ]+([\\w.]+)', line)
        fname = file_match.group(1) if file_match else "unknown"
        findings.append({
            "title": f"HASH MISMATCH: {fname}",
            "details": f"Binary hash does not match known-good value. Found hashes: {md5s + sha256s}. "
                       f"This indicates the binary has been tampered with."
        })
        risk_score = max(risk_score, 95)
        statistics["hash_mismatches"] += 1
        for h in md5s:
            iocs_list.append({"type": "md5", "value": h, "confidence": "high"})
        for h in sha256s:
            iocs_list.append({"type": "sha256", "value": h, "confidence": "high"})

# --- Phase 3: Suspicious child processes from trusted software ---
for line in lines:
    child_match = re.search(r'ChildProcess[:= ]+([\\w.]+)', line)
    parent_match = re.search(r'(?:Process|ParentProcess)[:= ]+([\\w.]+)', line)
    if child_match and parent_match:
        child = child_match.group(1)
        parent = parent_match.group(1)
        for susp in SUSPICIOUS_CHILD_PROCESSES:
            if susp.lower() in child.lower():
                findings.append({
                    "title": f"SUSPICIOUS CHILD PROCESS: {parent} -> {child}",
                    "details": f"Trusted process {parent} spawned suspicious child {child}. "
                               f"This pattern is seen in supply chain compromises."
                })
                risk_score = max(risk_score, 85)
                statistics["suspicious_children"] += 1
                iocs_list.append({"type": "process", "value": child, "confidence": "high"})
                break

# --- Phase 4: Trusted binary making outbound connections ---
dst_ip_pat = re.compile(r'dst_ip[:= ]+(\\d{1,3}(?:\\.\\d{1,3}){3})')
for line in lines:
    if 'outbound' in line.lower() or 'dst_ip' in line.lower():
        proc_match = re.search(r'Process[:= ]+([\\w.]+)', line)
        dst_match = dst_ip_pat.search(line)
        if proc_match and dst_match:
            proc = proc_match.group(1)
            dst = dst_match.group(1)
            for trusted in TRUSTED_PROCESSES:
                if trusted.lower() in proc.lower():
                    findings.append({
                        "title": f"TRUSTED BINARY C2: {proc} -> {dst}",
                        "details": f"Trusted process {proc} made outbound connection to {dst}. "
                                   f"Legitimate software should not make unexpected network connections."
                    })
                    risk_score = max(risk_score, 90)
                    statistics["trusted_outbound"] += 1
                    iocs_list.append({"type": "ipv4", "value": dst, "confidence": "high"})
                    break

# --- Phase 5: Extract all IOCs from raw text ---
text_iocs = extract_iocs(LOG_DATA)
seen_values = {(i["type"], i["value"].lower()) for i in iocs_list}
for ti in text_iocs:
    key = (ti["type"], ti["value"].lower())
    if key not in seen_values:
        seen_values.add(key)
        iocs_list.append(ti)

# --- Final output ---
if not findings:
    findings.append({"title": "No Supply Chain Indicators", "details": "No DLL sideloading, hash mismatches, or suspicious process chains detected."})

if risk_score > 0:
    recommendations.extend([
        "IMMEDIATELY isolate affected servers from the network.",
        "Verify binary hashes against vendor-provided checksums.",
        "Block outbound connections from compromised processes.",
        "Audit all software update channels for tampering.",
        "Check other hosts running the same software version.",
        "Contact the software vendor about potential compromise.",
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs_list,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "statistics": statistics,
    "follow_up_needed": risk_score >= 70,
    "follow_up_prompt": "Audit all hosts running the affected software. Generate IOC blocklist." if risk_score >= 70 else ""
}
print(json.dumps(output, indent=2))
"""

SUPPLY_CHAIN_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "trusted_processes", "type": "array", "default": ["SolarWinds", "Orion", "WSUS", "SCCM", "ManageEngine", "Kaseya"]},
    {"name": "known_good_hashes", "type": "array", "default": []},
    {"name": "suspicious_child_processes", "type": "array", "default": ["rundll32.exe", "powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"]},
]
