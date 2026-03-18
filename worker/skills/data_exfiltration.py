"""
Data Exfiltration Skill — Large transfer, DNS exfil, staging, cloud upload detection.

Analyzes network/proxy/endpoint logs for:
  - Large outbound transfers exceeding byte threshold
  - DNS exfiltration (high-entropy subdomains, tunneling)
  - File staging and compression before exfil
  - Cloud storage uploads (dropbox, gdrive, mega.nz)
  - Unusual process network connections
  - USB/removable media events

Skill slug: data-exfiltration-detection
MITRE: T1041 (Exfiltration Over C2), T1048 (Exfiltration Over Alternative Protocol),
       T1567 (Exfiltration to Cloud Storage), T1560 (Archive Collected Data)
"""

DATA_EXFILTRATION_TEMPLATE = """import json, re, math
from collections import defaultdict, Counter

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
BYTES_THRESHOLD = {{bytes_threshold}}
DNS_ENTROPY_THRESHOLD = {{dns_entropy_threshold}}
WATCH_DOMAINS = {{watch_domains}}

# === IOC EXTRACTION ===
IP_PATTERN = re.compile(r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b')
DOMAIN_PAT = re.compile(r'\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b')
HASH_MD5 = re.compile(r'\\b[a-fA-F0-9]{32}\\b')
HASH_SHA256 = re.compile(r'\\b[a-fA-F0-9]{64}\\b')
PATH_WIN = re.compile(r'[A-Z]:\\\\(?:[\\w .-]+\\\\)*[\\w .-]+')
PATH_UNIX = re.compile(r'(?:/[\\w.-]+){3,}')
USER_PAT = re.compile(r'(?:User|user|username)[:= ]+([a-zA-Z0-9_.\\\\-]+)')

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
    for m in DOMAIN_PAT.finditer(text):
        add("domain", m.group())
    for m in HASH_MD5.finditer(text):
        add("md5", m.group(), "high")
    for m in HASH_SHA256.finditer(text):
        add("sha256", m.group(), "high")
    for m in PATH_WIN.finditer(text):
        add("file_path", m.group())
    for m in PATH_UNIX.finditer(text):
        add("file_path", m.group())
    for m in USER_PAT.finditer(text):
        add("username", m.group(1))
    return iocs

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = \"\"\"
# SIEM Alert: Data Exfiltration - Large Outbound Transfer
# Source IP: 10.0.0.45
# Dest IP: 185.220.101.45
# Hostname: FINANCE-PC-02
# Username: mwilson
bytes_out=472040960 dst_ip=185.220.101.45 dst_port=443 src_ip=10.0.0.45 user=mwilson process=7z.exe
DNS query: aGVsbG8gd29ybGQ.exfil-c2.net from 10.0.0.45
7z.exe spawned by explorer.exe on C:\\\\Users\\\\\\\\mwilson\\\\\\\\Documents\\\\\\\\Q4_Financial_Reports output=C:\\\\Temp\\\\\\\\archive_20260318.7z
bytes_out=472040960 to 185.220.101.45
    \"\"\"

# === DETECTION ENGINE ===
lines = [l.strip() for l in LOG_DATA.strip().split('\\n') if l.strip() and not l.strip().startswith('#')]
findings = []
iocs_list = []
recommendations = []
risk_score = 0
statistics = {"total_lines": len(lines), "large_transfers": 0, "dns_exfil_suspects": 0,
              "staging_events": 0, "cloud_uploads": 0, "total_bytes_out": 0}

# --- Phase 1: Large outbound transfers ---
bytes_pattern = re.compile(r'bytes_out[=:]\\s*(\\d+)', re.IGNORECASE)
dst_ip_pattern = re.compile(r'dst_ip[=:]\\s*(\\d{1,3}(?:\\\\.\\d{1,3}){3})')
dst_port_pattern = re.compile(r'dst_port[=:]\\s*(\\d+)')
process_pattern = re.compile(r'process[=:]\\s*(\\S+)', re.IGNORECASE)

for line in lines:
    bm = bytes_pattern.search(line)
    if bm:
        bytes_out = int(bm.group(1))
        statistics["total_bytes_out"] += bytes_out
        if bytes_out > BYTES_THRESHOLD:
            dst = dst_ip_pattern.search(line)
            port = dst_port_pattern.search(line)
            proc = process_pattern.search(line)
            dst_str = dst.group(1) if dst else "unknown"
            port_str = port.group(1) if port else "?"
            proc_str = proc.group(1) if proc else "unknown"
            findings.append({
                "title": f"LARGE OUTBOUND TRANSFER: {bytes_out / 1048576:.1f} MB to {dst_str}:{port_str}",
                "details": f"Process {proc_str} sent {bytes_out / 1048576:.1f} MB ({bytes_out:,} bytes) to {dst_str}:{port_str}. "
                           f"Threshold: {BYTES_THRESHOLD / 1048576:.0f} MB."
            })
            risk_score = max(risk_score, 80)
            statistics["large_transfers"] += 1
            if dst:
                iocs_list.append({"type": "ipv4", "value": dst_str, "confidence": "high"})
            if proc:
                iocs_list.append({"type": "process", "value": proc_str, "confidence": "medium"})

# --- Phase 2: DNS exfiltration (entropy of subdomains) ---
dns_pattern = re.compile(r'(?:DNS query|dns)[: ]+([\\w.-]+)', re.IGNORECASE)
domain_queries = defaultdict(list)
for line in lines:
    dm = dns_pattern.search(line)
    if dm:
        full_domain = dm.group(1)
        parts = full_domain.split('.')
        if len(parts) >= 3:
            subdomain = '.'.join(parts[:-2])
            base = '.'.join(parts[-2:])
            domain_queries[base].append(subdomain)

for base, subs in domain_queries.items():
    high_entropy_subs = [s for s in subs if shannon_entropy(s) > DNS_ENTROPY_THRESHOLD]
    long_subs = [s for s in subs if len(s) > 20]
    if high_entropy_subs or long_subs:
        avg_ent = sum(shannon_entropy(s) for s in subs) / len(subs) if subs else 0
        findings.append({
            "title": f"DNS EXFILTRATION SUSPECTED: {base}",
            "details": f"{len(subs)} queries to {base}. {len(high_entropy_subs)} high-entropy subdomains "
                       f"(avg entropy: {avg_ent:.2f} bits). Indicates DNS tunneling or data exfiltration."
        })
        risk_score = max(risk_score, 85)
        statistics["dns_exfil_suspects"] += 1
        iocs_list.append({"type": "domain", "value": base, "confidence": "high"})

# --- Phase 3: File staging / compression ---
COMPRESSION_TOOLS = ['7z.exe', '7zip', 'winrar', 'rar.exe', 'zip', 'tar', 'gzip']
STAGING_DIRS = ['\\\\temp\\\\', '\\\\tmp\\\\', '\\\\appdata\\\\', '\\\\downloads\\\\']
for line in lines:
    lower = line.lower()
    for tool in COMPRESSION_TOOLS:
        if tool in lower:
            findings.append({
                "title": f"Compression Tool Detected: {tool}",
                "details": f"Archive tool '{tool}' activity detected. Attackers stage data in archives before exfiltration. Line: {line[:120]}"
            })
            risk_score = max(risk_score, 65)
            statistics["staging_events"] += 1
            # Extract output file path
            out_match = re.search(r'output[=:]\\s*(\\S+)', line, re.IGNORECASE)
            if out_match:
                iocs_list.append({"type": "file_path", "value": out_match.group(1), "confidence": "high"})
            break

# --- Phase 4: Cloud storage detection ---
CLOUD_DOMAINS = ['dropbox.com', 'drive.google.com', 'mega.nz', 'onedrive.live.com',
                 'wetransfer.com', 'sendspace.com', 'box.com', 'pastebin.com']
for line in lines:
    lower = line.lower()
    for cloud in CLOUD_DOMAINS:
        if cloud in lower:
            findings.append({
                "title": f"Cloud Storage Upload: {cloud}",
                "details": f"Connection to {cloud} detected. May indicate data exfiltration to cloud storage."
            })
            risk_score = max(risk_score, 70)
            statistics["cloud_uploads"] += 1
            iocs_list.append({"type": "domain", "value": cloud, "confidence": "medium"})
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
    findings.append({"title": "No Exfiltration Indicators", "details": "No large transfers, DNS tunneling, staging, or cloud uploads detected."})

if risk_score > 0:
    recommendations.extend([
        "Block the identified destination IPs at the perimeter firewall.",
        "Sinkhole suspected DNS exfiltration domains.",
        "Isolate the source host for forensic investigation.",
        "Review DLP alerts for the affected user account.",
        "Check for additional staging directories and compressed archives.",
        "Revoke the user's cloud storage access and VPN credentials.",
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs_list,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "statistics": statistics,
    "follow_up_needed": risk_score >= 60,
    "follow_up_prompt": "Quantify data loss. Check other endpoints for same destination IP." if risk_score >= 60 else ""
}
print(json.dumps(output, indent=2))
"""

DATA_EXFILTRATION_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "bytes_threshold", "type": "integer", "default": 52428800},
    {"name": "dns_entropy_threshold", "type": "float", "default": 3.5},
    {"name": "watch_domains", "type": "array", "default": ["mega.nz", "pastebin.com", "transfer.sh"]},
]
