"""
Network Beaconing Skill — C2 beacon detection and DNS tunneling analysis.

Analyzes Zeek connection logs (conn.log) and DNS logs for:
  - Periodic beaconing (jitter/interval analysis)
  - DNS tunneling (subdomain entropy + query length)
  - Long-lived connections to rare external hosts
  - Port-protocol mismatches (HTTPS on non-443)

Skill slug: network-beaconing
MITRE: T1071 (Application Layer Protocol), T1071.004 (DNS),
       T1095 (Non-Application Layer Protocol), T1572 (Protocol Tunneling)
"""

# Python code template for sandbox execution.
# Parameters are filled by fill_skill_parameters activity via {{variable}} substitution.

NETWORK_BEACONING_TEMPLATE = """import json, re, math, hashlib
from collections import defaultdict, Counter
from datetime import datetime, timedelta

# === PARAMETERS (filled by LLM from alert context) ===
LOG_DATA = '''{{log_data}}'''
BEACON_JITTER_THRESHOLD = {{beacon_jitter_threshold}}
DNS_ENTROPY_THRESHOLD = {{dns_entropy_threshold}}
DNS_LENGTH_THRESHOLD = {{dns_length_threshold}}
MIN_BEACON_COUNT = {{min_beacon_count}}
SUSPICIOUS_PORTS = {{suspicious_ports}}
WATCH_IPS = {{watch_ips}}

# === IOC EXTRACTION ===
IOC_PATTERNS = {
    "ipv4": r'\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b',
    "domain": r'\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b',
    "url": r'https?://[^\\s<>\"\\']+',
}

def extract_iocs(text, ioc_types=None):
    import re as _re
    patterns = IOC_PATTERNS
    if ioc_types:
        patterns = {k: v for k, v in patterns.items() if k in ioc_types}
    iocs = []
    seen = set()
    for ioc_type, pattern in patterns.items():
        for match in _re.finditer(pattern, text):
            value = match.group()
            key = (ioc_type, value.lower())
            if key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": value, "confidence": "medium"})
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
# Zeek conn.log format: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes
1709312400.000000 CYnL1t 10.0.0.50 49152 198.51.100.23 443 tcp ssl 0.5 120 250
1709312700.000000 CYnL2t 10.0.0.50 49153 198.51.100.23 443 tcp ssl 0.5 115 245
1709313000.000000 CYnL3t 10.0.0.50 49154 198.51.100.23 443 tcp ssl 0.5 118 248
1709313300.000000 CYnL4t 10.0.0.50 49155 198.51.100.23 443 tcp ssl 0.5 122 252
1709313600.000000 CYnL5t 10.0.0.50 49156 198.51.100.23 443 tcp ssl 0.5 119 247
1709313900.000000 CYnL6t 10.0.0.50 49157 198.51.100.23 443 tcp ssl 0.5 121 249
# Zeek dns.log: ts uid id.orig_h query qtype answers
1709312400.100000 DYnL1t 10.0.0.50 a8f3k2j4h5g6.c2-beacon.evil.com A 198.51.100.23
1709312700.100000 DYnL2t 10.0.0.50 b9e4m3n5p7q8.c2-beacon.evil.com A 198.51.100.23
1709313000.100000 DYnL3t 10.0.0.50 c7d2f6g8h1j3.c2-beacon.evil.com A 198.51.100.23
1709313300.100000 DYnL4t 10.0.0.50 d5c3e7f9g2h4.c2-beacon.evil.com TXT -
    \"\"\"

# === DETECTION ENGINE ===
lines = [l.strip() for l in LOG_DATA.strip().split('\\n') if l.strip() and not l.strip().startswith('#')]
findings = []
iocs_list = []
recommendations = []
risk_score = 0
statistics = {}

# --- Phase 1: Parse connections and group by (src, dst) pair ---
conn_flows = defaultdict(list)  # (src_ip, dst_ip, dst_port) -> [timestamps]
dns_queries = []                # [(timestamp, src_ip, query_domain, qtype)]

ts_pattern = re.compile(r'^(\\d+\\.\\d+)\\s+')
conn_pattern = re.compile(
    r'^(\\d+\\.\\d+)\\s+\\S+\\s+'
    r'(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(\\d+)\\s+'
    r'(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+(\\d+)\\s+'
    r'(\\w+)\\s+(\\S+)\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)'
)
dns_pattern = re.compile(
    r'^(\\d+\\.\\d+)\\s+\\S+\\s+'
    r'(\\d{1,3}(?:\\.\\d{1,3}){3})\\s+'
    r'(\\S+)\\s+(\\w+)\\s+(\\S+)'
)

for line in lines:
    # Try conn.log format
    cm = conn_pattern.match(line)
    if cm:
        ts, src, sport, dst, dport, proto, svc, dur, obytes, rbytes = cm.groups()
        conn_flows[(src, dst, int(dport))].append(float(ts))
        continue

    # Try dns.log format
    dm = dns_pattern.match(line)
    if dm:
        ts, src, query, qtype, answer = dm.groups()
        dns_queries.append((float(ts), src, query, qtype))

# --- Phase 2: Beacon detection via interval jitter analysis ---
beacon_candidates = []

for (src, dst, dport), timestamps in conn_flows.items():
    if len(timestamps) < MIN_BEACON_COUNT:
        continue
    timestamps.sort()
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
    if not intervals:
        continue
    mean_interval = sum(intervals) / len(intervals)
    if mean_interval == 0:
        continue
    std_dev = (sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5
    jitter = std_dev / mean_interval  # coefficient of variation

    if jitter <= BEACON_JITTER_THRESHOLD:
        beacon_candidates.append({
            "src": src, "dst": dst, "port": dport,
            "count": len(timestamps),
            "mean_interval_s": round(mean_interval, 1),
            "jitter": round(jitter, 4),
        })

if beacon_candidates:
    for b in beacon_candidates:
        findings.append({
            "title": f"C2 Beaconing Detected: {b['src']} → {b['dst']}:{b['port']}",
            "details": (
                f"{b['count']} connections with mean interval {b['mean_interval_s']}s "
                f"and jitter {b['jitter']} (threshold: {BEACON_JITTER_THRESHOLD}). "
                f"Low jitter indicates automated periodic communication."
            )
        })
        iocs_list.append({"type": "ipv4", "value": b["dst"], "confidence": "high"})
        iocs_list.append({"type": "ipv4", "value": b["src"], "confidence": "low"})
    risk_score += min(60, 30 * len(beacon_candidates))

statistics["beacon_candidates"] = len(beacon_candidates)

# --- Phase 3: DNS tunneling detection (subdomain entropy + length) ---
domain_queries = defaultdict(list)  # base_domain -> [full_queries]
for ts, src, query, qtype in dns_queries:
    parts = query.split('.')
    if len(parts) >= 3:
        base = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
        domain_queries[base].append(subdomain)

dns_tunnel_suspects = []
for base_domain, subdomains in domain_queries.items():
    long_subs = [s for s in subdomains if len(s) > DNS_LENGTH_THRESHOLD]
    if long_subs:
        avg_entropy = sum(shannon_entropy(s) for s in long_subs) / len(long_subs)
        if avg_entropy > DNS_ENTROPY_THRESHOLD:
            dns_tunnel_suspects.append({
                "domain": base_domain,
                "query_count": len(subdomains),
                "long_subdomain_count": len(long_subs),
                "avg_entropy": round(avg_entropy, 2),
            })

if dns_tunnel_suspects:
    for d in dns_tunnel_suspects:
        findings.append({
            "title": f"DNS Tunneling Suspected: {d['domain']}",
            "details": (
                f"{d['query_count']} queries with {d['long_subdomain_count']} unusually long subdomains. "
                f"Average subdomain entropy: {d['avg_entropy']} bits (threshold: {DNS_ENTROPY_THRESHOLD}). "
                f"High entropy + long subdomains indicate DNS-based C2 or data exfiltration."
            )
        })
        iocs_list.append({"type": "domain", "value": d["domain"], "confidence": "high"})
    risk_score += min(50, 25 * len(dns_tunnel_suspects))

statistics["dns_tunnel_suspects"] = len(dns_tunnel_suspects)

# --- Phase 4: Port-protocol mismatch detection ---
port_mismatches = []
standard_ports = {80: "http", 443: "ssl", 53: "dns", 22: "ssh", 25: "smtp"}
for (src, dst, dport), timestamps in conn_flows.items():
    if dport in SUSPICIOUS_PORTS and dport not in standard_ports:
        port_mismatches.append({"src": src, "dst": dst, "port": dport, "count": len(timestamps)})

if port_mismatches:
    for pm in port_mismatches:
        findings.append({
            "title": f"Suspicious Port: {pm['src']} → {pm['dst']}:{pm['port']}",
            "details": f"{pm['count']} connections on non-standard port {pm['port']}."
        })
        iocs_list.append({"type": "ipv4", "value": pm["dst"], "confidence": "medium"})
    risk_score += 20

# --- Phase 5: Extract IOCs from raw log text ---
text_iocs = extract_iocs(LOG_DATA)
seen_values = {(i["type"], i["value"]) for i in iocs_list}
for ti in text_iocs:
    key = (ti["type"], ti["value"])
    if key not in seen_values:
        seen_values.add(key)
        iocs_list.append(ti)

# --- Final output ---
if not findings:
    findings.append({"title": "No C2 Indicators", "details": "No beaconing, DNS tunneling, or suspicious ports detected in the provided logs."})

if risk_score > 0:
    recommendations.extend([
        "Block identified C2 destination IPs at the perimeter firewall.",
        "Sinkhole suspected DNS tunneling domains.",
        "Isolate the source host for forensic investigation.",
        "Review proxy logs for data exfiltration payloads in beaconing sessions.",
        "Deploy Suricata/Snort rules for the identified beacon interval patterns."
    ])

risk_score = min(100, risk_score)
statistics["total_connections"] = sum(len(ts) for ts in conn_flows.values())
statistics["total_dns_queries"] = len(dns_queries)
statistics["unique_dst_ips"] = len(set(dst for (_, dst, _) in conn_flows.keys()))

output = {
    "findings": findings,
    "iocs": iocs_list,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "statistics": statistics,
    "follow_up_needed": risk_score >= 50,
    "follow_up_prompt": "Correlate beacon destinations against threat intelligence. Generate firewall blocklist." if risk_score >= 50 else ""
}
print(json.dumps(output, indent=2))
"""

NETWORK_BEACONING_PARAMS = [
    {"name": "log_data", "type": "string", "default": ""},
    {"name": "beacon_jitter_threshold", "type": "float", "default": 0.15},
    {"name": "dns_entropy_threshold", "type": "float", "default": 3.5},
    {"name": "dns_length_threshold", "type": "integer", "default": 20},
    {"name": "min_beacon_count", "type": "integer", "default": 5},
    {"name": "suspicious_ports", "type": "array", "default": [4444, 8080, 8443, 1337, 31337, 9001, 5555]},
    {"name": "watch_ips", "type": "array", "default": []},
]
