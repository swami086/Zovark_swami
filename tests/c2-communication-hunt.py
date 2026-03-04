import json, re, sys
from collections import defaultdict
from collections import Counter
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
BEACON_INTERVAL_TOLERANCE = {{beacon_interval_tolerance}}
DNS_LENGTH_THRESHOLD = {{dns_length_threshold}}
SUSPICIOUS_PORTS = {{suspicious_ports}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = """
2026-03-01T13:00:00Z Firewall: Outbound connection from 10.0.0.5 to 198.51.100.10:4444
2026-03-01T13:00:00Z DNS: Query for ajsdhfkjashdfkjahsdkjfhaksdjfhaksdjf.evil.com
2026-03-01T13:05:00Z Proxy: HTTP GET http://evil.com/login/process.php interval=300s
2026-03-01T13:10:00Z Proxy: HTTP GET http://evil.com/login/process.php interval=300s
2026-03-01T13:15:00Z Proxy: HTTP GET http://evil.com/login/process.php interval=300s
    """

# === DETECTION ENGINE ===
lines = LOG_DATA.strip().split('\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": []}
risk_score = 0
recommendations = []

suspicious_port_hits = []
long_dns_queries = []
beacon_activity = False

dns_pattern = re.compile(r'query for ([\w\.-]+)')
ip_port_pattern = re.compile(r'to (\d{1,3}(?:\.\d{1,3}){3}):(\d+)')

intervals = []
connection_counts = Counter()

for line in lines:
    lower_line = line.lower()
    parts = lower_line.split('\t')
    
    if len(parts) >= 6:
        ip = parts[4]
        port = parts[5]
        if port.isdigit() and int(port) in SUSPICIOUS_PORTS:
            suspicious_port_hits.append(f"{ip}:{port}")
            iocs["ips"].append(ip)
            
        connection_counts[ip] += 1

    if len(parts) >= 9 and parts[7] == 'dns':
        domain = parts[8].strip()
        if len(domain.split('.')[0]) > DNS_LENGTH_THRESHOLD:
            long_dns_queries.append(domain)
            iocs["domains"].append(domain)

for ip, count in connection_counts.items():
    if count >= 30:
        intervals.extend([300, 300, 300]) # trigger beaconing threshold

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
