"""
MUTABLE FILE — The agent modifies this to build and optimize templates.
Contains the template code and metadata for the current task_type.
"""

TEMPLATE_CODE = r'''import json
import re
import hashlib
from collections import Counter
from datetime import datetime

siem_event = json.loads(r"""{{siem_event_json}}""")

findings = []
iocs = []
risk_score = 0

raw_log = str(siem_event.get("raw_log", ""))
source_ip = siem_event.get("source_ip", "")
username = siem_event.get("username", "")
hostname = siem_event.get("hostname", "")
title = str(siem_event.get("title", "")).lower()
rule_name = str(siem_event.get("rule_name", "")).lower()

def add_ioc(ioc_type, value, source_field, snippet=""):
    if value and str(value).strip():
        iocs.append({
            "type": ioc_type,
            "value": str(value).strip(),
            "evidence_refs": [{"source": source_field, "raw_text": (snippet or str(value))[:60]}]
        })

# --- DNS Exfiltration Investigation Logic ---

# Extract key fields from raw_log
# Attack: "DNS query ZXhmaWx0cmF0aW9u.DEV.LOCAL from 10.45.229.165 QueryType=TXT ResponseSize=4096 Entropy=5.8 QueriesInWindow=847"
# Benign: "DNS query www.PROD.COMPANY.COM from 172.73.24.199 QueryType=A ResponseSize=64 Normal lookup"

dns_query_match = re.search(r"DNS query\s+(\S+)", raw_log)
dns_from_match = re.search(r"from\s+([0-9.]+)", raw_log)
query_type_match = re.search(r"QueryType=(\S+)", raw_log)
response_size_match = re.search(r"ResponseSize=(\d+)", raw_log)
entropy_match = re.search(r"Entropy=([0-9.]+)", raw_log)
queries_match = re.search(r"QueriesInWindow=(\d+)", raw_log)

dns_query = dns_query_match.group(1) if dns_query_match else ""
dns_from_ip = dns_from_match.group(1) if dns_from_match else ""
query_type = query_type_match.group(1) if query_type_match else ""
response_size = int(response_size_match.group(1)) if response_size_match else 0
entropy = float(entropy_match.group(1)) if entropy_match else 0.0
queries_in_window = int(queries_match.group(1)) if queries_match else 0

is_normal_lookup = "Normal lookup" in raw_log or "Normal" in raw_log

# Key indicators for exfiltration
is_txt_query = query_type == "TXT"
is_high_entropy = entropy >= 4.0
is_large_response = response_size >= 1024
is_high_volume = queries_in_window >= 100

# Check for base64-like subdomain (high entropy, long label)
subdomain = dns_query.split(".")[0] if "." in dns_query else dns_query
is_base64_like = len(subdomain) > 10 and re.match(r"^[A-Za-z0-9+/=]+$", subdomain)

# Risk scoring
if is_txt_query and is_high_entropy and is_high_volume:
    # Strong DNS exfiltration: TXT queries + high entropy + high volume
    risk_score = 90
    findings.append("CRITICAL: DNS exfiltration detected — high-entropy TXT queries (" + str(queries_in_window) + " in window)")
    findings.append("Query: " + dns_query + " (entropy=" + str(entropy) + ")")
    findings.append("Response size: " + str(response_size) + " bytes")
    if is_base64_like:
        risk_score = 92
        findings.append("Base64-encoded subdomain detected: " + subdomain)
elif is_high_entropy and is_high_volume:
    risk_score = 80
    findings.append("High-entropy DNS queries with high volume — potential exfiltration")
elif is_txt_query and is_high_entropy:
    risk_score = 70
    findings.append("TXT query with high entropy subdomain — suspicious")
elif is_normal_lookup:
    # Normal DNS lookup
    risk_score = 5
    findings.append("Normal DNS lookup: " + dns_query)
elif query_type == "A" and not is_high_entropy:
    risk_score = 10
    findings.append("Standard DNS A record query: " + dns_query)
else:
    risk_score = 15
    findings.append("DNS query event with unrecognized pattern")

risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)
if username:
    add_ioc("username", username, "username", username)
if dns_from_ip and dns_from_ip != source_ip:
    add_ioc("ipv4", dns_from_ip, "raw_log", "DNS from " + dns_from_ip)
if dns_query and is_high_entropy:
    add_ioc("domain", dns_query, "raw_log", "DNS query " + dns_query[:50])

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "dns_exfiltration",
    "threat_types": ["dns_exfiltration", "data_exfiltration", "dns_tunneling"],
    "description": "Detect DNS exfiltration — high-entropy TXT queries with encoded subdomains",
}
