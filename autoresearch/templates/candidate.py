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

# --- Golden Ticket Investigation Logic ---

# Extract key fields from raw_log
encryption_match = re.search(r"TicketEncryptionType=(0x[0-9a-fA-F]+)", raw_log)
event_id_match = re.search(r"EventID=(\d+)", raw_log)
service_match = re.search(r"ServiceName=(\S+)", raw_log)
status_match = re.search(r"Status=(0x[0-9a-fA-F]+)", raw_log)
client_addr_match = re.search(r"ClientAddress=([0-9.]+)", raw_log)
target_user_match = re.search(r"TargetUserName=(\S+)", raw_log)
ticket_options_match = re.search(r"TicketOptions=(0x[0-9a-fA-F]+)", raw_log)
lifetime_match = re.search(r"Lifetime=(\d+)h", raw_log)

encryption_type = encryption_match.group(1) if encryption_match else ""
event_id = event_id_match.group(1) if event_id_match else ""
service_name = service_match.group(1) if service_match else ""
status_code = status_match.group(1) if status_match else ""
client_address = client_addr_match.group(1) if client_addr_match else ""
target_user = target_user_match.group(1) if target_user_match else ""
ticket_options = ticket_options_match.group(1) if ticket_options_match else ""
lifetime_hours = int(lifetime_match.group(1)) if lifetime_match else 0

# Determine encryption type
is_rc4 = encryption_type.lower() == "0x17"
is_aes256 = encryption_type.lower() == "0x12"

# Determine if TGT request (EventID 4768 — golden ticket uses TGT, not TGS)
is_tgt_request = event_id == "4768"

# Determine if service is krbtgt (golden ticket targets krbtgt)
is_krbtgt = service_name.lower().startswith("krbtgt")

# Abnormal ticket lifetime (normal is ~10h, golden ticket often 87600h = 10 years)
is_abnormal_lifetime = lifetime_hours > 24

# Suspicious ticket options (0x50800000 = forwardable + renewable + other flags)
has_suspicious_options = ticket_options != "" and ticket_options != "0x0"

# Risk scoring logic for golden ticket
indicators = 0

if is_rc4 and is_tgt_request and is_krbtgt:
    # Core golden ticket pattern: RC4 + TGT request + krbtgt service
    risk_score = 85
    indicators += 3
    findings.append("CRITICAL: TGT request with RC4 encryption (0x17) targeting krbtgt — golden ticket indicator")

    if is_abnormal_lifetime:
        risk_score += 5
        indicators += 1
        findings.append("Abnormal ticket lifetime: " + str(lifetime_hours) + "h (normal ~10h) — forged TGT indicator")

    if has_suspicious_options:
        risk_score += 3
        indicators += 1
        findings.append("Suspicious TicketOptions: " + ticket_options + " — indicates forwardable/renewable forged ticket")

elif is_aes256 and is_krbtgt:
    # Normal: AES256 + krbtgt = routine TGT request
    risk_score = 10
    findings.append("Normal TGT request: AES256 encryption with krbtgt service — routine authentication")

elif is_rc4 and not is_krbtgt:
    # RC4 on non-krbtgt — could be kerberoasting, not golden ticket
    risk_score = 40
    findings.append("RC4 encryption on non-krbtgt service — may indicate kerberoasting, not golden ticket")

elif is_aes256 and not is_krbtgt:
    # Normal service access
    risk_score = 15
    findings.append("Normal service access with AES256 encryption")

else:
    # Unknown pattern
    risk_score = 20
    findings.append("Kerberos event with unrecognized pattern")

# Cap risk score
risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)

if username:
    add_ioc("username", username, "username", username)

# Extract client address from raw_log
if client_address and client_address != source_ip:
    add_ioc("ipv4", client_address, "raw_log", "ClientAddress=" + client_address)

# Extract domain from service name if golden ticket detected
if is_krbtgt and is_rc4 and "/" in service_name:
    domain = service_name.split("/", 1)[1]
    add_ioc("domain", domain, "raw_log", "ServiceName=" + service_name)

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "golden_ticket",
    "threat_types": ["golden_ticket", "kerberos_tgt_forgery"],
    "description": "Detect forged Kerberos TGT (Golden Ticket) attacks via RC4 encryption and abnormal ticket lifetimes",
}
