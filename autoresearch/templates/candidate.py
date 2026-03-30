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

# --- DCSync Investigation Logic ---

# Extract key fields from raw_log
event_id_match = re.search(r"EventID=(\d+)", raw_log)
properties_match = re.search(r"Properties=(\S+)", raw_log)
subject_user_match = re.search(r"SubjectUserName=(\S+)", raw_log)
subject_domain_match = re.search(r"SubjectDomainName=(\S+)", raw_log)
source_addr_match = re.search(r"SourceAddress=([0-9.]+)", raw_log)

event_id = event_id_match.group(1) if event_id_match else ""
properties = properties_match.group(1) if properties_match else ""
subject_user = subject_user_match.group(1) if subject_user_match else ""
subject_domain = subject_domain_match.group(1) if subject_domain_match else ""
source_address = source_addr_match.group(1) if source_addr_match else ""

# Key indicators
is_replication_event = event_id == "4662"
has_replication_properties = "Replicating-Directory-Changes" in properties
is_machine_account = subject_user.endswith("$")
is_normal_replication = "Normal replication" in raw_log

# Risk scoring
if is_replication_event and has_replication_properties and not is_machine_account:
    # DCSync attack: replication request from non-DC (user account, not machine account)
    risk_score = 92
    findings.append("CRITICAL: Directory replication request from non-machine account '" + subject_user + "' — DCSync attack indicator")
    findings.append("Domain: " + subject_domain)
    findings.append("Properties: " + properties + " — used by mimikatz/impacket for credential theft")
elif is_replication_event and is_machine_account:
    # Normal: machine account (DC) doing replication
    risk_score = 10
    findings.append("Normal AD replication from domain controller account: " + subject_user)
elif is_normal_replication:
    # Explicitly marked as normal
    risk_score = 5
    findings.append("Normal replication cycle detected")
else:
    risk_score = 20
    findings.append("Directory access event with unrecognized pattern")

risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)
if username:
    add_ioc("username", username, "username", username)
if source_address and source_address != source_ip:
    add_ioc("ipv4", source_address, "raw_log", "SourceAddress=" + source_address)
if subject_user and not is_machine_account and has_replication_properties:
    add_ioc("username", subject_user, "raw_log", "SubjectUserName=" + subject_user)

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "dcsync",
    "threat_types": ["dcsync", "credential_dumping", "ad_replication_abuse"],
    "description": "Detect DCSync attacks — directory replication requests from non-DC accounts",
}
