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

# --- Kerberoasting Investigation Logic ---

# Extract key fields from raw_log
encryption_match = re.search(r"TicketEncryptionType=(0x[0-9a-fA-F]+)", raw_log)
event_id_match = re.search(r"EventID=(\d+)", raw_log)
service_match = re.search(r"ServiceName=(\S+)", raw_log)
status_match = re.search(r"Status=(0x[0-9a-fA-F]+)", raw_log)
client_addr_match = re.search(r"ClientAddress=([0-9.]+)", raw_log)
target_user_match = re.search(r"TargetUserName=(\S+)", raw_log)

encryption_type = encryption_match.group(1) if encryption_match else ""
event_id = event_id_match.group(1) if event_id_match else ""
service_name = service_match.group(1) if service_match else ""
status_code = status_match.group(1) if status_match else ""
client_address = client_addr_match.group(1) if client_addr_match else ""
target_user = target_user_match.group(1) if target_user_match else ""

# Determine if RC4 encryption (weak, kerberoasting indicator)
is_rc4 = encryption_type.lower() == "0x17"
is_aes256 = encryption_type.lower() == "0x12"

# Determine if TGS request (EventID 4769)
is_tgs_request = event_id == "4769"

# Determine if service is krbtgt (normal TGT renewal, not suspicious)
is_krbtgt = service_name.lower().startswith("krbtgt")

# Determine if service is a real SPN (MSSQLSvc, HTTP, DNS, HOST, FTP, LDAP, CIFS, etc.)
spn_pattern = re.compile(r"^(MSSQLSvc|HTTP|DNS|HOST|FTP|LDAP|CIFS|SMTP|POP|IMAP|TERMSRV|WSMAN|RPCSS|MSSQL|SIP|exchangeMDB|exchangeRFR|exchangeAB)/", re.IGNORECASE)
is_spn_service = bool(spn_pattern.match(service_name))

# Risk scoring logic
if is_rc4 and is_tgs_request and not is_krbtgt:
    # Strong kerberoasting indicator: RC4 + TGS request + non-krbtgt service
    risk_score = 88
    findings.append("CRITICAL: TGS request with RC4 encryption (0x17) detected — strong kerberoasting indicator")
    findings.append("Service targeted: " + service_name)
    if is_spn_service:
        risk_score = 90
        findings.append("Target is a known SPN service type — high confidence kerberoasting")
elif is_rc4 and not is_krbtgt:
    # RC4 but not TGS — still suspicious
    risk_score = 65
    findings.append("RC4 encryption detected on non-krbtgt service — potential kerberoasting")
elif is_aes256 and is_krbtgt:
    # Normal: AES256 + krbtgt = routine TGT renewal
    risk_score = 10
    findings.append("Normal Kerberos authentication: AES256 encryption with krbtgt service")
elif is_aes256:
    # AES256 but non-krbtgt — normal service access
    risk_score = 15
    findings.append("Normal Kerberos service access with AES256 encryption")
else:
    # Unknown pattern
    risk_score = 20
    findings.append("Kerberos event with unrecognized encryption/service pattern")

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)

if username:
    add_ioc("username", username, "username", username)

# Extract IPs from raw_log
if client_address and client_address != source_ip:
    add_ioc("ipv4", client_address, "raw_log", "ClientAddress=" + client_address)

# Extract ServiceName as IOC if suspicious
if service_name and not is_krbtgt and is_rc4:
    add_ioc("service_principal", service_name, "raw_log", "ServiceName=" + service_name)

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": min(100, max(0, risk_score)),
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "kerberoasting",
    "threat_types": ["kerberoasting", "kerberos_tgs_anomaly"],
    "description": "Detect Kerberos TGS request anomalies indicative of Kerberoasting",
}
