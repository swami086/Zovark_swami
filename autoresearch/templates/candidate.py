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

# --- RDP Tunneling Investigation Logic ---

# Extract key fields from raw_log
# Attack: "RDP connection from 10.16.87.138:4443 to WS-014:3389 User=backup_admin TunnelDetected=true SSHProcess=plink.exe"
# Benign: "RDP connection from 10.169.42.183 to WS-011:3389 User=contractor01 Status=Success NLA=true"

rdp_from_match = re.search(r"RDP connection from ([0-9.]+)(?::(\d+))?", raw_log)
rdp_to_match = re.search(r"to (\S+):(\d+)", raw_log)
user_match = re.search(r"User=(\S+)", raw_log)
tunnel_match = re.search(r"TunnelDetected=(true|false)", raw_log)
ssh_proc_match = re.search(r"SSHProcess=(\S+)", raw_log)
nla_match = re.search(r"NLA=(true|false)", raw_log)
status_match = re.search(r"Status=(\S+)", raw_log)

rdp_source_ip = rdp_from_match.group(1) if rdp_from_match else ""
rdp_source_port = rdp_from_match.group(2) if rdp_from_match and rdp_from_match.group(2) else ""
rdp_dest_host = rdp_to_match.group(1) if rdp_to_match else ""
rdp_dest_port = rdp_to_match.group(2) if rdp_to_match else ""
log_user = user_match.group(1) if user_match else ""
tunnel_detected = tunnel_match.group(1) if tunnel_match else ""
ssh_process = ssh_proc_match.group(1) if ssh_proc_match else ""
nla_enabled = nla_match.group(1) if nla_match else ""
status = status_match.group(1) if status_match else ""

# Key indicators
is_tunnel = tunnel_detected == "true"
has_ssh_process = bool(ssh_process)
has_unusual_port = bool(rdp_source_port) and rdp_source_port not in ("", "3389")
is_normal_rdp = status == "Success" and nla_enabled == "true" and not is_tunnel

# Risk scoring
if is_tunnel and has_ssh_process:
    # RDP tunneling with SSH process detected
    risk_score = 88
    findings.append("CRITICAL: RDP tunneling detected via " + ssh_process + " — source " + rdp_source_ip)
    if has_unusual_port:
        risk_score = 90
        findings.append("Unusual source port: " + rdp_source_port + " (typical tunnel indicator)")
    findings.append("Destination: " + rdp_dest_host + ":" + rdp_dest_port)
elif is_tunnel:
    risk_score = 80
    findings.append("RDP tunnel detected from " + rdp_source_ip)
elif has_unusual_port and not is_normal_rdp:
    risk_score = 60
    findings.append("RDP connection with unusual source port: " + rdp_source_port)
elif is_normal_rdp:
    # Normal: successful RDP with NLA
    risk_score = 10
    findings.append("Normal RDP session: " + rdp_source_ip + " -> " + rdp_dest_host + " (NLA enabled)")
else:
    risk_score = 15
    findings.append("RDP connection event with unrecognized pattern")

risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)
if username:
    add_ioc("username", username, "username", username)
if rdp_source_ip and rdp_source_ip != source_ip:
    add_ioc("ipv4", rdp_source_ip, "raw_log", "RDP from " + rdp_source_ip)

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "rdp_tunneling",
    "threat_types": ["rdp_tunneling", "lateral_movement", "tunnel_abuse"],
    "description": "Detect RDP tunneling — SSH/plink tunnels used to proxy RDP connections",
}
