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

# --- WMI Lateral Movement Investigation Logic ---

# Extract key fields from raw_log
remote_host_match = re.search(r"remote host\s+(\S+)", raw_log)
cmdline_match = re.search(r"CommandLine='([^']*)'", raw_log)
user_match = re.search(r"User=(\S+)", raw_log)
source_addr_match = re.search(r"SourceAddress=([0-9.]+)", raw_log)

remote_host = remote_host_match.group(1) if remote_host_match else ""
command_line = cmdline_match.group(1) if cmdline_match else ""
log_user = user_match.group(1) if user_match else ""
source_address = source_addr_match.group(1) if source_addr_match else ""

# Key indicators
is_remote_process_create = "process create" in raw_log.lower() and "remote host" in raw_log.lower()
is_local_query = "on localhost" in raw_log.lower() or "localhost" in raw_log.lower()
is_normal_monitoring = "Normal monitoring" in raw_log or "Normal" in raw_log
is_wmi_query = "WMI query" in raw_log

# Suspicious commands in WMI lateral movement
suspicious_commands = ["powershell", "cmd /c", "net user", "whoami", "mimikatz", "-enc", "certutil"]
has_suspicious_cmd = any(sc in command_line.lower() for sc in suspicious_commands) if command_line else False

# Risk scoring
if is_remote_process_create and command_line:
    # WMI process creation on remote host = lateral movement
    risk_score = 88
    findings.append("CRITICAL: WMI remote process creation on " + remote_host + " — lateral movement")
    findings.append("Command executed: " + command_line)
    if has_suspicious_cmd:
        risk_score = 92
        findings.append("Suspicious command pattern detected in remote execution")
elif is_wmi_query and is_local_query and is_normal_monitoring:
    # Normal: WMI query on localhost for monitoring
    risk_score = 5
    findings.append("Normal WMI monitoring query on localhost")
elif is_wmi_query and is_local_query:
    risk_score = 10
    findings.append("WMI query on localhost")
elif is_wmi_query:
    risk_score = 15
    findings.append("WMI query event")
else:
    risk_score = 15
    findings.append("WMI event with unrecognized pattern")

risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)
if username:
    add_ioc("username", username, "username", username)
if source_address and source_address != source_ip:
    add_ioc("ipv4", source_address, "raw_log", "SourceAddress=" + source_address)
if remote_host and is_remote_process_create:
    add_ioc("hostname", remote_host, "raw_log", "remote host " + remote_host)

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "wmi_lateral",
    "threat_types": ["wmi_lateral_movement", "lateral_movement", "remote_execution"],
    "description": "Detect WMI-based lateral movement — remote process creation on other hosts",
}
