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

# --- Process Injection Investigation Logic ---

# Extract key fields from raw_log
source_proc_match = re.search(r"SourceProcess=(\S+)", raw_log)
target_proc_match = re.search(r"TargetProcess=(\S+)", raw_log)
api_match = re.search(r"API=(\S+)", raw_log)
target_pid_match = re.search(r"TargetPID=(\d+)", raw_log)
user_match = re.search(r"User=(\S+)", raw_log)
source_addr_match = re.search(r"SourceAddress=([0-9.]+)", raw_log)

source_proc = source_proc_match.group(1) if source_proc_match else ""
target_proc = target_proc_match.group(1) if target_proc_match else ""
api_call = api_match.group(1) if api_match else ""
target_pid = target_pid_match.group(1) if target_pid_match else ""
log_user = user_match.group(1) if user_match else ""
source_address = source_addr_match.group(1) if source_addr_match else ""

# Key indicators
is_remote_thread = api_call == "CreateRemoteThread"
is_normal_thread = api_call == "CreateThread"
is_normal_startup = "Normal service startup" in raw_log or "Normal" in raw_log

# Suspicious source processes (often used for injection)
suspicious_sources = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
is_suspicious_source = source_proc.lower() in suspicious_sources

# Critical target processes (high-value injection targets)
critical_targets = ["lsass.exe", "winlogon.exe", "csrss.exe", "services.exe", "svchost.exe", "explorer.exe"]
is_critical_target = target_proc.lower() in critical_targets

# Normal source process (services.exe starting svchost is normal)
is_services_to_svchost = source_proc.lower() == "services.exe" and target_proc.lower() == "svchost.exe"

# Risk scoring
if is_remote_thread and not is_services_to_svchost:
    # CreateRemoteThread into another process = injection
    risk_score = 88
    findings.append("CRITICAL: CreateRemoteThread detected — " + source_proc + " injecting into " + target_proc)
    findings.append("Target PID: " + target_pid)
    if is_suspicious_source:
        risk_score = 92
        findings.append("Suspicious source process: " + source_proc)
    if is_critical_target:
        risk_score = min(risk_score + 3, 100)
        findings.append("Critical system process targeted: " + target_proc)
elif is_normal_thread and is_normal_startup:
    # Normal: CreateThread in service startup
    risk_score = 5
    findings.append("Normal thread creation: " + source_proc + " -> " + target_proc)
elif is_normal_thread:
    risk_score = 10
    findings.append("CreateThread detected (non-remote): " + source_proc)
else:
    risk_score = 15
    findings.append("Thread/process event with unrecognized pattern")

risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)
if username:
    add_ioc("username", username, "username", username)
if source_address and source_address != source_ip:
    add_ioc("ipv4", source_address, "raw_log", "SourceAddress=" + source_address)

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "process_injection",
    "threat_types": ["process_injection", "code_injection", "defense_evasion"],
    "description": "Detect process injection via CreateRemoteThread into critical system processes",
}
