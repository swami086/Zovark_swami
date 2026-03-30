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

# --- DLL Sideloading Investigation Logic ---

# Extract key fields from raw_log
process_match = re.search(r"Process=(\S+)", raw_log)
dll_name_match = re.search(r"loaded\s+(unsigned|signed)\s+DLL\s+(\S+)", raw_log)
dll_path_match = re.search(r"from\s+(C:\\[^\s]+(?:\s+[^\s]+)*?)(?:\s+PID=|\s*$)", raw_log)
pid_match = re.search(r"PID=(\d+)", raw_log)
user_match = re.search(r"User=(\S+)", raw_log)
source_addr_match = re.search(r"SourceAddress=([0-9.]+)", raw_log)

process_name = process_match.group(1) if process_match else ""
dll_signed = dll_name_match.group(1) if dll_name_match else ""
dll_name = dll_name_match.group(2) if dll_name_match else ""
dll_path = dll_path_match.group(1).strip() if dll_path_match else ""
pid = pid_match.group(1) if pid_match else ""
log_user = user_match.group(1) if user_match else ""
source_address = source_addr_match.group(1) if source_addr_match else ""

# Key indicators
is_unsigned = dll_signed == "unsigned"
is_signed = dll_signed == "signed"

# Suspicious paths (not System32, not Windows)
suspicious_paths = ["C:\\Temp", "C:\\Users\\Public", "C:\\ProgramData", "C:\\Users\\"]
is_suspicious_path = any(dll_path.startswith(p) or dll_path == p for p in suspicious_paths)

# System paths (normal)
system_paths = ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\Windows\\"]
is_system_path = any(dll_path.startswith(p) for p in system_paths)

# Known sideloading processes
sideload_processes = ["rundll32.exe", "msiexec.exe", "svchost.exe", "regsvr32.exe", "dllhost.exe"]
is_known_sideload_host = process_name.lower() in sideload_processes

# Risk scoring
if is_unsigned and is_suspicious_path:
    # Strong sideloading indicator: unsigned DLL from suspicious path
    risk_score = 85
    findings.append("CRITICAL: Unsigned DLL '" + dll_name + "' loaded from suspicious path '" + dll_path + "'")
    findings.append("Host process: " + process_name + " (PID=" + pid + ")")
    if is_known_sideload_host:
        risk_score = 88
        findings.append("Process '" + process_name + "' is a known DLL sideloading host")
elif is_unsigned and not is_system_path:
    risk_score = 70
    findings.append("Unsigned DLL loaded from non-system path: " + dll_path)
elif is_signed and is_system_path:
    # Normal: signed DLL from system path
    risk_score = 5
    findings.append("Normal DLL load: signed '" + dll_name + "' from " + dll_path)
elif is_signed:
    risk_score = 10
    findings.append("Signed DLL load from: " + dll_path)
else:
    risk_score = 15
    findings.append("DLL load event with unrecognized pattern")

risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)
if username:
    add_ioc("username", username, "username", username)
if source_address and source_address != source_ip:
    add_ioc("ipv4", source_address, "raw_log", "SourceAddress=" + source_address)
if dll_name and is_unsigned:
    add_ioc("filename", dll_name, "raw_log", "loaded unsigned DLL " + dll_name)

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "dll_sideloading",
    "threat_types": ["dll_sideloading", "dll_hijacking", "defense_evasion"],
    "description": "Detect DLL sideloading — unsigned DLLs loaded from suspicious paths by legitimate processes",
}
