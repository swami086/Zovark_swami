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

# --- LOLBin Abuse Investigation Logic ---

# Extract key fields from raw_log
process_match = re.search(r"Process=(\S+)", raw_log)
cmdline_match = re.search(r"CommandLine='([^']*)'", raw_log)
user_match = re.search(r"User=(\S+)", raw_log)
pid_match = re.search(r"PID=(\d+)", raw_log)

process_name = process_match.group(1) if process_match else ""
command_line = cmdline_match.group(1) if cmdline_match else ""
log_user = user_match.group(1) if user_match else ""
command_lower = command_line.lower()

# LOLBin abuse indicators
is_certutil = process_name.lower() == "certutil.exe"

# Certutil download pattern: -urlcache -split -f <url>
has_download_flags = "-urlcache" in command_lower and "-f" in command_lower
has_url = bool(re.search(r"https?://", command_line))

# Extract URL from command line
url_match = re.search(r"(https?://[^\s'\"]+)", command_line)
extracted_url = url_match.group(1) if url_match else ""

# Extract IP from URL
url_ip_match = re.search(r"https?://([0-9.]+)", command_line)
url_ip = url_ip_match.group(1) if url_ip_match else ""

# Benign certutil patterns
is_verify = "-verify" in command_lower
is_normal_usage = "Normal" in raw_log or is_verify

# Risk scoring
if is_certutil and has_download_flags and has_url:
    # Classic LOLBin abuse: certutil downloading a file
    risk_score = 88
    findings.append("CRITICAL: certutil.exe used to download file via -urlcache — LOLBin abuse")
    findings.append("Command: " + command_line)
    if extracted_url:
        findings.append("Download URL: " + extracted_url)
elif is_certutil and has_download_flags:
    risk_score = 75
    findings.append("certutil.exe with download flags detected — potential LOLBin abuse")
elif is_certutil and is_normal_usage:
    # Normal certificate operations
    risk_score = 10
    findings.append("Normal certutil usage: " + command_line)
elif is_certutil:
    risk_score = 15
    findings.append("certutil.exe invoked: " + command_line)
else:
    risk_score = 15
    findings.append("Process execution event with unrecognized pattern")

risk_score = min(100, max(0, risk_score))

# Extract IOCs
if source_ip:
    add_ioc("ipv4", source_ip, "source_ip", source_ip)
if username:
    add_ioc("username", username, "username", username)
if url_ip and url_ip != source_ip:
    add_ioc("ipv4", url_ip, "raw_log", "URL IP: " + url_ip)
if extracted_url and has_download_flags:
    add_ioc("url", extracted_url, "raw_log", extracted_url[:60])

print(json.dumps({
    "findings": findings,
    "iocs": iocs,
    "risk_score": risk_score,
    "verdict": "true_positive" if risk_score >= 70 else "suspicious" if risk_score >= 50 else "benign",
    "recommendations": ["Investigate further"]
}))
'''

TEMPLATE_METADATA = {
    "task_type": "lolbin_abuse",
    "threat_types": ["lolbin_abuse", "living_off_the_land", "defense_evasion"],
    "description": "Detect LOLBin abuse — certutil/mshta/regsvr32 used for download/execution",
}
