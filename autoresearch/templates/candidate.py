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

# --- PowerShell Obfuscation Investigation Logic ---

# Extract key fields from raw_log
# Attack: "Process=powershell.exe CommandLine='powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A' User=jsmith PID=52425 ParentProcess=explorer.exe SourceAddress=172.102.172.182"
# Benign: "Process=powershell.exe CommandLine='Get-Process | Format-Table' User=admin Signed=true Normal admin script"

process_match = re.search(r"Process=(\S+)", raw_log)
cmdline_match = re.search(r"CommandLine='([^']*)'", raw_log)
user_match = re.search(r"User=(\S+)", raw_log)
pid_match = re.search(r"PID=(\d+)", raw_log)
parent_match = re.search(r"ParentProcess=(\S+)", raw_log)
source_addr_match = re.search(r"SourceAddress=([0-9.]+)", raw_log)
signed_match = re.search(r"Signed=(true|false)", raw_log)

process_name = process_match.group(1) if process_match else ""
command_line = cmdline_match.group(1) if cmdline_match else ""
log_user = user_match.group(1) if user_match else ""
pid = pid_match.group(1) if pid_match else ""
parent_process = parent_match.group(1) if parent_match else ""
source_address = source_addr_match.group(1) if source_addr_match else ""
is_signed = signed_match and signed_match.group(1) == "true"

command_lower = command_line.lower()

# Key indicators
is_powershell = process_name.lower() == "powershell.exe"
has_encoded_flag = "-enc" in command_lower or "-encodedcommand" in command_lower
is_normal_script = "Normal" in raw_log
has_iex = "iex" in command_lower or "invoke-expression" in command_lower
has_download_cradle = "downloadstring" in command_lower or "net.webclient" in command_lower

# Extract the base64 payload
enc_payload_match = re.search(r"-enc\s+(\S+)", command_line, re.IGNORECASE)
enc_payload = enc_payload_match.group(1) if enc_payload_match else ""

# Suspicious parent processes (Office apps, browser = spearphishing indicator)
suspicious_parents = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "iexplore.exe", "chrome.exe"]
has_suspicious_parent = parent_process.lower() in suspicious_parents

# Risk scoring
if is_powershell and has_encoded_flag:
    # Encoded PowerShell = obfuscation
    risk_score = 88
    findings.append("CRITICAL: Encoded PowerShell execution detected — obfuscation indicator")
    findings.append("Encoded payload: " + enc_payload[:40] + ("..." if len(enc_payload) > 40 else ""))
    if has_suspicious_parent:
        risk_score = 93
        findings.append("Spawned by suspicious parent process: " + parent_process + " — possible spearphishing")
    if parent_process:
        findings.append("Parent process: " + parent_process)
elif is_powershell and (has_iex or has_download_cradle):
    risk_score = 82
    findings.append("PowerShell with Invoke-Expression or download cradle detected")
elif is_powershell and is_normal_script and is_signed:
    # Normal: signed admin script
    risk_score = 5
    findings.append("Normal signed PowerShell script: " + command_line[:60])
elif is_powershell and is_normal_script:
    risk_score = 10
    findings.append("Normal PowerShell execution: " + command_line[:60])
elif is_powershell:
    risk_score = 15
    findings.append("PowerShell execution: " + command_line[:60])
else:
    risk_score = 15
    findings.append("Process execution event with unrecognized pattern")

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
    "task_type": "powershell_obfuscation",
    "threat_types": ["powershell_obfuscation", "execution", "defense_evasion"],
    "description": "Detect obfuscated PowerShell — encoded commands, IEX, download cradles",
}

_SIEM_PLACEHOLDER = "{{siem_event_json}}"


def render_template_code(code: str, siem_event: dict) -> tuple[str, str]:
    """Inject SIEM JSON into template source using AST Constant replacement.

    Returns (rendered_code, method) where method is ``ast`` or ``string_fallback``.
    String replace is only used when parse/transform fails (explicit warning logged).
    """
    import ast
    import json as _json
    import logging as _logging

    log = _logging.getLogger(__name__)
    payload = _json.dumps(siem_event, ensure_ascii=False)
    try:
        tree = ast.parse(code)
    except SyntaxError:
        log.warning(
            "template_mutation: syntax error in template — using string placeholder fallback"
        )
        return code.replace(_SIEM_PLACEHOLDER, payload), "string_fallback"

    class _Inject(ast.NodeTransformer):
        def visit_Constant(self, node):
            if isinstance(node.value, str) and _SIEM_PLACEHOLDER in node.value:
                new_val = node.value.replace(_SIEM_PLACEHOLDER, payload)
                return ast.copy_location(ast.Constant(value=new_val), node)
            return node

    try:
        new_tree = ast.fix_missing_locations(_Inject().visit(tree))
        out = ast.unparse(new_tree)
        return out, "ast"
    except Exception as e:
        log.warning(
            "template_mutation: AST transform failed (%s) — string fallback", e
        )
        return code.replace(_SIEM_PLACEHOLDER, payload), "string_fallback"
