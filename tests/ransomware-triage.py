import json, re, sys
from collections import defaultdict
from datetime import datetime

# === PARAMETERS ===
LOG_DATA = '''{{log_data}}'''
FILE_RENAME_THRESHOLD = {{file_rename_threshold}}
KNOWN_EXTENSIONS = {{known_extensions}}

# === MOCK DATA FALLBACK ===
if not LOG_DATA.strip():
    LOG_DATA = """
2026-03-01T11:00:00Z WARN File Activity: C:\\Users\Admin\Documents\report.pdf renamed to C:\\Users\Admin\Documents\report.pdf.encrypted
2026-03-01T11:00:01Z WARN File Activity: C:\\Users\Admin\Documents\financials.xlsx renamed to C:\\Users\Admin\Documents\financials.xlsx.encrypted
2026-03-01T11:00:02Z WARN File Activity: C:\\Users\Admin\Documents\budget.docx renamed to C:\\Users\Admin\Documents\budget.docx.encrypted
2026-03-01T11:00:03Z CRIT Process Execution: vssadmin.exe delete shadows /all /quiet
2026-03-01T11:00:05Z INFO Network Activity: High volume SMB transfer to 10.0.0.50
    """

# === DETECTION ENGINE ===
lines = LOG_DATA.strip().split('\n')
findings = []
iocs = {"ips": [], "domains": [], "hashes": [], "filenames": []}
risk_score = 0
recommendations = []

rename_count = 0
shadow_copy_deleted = False
smb_activity = False

for line in lines:
    lower_line = line.lower()
    
    # Mass renames and known extensions (Sysmon Event 11 XML)
    if "eventid>11</eventid>" in lower_line and ".encrypted</data>" in lower_line:
        rename_count += 1
        for ext in KNOWN_EXTENSIONS:
            if ext.lower() in lower_line:
                iocs["filenames"].append(ext)
                
    # Shadow copy deletion
    if any(cmd in lower_line for cmd in ["vssadmin.exe delete shadows", "wbadmin delete", "bcdedit /set {default}"]):
        shadow_copy_deleted = True
        
    # SMB lateral movement indicator (Sysmon Event 3 XML)
    if "eventid>3</eventid>" in lower_line and ":445</data>" in lower_line:
        smb_activity = True

if rename_count > 0:
    findings.append({"title": "Mass File Renames", "details": f"Observed {rename_count} file rename events, potentially encryption."})
    if iocs["filenames"]:
        findings[-1]["details"] += f" Known ransomware extensions matched: {', '.join(set(iocs['filenames']))}."
        risk_score += 60

if shadow_copy_deleted:
    findings.append({"title": "Shadow Copy Deletion", "details": "Detected commands typically used by ransomware to prevent recovery (vssadmin/wbadmin/bcdedit)."})
    risk_score += 40
    
if smb_activity:
    findings.append({"title": "Anomalous SMB Activity", "details": "High volume SMB transfers detected, possible lateral movement or remote encryption."})
    risk_score += 20

if not findings:
    findings.append({"title": "No Ransomware Activity", "details": "No indicators of ransomware encryption or backup deletion found."})

if risk_score > 0:
    recommendations.extend([
        "Immediately isolate affected endpoints from the network.",
        "Preserve memory and disk artifacts for forensic analysis.",
        "Verify status of offline backups."
    ])

risk_score = min(100, risk_score)
output = {
    "findings": findings,
    "iocs": iocs,
    "recommendations": recommendations,
    "risk_score": risk_score,
    "follow_up_needed": risk_score >= 80,
    "follow_up_prompt": "Ransomware activity confirmed. Do you want to initiate network isolation procedures?" if risk_score >= 80 else ""
}
print(json.dumps(output, indent=2))
