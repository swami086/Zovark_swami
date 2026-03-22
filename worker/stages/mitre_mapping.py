"""MITRE ATT&CK technique mapping for HYDRA investigation types."""

MITRE_MAP = {
    "phishing_investigation": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
        {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
        {"id": "T1204.001", "name": "Malicious Link", "tactic": "Execution"},
    ],
    "ransomware_triage": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    ],
    "brute_force_investigation": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
        {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access"},
    ],
    "c2_communication_hunt": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    ],
    "data_exfiltration_detection": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    ],
    "privilege_escalation_hunt": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
        {"id": "T1134", "name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
    ],
    "lateral_movement_detection": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
        {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution"},
    ],
    "insider_threat_detection": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
        {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"},
        {"id": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    ],
    "network_beaconing": [
        {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
        {"id": "T1573.001", "name": "Symmetric Cryptography", "tactic": "Command and Control"},
    ],
    "cloud_infrastructure_attack": [
        {"id": "T1078.004", "name": "Cloud Accounts", "tactic": "Persistence"},
        {"id": "T1580", "name": "Cloud Infrastructure Discovery", "tactic": "Discovery"},
        {"id": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "Exfiltration"},
    ],
    "supply_chain_compromise": [
        {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access"},
        {"id": "T1195.002", "name": "Compromise Software Supply Chain", "tactic": "Initial Access"},
        {"id": "T1195.001", "name": "Compromise Software Dependencies", "tactic": "Initial Access"},
    ],
}

def get_mitre_techniques(task_type: str) -> list:
    """Get MITRE ATT&CK techniques for a task type."""
    if task_type in MITRE_MAP:
        return MITRE_MAP[task_type]
    normalized = task_type.replace("-", "_")
    if normalized in MITRE_MAP:
        return MITRE_MAP[normalized]
    for key, techniques in MITRE_MAP.items():
        if key in task_type or task_type in key:
            return techniques
    return []

def get_all_tactics() -> list:
    """Get all unique MITRE ATT&CK tactics."""
    tactics = set()
    for techniques in MITRE_MAP.values():
        for t in techniques:
            tactics.add(t["tactic"])
    return sorted(tactics)
