"""Enrichment tools — MITRE mapping, known-bad lookup, correlation, institutional knowledge."""
import json
import os
from datetime import datetime


# --- MITRE ATT&CK mapping (subset of commonly encountered techniques) ---
MITRE_TECHNIQUES = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries may use brute force techniques to gain access to accounts."},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access", "description": "Adversaries may guess passwords to attempt access to accounts."},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access", "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts."},
    "T1110.004": {"name": "Credential Stuffing", "tactic": "Credential Access", "description": "Adversaries may use credentials obtained from breach dumps to gain access."},
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "description": "Adversaries may send phishing messages to gain access to victim systems."},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access", "description": "Adversaries may send spearphishing emails with a malicious attachment."},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access", "description": "Adversaries may send spearphishing emails with a malicious link."},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries may encrypt data on target systems to interrupt availability."},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact", "description": "Adversaries may delete or remove built-in OS data and turn off services designed to aid in system recovery."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "description": "Adversaries may steal data by exfiltrating it over a different protocol than the existing command and control channel."},
    "T1048.001": {"name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "tactic": "Exfiltration", "description": "Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol."},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries may communicate using OSI application layer protocols."},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control", "description": "Adversaries may communicate using application layer protocols associated with web traffic."},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control", "description": "Adversaries may communicate using the DNS application layer protocol."},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access", "description": "Adversaries may attempt to subvert Kerberos authentication."},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access", "description": "Adversaries may abuse Kerberos TGS ticket requests to extract service account hashes for offline cracking."},
    "T1558.001": {"name": "Golden Ticket", "tactic": "Credential Access", "description": "Adversaries who have the KRBTGT account password hash may forge Kerberos TGTs."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Adversaries may attempt to dump credentials from the OS."},
    "T1003.006": {"name": "DCSync", "tactic": "Credential Access", "description": "Adversaries may attempt to replicate domain controller data using directory replication services."},
    "T1574": {"name": "Hijack Execution Flow", "tactic": "Persistence", "description": "Adversaries may execute their own payload by hijacking the way an OS runs programs."},
    "T1574.002": {"name": "DLL Side-Loading", "tactic": "Persistence", "description": "Adversaries may execute their own malicious payloads by side-loading DLLs."},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion", "description": "Adversaries may bypass process/signature defenses by proxying execution of malicious content with signed binaries."},
    "T1218.001": {"name": "Compiled HTML File", "tactic": "Defense Evasion", "description": "Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code."},
    "T1218.005": {"name": "Mshta", "tactic": "Defense Evasion", "description": "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files."},
    "T1218.011": {"name": "Rundll32", "tactic": "Defense Evasion", "description": "Adversaries may abuse rundll32.exe to proxy execution of malicious code."},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "description": "Adversaries may inject code into processes to evade process-based defenses."},
    "T1055.001": {"name": "Dynamic-link Library Injection", "tactic": "Defense Evasion", "description": "Adversaries may inject DLLs into processes to evade process-based defenses."},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution", "description": "Adversaries may abuse WMI to execute malicious commands and payloads."},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections."},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "description": "Adversaries may use Valid Accounts to log into a computer using RDP."},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "description": "Adversaries may use Valid Accounts to interact with a remote network share using SMB."},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement", "description": "Adversaries may use Valid Accounts to interact with remote systems using WinRM."},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries may abuse command and script interpreters to execute commands."},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "description": "Adversaries may abuse PowerShell commands and scripts for execution."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion", "description": "Adversaries may obtain and abuse credentials of existing accounts."},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "description": "Adversaries may circumvent mechanisms designed to control elevated privileges."},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "description": "Adversaries may exploit software vulnerabilities to escalate privileges."},
    "T1056": {"name": "Input Capture", "tactic": "Collection", "description": "Adversaries may use methods of capturing user input to obtain credentials or collect information."},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "Initial Access", "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt."},
    "T1568": {"name": "Dynamic Resolution", "tactic": "Command and Control", "description": "Adversaries may dynamically establish connections to C2 infrastructure to evade common detections."},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "Command and Control", "description": "Adversaries may make use of DGAs to dynamically identify a destination domain for C2 traffic."},
}


def map_mitre(technique_ids: list) -> list:
    """Map MITRE ATT&CK technique IDs to names, tactics, descriptions."""
    if not technique_ids:
        return []
    results = []
    for tid in technique_ids:
        tid = str(tid).strip()
        if tid in MITRE_TECHNIQUES:
            entry = MITRE_TECHNIQUES[tid].copy()
            entry["technique_id"] = tid
            results.append(entry)
        else:
            results.append({"technique_id": tid, "name": "Unknown", "tactic": "Unknown", "description": f"Technique {tid} not in local database"})
    return results


# --- Known-bad IOC database (local, minimal for air-gap) ---
KNOWN_BAD_IPS = {
    "185.220.101.45": "tor_exit_node",
    "185.220.101.46": "tor_exit_node",
    "185.220.101.47": "tor_exit_node",
    "45.155.205.233": "known_scanner",
    "194.26.29.102": "known_scanner",
    "198.51.100.77": "c2_infrastructure",
}

KNOWN_BAD_DOMAINS = {
    "evil-cdn.net": "malware_distribution",
    "evil-login.com": "phishing",
    "company-secure-login.com": "phishing",
}


def lookup_known_bad(value: str, ioc_type: str) -> dict:
    """Check IOC against local known-bad list."""
    result = {"is_known_bad": False, "category": None, "source": "local_threat_intel"}

    if ioc_type in ("ipv4", "ip"):
        if value in KNOWN_BAD_IPS:
            result["is_known_bad"] = True
            result["category"] = KNOWN_BAD_IPS[value]
    elif ioc_type in ("domain", "hostname"):
        value_lower = value.lower()
        if value_lower in KNOWN_BAD_DOMAINS:
            result["is_known_bad"] = True
            result["category"] = KNOWN_BAD_DOMAINS[value_lower]
    elif ioc_type == "hash":
        result["note"] = "hash_lookup_not_implemented"

    return result


def correlate_with_history(ioc_values: list, lookback_hours: int, history_context: dict) -> dict:
    """Check if IOCs appeared in recent investigations. Uses pre-loaded history_context."""
    result = {
        "related_investigations": [],
        "kill_chain_stage": "unknown",
        "escalation_recommended": False,
        "correlation_count": 0,
    }

    if not ioc_values:
        return result

    history_context = history_context or {}
    investigations = history_context.get("investigations", [])

    # Find investigations that share IOCs
    related = []
    # Handle both plain string IOCs and IOC dicts with "value" key
    ioc_set = set()
    for v in ioc_values:
        if isinstance(v, dict):
            ioc_set.add(str(v.get("value", "")))
        else:
            ioc_set.add(str(v))
    ioc_set.discard("")

    for inv in investigations:
        # Check source_ip, dest_ip, username, and any IOC fields
        inv_iocs = set()
        for field in ("source_ip", "dest_ip", "username", "hostname"):
            val = inv.get(field, "")
            if val:
                inv_iocs.add(str(val))

        # Check nested IOCs
        for ioc in inv.get("iocs", []):
            if isinstance(ioc, dict):
                inv_iocs.add(str(ioc.get("value", "")))
            elif isinstance(ioc, str):
                inv_iocs.add(ioc)

        overlap = ioc_set & inv_iocs
        if overlap:
            related.append({
                "task_type": inv.get("task_type", "unknown"),
                "risk_score": inv.get("risk_score", 0),
                "timestamp": inv.get("timestamp", ""),
                "shared_iocs": list(overlap),
            })

    tenant_id = history_context.get("tenant_id", "")
    if tenant_id and os.environ.get("ZOVARK_SURREAL_ENABLED", "").lower() in ("1", "true", "yes") and ioc_set:
        try:
            from surreal_graph import surreal_entity_reachability_sync

            max_hops = max(1, min(8, (lookback_hours // 24) or 3))
            extra_ids = surreal_entity_reachability_sync(tenant_id, list(ioc_set), max_hops)
            seen_inv = {r.get("investigation_id") for r in related if r.get("investigation_id")}
            for iid in extra_ids:
                if not iid or iid in seen_inv:
                    continue
                related.append({
                    "task_type": "graph_reachability",
                    "risk_score": 0,
                    "timestamp": "",
                    "shared_iocs": list(ioc_set)[:8],
                    "investigation_id": iid,
                })
                seen_inv.add(iid)
        except Exception:
            pass

    result["related_investigations"] = related
    result["correlation_count"] = len(related)

    # Kill chain stage assessment based on attack progression
    if related:
        attack_types = [r["task_type"] for r in related]
        stage = _assess_kill_chain(attack_types)
        result["kill_chain_stage"] = stage

    # Escalation recommendation
    if len(related) >= 2:
        result["escalation_recommended"] = True
    elif any(r.get("risk_score", 0) >= 80 for r in related):
        result["escalation_recommended"] = True

    return result


def _assess_kill_chain(attack_types: list) -> str:
    """Determine kill chain stage from attack type progression."""
    stages = {
        "reconnaissance": ["port_scan", "network_scan", "vulnerability_scan"],
        "initial_access": ["phishing", "phishing_investigation", "exploit", "supply_chain"],
        "execution": ["lolbin_abuse", "powershell_obfuscation", "process_injection", "wmi_lateral"],
        "persistence": ["dll_sideloading", "registry_modification", "scheduled_task"],
        "lateral_movement": ["lateral_movement", "lateral_movement_detection", "rdp_tunneling", "pass_the_hash"],
        "exfiltration": ["data_exfiltration", "data_exfiltration_detection", "dns_exfiltration"],
    }
    type_set = set(t.lower() for t in attack_types)
    # Return the most advanced stage seen
    for stage in reversed(list(stages.keys())):
        if any(t in type_set for t in stages[stage]):
            return stage
    if any("brute" in t or "credential" in t or "kerberos" in t or "golden" in t or "dcsync" in t for t in type_set):
        return "credential_access"
    return "unknown"


def lookup_institutional_knowledge(entities: list, knowledge_base: dict) -> dict:
    """Check if entities have analyst-provided baselines or environmental context."""
    result = {
        "known_entities": [],
        "baselines": [],
        "analyst_notes": [],
        "has_context": False,
    }

    if not entities or not knowledge_base:
        return result

    for entity in entities:
        entity_str = str(entity)
        if entity_str in knowledge_base:
            info = knowledge_base[entity_str]
            result["has_context"] = True
            result["known_entities"].append({
                "entity": entity_str,
                "description": info.get("description", ""),
                "expected_behavior": info.get("expected_behavior", ""),
            })
            if info.get("hours_active"):
                result["baselines"].append({
                    "entity": entity_str,
                    "baseline_description": info.get("expected_behavior", ""),
                    "hours_active": info.get("hours_active", ""),
                })
            if info.get("analyst_notes"):
                result["analyst_notes"].append(info["analyst_notes"])

    return result
