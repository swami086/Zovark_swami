"""
HYDRA DPO Prompt Library

Two versions of each prompt:
- FULL_*: Used for Kimi API calls (no token limit)
- COMPACT_*: Used for training dataset (<=600 token prompt budget)
"""

# ─── SYSTEM PROMPTS ───────────────────────────────────────────────

FULL_SYSTEM = """You are an elite Tier-3 Security Operations Center (SOC) Lead Analyst \
with deep expertise in the MITRE ATT&CK framework, forensic log analysis, \
and Python scripting for security automation.

Your code will be executed in a restricted, air-gapped Docker sandbox \
with the following hard constraints:
- No network sockets or HTTP requests
- No shell execution (subprocess, os.system, os.popen)
- No dynamic imports (importlib, __import__)
- No eval() or exec()
- No file system writes

Permitted standard libraries only: re, json, datetime, collections, \
hashlib, ipaddress, base64, binascii, struct, math, statistics

You must output your analysis strictly in the JSON formats specified \
in each request. Do not include markdown formatting, code fences, \
or any explanation outside the JSON object."""


COMPACT_SYSTEM = """You are a Tier-3 SOC analyst expert in MITRE ATT&CK and Python security scripting.

Sandbox constraints: No network, no subprocess, no eval/exec, no dynamic imports, no file writes.
Allowed libs: re, json, datetime, collections, hashlib, ipaddress, base64, binascii.
Output: JSON only, no markdown."""


# ─── PROMPT 1: ALERT GENERATION ───────────────────────────────────

ALERT_GENERATION = """Generate a highly realistic raw SIEM alert JSON payload for:

Technique: {ttp_id} - {ttp_name}
Environment: {environment}
Difficulty: {difficulty}

Difficulty definitions:
- easy: Single clear indicator, obvious malicious signal
- medium: Multiple indicators, some benign-looking traffic mixed in
- hard: Attacker using evasion, low-and-slow, legitimate tool abuse
- expert: Living-off-the-land, no malware, pure behavioral anomaly

Requirements:
- Realistic synthetic RFC-1918 IPs and hostnames (e.g., CORP-WKS-047)
- Timestamp within last 30 days
- Full raw_log as the source system would produce it
- For hard/expert: include plausible benign noise

Output ONLY valid JSON:
{{
  "alert_id": "synth-{ttp_id}-{difficulty}-001",
  "timestamp": "ISO8601",
  "severity": "critical|high|medium|low",
  "title": "Brief alert title",
  "source_system": "Windows Security Log|AWS CloudTrail|Zeek|Sysmon|etc",
  "environment": "{environment}",
  "ttp_id": "{ttp_id}",
  "ttp_name": "{ttp_name}",
  "difficulty": "{difficulty}",
  "raw_log": {{
    "EventID": "...",
    "ProcessName": "...",
    "CommandLine": "...",
    "SourceIP": "...",
    "DestIP": "...",
    "User": "...",
    "Hostname": "...",
    "AdditionalFields": {{}}
  }}
}}"""


# ─── PROMPT 2: INVESTIGATION ATTEMPT ──────────────────────────────

FULL_INVESTIGATION = """Review the following SIEM alert and investigate it as an automated SOC system.

Alert:
{alert_json}

Your task:
1. Analyze whether this is a true positive, false positive, or inconclusive
2. Write a standalone Python 3 investigation script

Code constraints (sandbox-enforced):
- Alert is passed as a dict named alert_data
- Use only: re, json, datetime, collections, hashlib, ipaddress, base64, binascii
- Do NOT use: eval, exec, subprocess, socket, importlib, requests
- Function signature: def investigate_alert(alert_data: dict) -> dict
- Always use .get() for dict access
- Return dict must contain exactly:
    status: "true_positive" | "false_positive" | "inconclusive"
    risk_score: integer 0-100
    extracted_entities: list of strings
    mitre_techniques: list of technique IDs
    confidence: "high" | "medium" | "low"
    summary: string (2-3 sentences)
    indicators_of_compromise: list of dicts with keys: type, value, malicious

Output ONLY valid JSON:
{{
  "chain_of_thought": "Step-by-step reasoning",
  "python_code": "def investigate_alert(alert_data: dict) -> dict:\\n    ..."
}}"""


COMPACT_INVESTIGATION = """Investigate this SIEM alert. Write a Python function.

Alert:
{alert_json}

Function: def investigate_alert(alert_data: dict) -> dict
Use .get() for all dict access. No eval/exec/subprocess/socket/importlib.
Allowed: re, json, datetime, collections, hashlib, ipaddress, base64, binascii.
Return: status, risk_score, extracted_entities, mitre_techniques, confidence, summary, indicators_of_compromise.

Output JSON: {{"chain_of_thought": "reasoning", "python_code": "def investigate_alert(alert_data: dict) -> dict:\\n    ..."}}"""


# ─── PROMPT 3: ERROR CORRECTION ───────────────────────────────────

ERROR_CORRECTION = """Your previous investigation code failed in the sandbox.

Original Alert:
{alert_json}

Failed Code:
{failed_code}

Sandbox Error:
{error_traceback}

Diagnose the failure. Common causes:
- Hallucinated import (pandas, numpy, requests — not permitted)
- KeyError (always use .get())
- Regex syntax error
- Missing required return keys
- Incorrect return types

Fix the code. Preserve investigation logic unless the error is logical.

Output ONLY valid JSON:
{{
  "chain_of_thought": "Diagnosis and corrected reasoning",
  "python_code": "def investigate_alert(alert_data: dict) -> dict:\\n    ..."
}}"""


# ─── PROMPT 4: LLM-AS-JUDGE ──────────────────────────────────────

JUDGE = """You are a SOC QA Auditor reviewing automated investigation output.

Original Alert:
{alert_json}

MITRE Technique: {ttp_id} - {ttp_name}

Known Ground Truth Indicators:
{ground_truth_indicators}

Script Output:
{sandbox_output}

Evaluate:
1. VERDICT ACCURACY: Is status correct for this alert?
2. ENTITY EXTRACTION: All malicious entities found? False extractions?
3. MITRE MAPPING: Technique IDs correct and complete?
4. HALLUCINATION CHECK: Any IOCs fabricated (not in raw_log)? AUTO FAIL.
5. RISK SCORE: Appropriate for severity and difficulty?

Output ONLY valid JSON:
{{
  "is_correct": true/false,
  "verdict_accurate": true/false,
  "entities_complete": true/false,
  "hallucination_detected": true/false,
  "risk_score_appropriate": true/false,
  "reasoning": "2-3 sentence assessment",
  "missed_indicators": ["list"],
  "fabricated_indicators": ["list"]
}}

Auto-fail (is_correct: false) if:
- hallucination_detected is true
- verdict wrong on unambiguous alert
- extracted_entities empty on true_positive
- risk_score below 60 on critical severity"""


# ─── PROMPT 5: AST MUTATION ───────────────────────────────────────

MUTATION = """You are a code mutation engine generating DPO training data.

This Python function correctly investigates a security alert:

{golden_code}

Apply exactly this mutation: {mutation_type}

Mutations:
- VERDICT_FLIP: Change status from TP->FP or FP->TP. Leave logic intact.
- ENTITY_MISS: Break entity extraction (wrong regex or field).
- MITRE_WRONG: Return incorrect or empty mitre_techniques.
- RISK_INVERT: Flip risk_score to opposite end (>50-><30, <50->70).
- CONFIDENCE_WRONG: Return low on clear TP, high on inconclusive.

Rules:
- Minimal change only
- Must be syntactically valid Python
- Must execute without crashing
- No comments explaining the mutation
- Keep function signature unchanged

Output ONLY valid JSON:
{{
  "mutation_type": "{mutation_type}",
  "mutation_description": "One sentence: what was changed",
  "mutated_code": "def investigate_alert(alert_data: dict) -> dict:\\n    ..."
}}"""


# ─── PROMPT 6: BASELINE BENCHMARK ────────────────────────────────

BASELINE = """You are a security analyst. Investigate the following SIEM alert.

Alert:
{alert_json}

Write a Python function to investigate this alert.

The function must:
- Be named investigate_alert
- Accept a single dict argument named alert_data
- Return a dict with keys: status, risk_score, extracted_entities,
  mitre_techniques, confidence, summary, indicators_of_compromise

Output ONLY valid JSON:
{{
  "chain_of_thought": "your reasoning",
  "python_code": "def investigate_alert(alert_data: dict) -> dict:\\n    ..."
}}"""


# ─── MUTATION TYPES ───────────────────────────────────────────────

MUTATION_TYPES = [
    "VERDICT_FLIP",
    "ENTITY_MISS",
    "MITRE_WRONG",
    "RISK_INVERT",
    "CONFIDENCE_WRONG",
]


# ─── IOC REGEX PATTERNS ─────────────────────────────────────────────

IOC_REGEX_PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "ipv6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk)\b',
    "url": r'https?://[^\s<>"\']+',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "mac_address": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
    "base64_blob": r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    "windows_path": r'[A-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*',
    "unix_path": r'(?:/[a-zA-Z0-9._-]+){2,}',
    "registry_key": r'(?:HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s]+',
}


# ─── TECHNIQUE → IOC MAP ────────────────────────────────────────────

TECHNIQUE_IOC_MAP = {
    "brute_force": {
        "required_iocs": ["ipv4", "email"],
        "optional_iocs": ["domain", "url"],
        "description": "Authentication attacks — extract source IPs, targeted accounts, timestamps",
    },
    "malware": {
        "required_iocs": ["md5", "sha256", "ipv4", "domain"],
        "optional_iocs": ["url", "registry_key", "windows_path", "unix_path"],
        "description": "Malware execution — extract hashes, C2 IPs/domains, file paths, registry persistence",
    },
    "phishing": {
        "required_iocs": ["email", "url", "domain", "ipv4"],
        "optional_iocs": ["md5", "sha256"],
        "description": "Phishing campaigns — extract sender addresses, malicious URLs, payload hashes",
    },
    "exfiltration": {
        "required_iocs": ["ipv4", "domain", "url"],
        "optional_iocs": ["base64_blob", "email"],
        "description": "Data exfiltration — extract destination IPs, domains, encoded payloads",
    },
    "lateral_movement": {
        "required_iocs": ["ipv4", "mac_address"],
        "optional_iocs": ["domain", "windows_path", "registry_key"],
        "description": "Lateral movement — extract internal IPs, compromised hosts, service accounts",
    },
    "command_and_control": {
        "required_iocs": ["ipv4", "domain", "url"],
        "optional_iocs": ["base64_blob", "cve"],
        "description": "C2 beaconing — extract callback IPs/domains, beacon intervals, encoded payloads",
    },
    "privilege_escalation": {
        "required_iocs": ["ipv4", "cve", "windows_path"],
        "optional_iocs": ["registry_key", "unix_path"],
        "description": "Privilege escalation — extract exploit CVEs, modified files, escalated accounts",
    },
    "defense_evasion": {
        "required_iocs": ["md5", "sha256", "base64_blob"],
        "optional_iocs": ["windows_path", "registry_key", "unix_path"],
        "description": "Defense evasion — extract obfuscated payloads, modified security tools, encoded commands",
    },
}


# ─── IOC CORPUS CATEGORIES ──────────────────────────────────────────

IOC_CORPUS_CATEGORIES = {
    "network": {
        "patterns": ["ipv4", "ipv6", "domain", "url", "mac_address"],
        "description": "Network-layer indicators",
    },
    "file": {
        "patterns": ["md5", "sha1", "sha256", "windows_path", "unix_path"],
        "description": "File-system and hash indicators",
    },
    "identity": {
        "patterns": ["email", "registry_key"],
        "description": "Identity and system configuration indicators",
    },
    "encoded": {
        "patterns": ["base64_blob", "cve"],
        "description": "Encoded payloads and vulnerability references",
    },
}


# ─── EXTRACT_IOCS TEMPLATE (injected into generated code) ───────────

EXTRACT_IOCS_TEMPLATE = '''def extract_iocs(text, ioc_types=None):
    """Extract IOCs from text using regex patterns."""
    import re
    patterns = {
        "ipv4": r'\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b',
        "domain": r'\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk)\\b',
        "url": r'https?://[^\\s<>"\\']+',
        "email": r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
        "md5": r'\\b[a-fA-F0-9]{32}\\b',
        "sha1": r'\\b[a-fA-F0-9]{40}\\b',
        "sha256": r'\\b[a-fA-F0-9]{64}\\b',
        "base64_blob": r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        "registry_key": r'(?:HKLM|HKCU|HKU|HKCR|HKCC)\\\\\\\\[^\\s]+',
        "cve": r'CVE-\\d{4}-\\d{4,7}',
    }
    if ioc_types:
        patterns = {k: v for k, v in patterns.items() if k in ioc_types}
    iocs = []
    seen = set()
    for ioc_type, pattern in patterns.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group()
            key = (ioc_type, value.lower())
            if key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": value, "malicious": True})
    return iocs'''


# ─── PROMPT 7: RAG IOC CONTEXT ──────────────────────────────────────

RAG_IOC_CONTEXT_PROMPT = """## IOC Extraction Requirements

Your investigation code MUST extract Indicators of Compromise (IOCs) from the alert data.
Use the extract_iocs() helper function defined below to scan all text fields in the alert.

{extract_iocs_function}

### Required IOC Types for This Alert Category ({technique_category}):
{required_iocs}

### How to Use:
1. Flatten all string values from alert_data (including nested dicts) into a single text blob
2. Call extract_iocs(text_blob, ioc_types={ioc_type_list}) to get structured IOCs
3. Add the results to your return dict under "indicators_of_compromise"
4. Also decode any Base64 content and scan the decoded text for additional IOCs

### Similar Past Investigations:
{similar_investigations}"""


# ─── PROMPT 8: RAG INVESTIGATION ────────────────────────────────────

RAG_INVESTIGATION_PROMPT = """Investigate this SIEM alert. Write a Python function.

Alert:
{alert_json}

{rag_context}

Function: def investigate_alert(alert_data: dict) -> dict
Use .get() for all dict access. No eval/exec/subprocess/socket/importlib.
Allowed: re, json, datetime, collections, hashlib, ipaddress, base64, binascii.

CRITICAL: Your function MUST:
1. Include the extract_iocs() function from the IOC Requirements above
2. Call extract_iocs() on ALL text fields in alert_data (CommandLine, SourceIP, DestIP, etc.)
3. Decode any Base64 content and extract IOCs from decoded text
4. Return ALL extracted IOCs in indicators_of_compromise list

Return dict keys: status, risk_score, extracted_entities, mitre_techniques, confidence, summary, indicators_of_compromise.

Output JSON: {{"chain_of_thought": "reasoning", "python_code": "def investigate_alert(alert_data: dict) -> dict:\\n    ..."}}"""


# ─── RAG HELPERS ────────────────────────────────────────────────────

def build_rag_context(technique_category, retrieved_patterns=None, similar_investigations=None):
    """Build RAG context string for IOC-augmented investigation prompt."""
    technique_info = TECHNIQUE_IOC_MAP.get(
        technique_category,
        TECHNIQUE_IOC_MAP.get("malware")  # sensible default
    )

    required = technique_info["required_iocs"]
    optional = technique_info.get("optional_iocs", [])
    all_iocs = required + optional

    required_text = (
        f"- Primary: {', '.join(required)}\n"
        f"- Secondary: {', '.join(optional)}\n"
        f"- Focus: {technique_info['description']}"
    )

    if similar_investigations:
        similar_text = "\n".join(
            f"- Investigation {inv.get('id', 'N/A')}: {inv.get('summary', 'No summary')}"
            for inv in similar_investigations[:3]
        )
    else:
        similar_text = "No similar past investigations available yet."

    return RAG_IOC_CONTEXT_PROMPT.format(
        extract_iocs_function=EXTRACT_IOCS_TEMPLATE,
        technique_category=technique_category,
        required_iocs=required_text,
        ioc_type_list=all_iocs,
        similar_investigations=similar_text,
    )


def format_rag_investigation(alert_json, rag_context):
    """Format the complete RAG-augmented investigation prompt."""
    return RAG_INVESTIGATION_PROMPT.format(
        alert_json=alert_json,
        rag_context=rag_context,
    )
