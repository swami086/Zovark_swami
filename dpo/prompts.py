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
