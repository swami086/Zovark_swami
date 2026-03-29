"""
ZOVARK — Complete Prompt Library v2
===================================
Modular architecture. Every prompt is split into composable blocks:
  SYSTEM  — agent identity + hard constraints (stable, cached)
  TASK    — investigation-specific instructions (per-alert)
  TOOLS   — IOC patterns, regex library, allowed/forbidden imports (stable, cached)
  EXAMPLES — RAG-retrieved past investigations (dynamic, per-alert)

Patterns incorporated:
  - Modular prompt structure (from leaked Manus/Devin/Claude Code prompts)
  - Objective recitation at END of context (Manus todo.md pattern)
  - Retry with error feedback (Manus "keep wrong stuff in" principle)
  - RAG context injection from pgvector (past investigations as few-shot)
  - Single retry loop: if IOC count = 0, re-run with failure visible

Total prompts: 16
  Core pipeline:     6 (system, task, tools, examples, objective, full assembly)
  DPO forge:         6 (alert gen, investigation, judge, mutation, error correction, skill params)
  New patterns:      4 (retry, planning, report assembly, investigation specialist)

Usage:
    from zovark_prompts_v2 import PromptAssembler
    assembler = PromptAssembler()
    full_prompt = assembler.build_investigation_prompt(
        alert_json=alert,
        skill_type="brute_force",
        skill_template=template,
        rag_examples=retrieved_investigations,
    )
"""

from typing import Optional


# =============================================================================
# BLOCK 1: SYSTEM IDENTITY (stable — never changes between investigations)
# =============================================================================
# This block sits at the TOP of every prompt. It defines who ZOVARK is.
# Because it never changes, it gets KV-cached across all investigations.
# Manus principle: "Keep your prompt prefix stable."

SYSTEM_IDENTITY = """You are ZOVARK, an autonomous Security Operations Center investigation engine.

You run air-gapped on-premise. You never send data to external APIs.
You investigate SIEM alerts by generating Python code that runs in a sandboxed Docker container.
Your output is a structured JSON verdict with findings, IOCs, risk scores, and recommendations.

Hard constraints:
- You generate ONLY valid Python code. No markdown. No explanation. No backticks.
- Your code MUST print exactly ONE JSON object as the LAST line of stdout.
- You MUST extract ALL indicators of compromise from every text field in the alert.
- IOC extraction is your PRIMARY metric. An investigation with 0 IOCs is a failure.
- You NEVER use forbidden imports. Violation terminates execution immediately."""


# =============================================================================
# BLOCK 2: TOOL DEFINITIONS (stable — cached alongside system identity)
# =============================================================================
# Defines the IOC extraction toolkit available to generated code.
# Manus principle: "Mask, don't remove" — all tools always present.

TOOL_DEFINITIONS = """## Forbidden Imports (AST prefilter blocks these — code will not execute)
os, sys, subprocess, shutil, pathlib, importlib, ctypes, socket, http, urllib,
requests, eval, exec, compile, __import__, globals, locals, breakpoint

## Allowed Imports
json, re, datetime, hashlib, base64, collections, ipaddress, typing,
dataclasses, time, math, logging

## IOC Regex Pattern Library — USE THESE IN YOUR CODE
IOC_PATTERNS = {
    "ipv4":              r'\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b',
    "ipv6":              r'\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b',
    "domain":            r'\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b',
    "url":               r'https?://[^\\s<>\"\\']+',
    "email":             r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}',
    "md5":               r'\\b[a-fA-F0-9]{32}\\b',
    "sha1":              r'\\b[a-fA-F0-9]{40}\\b',
    "sha256":            r'\\b[a-fA-F0-9]{64}\\b',
    "cve":               r'CVE-\\d{4}-\\d{4,7}',
    "file_path_unix":    r'(?:/[\\w.-]+){3,}',
    "file_path_windows": r'[A-Z]:\\\\(?:[\\w.-]+\\\\)*[\\w.-]+',
    "mac_address":       r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',
    "registry_key":      r'(?:HKLM|HKCU|HKU|HKCR|HKCC)\\\\[\\w\\\\.-]+',
}

## IOC Extraction Function — INCLUDE THIS IN YOUR GENERATED CODE
def extract_iocs(raw_text: str) -> list:
    import re, ipaddress
    iocs, seen = [], set()
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in re.finditer(pattern, raw_text):
            value = match.group(0)
            if ioc_type == "ipv4":
                try:
                    addr = ipaddress.ip_address(value)
                    confidence = "low" if (addr.is_private or addr.is_loopback) else "high"
                except ValueError:
                    continue
            elif ioc_type in ("md5", "sha1", "sha256"):
                confidence = "high"
            elif ioc_type == "cve":
                confidence = "high"
            else:
                confidence = "medium"
            key = (ioc_type, value)
            if key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": value, "confidence": confidence})
    return iocs

## Mandatory Output Schema
{
    "status": "completed",
    "risk_score": <int 0-100>,
    "findings": ["<specific, data-backed finding strings>"],
    "iocs": [{"type": "<type>", "value": "<value>", "confidence": "<high|medium|low>"}],
    "recommendations": ["<actionable recommendation strings>"],
    "execution_ms": <int>,
    "code_generated": true,
    "sandbox_passed": true
}"""


# =============================================================================
# BLOCK 3: TECHNIQUE-TO-IOC MAP (stable — tells model what to look for)
# =============================================================================

TECHNIQUE_IOC_MAP = {
    "brute_force":          {"required": ["ipv4"], "optional": ["domain", "email"]},
    "malware":              {"required": ["sha256", "file_path_unix", "file_path_windows", "ipv4"], "optional": ["domain", "url", "md5", "registry_key"]},
    "lateral_movement":     {"required": ["ipv4", "domain"], "optional": ["file_path_windows", "registry_key"]},
    "data_exfiltration":    {"required": ["ipv4", "domain", "url"], "optional": ["email", "file_path_unix"]},
    "phishing":             {"required": ["email", "domain", "url"], "optional": ["ipv4", "sha256"]},
    "privilege_escalation": {"required": ["ipv4", "file_path_unix", "file_path_windows"], "optional": ["cve", "registry_key"]},
    "c2_communication":     {"required": ["ipv4", "domain", "url"], "optional": ["sha256"]},
    "ransomware":           {"required": ["sha256", "file_path_windows", "ipv4"], "optional": ["domain", "url", "registry_key", "cve"]},
    "insider_threat":       {"required": ["ipv4", "email", "file_path_unix"], "optional": ["domain", "url"]},
    "vulnerability_exploit": {"required": ["cve", "ipv4"], "optional": ["url", "sha256", "file_path_unix"]},
}


# =============================================================================
# BLOCK 4: TASK INSTRUCTIONS (dynamic — changes per alert)
# =============================================================================
# This is the per-investigation context. Assembled at runtime.

TASK_TEMPLATE = """## Alert to Investigate
```json
{alert_json}
```

## Skill Context
Type: {skill_type}
{skill_template}

## Required IOC Types for This Alert
Required (MUST extract): {required_iocs}
Optional (extract if present): {optional_iocs}

## Assessment Rules

1. ZERO HALLUCINATION POLICY: ONLY extract IOCs explicitly present in the raw log data or SIEM event fields. If an IOC is not physically present in the text, do NOT extract it.

2. EVIDENCE REQUIREMENT: Every IOC must include a context field citing specific log evidence.

3. SCORING ANCHORS (use these as reference points):
   - SSH brute force (500+ failed attempts from single IP): risk 95-100
   - Phishing URL clicked (typosquatting domain, credential harvest): risk 80-90
   - Lateral movement with mimikatz: risk 90-100
   - Ransomware (shadow copy deletion + mass encryption): risk 95-100
   - Kerberoasting (RC4 downgrade, service ticket request): risk 80-90
   - Data exfiltration (large transfer to external IP, off-hours): risk 75-85
   - C2 beaconing (regular interval callbacks to suspicious domain): risk 70-80
   - Single failed login: risk 15-25
   - Port scan from internal IP: risk 40-55

4. CALIBRATED RISK SCORING:
   - Routine operations (password changes, updates, backups, health checks, cert renewals, scheduled tasks, service restarts, log rotation, AV updates): risk 10-25
   - Ambiguous activity without clear malicious indicators: risk 35-55
   - Single weak indicator (unusual port, non-standard user agent): risk 40-55
   - Multiple correlated indicators (suspicious IP + encoded payload + off-hours): risk 65-80
   - Confirmed attack pattern with evidence chain: risk 80-100

5. BENIGN RECOGNITION: Routine administrative and operational actions MUST score risk 10-25. The presence of security-adjacent keywords (password, credential, admin, root, execute, modify) in routine operation logs is NOT evidence of a threat.

6. MULTI-SIGNAL REASONING: A single indicator is weak. Multiple independent indicators from different log fields compound risk. Score based on the NUMBER and INDEPENDENCE of suspicious signals, not on the scariest single keyword.

7. FALSE POSITIVE BIAS: When uncertain between suspicious and benign, prefer benign. SOC analysts lose more productivity from false positives than from alerts classified as suspicious. Under-scoring is better than over-scoring.

8. SCOPE: Score this alert in isolation. Do not assume other related alerts exist. Do not speculate about attack chains beyond what is evidenced in this single alert.

## Investigation Steps
1. Parse the alert JSON and extract all text fields
2. Run extract_iocs() on EVERY text field: raw_log, description, source_ip, destination_ip, hostname, url, file_hash, process_name, username
3. Also extract IOCs from any nested or concatenated strings
4. Correlate indicators (e.g., same IP appearing in multiple fields)
5. Assess risk based on technique severity and IOC confidence levels
6. Generate specific, data-backed findings (reference actual values from the alert)
7. Produce actionable recommendations tied to the findings
8. Output the mandatory JSON schema as the LAST line of stdout"""


# =============================================================================
# BLOCK 5: RAG EXAMPLES (dynamic — retrieved from pgvector per alert type)
# =============================================================================
# Past successful investigations as few-shot examples.
# Manus principle: "file system as context" — retrieve, don't memorize.

RAG_EXAMPLES_TEMPLATE = """## Similar Past Investigations (for reference)
{examples}

Use these as guidance for what a successful investigation looks like for this alert type.
Your code should extract AT LEAST as many IOCs as shown in these examples."""

RAG_EXAMPLE_FORMAT = """### Investigation: {task_type} (risk_score: {risk_score})
IOCs extracted: {ioc_count}
{ioc_summary}
Findings: {findings_summary}"""


# =============================================================================
# BLOCK 6: OBJECTIVE RECITATION (goes at the END of every prompt)
# =============================================================================
# Manus principle: "Manipulate attention through recitation."
# The model's attention is strongest at the START and END of context.
# By restating the objective at the end, we push it into the model's
# recent attention span, preventing "lost in the middle" drift.

OBJECTIVE_RECITATION = """## REMINDER — YOUR PRIMARY OBJECTIVE
You are investigating a {skill_type} alert.
You MUST extract ALL IOCs. Required types: {required_iocs}.
Call extract_iocs() on every text field. An investigation with 0 IOCs is a FAILURE.
Output ONE valid JSON object as the LAST line of stdout. Nothing else."""


# =============================================================================
# BLOCK 7: RETRY PROMPT (used when first attempt extracts 0 IOCs)
# =============================================================================
# Manus principle: "Keep the wrong stuff in."
# When the first attempt fails, show the model its own failure and ask it to fix.
# One retry max — if the second attempt also fails, ship what you have.

RETRY_PROMPT = """## PREVIOUS ATTEMPT FAILED — IOC EXTRACTION INCOMPLETE

Your previous investigation code produced this output:
```json
{previous_output}
```

PROBLEM: The iocs array is empty or contains fewer than {minimum_iocs} IOCs.
The alert's raw_log field contains at least {expected_ioc_count} extractable indicators.

Specifically, the raw_log contains these patterns you missed:
{missed_pattern_hints}

INSTRUCTIONS:
1. Include the extract_iocs() function from the Tool Definitions above
2. Call extract_iocs() on the raw_log field AND the description field AND all other string fields
3. Do NOT hardcode IOC values — extract them dynamically using regex
4. Ensure the iocs array in your output JSON is populated

Generate corrected Python code. No markdown. No explanation. No backticks."""


# =============================================================================
# DPO FORGE PROMPTS (6 prompts for the training pipeline)
# =============================================================================
# These use the same modular structure but are called via Kimi K2.5 / NVIDIA API.

# --- DPO 1: Alert Generation ---
DPO_ALERT_GENERATION = """You are a SIEM alert generator for security operations testing.

Given a MITRE ATT&CK technique, environment type, and difficulty level, generate a realistic SIEM alert JSON.

## Input
- Technique: {technique_id} — {technique_name}
- Environment: {environment}
- Difficulty: {difficulty}

## Requirements
1. Output MUST be valid JSON matching this schema:
{{
    "alert_id": "ALERT-<uuid4>",
    "timestamp": "<ISO 8601>",
    "source": "<siem_name>",
    "rule_name": "<detection_rule_name>",
    "severity": "<critical|high|medium|low>",
    "description": "<human-readable summary>",
    "raw_log": "<realistic log entry with embedded IOCs>",
    "source_ip": "<realistic IP>",
    "destination_ip": "<realistic IP>",
    "hostname": "<realistic hostname for the environment>",
    "username": "<realistic username>",
    "process_name": "<if applicable>",
    "file_hash": "<if applicable, SHA-256>",
    "url": "<if applicable>",
    "metadata": {{
        "technique_id": "{technique_id}",
        "environment": "{environment}",
        "difficulty": "{difficulty}"
    }}
}}

2. raw_log MUST contain at least 3 extractable IOCs (IPs, domains, hashes, CVEs, file paths)
3. IOCs must be embedded naturally in the log — not listed separately
4. Severity must match the technique's typical impact level
5. Environment context reflected in hostnames, usernames, network ranges:
   - corporate: 10.x.x.x, AD usernames, Windows hostnames
   - cloud: AWS/Azure IPs, IAM users, cloud instance names
   - hybrid: mix of on-prem and cloud indicators
   - ot/ics: industrial protocol references, PLC hostnames

## Difficulty Scaling
- easy: Single clear indicator, obvious malicious activity
- medium: Multiple indicators, some noise, requires correlation
- hard: Subtle indicators, living-off-the-land, encrypted C2

Respond with ONLY the JSON object. No markdown, no explanation."""


# --- DPO 2: Investigation Code Generation ---
DPO_INVESTIGATION_CODE = """{system_identity}

{tool_definitions}

{task_instructions}

{objective_recitation}"""


# --- DPO 3: Judge Evaluation ---
DPO_JUDGE_EVALUATION = """You are a SOC investigation quality judge. Score the investigation output against ground truth criteria.

## Investigation Code
```python
{investigation_code}
```

## Execution Output
```json
{execution_output}
```

## Ground Truth Anchor for {technique_id}
```json
{ground_truth_anchor}
```

## Scoring (100 points total)

### IOC Extraction Completeness — 40 points (HIGHEST WEIGHT)
- 40: All IOCs from alert data extracted with correct types
- 30: >75% of IOCs extracted, types mostly correct
- 20: >50% of IOCs extracted
- 10: Some IOCs but significant gaps
- 0:  Empty or missing iocs array
AUTOMATIC FAIL: Score below 20 here fails the entire investigation.

### Finding Quality — 25 points
- 25: Specific findings referencing actual alert data, mapped to technique
- 15: Relevant but generic
- 5:  Vague or boilerplate
- 0:  Missing or nonsensical

### Risk Score Accuracy — 15 points
- 15: Aligns with technique severity and IOC confidence
- 10: Reasonable range but not well-justified
- 5:  Present but arbitrary
- 0:  Missing or clearly wrong (critical attack scored <20)

### Recommendation Quality — 10 points
- 10: Specific, actionable, tied to findings
- 5:  Generic but relevant
- 0:  Missing or harmful

### Code Quality — 10 points
- 10: Clean, well-structured, proper error handling
- 5:  Functional but messy
- 0:  Errors or security issues

## Fail Conditions
- iocs array empty → AUTOMATIC FAIL
- IOC score < 20 → AUTOMATIC FAIL
- Total score < 60 → FAIL

## Response Format (ONLY this JSON)
{{
    "verdict": "<pass|fail>",
    "total_score": <int 0-100>,
    "breakdown": {{
        "ioc_extraction": <int 0-40>,
        "finding_quality": <int 0-25>,
        "risk_score_accuracy": <int 0-15>,
        "recommendation_quality": <int 0-10>,
        "code_quality": <int 0-10>
    }},
    "ioc_gap_analysis": "<what IOCs were missed and why>",
    "rationale": "<2-3 sentence explanation>"
}}"""


# --- DPO 4: Mutation (creates degraded rejected pairs) ---
DPO_MUTATION = """You are a code mutation engine for DPO training data. Given good investigation code, create a subtly degraded version.

## Good Code (to degrade)
```python
{good_code}
```

## Apply 2-3 of these degradations:

### IOC Degradations (apply at least 1)
- Remove regex patterns for 1-2 IOC types
- Broaden regex to match garbage (e.g., r'[0-9.]+' instead of proper IP regex)
- Hardcode IOC list instead of extracting from alert
- Return empty iocs array
- Remove deduplication
- Set all confidence to "low"

### Finding Degradations
- Make findings generic: "Suspicious activity detected"
- Remove references to actual alert data
- Copy alert description as the only finding

### Risk Score Degradations
- Hardcode risk_score to 50
- Invert logic (critical → low score)

### Code Quality Degradations
- Remove error handling
- Use string concatenation instead of json.dumps

## Rules
1. Degraded code MUST be syntactically valid Python
2. MUST produce valid JSON output matching the result schema
3. MUST NOT use forbidden imports
4. Degradation must be SUBTLE — needs 30+ seconds to spot the difference
5. MUST produce fewer or lower-quality IOCs than original

Respond with ONLY the degraded Python code. No markdown, no explanation."""


# --- DPO 5: Error Correction (Path A recovery) ---
DPO_ERROR_CORRECTION = """You are a Python debugging assistant. Fix investigation code that failed in sandbox.

## Failed Code
```python
{failed_code}
```

## Error
```
{error_output}
```

## Common Fixes
1. ImportError: Replace forbidden imports with allowed alternatives
   - os.path → string operations
   - subprocess → not needed for log analysis
   - requests → not available in sandbox
   - socket → use ipaddress module

2. JSONDecodeError: Result JSON must be LAST line of stdout
   - Remove print() statements before final json.dumps
   - Wrap debug output in logging, not print

3. KeyError: Use .get() with defaults, not direct key access

4. regex errors: Use raw strings (r'...')

5. TypeError: json.dumps needs serializable types; risk_score must be int

## Requirements
- Valid Python, no forbidden imports
- Standard result JSON as last line of stdout
- PRESERVE all IOC extraction logic — don't simplify to "fix"

Respond with ONLY corrected Python code. No markdown, no explanation."""


# --- DPO 6: Skill Parameter Filling ---
DPO_SKILL_PARAMETERS = """You are ZOVARK's skill parameter resolver. Fill template variables with values from the alert.

## Skill Template
{skill_template}

## Alert Data
```json
{alert_data}
```

## Investigation Context
- Investigation ID: {investigation_id}
- Task type: {task_type}
- Severity: {severity}

## Instructions
1. Replace all {{{{variable}}}} placeholders with actual values from alert data
2. Defaults for missing fields: IPs → "0.0.0.0", hostnames → "unknown", hashes → ""
3. Do NOT modify investigation logic — only fill parameters
4. PRESERVE all IOC extraction code exactly as written
5. Output must be valid Python

Respond with ONLY the filled Python code."""


# =============================================================================
# NEW PATTERN PROMPTS
# =============================================================================

# --- Investigation Planning (lightweight — one LLM call) ---
# Devin pattern: plan before execute. BUT kept minimal for 1.5B model.
# NOT a separate LLM call — injected as a structured prefix in the task block.

PLANNING_INJECTION = """## Investigation Plan for {skill_type} alert
Steps:
1. Parse alert JSON, extract all string fields
2. Run IOC extraction on: {fields_to_scan}
3. Expected IOC types: {required_iocs}
4. Correlate: check if source_ip appears in raw_log
5. Risk assessment: {severity} severity → baseline risk {baseline_risk}
6. Output structured JSON verdict"""


# --- Investigation Specialist Personas (lightweight role priming) ---
# Instead of swapping skill templates (breaks cache), prime the model's role.

SPECIALIST_PERSONAS = {
    "brute_force": "You are a credential abuse specialist. Focus on login patterns, source IPs, and authentication failures.",
    "malware": "You are a malware analyst. Focus on file hashes, process execution chains, and C2 communication indicators.",
    "lateral_movement": "You are a lateral movement analyst. Focus on internal IP-to-IP communication, unusual service access, and credential reuse.",
    "data_exfiltration": "You are a data loss prevention analyst. Focus on outbound data volumes, unusual destinations, and staging behavior.",
    "phishing": "You are a phishing analyst. Focus on sender domains, embedded URLs, attachment hashes, and social engineering indicators.",
    "privilege_escalation": "You are a privilege escalation analyst. Focus on permission changes, exploit indicators (CVEs), and unusual process elevation.",
    "c2_communication": "You are a C2 detection specialist. Focus on beaconing patterns, domain generation algorithms, and encrypted tunnel indicators.",
    "ransomware": "You are a ransomware analyst. Focus on file encryption patterns, ransom note indicators, and lateral spread through SMB/RDP.",
    "insider_threat": "You are an insider threat analyst. Focus on access timing anomalies, data staging patterns, and policy violations.",
    "vulnerability_exploit": "You are a vulnerability analyst. Focus on CVE identification, exploit payload indicators, and patch status.",
}


# =============================================================================
# PROMPT ASSEMBLER — builds the full prompt from modular blocks
# =============================================================================

class PromptAssembler:
    """
    Assembles investigation prompts from modular blocks.

    The block order matters for KV-cache efficiency:
      1. SYSTEM_IDENTITY      (stable — cached across all investigations)
      2. TOOL_DEFINITIONS      (stable — cached)
      3. SPECIALIST_PERSONA    (semi-stable — cached per skill_type)
      4. TASK_TEMPLATE         (dynamic — per alert)
      5. RAG_EXAMPLES          (dynamic — per alert)
      6. PLANNING_INJECTION    (dynamic — per alert)
      7. OBJECTIVE_RECITATION  (dynamic but short — end of context)

    Stable blocks at the top = maximum KV-cache hit rate.
    Objective recitation at the bottom = maximum attention on the goal.
    """

    def build_investigation_prompt(
        self,
        alert_json: str,
        skill_type: str,
        skill_template: str,
        rag_examples: Optional[list[dict]] = None,
        is_retry: bool = False,
        previous_output: Optional[str] = None,
        missed_hints: Optional[str] = None,
    ) -> str:
        """Build the full investigation prompt for local Ollama."""

        ioc_map = TECHNIQUE_IOC_MAP.get(skill_type, {"required": ["ipv4"], "optional": []})
        required = ", ".join(ioc_map["required"])
        optional = ", ".join(ioc_map["optional"]) if ioc_map["optional"] else "none"

        # Block 1: System identity (stable)
        blocks = [SYSTEM_IDENTITY]

        # Block 2: Tool definitions (stable)
        blocks.append(TOOL_DEFINITIONS)

        # Block 3: Specialist persona (semi-stable)
        persona = SPECIALIST_PERSONAS.get(skill_type, "")
        if persona:
            blocks.append(f"## Your Role\n{persona}")

        # Block 4: Task instructions (dynamic)
        # Determine which fields to scan based on alert content
        fields_to_scan = "raw_log, description, source_ip, destination_ip, hostname, url, file_hash, process_name, username"

        task = TASK_TEMPLATE.format(
            alert_json=alert_json,
            skill_type=skill_type,
            skill_template=skill_template,
            required_iocs=required,
            optional_iocs=optional,
        )
        blocks.append(task)

        # Block 5: RAG examples (dynamic, if available)
        if rag_examples:
            examples_text = "\n\n".join(
                RAG_EXAMPLE_FORMAT.format(
                    task_type=ex.get("task_type", "unknown"),
                    risk_score=ex.get("risk_score", "?"),
                    ioc_count=len(ex.get("iocs", [])),
                    ioc_summary=", ".join(
                        f"{i['type']}:{i['value']}" for i in ex.get("iocs", [])[:5]
                    ),
                    findings_summary="; ".join(ex.get("findings", [])[:3]),
                )
                for ex in rag_examples[:3]  # Max 3 examples to stay in token budget
            )
            blocks.append(RAG_EXAMPLES_TEMPLATE.format(examples=examples_text))

        # Block 6: Planning injection (dynamic, lightweight)
        severity = "high"  # Default; override from alert if available
        baseline_risk = {"critical": 85, "high": 70, "medium": 50, "low": 30}.get(severity, 50)
        planning = PLANNING_INJECTION.format(
            skill_type=skill_type,
            fields_to_scan=fields_to_scan,
            required_iocs=required,
            severity=severity,
            baseline_risk=baseline_risk,
        )
        blocks.append(planning)

        # Block 7: Retry context (only on second attempt)
        if is_retry and previous_output:
            retry = RETRY_PROMPT.format(
                previous_output=previous_output,
                minimum_iocs=len(ioc_map["required"]),
                expected_ioc_count=max(3, len(ioc_map["required"])),
                missed_pattern_hints=missed_hints or "Check for IP addresses, domains, and hashes in raw_log.",
            )
            blocks.append(retry)

        # Block 8: Objective recitation (ALWAYS last)
        recitation = OBJECTIVE_RECITATION.format(
            skill_type=skill_type,
            required_iocs=required,
        )
        blocks.append(recitation)

        return "\n\n".join(blocks)

    def build_dpo_investigation_prompt(
        self,
        alert_json: str,
        skill_type: str,
        skill_template: str,
    ) -> str:
        """Build investigation prompt for DPO forge (Kimi K2.5 via NVIDIA API)."""
        ioc_map = TECHNIQUE_IOC_MAP.get(skill_type, {"required": ["ipv4"], "optional": []})
        required = ", ".join(ioc_map["required"])
        optional = ", ".join(ioc_map["optional"]) if ioc_map["optional"] else "none"

        task = TASK_TEMPLATE.format(
            alert_json=alert_json,
            skill_type=skill_type,
            skill_template=skill_template,
            required_iocs=required,
            optional_iocs=optional,
        )
        recitation = OBJECTIVE_RECITATION.format(
            skill_type=skill_type,
            required_iocs=required,
        )
        return "\n\n".join([SYSTEM_IDENTITY, TOOL_DEFINITIONS, task, recitation])

    def build_retry_prompt(
        self,
        original_prompt: str,
        previous_output: str,
        skill_type: str,
        missed_hints: str = "",
    ) -> str:
        """Append retry context to the original prompt for second attempt."""
        ioc_map = TECHNIQUE_IOC_MAP.get(skill_type, {"required": ["ipv4"], "optional": []})
        retry = RETRY_PROMPT.format(
            previous_output=previous_output,
            minimum_iocs=len(ioc_map["required"]),
            expected_ioc_count=max(3, len(ioc_map["required"])),
            missed_pattern_hints=missed_hints or "Check for IP addresses, domains, and hashes in raw_log.",
        )
        recitation = OBJECTIVE_RECITATION.format(
            skill_type=skill_type,
            required_iocs=", ".join(ioc_map["required"]),
        )
        # Append retry + fresh recitation at the end
        return f"{original_prompt}\n\n{retry}\n\n{recitation}"


# =============================================================================
# FORMAT HELPERS for DPO forge prompts
# =============================================================================

def format_alert_generation(
    technique_id: str,
    technique_name: str,
    environment: str,
    difficulty: str,
) -> str:
    return DPO_ALERT_GENERATION.format(
        technique_id=technique_id,
        technique_name=technique_name,
        environment=environment,
        difficulty=difficulty,
    )


def format_judge_evaluation(
    investigation_code: str,
    execution_output: str,
    technique_id: str,
    ground_truth_anchor: str,
) -> str:
    return DPO_JUDGE_EVALUATION.format(
        investigation_code=investigation_code,
        execution_output=execution_output,
        technique_id=technique_id,
        ground_truth_anchor=ground_truth_anchor,
    )


def format_mutation(good_code: str) -> str:
    return DPO_MUTATION.format(good_code=good_code)


def format_error_correction(failed_code: str, error_output: str) -> str:
    return DPO_ERROR_CORRECTION.format(
        failed_code=failed_code,
        error_output=error_output,
    )


def format_skill_parameters(
    skill_template: str,
    alert_data: str,
    investigation_id: str,
    task_type: str,
    severity: str,
) -> str:
    return DPO_SKILL_PARAMETERS.format(
        skill_template=skill_template,
        alert_data=alert_data,
        investigation_id=investigation_id,
        task_type=task_type,
        severity=severity,
    )


# =============================================================================
# IOC CORPUS for pgvector RAG seeding
# =============================================================================
# One-time setup: insert these into pgvector as the retrieval knowledge base.

IOC_CORPUS = {
    "network_indicators": {
        "description": "IP addresses, domains, URLs, and network-level IOCs",
        "patterns": [
            {"type": "ipv4", "regex": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
             "examples": ["192.168.1.1", "10.0.0.99", "203.0.113.42"]},
            {"type": "domain", "regex": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
             "examples": ["evil-c2.example.com", "malware-drop.xyz"]},
            {"type": "url", "regex": r'https?://[^\s<>"\']+',
             "examples": ["https://evil.com/payload.exe", "http://c2.bad.org:8080/beacon"]},
            {"type": "email", "regex": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
             "examples": ["phisher@evil.com"]},
        ],
    },
    "file_indicators": {
        "description": "File hashes, paths, and filesystem IOCs",
        "patterns": [
            {"type": "md5", "regex": r'\b[a-fA-F0-9]{32}\b',
             "examples": ["d41d8cd98f00b204e9800998ecf8427e"]},
            {"type": "sha1", "regex": r'\b[a-fA-F0-9]{40}\b',
             "examples": ["da39a3ee5e6b4b0d3255bfef95601890afd80709"]},
            {"type": "sha256", "regex": r'\b[a-fA-F0-9]{64}\b',
             "examples": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},
            {"type": "file_path_unix", "regex": r'(?:/[\w.-]+){3,}',
             "examples": ["/tmp/.hidden/malware.elf", "/var/log/auth.log"]},
            {"type": "file_path_windows", "regex": r'[A-Z]:\\(?:[\w.-]+\\)*[\w.-]+',
             "examples": ["C:\\Windows\\Temp\\payload.exe"]},
        ],
    },
    "vuln_indicators": {
        "description": "CVEs and vulnerability references",
        "patterns": [
            {"type": "cve", "regex": r'CVE-\d{4}-\d{4,7}',
             "examples": ["CVE-2024-21762", "CVE-2023-44487"]},
        ],
    },
    "host_indicators": {
        "description": "Registry keys, MAC addresses, and host-level IOCs",
        "patterns": [
            {"type": "registry_key", "regex": r'(?:HKLM|HKCU|HKU|HKCR|HKCC)\\[\w\\.-]+',
             "examples": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware"]},
            {"type": "mac_address", "regex": r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',
             "examples": ["00:1A:2B:3C:4D:5E"]},
        ],
    },
}


# =============================================================================
# GROUND TRUTH ANCHOR SCHEMA (reference for docs/ground_truth_anchors.json)
# =============================================================================

GROUND_TRUTH_ANCHOR_SCHEMA = {
    "<technique_id>": {
        "technique_name": "<MITRE ATT&CK technique name>",
        "expected_ioc_types": ["ip", "domain", "hash"],
        "minimum_ioc_count": 2,
        "expected_findings_keywords": ["failed login", "brute force"],
        "severity_range": ["medium", "high"],
        "risk_score_range": [50, 85],
        "required_recommendations": ["block", "reset", "MFA"],
        "technique_description": "<brief description>",
    },
    # Example:
    "T1110.001": {
        "technique_name": "Brute Force: Password Guessing",
        "expected_ioc_types": ["ip", "domain"],
        "minimum_ioc_count": 2,
        "expected_findings_keywords": ["failed login", "brute force", "password", "attempts"],
        "severity_range": ["medium", "high"],
        "risk_score_range": [50, 85],
        "required_recommendations": ["block", "reset", "MFA"],
        "technique_description": "Adversary uses password guessing to attempt authentication",
    },
}


# =============================================================================
# RETRY LOOP INTEGRATION — drop this into the investigation pipeline
# =============================================================================

def should_retry(sandbox_output: dict, skill_type: str) -> bool:
    """Check if investigation output needs a retry."""
    iocs = sandbox_output.get("iocs", [])
    ioc_map = TECHNIQUE_IOC_MAP.get(skill_type, {"required": ["ipv4"], "optional": []})
    min_required = len(ioc_map["required"])

    # Retry if: no IOCs, or fewer IOCs than required types
    if len(iocs) == 0:
        return True
    if len(iocs) < min_required:
        return True
    return False


def generate_retry_hints(sandbox_output: dict, alert_data: dict) -> str:
    """Generate hints about what the retry should look for."""
    import re

    hints = []
    raw_log = alert_data.get("raw_log", "")

    # Check for IPs in raw_log that weren't extracted
    extracted_values = {i.get("value") for i in sandbox_output.get("iocs", [])}
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips_in_log = set(re.findall(ip_pattern, raw_log))
    missed_ips = ips_in_log - extracted_values
    if missed_ips:
        hints.append(f"raw_log contains IPs not extracted: {', '.join(list(missed_ips)[:3])}")

    # Check for hashes
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    hashes_in_log = set(re.findall(hash_pattern, raw_log))
    missed_hashes = hashes_in_log - extracted_values
    if missed_hashes:
        hints.append(f"raw_log contains hashes not extracted: {', '.join(list(missed_hashes)[:2])}")

    # Check for domains
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains_in_log = set(re.findall(domain_pattern, raw_log))
    missed_domains = domains_in_log - extracted_values
    if missed_domains:
        hints.append(f"raw_log contains domains not extracted: {', '.join(list(missed_domains)[:3])}")

    # Check for CVEs
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cves_in_log = set(re.findall(cve_pattern, raw_log))
    missed_cves = cves_in_log - extracted_values
    if missed_cves:
        hints.append(f"raw_log contains CVEs not extracted: {', '.join(list(missed_cves)[:2])}")

    if not hints:
        hints.append("Ensure extract_iocs() is called on raw_log, description, and all string fields.")

    return "\n".join(f"- {h}" for h in hints)
