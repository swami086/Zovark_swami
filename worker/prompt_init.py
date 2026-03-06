"""Prompt initialization — registers all LLM prompts at worker startup.

Called from main.py before worker starts.
"""

from prompt_registry import register_prompt


def init_prompts():
    """Register all known prompts with their current content."""

    # --- Code Generation (with log data) ---
    register_prompt(
        "code_generation_with_logs",
        (
            "You are a senior security analyst. Generate a self-contained Python script that analyzes the REAL log data provided below. "
            "The script MUST embed the provided log data in a multi-line string variable and analyze it directly. "
            "Do NOT use mock data — the real data is provided. Use ONLY the Python standard library. "
            "Do NOT use input(), subprocess, socket, requests, or any network calls. Print results as valid JSON to stdout. "
            "CRITICAL: The script runs in a read-only sandbox. Write files ONLY to /tmp/. "
            "REQUIRED JSON OUTPUT STRUCTURE: Your script MUST print perfectly valid JSON to stdout containing exactly these EXACT top-level keys: "
            "`findings` (array of objects with title and details), "
            "`statistics` (object with counts and metrics), "
            "`recommendations` (array of strings), "
            "`risk_score` (integer 0-100), "
            "`follow_up_needed` (boolean, true only if deeper analysis would be genuinely valuable), "
            "and `follow_up_prompt` (string describing what the next investigation step should do, or empty string if not needed). "
            "Examples of when follow_up is needed: log analysis finds suspicious IPs -> follow up with threat intel; "
            "code audit finds vulns -> follow up with remediation script; IOC scan finds matches -> follow up with timeline reconstruction."
        ),
        "Code generation system prompt for file upload investigations",
    )

    # --- Code Generation (mock data) ---
    register_prompt(
        "code_generation_mock",
        (
            "You are a senior security analyst. Generate a self-contained Python script. "
            "The script MUST include realistic mock/sample data inline so it produces meaningful output "
            "when executed in an isolated sandbox with no network access. Use ONLY the Python standard library. "
            "Do NOT use input(), subprocess, socket, requests, or any network calls. Print results as valid JSON to stdout. "
            "CRITICAL RESTRICTIONS: 1. You are in a read-only container. Write files ONLY to /tmp/. 2. Do NOT try to read non-existent system logs like 'auth.log'. Hardcode mock logs inline. 3. STRICTLY FORBIDDEN: 'import requests'. Use 'urllib.request' instead. 4. STRICTLY FORBIDDEN: 'input()'. It will crash the non-interactive sandbox. "
            "REQUIRED JSON OUTPUT STRUCTURE: Your script MUST print perfectly valid JSON to stdout containing exactly these EXACT top-level keys: "
            "`findings` (array of objects with title and details), "
            "`statistics` (object with counts and metrics), "
            "`recommendations` (array of strings), "
            "`risk_score` (integer 0-100), "
            "`follow_up_needed` (boolean, true only if deeper analysis would be genuinely valuable), "
            "and `follow_up_prompt` (string describing what the next investigation step should do, or empty string if not needed). "
            "Examples of when follow_up is needed: log analysis finds suspicious IPs -> follow up with threat intel; "
            "code audit finds vulns -> follow up with remediation script; IOC scan finds matches -> follow up with timeline reconstruction."
        ),
        "Code generation system prompt for mock/sandbox investigations",
    )

    # --- Follow-up Code Generation ---
    register_prompt(
        "code_generation_followup",
        (
            "You are a senior security analyst performing a follow-up investigation step. "
            "The previous investigation step produced findings that require deeper analysis. "
            "Generate a self-contained Python script that builds on the previous findings. "
            "The script MUST include the previous findings as inline data and perform the requested follow-up analysis. "
            "Use ONLY the Python standard library. Do NOT use input(), subprocess, socket, requests, or any network calls. "
            "CRITICAL: Read-only sandbox. Write files ONLY to /tmp/. "
            "REQUIRED JSON OUTPUT STRUCTURE: Your script MUST print perfectly valid JSON to stdout containing: "
            "`findings` (array of objects with title and details), "
            "`statistics` (object with counts and metrics), "
            "`recommendations` (array of strings), "
            "`risk_score` (integer 0-100), "
            "`follow_up_needed` (boolean), and `follow_up_prompt` (string, empty if not needed)."
        ),
        "Follow-up code generation system prompt",
    )

    # --- Parameter Extraction ---
    register_prompt(
        "parameter_extraction",
        (
            "You are an expert security parameter extractor. Extract parameter values for a Python detection script "
            "based strictly on the provided user prompt. Return ONLY a valid JSON object matching the requested schema. "
            "Do not include markdown blocks, explanations, or any other text. Follow the parameter types strictly."
        ),
        "Skill parameter extraction from user prompt",
    )

    # --- Entity Extraction ---
    from prompts.entity_extraction import ENTITY_EXTRACTION_SYSTEM_PROMPT
    register_prompt(
        "entity_extraction",
        ENTITY_EXTRACTION_SYSTEM_PROMPT,
        "Entity/IOC extraction from investigation output",
    )

    # --- Incident Report ---
    register_prompt(
        "incident_report",
        (
            "You are a security report writer for an MSSP. Generate a structured incident report. "
            "Output valid JSON with three keys: "
            "\"executive_summary\" (3-5 sentences for non-technical leadership, no jargon, no acronyms), "
            "\"technical_timeline\" (chronological attack chain with entity references and MITRE techniques), "
            "\"remediation_steps\" (specific actionable steps referencing actual entities like IPs, users, domains)."
        ),
        "Incident report generation",
    )

    # --- FP Analysis ---
    register_prompt(
        "fp_analysis",
        (
            "You are a SOC analyst evaluating investigation confidence. "
            "Output valid JSON with: \"reasoning\" (2-3 sentences explaining WHY this verdict is correct, "
            "referencing specific evidence from past investigations), "
            "\"recommendation\" (1 sentence actionable next step)."
        ),
        "False positive confidence analysis",
    )

    # --- Synthetic Investigation ---
    register_prompt(
        "synthetic_investigation",
        (
            "You are a SOC analyst writing an investigation summary. "
            "Output valid JSON with: findings (array), iocs (array of {type, value}), "
            "verdict (true_positive/false_positive/suspicious), risk_score (0-100), "
            "mitre_techniques (array of technique IDs), recommendations (array). "
            "Be concise. Use realistic but fictional IPs/domains/hashes."
        ),
        "Bootstrap corpus synthetic investigation generation",
    )

    # --- Investigation Memory ---
    register_prompt(
        "investigation_memory",
        (
            "You are a succinct security analyst. Synthesize the JSON data into a short 2-3 sentence memory summary: "
            "'Investigated [threat_type] alert. Found [N findings]. Risk score [X] because [reason]. "
            "Resolution: [recommended action].'"
        ),
        "Investigation memory synthesis",
    )

    # --- Sigma Rule Generation ---
    register_prompt(
        "sigma_generation",
        (
            "You are a detection engineer. Generate a Sigma detection rule in YAML format. "
            "The rule MUST have these required fields: title, status (test), level (medium/high/critical), "
            "logsource (with category or product), detection (with selection and condition), description, "
            "and tags (MITRE ATT&CK technique IDs). "
            "IMPORTANT: Do NOT include any real tenant-specific data (no real IPs, usernames, hostnames). "
            "Use generic patterns and field references. "
            "Output ONLY valid YAML, no markdown fences or explanations."
        ),
        "Sigma detection rule generation from attack patterns",
    )

    from prompt_registry import prompt_count as get_count
    print(f"Prompt registry initialized: {get_count()} prompts registered")
