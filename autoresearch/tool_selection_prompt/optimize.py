#!/usr/bin/env python3
"""Quick optimization loop for tool selection prompt."""
import os
import json
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(SCRIPT_DIR, "..", ".venv", "Scripts", "python.exe")
PROMPT_PATH = os.path.join(SCRIPT_DIR, "current_prompt.txt")

prompts = [
    # Iteration 1: Add strong example and anti-bias instruction
    """You are Zovark's investigation planner. Given a SIEM alert, select the EXACT tools needed to investigate it.

{catalog_text}

{institutional_context}

Output ONLY valid JSON:
{"steps": [{"tool": "tool_name", "args": {"arg": "value"}}]}

Variable references:
- $raw_log = the alert's raw log text
- $siem_event = the full SIEM event dict
- $siem_event.field_name = a specific field
- $stepN = output of step N (1-indexed)
- $stepN.field = specific field from step N

CRITICAL RULES:
1. Match tools to the ALERT TYPE. Do NOT default to phishing/email tools for non-phishing alerts.
2. For brute_force alerts: use parse_auth_log, extract_ipv4, extract_usernames, count_pattern, score_brute_force.
3. For ransomware alerts: use parse_windows_event, extract_hashes, detect_ransomware, count_pattern.
4. For lateral_movement: use parse_windows_event, extract_ipv4, extract_usernames, score_lateral_movement.
5. For C2 alerts: use extract_ipv4, extract_domains, calculate_entropy, detect_c2, score_c2_beacon.
6. Always start with extraction tools for IOCs.
7. Always include a scoring or detection tool matching the alert type.
8. Always end with correlate_with_history and map_mitre.
9. Output ONLY JSON. No prose, no markdown.

Example for brute_force:
{"steps": [{"tool": "parse_auth_log", "args": {"raw_log": "$raw_log"}}, {"tool": "extract_ipv4", "args": {"text": "$raw_log"}}, {"tool": "extract_usernames", "args": {"text": "$raw_log"}}, {"tool": "count_pattern", "args": {"text": "$raw_log", "pattern": "(?i)fail|denied"}}, {"tool": "score_brute_force", "args": {"failed_count": "$step4", "unique_sources": "$step2.count", "timespan_minutes": 60}}, {"tool": "correlate_with_history", "args": {"ioc_values": "$step2", "lookback_hours": 72, "history_context": "$correlation_context"}}, {"tool": "map_mitre", "args": {"technique_ids": ["T1110"]}}]}
""",

    # Iteration 2: Even more explicit with task-type mapping
    """You are Zovark's investigation planner. Select tools based STRICTLY on the alert's task_type.

{catalog_text}

{institutional_context}

Output ONLY valid JSON: {"steps": [{"tool": "...", "args": {...}}]}

Variable refs: $raw_log, $siem_event, $siem_event.field, $stepN, $stepN.field

TASK-TYPE TO TOOL MAPPING (follow exactly):
- brute_force → parse_auth_log, extract_ipv4, extract_usernames, count_pattern, score_brute_force
- phishing → extract_urls, extract_domains, extract_emails, detect_phishing, score_phishing
- ransomware → parse_windows_event, extract_hashes, detect_ransomware, count_pattern
- c2 → extract_ipv4, extract_domains, calculate_entropy, detect_c2, score_c2_beacon
- lateral_movement → parse_windows_event, extract_ipv4, extract_usernames, score_lateral_movement
- data_exfiltration → extract_ipv4, extract_domains, extract_urls, detect_data_exfil, score_exfiltration
- kerberoasting → parse_windows_event, extract_usernames, extract_ipv4, detect_kerberoasting
- lolbin_abuse → parse_windows_event, extract_ipv4, extract_urls, detect_lolbin_abuse
- ALL types end with: correlate_with_history, map_mitre

Rules:
1. Select 3-8 tools total
2. Start with extraction tools
3. Include detection/scoring tool matching task_type
4. End with correlate_with_history and map_mitre
5. ONLY JSON output
""",

    # Iteration 3: Ultra-direct
    """Select investigation tools for a SIEM alert. Output JSON only.

{catalog_text}

Format: {"steps": [{"tool": "NAME", "args": {"arg": "value"}}]}

Mapping:
brute_force=parse_auth_log,extract_ipv4,extract_usernames,count_pattern,score_brute_force
phishing=extract_urls,extract_domains,extract_emails,detect_phishing,score_phishing
ransomware=parse_windows_event,extract_hashes,detect_ransomware,count_pattern
c2=extract_ipv4,extract_domains,calculate_entropy,detect_c2,score_c2_beacon
lateral_movement=parse_windows_event,extract_ipv4,extract_usernames,score_lateral_movement
data_exfil=extract_ipv4,extract_domains,extract_urls,detect_data_exfil,score_exfiltration
kerberoasting=parse_windows_event,extract_usernames,extract_ipv4,detect_kerberoasting
lolbin=parse_windows_event,extract_ipv4,extract_urls,detect_lolbin_abuse

All end with: correlate_with_history, map_mitre
Use $raw_log, $siem_event, $stepN for variables.
No markdown. No prose.""",
]

best_fitness = 0.3910
best_prompt = open(PROMPT_PATH, encoding="utf-8").read()

for i, prompt in enumerate(prompts, start=2):
    print(f"\n=== Iteration {i} ===")
    with open(PROMPT_PATH, "w", encoding="utf-8") as f:
        f.write(prompt)
    
    result = subprocess.run(
        [VENV_PYTHON, "evaluate.py"],
        cwd=SCRIPT_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
    )
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr[:500])
    
    results_file = os.path.join(SCRIPT_DIR, "results.jsonl")
    fitness = 0.0
    if os.path.exists(results_file):
        with open(results_file, encoding="utf-8") as f:
            lines = f.readlines()
            if lines:
                last = json.loads(lines[-1])
                fitness = last.get("fitness", 0.0)
    
    print(f"Iteration {i}: fitness={fitness:.4f}")
    
    if fitness > best_fitness:
        best_fitness = fitness
        best_prompt = prompt
        print(f"NEW BEST: {best_fitness:.4f}")
    else:
        print(f"No improvement — reverting to best")
        with open(PROMPT_PATH, "w", encoding="utf-8") as f:
            f.write(best_prompt)

with open(PROMPT_PATH, "w", encoding="utf-8") as f:
    f.write(best_prompt)

print(f"\n=== BEST ===")
print(f"Fitness: {best_fitness:.4f}")
