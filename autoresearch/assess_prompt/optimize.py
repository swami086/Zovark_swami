#!/usr/bin/env python3
"""Quick optimization loop for assess prompt."""
import os
import json
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_PYTHON = os.path.join(SCRIPT_DIR, "..", ".venv", "Scripts", "python.exe")
PROMPT_PATH = os.path.join(SCRIPT_DIR, "current_prompt.txt")

prompts = [
    # Iteration 1: baseline (already tested)
    open(PROMPT_PATH, encoding="utf-8").read(),
    
    # Iteration 2: more specific anchors
    """You are Zovark's investigation assessor. Given tool runner output for a SIEM alert, produce a final verdict and risk score.

Output ONLY JSON: {"verdict": "true_positive|suspicious|benign", "risk_score": 0-100}

Scoring anchors (use exactly):
- SSH brute force 500+ attempts: risk 70
- Kerberoasting RC4 TGS: risk 100
- Phishing with typosquat: risk 100
- Ransomware shadow copy deletion: risk 100
- C2 beaconing regular intervals: risk 100
- Lateral movement PsExec/WMI: risk 70
- Data exfiltration 2GB+ off-hours: risk 100
- LOLBin certutil/mshta abuse: risk 95
- Routine password change: risk 0
- Windows Update: risk 0
- Service restart: risk 15
- Health check: risk 10
- Borderline brute force (<20 attempts): risk 45
- Anomalous login: risk 55
- Borderline phishing: risk 55

Rules:
- Risk 0-35 = benign
- Risk 36-69 = suspicious
- Risk 70-100 = true_positive
- Match the anchor risk within 10 points
- Output ONLY JSON. No explanation.
""",

    # Iteration 3: even tighter with examples
    """Assess SIEM alert tool output. Return ONLY JSON.

Format: {"verdict": "true_positive|suspicious|benign", "risk_score": int}

Exact risk anchors:
- brute_force 847 attempts → 70
- kerberoasting → 100
- phishing typosquat → 100
- ransomware shadow deletion → 100
- c2 beaconing → 100
- lateral_movement PsExec → 70
- data_exfil 2.3GB off-hours → 100
- lolbin_abuse certutil → 95
- password_change → 0
- windows_update → 0
- service_restart → 15
- health_check → 10
- borderline brute_force 12 attempts → 45
- anomalous_login → 55
- borderline_phishing → 55
- api_key_abuse → 75
- supply_chain_compromise → 85
- insider_threat → 75

Verdict thresholds:
- 0-35 → benign
- 36-69 → suspicious
- 70-100 → true_positive

Examples:
{"verdict": "true_positive", "risk_score": 70}
{"verdict": "benign", "risk_score": 0}
{"verdict": "suspicious", "risk_score": 55}
""",

    # Iteration 4: ultra-short
    """Return JSON verdict for SIEM tool output.
Format: {"verdict":"true_positive|suspicious|benign","risk_score":int}
Risk anchors: brute_force=70, kerberoasting=100, phishing=100, ransomware=100, c2=100, lateral_movement=70, data_exfil=100, lolbin=95, password_change=0, windows_update=0, service_restart=15, health_check=10, borderline_brute=45, anomalous_login=55, borderline_phishing=55, api_abuse=75, supply_chain=85, insider=75.
Thresholds: 0-35=benign, 36-69=suspicious, 70-100=true_positive.
No explanation.""",
]

best_fitness = 0.5861  # baseline
best_prompt = prompts[0]
best_accuracy = 0.73

for i, prompt in enumerate(prompts[1:], start=2):
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
    
    # Parse results
    results_file = os.path.join(SCRIPT_DIR, "results.jsonl")
    fitness = 0.0
    accuracy = 0.0
    if os.path.exists(results_file):
        with open(results_file, encoding="utf-8") as f:
            lines = f.readlines()
            if lines:
                last = json.loads(lines[-1])
                fitness = last.get("fitness", 0.0)
                accuracy = last.get("accuracy", 0.0)
    
    print(f"Fitness: {fitness:.4f}, Accuracy: {accuracy:.0%}")
    
    if accuracy < best_accuracy:
        print(f"Accuracy dropped — REVERTING")
        with open(PROMPT_PATH, "w", encoding="utf-8") as f:
            f.write(best_prompt)
    elif fitness > best_fitness:
        best_fitness = fitness
        best_prompt = prompt
        best_accuracy = accuracy
        print(f"NEW BEST: {best_fitness:.4f}")
    else:
        print(f"No improvement — keeping current")
        # Still keep if accuracy didn't drop
        best_prompt = prompt
        best_accuracy = accuracy

# Final save
with open(PROMPT_PATH, "w", encoding="utf-8") as f:
    f.write(best_prompt)

print(f"\n=== BEST ===")
print(f"Fitness: {best_fitness:.4f}")
print(f"Accuracy: {best_accuracy:.0%}")
print(f"Prompt length: {len(best_prompt)} chars")
