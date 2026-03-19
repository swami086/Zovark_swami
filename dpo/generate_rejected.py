#!/usr/bin/env python3
"""Generate rejected DPO examples from chosen examples.

For each chosen example, creates 2 degraded versions:
  A: Remove IOC extraction (replace with TODO)
  B: Remove regex patterns (replace with hardcoded fakes)

Usage:
    python dpo/generate_rejected.py
"""
import json
import re
import hashlib
from pathlib import Path

CHOSEN_PATH = Path("dpo/chosen_examples.jsonl")
OUTPUT_PATH = Path("dpo/rejected_examples.jsonl")


def degrade_remove_iocs(code):
    """Degradation A: Remove IOC extraction logic."""
    d = code
    # Remove re.findall calls
    d = re.sub(r'for\s+\w+\s+in\s+re\.findall\([^)]+\):[^\n]*\n(\s+[^\n]+\n)*', '# TODO: extract IOCs\n', d)
    d = re.sub(r'\w+\s*=\s*re\.findall\([^)]+\)', '# TODO: extract patterns', d)
    # Clear the IOC list
    d = re.sub(r'(iocs\s*=\s*)\[[^\]]*\]', r'\1[]', d, flags=re.DOTALL)
    d = re.sub(r'(iocs\s*\.\s*append\([^)]+\))', '# IOC extraction removed', d)
    # Set risk to 0
    d = re.sub(r'(risk_score\s*[=:]\s*)\d+', r'\g<1>0', d)
    return d


def degrade_fake_values(code):
    """Degradation B: Replace regex with hardcoded fake values."""
    d = code
    # Replace IP regex with fake
    d = re.sub(
        r"re\.findall\(r['\"].*?(?:d\{1,3\}|\\d).*?['\"],\s*\w+\)",
        '["192.168.1.1"]  # hardcoded fake',
        d
    )
    # Replace hash regex with fake
    d = re.sub(
        r"re\.findall\(r['\"].*?(?:a-f|a-fA-F).*?['\"],\s*\w+\)",
        '["0000000000000000000000000000000"]  # fake hash',
        d
    )
    # Replace username regex with fake
    d = re.sub(
        r"re\.findall\(r['\"].*?(?:User|user).*?['\"],\s*\w+\)",
        '["unknown_user"]  # fake user',
        d
    )
    # Remove findings
    d = re.sub(
        r'(findings\s*=\s*)\[.*?\]',
        r'\1[{"title": "No analysis performed", "details": "N/A"}]',
        d,
        flags=re.DOTALL
    )
    d = re.sub(r'(risk_score\s*[=:]\s*)\d+', r'\g<1>10', d)
    return d


def main():
    if not CHOSEN_PATH.exists():
        print(f"No chosen examples at {CHOSEN_PATH}")
        return

    chosen = []
    with open(CHOSEN_PATH) as f:
        for line in f:
            if line.strip():
                chosen.append(json.loads(line))

    print(f"Loaded {len(chosen)} chosen examples")

    pairs = []
    for ex in chosen:
        code = ex["generated_code"]
        prompt = f"<|im_start|>system\n{ex['system_prompt']}<|im_end|>\n<|im_start|>user\n{ex['user_prompt']}<|im_end|>\n<|im_start|>assistant\n"

        # Degradation A: no IOC extraction
        rejected_a = degrade_remove_iocs(code)
        if rejected_a != code:  # Only add if actually different
            pairs.append({
                "prompt": prompt,
                "chosen": f"```python\n{code}\n```",
                "rejected": f"```python\n{rejected_a}\n```",
                "metadata": {
                    "source": "batch_generate",
                    "alert_id": ex["alert_id"],
                    "category": ex["category"],
                    "degradation": "remove_iocs",
                    "chosen_iocs": ex["iocs_matched"],
                    "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:12],
                }
            })

        # Degradation B: fake values
        rejected_b = degrade_fake_values(code)
        if rejected_b != code and rejected_b != rejected_a:
            pairs.append({
                "prompt": prompt,
                "chosen": f"```python\n{code}\n```",
                "rejected": f"```python\n{rejected_b}\n```",
                "metadata": {
                    "source": "batch_generate",
                    "alert_id": ex["alert_id"],
                    "category": ex["category"],
                    "degradation": "fake_values",
                    "chosen_iocs": ex["iocs_matched"],
                    "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:12],
                }
            })

    with open(OUTPUT_PATH, "w") as f:
        for pair in pairs:
            f.write(json.dumps(pair) + "\n")

    print(f"Generated {len(pairs)} rejected pairs -> {OUTPUT_PATH}")
    by_deg = {}
    for p in pairs:
        d = p["metadata"]["degradation"]
        by_deg[d] = by_deg.get(d, 0) + 1
    for d, c in by_deg.items():
        print(f"  {d}: {c} pairs")


if __name__ == "__main__":
    main()
