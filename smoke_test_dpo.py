#!/usr/bin/env python3
"""Smoke test: validate hydra_dpo_dataset.jsonl format for DPO training."""

import json
import sys
from pathlib import Path

DATASET = Path(__file__).parent / "hydra_dpo_dataset.jsonl"
REQUIRED_FIELDS = {"prompt", "chosen", "rejected"}
EXPECTED_PAIRS = 5


def tokenize_simple(text: str) -> list[str]:
    """Whitespace tokenizer — no dependencies needed."""
    return text.split()


def main() -> int:
    if not DATASET.exists():
        print(f"FAIL: {DATASET} not found")
        return 1

    pairs = []
    with open(DATASET, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"FAIL: line {i} is not valid JSON — {e}")
                return 1
            missing = REQUIRED_FIELDS - row.keys()
            if missing:
                print(f"FAIL: line {i} missing fields: {missing}")
                return 1
            for field in REQUIRED_FIELDS:
                if not isinstance(row[field], str) or len(row[field]) == 0:
                    print(f"FAIL: line {i} field '{field}' is empty or not a string")
                    return 1
            prompt_tokens = tokenize_simple(row["prompt"])
            chosen_tokens = tokenize_simple(row["chosen"])
            rejected_tokens = tokenize_simple(row["rejected"])
            pairs.append({
                "line": i,
                "prompt_tokens": len(prompt_tokens),
                "chosen_tokens": len(chosen_tokens),
                "rejected_tokens": len(rejected_tokens),
            })

    if len(pairs) != EXPECTED_PAIRS:
        print(f"FAIL: expected {EXPECTED_PAIRS} pairs, got {len(pairs)}")
        return 1

    print(f"Loaded {len(pairs)} DPO pairs from {DATASET.name}\n")
    print(f"{'Pair':<6} {'Prompt toks':<14} {'Chosen toks':<14} {'Rejected toks'}")
    print("-" * 50)
    for p in pairs:
        print(f"{p['line']:<6} {p['prompt_tokens']:<14} {p['chosen_tokens']:<14} {p['rejected_tokens']}")
    total = sum(p["prompt_tokens"] + p["chosen_tokens"] + p["rejected_tokens"] for p in pairs)
    print(f"\nTotal tokens (whitespace): {total:,}")
    print("\nDPO dataset format: VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
