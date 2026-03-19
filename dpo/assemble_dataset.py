#!/usr/bin/env python3
"""Assemble final DPO training dataset from all sources.

Merges:
  - dpo/path_b_pairs.jsonl (3 manual pairs from Path B tests)
  - dpo/rejected_examples.jsonl (batch-generated pairs)

Validates, deduplicates, and outputs final dataset.

Usage:
    python dpo/assemble_dataset.py
"""
import json
import hashlib
from pathlib import Path
from collections import Counter

SOURCES = [
    Path("dpo/path_b_pairs.jsonl"),
    Path("dpo/rejected_examples.jsonl"),
]
OUTPUT = Path("dpo/training_dataset.jsonl")
STATS_OUTPUT = Path("dpo/dataset_stats.json")


def validate_pair(pair, idx):
    """Validate a DPO pair."""
    errors = []
    if "prompt" not in pair:
        errors.append("missing prompt")
    if "chosen" not in pair:
        errors.append("missing chosen")
    if "rejected" not in pair:
        errors.append("missing rejected")
    if pair.get("chosen") == pair.get("rejected"):
        errors.append("chosen == rejected")
    if len(pair.get("chosen", "")) < 50:
        errors.append(f"chosen too short ({len(pair.get('chosen', ''))} chars)")
    if len(pair.get("rejected", "")) < 50:
        errors.append(f"rejected too short ({len(pair.get('rejected', ''))} chars)")
    # Check that chosen contains Python code
    if "```python" not in pair.get("chosen", ""):
        errors.append("chosen missing code block")
    return errors


def quality_score(pair):
    """Score pair quality 1-5."""
    score = 3.0  # base
    chosen = pair.get("chosen", "")
    rejected = pair.get("rejected", "")

    # Length difference (longer chosen = better quality gap)
    len_ratio = len(chosen) / max(len(rejected), 1)
    if len_ratio > 1.2:
        score += 0.5
    if len_ratio > 1.5:
        score += 0.5

    # Code features in chosen
    if "re.findall" in chosen or "re.compile" in chosen:
        score += 0.5  # has regex IOC extraction
    if "iocs" in chosen and "append" in chosen:
        score += 0.5  # builds IOC list

    # Degradation quality in rejected
    if "TODO" in rejected or "# IOC" in rejected or "fake" in rejected.lower():
        score += 0.5  # clear degradation visible

    # Cap at 5
    return min(5.0, round(score, 1))


def main():
    all_pairs = []
    source_counts = Counter()

    for source in SOURCES:
        if not source.exists():
            print(f"  SKIP {source} (not found)")
            continue
        count = 0
        with open(source) as f:
            for line in f:
                if line.strip():
                    pair = json.loads(line)
                    pair.setdefault("metadata", {})["source_file"] = str(source)
                    all_pairs.append(pair)
                    count += 1
        source_counts[str(source)] = count
        print(f"  Loaded {count} pairs from {source}")

    print(f"\nTotal raw pairs: {len(all_pairs)}")

    # Validate
    valid_pairs = []
    for i, pair in enumerate(all_pairs):
        errors = validate_pair(pair, i)
        if errors:
            print(f"  INVALID pair {i}: {errors}")
        else:
            pair["metadata"]["quality_score"] = quality_score(pair)
            valid_pairs.append(pair)

    print(f"Valid pairs: {len(valid_pairs)}/{len(all_pairs)}")

    # Deduplicate by prompt hash
    seen = set()
    unique_pairs = []
    for pair in valid_pairs:
        h = hashlib.sha256(pair["prompt"].encode()).hexdigest()[:16]
        # Allow multiple pairs per prompt (different degradations)
        key = h + "|" + pair.get("metadata", {}).get("degradation", "manual")
        if key not in seen:
            seen.add(key)
            unique_pairs.append(pair)

    print(f"After dedup: {len(unique_pairs)}")

    # Write output
    with open(OUTPUT, "w") as f:
        for pair in unique_pairs:
            f.write(json.dumps(pair) + "\n")

    # Statistics
    categories = Counter()
    scores = []
    degradations = Counter()
    for pair in unique_pairs:
        meta = pair.get("metadata", {})
        categories[meta.get("category", "manual")] += 1
        scores.append(meta.get("quality_score", 3.0))
        degradations[meta.get("degradation", "manual")] += 1

    stats = {
        "total_pairs": len(unique_pairs),
        "sources": dict(source_counts),
        "by_category": dict(categories),
        "by_degradation": dict(degradations),
        "quality_scores": {
            "mean": round(sum(scores) / max(len(scores), 1), 2),
            "min": min(scores) if scores else 0,
            "max": max(scores) if scores else 0,
        },
    }

    with open(STATS_OUTPUT, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"\n{'='*60}")
    print(f"DATASET ASSEMBLED: {len(unique_pairs)} pairs -> {OUTPUT}")
    print(f"Categories: {dict(categories)}")
    print(f"Degradations: {dict(degradations)}")
    print(f"Quality: mean={stats['quality_scores']['mean']}, "
          f"min={stats['quality_scores']['min']}, max={stats['quality_scores']['max']}")
    print(f"Stats saved to {STATS_OUTPUT}")


if __name__ == "__main__":
    main()
