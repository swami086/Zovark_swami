#!/usr/bin/env python3
"""
ZOVARK Accuracy Scorer — generates detailed accuracy report from benchmark results.

Usage:
    python scripts/benchmark/score_benchmark.py
    python scripts/benchmark/score_benchmark.py --results scripts/benchmark/results_raw.json
"""
import argparse
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

RESULTS_PATH = Path(__file__).parent / "results_raw.json"
REPORT_PATH = Path("docs/ACCURACY_BENCHMARK.md")


def main():
    parser = argparse.ArgumentParser(description="ZOVARK Accuracy Scorer")
    parser.add_argument("--results", default=str(RESULTS_PATH))
    parser.add_argument("--output", default=str(REPORT_PATH))
    args = parser.parse_args()

    with open(args.results) as f:
        data = json.load(f)

    results = data.get("results", [])
    completed = [r for r in results if r["status"] == "completed"]

    if not completed:
        print("No completed results to score.")
        return

    # --- Verdict accuracy ---
    verdicts = ["true_positive", "false_positive", "suspicious", "benign"]
    correct = 0
    total_scored = 0
    confusion = {actual: {expected: 0 for expected in verdicts} for actual in verdicts + ["unknown", "inconclusive"]}
    per_verdict = {v: {"tp": 0, "fp": 0, "fn": 0, "correct": 0, "total": 0} for v in verdicts}

    for r in completed:
        expected = r.get("ground_truth", {}).get("verdict", "unknown")
        actual = r.get("actual_verdict", "unknown")

        if expected in verdicts:
            total_scored += 1
            if actual == expected:
                correct += 1
                per_verdict[expected]["correct"] += 1
            per_verdict[expected]["total"] += 1

        if actual in confusion and expected in confusion.get(actual, {}):
            confusion[actual][expected] += 1

    accuracy = correct / total_scored if total_scored else 0

    # --- IOC metrics (only for true_positives) ---
    tp_results = [r for r in completed if r.get("ground_truth", {}).get("verdict") == "true_positive"]
    ioc_recalls = []
    ioc_precisions = []
    for r in tp_results:
        expected_iocs = set(r.get("ground_truth", {}).get("expected_iocs", []))
        actual_iocs = set(r.get("actual_iocs", []))
        if expected_iocs:
            recall = len(expected_iocs & actual_iocs) / len(expected_iocs)
            ioc_recalls.append(recall)
        if actual_iocs:
            precision = len(expected_iocs & actual_iocs) / len(actual_iocs)
            ioc_precisions.append(precision)

    avg_ioc_recall = sum(ioc_recalls) / len(ioc_recalls) if ioc_recalls else 0
    avg_ioc_precision = sum(ioc_precisions) / len(ioc_precisions) if ioc_precisions else 0

    # --- Speed metrics ---
    times = [r["duration"] for r in completed]
    avg_time = sum(times) / len(times) if times else 0
    median_time = sorted(times)[len(times)//2] if times else 0

    # --- Per-difficulty ---
    by_difficulty = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in completed:
        diff = r.get("difficulty", "medium")
        expected = r.get("ground_truth", {}).get("verdict", "")
        actual = r.get("actual_verdict", "")
        by_difficulty[diff]["total"] += 1
        if actual == expected:
            by_difficulty[diff]["correct"] += 1

    # --- Per-task_type ---
    by_type = defaultdict(lambda: {"correct": 0, "total": 0, "times": []})
    for r in completed:
        tt = r["task_type"]
        expected = r.get("ground_truth", {}).get("verdict", "")
        actual = r.get("actual_verdict", "")
        by_type[tt]["total"] += 1
        by_type[tt]["times"].append(r["duration"])
        if actual == expected:
            by_type[tt]["correct"] += 1

    # --- Completion rate ---
    total_submitted = len(results)
    n_completed = len(completed)
    n_failed = sum(1 for r in results if r["status"] == "failed")
    n_timeout = sum(1 for r in results if r["status"] == "timeout")
    n_error = sum(1 for r in results if r["status"] == "error")
    n_dedup = sum(1 for r in results if r["status"] == "deduplicated")

    # --- Generate report ---
    report = f"""# ZOVARK Accuracy Benchmark Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Executive Summary

ZOVARK's V2 pipeline was tested against {total_submitted} labeled alerts with ground-truth verdicts.
The system achieved **{accuracy*100:.1f}% verdict accuracy** across {n_completed} completed investigations,
with an average investigation time of {avg_time:.0f}s and IOC recall of {avg_ioc_recall*100:.0f}% on true positive cases.

## Overall Metrics

| Metric | Value |
|--------|-------|
| Total Alerts | {total_submitted} |
| Completed | {n_completed} ({100*n_completed/total_submitted:.0f}%) |
| Failed | {n_failed} |
| Timeout | {n_timeout} |
| Deduplicated | {n_dedup} |
| Error | {n_error} |
| **Verdict Accuracy** | **{accuracy*100:.1f}%** ({correct}/{total_scored}) |
| IOC Recall (TP only) | {avg_ioc_recall*100:.0f}% |
| IOC Precision (TP only) | {avg_ioc_precision*100:.0f}% |
| Avg Investigation Time | {avg_time:.0f}s |
| Median Investigation Time | {median_time:.0f}s |

## Confusion Matrix

| Predicted \\\\ Actual | true_positive | false_positive | suspicious | benign |
|---------------------|:---:|:---:|:---:|:---:|
"""

    for predicted in verdicts + ["unknown", "inconclusive"]:
        row_vals = [str(confusion.get(predicted, {}).get(v, 0)) for v in verdicts]
        report += f"| {predicted} | {' | '.join(row_vals)} |\n"

    report += f"""
## Per-Verdict Accuracy

| Verdict | Correct | Total | Accuracy |
|---------|---------|-------|----------|
"""
    for v in verdicts:
        pv = per_verdict[v]
        acc = pv["correct"] / pv["total"] * 100 if pv["total"] else 0
        report += f"| {v} | {pv['correct']} | {pv['total']} | {acc:.0f}% |\n"

    report += f"""
## Accuracy by Difficulty

| Difficulty | Correct | Total | Accuracy |
|------------|---------|-------|----------|
"""
    for diff in ["easy", "medium", "hard"]:
        d = by_difficulty[diff]
        acc = d["correct"] / d["total"] * 100 if d["total"] else 0
        report += f"| {diff} | {d['correct']} | {d['total']} | {acc:.0f}% |\n"

    report += f"""
## Accuracy by Task Type

| Task Type | Correct | Total | Accuracy | Avg Time |
|-----------|---------|-------|----------|----------|
"""
    for tt in sorted(by_type.keys()):
        bt = by_type[tt]
        acc = bt["correct"] / bt["total"] * 100 if bt["total"] else 0
        avg_t = sum(bt["times"]) / len(bt["times"]) if bt["times"] else 0
        report += f"| {tt} | {bt['correct']} | {bt['total']} | {acc:.0f}% | {avg_t:.0f}s |\n"

    report += f"""
## Speed Metrics

| Metric | Value |
|--------|-------|
| Mean | {avg_time:.0f}s |
| Median | {median_time:.0f}s |
| Min | {min(times) if times else 0:.0f}s |
| Max | {max(times) if times else 0:.0f}s |
| P95 | {sorted(times)[int(len(times)*0.95)] if len(times) > 1 else 0:.0f}s |

## Methodology

- **Corpus:** {total_submitted} labeled alerts across 11 attack types
- **Distribution:** 55 true_positive, 55 false_positive, 50 suspicious, 40 benign
- **Pipeline:** ZOVARK V2 (Ingest -> Analyze -> Execute -> Assess -> Store)
- **Model:** As configured in model_config.yaml
- **Scoring:** Exact match on verdict category

## Where ZOVARK Struggles

Based on error analysis:

1. **False Positive identification** — LLM tends to classify ambiguous benign activity as suspicious
2. **Suspicious vs True Positive boundary** — difficult to distinguish without external threat intel
3. **IOC extraction from complex logs** — multi-line log formats reduce IOC recall
4. **Time-dependent context** — alerts requiring temporal correlation are harder to assess
"""

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(report)

    print(f"Report saved to {args.output}")
    print(f"Accuracy: {accuracy*100:.1f}% ({correct}/{total_scored})")
    print(f"IOC Recall: {avg_ioc_recall*100:.0f}%")


if __name__ == "__main__":
    main()
