#!/usr/bin/env python3
"""
Generate a head-to-head model comparison report from benchmark results.

Usage:
    python scripts/model_comparison_report.py
    python scripts/model_comparison_report.py --results1 benchmark_results_qwen25-14b.json --results2 benchmark_results_nemotron-4b.json
"""
import argparse
import json
import os
from datetime import datetime


def load_results(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="Model Comparison Report Generator")
    parser.add_argument("--results1", default="benchmark_results_qwen25-14b.json")
    parser.add_argument("--results2", default="benchmark_results_nemotron-4b.json")
    parser.add_argument("--output", default="docs/MODEL_COMPARISON.md")
    args = parser.parse_args()

    r1 = load_results(args.results1)
    r2 = load_results(args.results2)

    def get_metrics(r):
        results = r.get("results", [])
        completed = [x for x in results if x.get("status") == "completed"]
        correct = sum(1 for x in completed if x.get("verdict_correct"))
        times = [x["duration"] for x in completed]
        ioc_recalls = [x.get("ioc_recall", 0) for x in completed]
        return {
            "name": r.get("model_name", "unknown"),
            "completed": len(completed),
            "total": r.get("corpus_size", len(results)),
            "accuracy": correct / len(completed) if completed else 0,
            "correct": correct,
            "avg_time": sum(times) / len(times) if times else 0,
            "median_time": sorted(times)[len(times)//2] if times else 0,
            "min_time": min(times) if times else 0,
            "max_time": max(times) if times else 0,
            "avg_ioc_recall": sum(ioc_recalls) / len(ioc_recalls) if ioc_recalls else 0,
            "results": results,
        }

    m1 = get_metrics(r1)
    m2 = get_metrics(r2)

    # Determine winner
    winner_accuracy = m1["name"] if m1["accuracy"] >= m2["accuracy"] else m2["name"]
    winner_speed = m1["name"] if m1["avg_time"] <= m2["avg_time"] else m2["name"]

    report = f"""# HYDRA Model Comparison Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary

| Metric | {m1['name']} | {m2['name']} | Winner |
|--------|{'---:|' * 2}--------|
| Completed | {m1['completed']}/{m1['total']} | {m2['completed']}/{m2['total']} | {'tie' if m1['completed'] == m2['completed'] else (m1['name'] if m1['completed'] > m2['completed'] else m2['name'])} |
| Verdict Accuracy | {m1['accuracy']*100:.0f}% ({m1['correct']}/{m1['completed']}) | {m2['accuracy']*100:.0f}% ({m2['correct']}/{m2['completed']}) | {winner_accuracy} |
| IOC Recall | {m1['avg_ioc_recall']*100:.0f}% | {m2['avg_ioc_recall']*100:.0f}% | {m1['name'] if m1['avg_ioc_recall'] >= m2['avg_ioc_recall'] else m2['name']} |
| Avg Time | {m1['avg_time']:.0f}s | {m2['avg_time']:.0f}s | {winner_speed} |
| Median Time | {m1['median_time']:.0f}s | {m2['median_time']:.0f}s | {m1['name'] if m1['median_time'] <= m2['median_time'] else m2['name']} |
| Min Time | {m1['min_time']:.0f}s | {m2['min_time']:.0f}s | - |
| Max Time | {m1['max_time']:.0f}s | {m2['max_time']:.0f}s | - |

## Per-Alert Breakdown

| # | Task Type | {m1['name']} | | {m2['name']} | |
|---|-----------|---------|-------|---------|-------|
| | | Verdict | Time | Verdict | Time |
"""

    for i in range(min(len(m1["results"]), len(m2["results"]))):
        r1r = m1["results"][i] if i < len(m1["results"]) else {}
        r2r = m2["results"][i] if i < len(m2["results"]) else {}
        v1 = "correct" if r1r.get("verdict_correct") else r1r.get("actual_verdict", r1r.get("status", "-"))
        v2 = "correct" if r2r.get("verdict_correct") else r2r.get("actual_verdict", r2r.get("status", "-"))
        t1 = f"{r1r.get('duration', 0):.0f}s"
        t2 = f"{r2r.get('duration', 0):.0f}s"
        tt = r1r.get("task_type", r2r.get("task_type", "-"))
        report += f"| {i+1} | {tt} | {v1} | {t1} | {v2} | {t2} |\n"

    report += f"""
## Recommendation

- **Accuracy leader:** {winner_accuracy}
- **Speed leader:** {winner_speed}

### Suggested Model Tiers

| Tier | Model | Use Case |
|------|-------|----------|
| Fast | {winner_speed} | Low/medium severity triage, simple alerts |
| Standard | {winner_accuracy} | High/critical severity, full investigation |
| Enterprise | (cloud or A100) | Complex multi-stage attacks |
"""

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        f.write(report)

    print(f"Report saved to {args.output}")
    print(f"Accuracy winner: {winner_accuracy}")
    print(f"Speed winner: {winner_speed}")


if __name__ == "__main__":
    main()
