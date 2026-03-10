#!/usr/bin/env python3
"""Accuracy validation runner for HYDRA investigation engine.

Loads labeled test alerts, submits each through the investigation pipeline,
compares verdicts to ground truth, and outputs precision/recall/F1 metrics.

Usage:
    docker compose exec -T worker python tests/accuracy/run_validation.py
    docker compose exec -T worker python tests/accuracy/run_validation.py --dry-run
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime
from pathlib import Path

# Temporal imports (only needed for real mode)
try:
    from temporalio.client import Client
    HAS_TEMPORAL = True
except ImportError:
    HAS_TEMPORAL = False


SCRIPT_DIR = Path(__file__).parent
ALERTS_FILE = SCRIPT_DIR / "test_alerts.json"
RESULTS_FILE = SCRIPT_DIR / "results.json"


def load_alerts():
    """Load labeled test alerts."""
    with open(ALERTS_FILE) as f:
        return json.load(f)


def classify_verdict(verdict_str):
    """Map investigation verdict to binary threat/benign."""
    if not verdict_str:
        return "unknown"
    v = verdict_str.lower().strip()
    threat_words = {"malicious", "threat", "true_positive", "suspicious", "critical", "high"}
    benign_words = {"benign", "false_positive", "clean", "safe", "low", "inconclusive"}
    if any(w in v for w in threat_words):
        return "threat"
    if any(w in v for w in benign_words):
        return "benign"
    return "unknown"


async def submit_investigation(client, alert, timeout_s=60):
    """Submit an alert as a Temporal workflow and wait for result."""
    from temporalio.common import RetryPolicy
    from datetime import timedelta

    task_input = {
        "prompt": alert["description"],
        "task_type": "investigation",
        "indicators": alert.get("indicators", {}),
    }

    handle = await client.start_workflow(
        "ExecuteTaskWorkflow",
        task_input,
        id=f"accuracy-test-{alert['id']}-{int(time.time())}",
        task_queue="hydra-tasks",
        retry_policy=RetryPolicy(maximum_attempts=1),
        execution_timeout=timedelta(seconds=timeout_s),
    )

    result = await handle.result()
    return result


def dry_run_verdict(alert):
    """Simulate a verdict for pipeline testing (no LLM needed)."""
    # 80% "correct" to simulate realistic but imperfect model
    correct = random.random() < 0.80
    if correct:
        return alert["label"]
    else:
        return "benign" if alert["label"] == "threat" else "threat"


def compute_metrics(results):
    """Compute accuracy, precision, recall, F1, FPR from results."""
    tp = sum(1 for r in results if r["expected"] == "threat" and r["got"] == "threat")
    tn = sum(1 for r in results if r["expected"] == "benign" and r["got"] == "benign")
    fp = sum(1 for r in results if r["expected"] == "benign" and r["got"] == "threat")
    fn = sum(1 for r in results if r["expected"] == "threat" and r["got"] == "benign")
    unknown = sum(1 for r in results if r["got"] == "unknown")

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "accuracy": round(accuracy, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "fpr": round(fpr, 3),
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "unknown": unknown},
    }


def compute_by_category(results):
    """Compute per-category metrics."""
    cats = {}
    for r in results:
        cat = r["type"]
        if cat not in cats:
            cats[cat] = []
        cats[cat].append(r)

    by_cat = {}
    for cat, cat_results in sorted(cats.items()):
        tp = sum(1 for r in cat_results if r["expected"] == "threat" and r["got"] == "threat")
        tn = sum(1 for r in cat_results if r["expected"] == "benign" and r["got"] == "benign")
        fp = sum(1 for r in cat_results if r["expected"] == "benign" and r["got"] == "threat")
        fn = sum(1 for r in cat_results if r["expected"] == "threat" and r["got"] == "benign")
        correct = tp + tn
        total = len(cat_results)
        by_cat[cat] = {
            "correct": correct, "total": total,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        }
    return by_cat


def recommendation(metrics):
    """PROCEED / IMPROVE / KILL based on metric thresholds."""
    vals = [metrics["accuracy"], metrics["precision"], metrics["recall"]]
    if all(v >= 0.85 for v in vals):
        return "PROCEED"
    if any(v < 0.70 for v in vals):
        return "KILL"
    return "IMPROVE"


async def run_real(alerts):
    """Run against live Temporal + LLM stack."""
    if not HAS_TEMPORAL:
        print("ERROR: temporalio not installed. Use --dry-run or install temporalio.")
        sys.exit(1)

    temporal_addr = os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")
    client = await Client.connect(temporal_addr)

    results = []
    for i, alert in enumerate(alerts):
        print(f"  [{i+1}/{len(alerts)}] {alert['id']} ({alert['type']})...", end=" ", flush=True)
        try:
            result = await submit_investigation(client, alert, timeout_s=60)
            verdict_raw = result.get("verdict", result.get("risk_level", "unknown"))
            verdict = classify_verdict(str(verdict_raw))
            confidence = result.get("confidence", 0)
            print(f"verdict={verdict} (raw={verdict_raw}, confidence={confidence})")
        except Exception as e:
            verdict = "unknown"
            confidence = 0
            print(f"ERROR: {e}")

        results.append({
            "id": alert["id"],
            "type": alert["type"],
            "expected": alert["label"],
            "got": verdict,
            "confidence": confidence,
        })

    return results


def run_dry(alerts):
    """Simulate verdicts without LLM."""
    random.seed(42)  # Reproducible
    results = []
    for alert in alerts:
        verdict = dry_run_verdict(alert)
        confidence = round(random.uniform(0.4, 0.95), 2)
        results.append({
            "id": alert["id"],
            "type": alert["type"],
            "expected": alert["label"],
            "got": verdict,
            "confidence": confidence,
        })
    return results


def main():
    parser = argparse.ArgumentParser(description="HYDRA Accuracy Validation")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate verdicts without LLM (test pipeline)")
    args = parser.parse_args()

    print("=" * 60)
    print("HYDRA ACCURACY VALIDATION")
    print(f"Mode: {'DRY RUN (simulated)' if args.dry_run else 'LIVE (Temporal + LLM)'}")
    print("=" * 60)

    alerts = load_alerts()
    print(f"Loaded {len(alerts)} test alerts")
    print()

    if args.dry_run:
        results = run_dry(alerts)
    else:
        import asyncio
        results = asyncio.run(run_real(alerts))

    # Compute metrics
    metrics = compute_metrics(results)
    by_category = compute_by_category(results)
    failures = [r for r in results if r["expected"] != r["got"]]
    rec = recommendation(metrics)

    # Build report
    report = {
        "validation_date": datetime.utcnow().strftime("%Y-%m-%d"),
        "mode": "dry_run" if args.dry_run else "live",
        "total_alerts": len(alerts),
        "metrics": metrics,
        "by_category": by_category,
        "failures": failures,
        "recommendation": rec,
    }

    # Write results
    with open(RESULTS_FILE, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Accuracy:  {metrics['accuracy']:.1%}")
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall:    {metrics['recall']:.1%}")
    print(f"  F1 Score:  {metrics['f1']:.1%}")
    print(f"  FPR:       {metrics['fpr']:.1%}")
    print(f"  Confusion: TP={metrics['confusion']['tp']} TN={metrics['confusion']['tn']} "
          f"FP={metrics['confusion']['fp']} FN={metrics['confusion']['fn']} "
          f"UNK={metrics['confusion']['unknown']}")
    print()
    print("By Category:")
    for cat, m in by_category.items():
        print(f"  {cat:25s} {m['correct']}/{m['total']} correct "
              f"(TP={m['tp']} TN={m['tn']} FP={m['fp']} FN={m['fn']})")
    if failures:
        print()
        print(f"Failures ({len(failures)}):")
        for f_item in failures:
            print(f"  {f_item['id']:8s} expected={f_item['expected']:7s} "
                  f"got={f_item['got']:7s} confidence={f_item['confidence']}")
    print()
    print(f"RECOMMENDATION: {rec}")
    print(f"Results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
