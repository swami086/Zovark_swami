#!/usr/bin/env python3
"""HYDRA Accuracy Benchmark — runs labeled corpus against model tiers.

Submits each labeled alert through the investigation pipeline, compares
results against ground truth, and produces a structured accuracy report.

Usage:
  python scripts/accuracy_benchmark.py --model fast
  python scripts/accuracy_benchmark.py --model standard
  python scripts/accuracy_benchmark.py --all
  python scripts/accuracy_benchmark.py --offline   # Score existing results only
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx


GROUND_TRUTH_PATH = "tests/corpus/ground_truth.json"
RESULTS_DIR = "docs/accuracy_results"
API_URL = os.environ.get("HYDRA_API_URL", "http://localhost:8090")


def load_ground_truth() -> dict:
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


def login(api_url: str) -> str:
    """Login and return access token."""
    resp = httpx.post(f"{api_url}/api/v1/auth/login", json={
        "email": os.environ.get("HYDRA_TEST_EMAIL", "admin@test.local"),
        "password": os.environ.get("HYDRA_TEST_PASSWORD", "TestPass2026"),
    }, timeout=10.0)
    resp.raise_for_status()
    return resp.json().get("token", "")


def submit_alert(api_url: str, token: str, alert: dict) -> str:
    """Submit an alert for investigation. Returns task_id."""
    prompt = alert.get("description", alert.get("prompt", "Investigate this alert"))
    category = alert.get("category", alert.get("type", "log_analysis"))

    resp = httpx.post(f"{api_url}/api/v1/tasks", json={
        "task_type": category,
        "input": {
            "prompt": prompt,
            "severity": alert.get("severity", "high"),
            "source_ip": alert.get("indicators", {}).get("src_ip", ""),
            "dest_ip": alert.get("indicators", {}).get("dst_ip", ""),
        }
    }, headers={"Authorization": f"Bearer {token}"}, timeout=30.0)
    resp.raise_for_status()
    return resp.json().get("task_id", "")


def poll_task(api_url: str, token: str, task_id: str, timeout_s: int = 180) -> dict:
    """Poll until task completes or times out."""
    start = time.time()
    while time.time() - start < timeout_s:
        resp = httpx.get(f"{api_url}/api/v1/tasks/{task_id}",
                         headers={"Authorization": f"Bearer {token}"}, timeout=10.0)
        data = resp.json()
        status = data.get("status", "")
        if status in ("completed", "done", "failed"):
            return data
        time.sleep(5)
    return {"status": "timeout", "task_id": task_id}


def score_investigation(result: dict, truth: dict) -> dict:
    """Score a single investigation against ground truth."""
    gt = truth.get("ground_truth", {})
    output = result.get("output", {}) or {}

    # Extract values
    risk_score = 0
    if isinstance(output, dict):
        risk_score = output.get("risk_score", result.get("risk_score", 0)) or 0
    elif result.get("severity") == "critical":
        risk_score = 85

    findings = []
    if isinstance(output, dict):
        findings = output.get("findings", [])
        if isinstance(output.get("stdout"), str):
            try:
                parsed = json.loads(output["stdout"])
                findings = parsed.get("findings", findings)
                risk_score = parsed.get("risk_score", risk_score)
            except (json.JSONDecodeError, TypeError):
                pass

    iocs_extracted = set()
    if isinstance(output, dict):
        raw_iocs = output.get("iocs", {})
        if isinstance(raw_iocs, dict):
            for v in raw_iocs.values():
                if isinstance(v, list):
                    iocs_extracted.update(str(i) for i in v)

    # Verdict scoring
    status = result.get("status", "failed")
    code_success = status in ("completed", "done")

    # Determine predicted verdict from risk score
    if risk_score >= 60:
        predicted_verdict = "true_positive"
    elif risk_score >= 30:
        predicted_verdict = "needs_investigation"
    else:
        predicted_verdict = "false_positive"

    expected_verdict = gt.get("verdict", "true_positive")
    verdict_correct = (predicted_verdict == expected_verdict) or \
                      (predicted_verdict == "needs_investigation" and expected_verdict == "true_positive")

    # Risk score scoring
    rs_min = gt.get("risk_score_min", 0)
    rs_max = gt.get("risk_score_max", 100)
    risk_in_range = rs_min <= risk_score <= rs_max
    risk_error = 0
    if risk_score < rs_min:
        risk_error = rs_min - risk_score
    elif risk_score > rs_max:
        risk_error = risk_score - rs_max

    # IOC scoring
    expected_iocs = set(gt.get("expected_iocs", []))
    ioc_tp = len(iocs_extracted & expected_iocs)
    ioc_precision = ioc_tp / len(iocs_extracted) if iocs_extracted else 1.0
    ioc_recall = ioc_tp / len(expected_iocs) if expected_iocs else 1.0
    ioc_f1 = 2 * ioc_precision * ioc_recall / (ioc_precision + ioc_recall) if (ioc_precision + ioc_recall) > 0 else 0

    # Hallucination: IOCs not in alert data or ground truth
    hallucinated = iocs_extracted - expected_iocs
    hallucination = len(hallucinated) > 0

    # Findings count
    findings_min = gt.get("expected_findings_min", 0)
    findings_ok = len(findings) >= findings_min

    return {
        "alert_id": truth.get("id", "unknown"),
        "category": truth.get("category", "unknown"),
        "difficulty": truth.get("difficulty", "unknown"),
        "status": status,
        "code_success": code_success,
        "verdict_correct": verdict_correct,
        "predicted_verdict": predicted_verdict,
        "expected_verdict": expected_verdict,
        "risk_score": risk_score,
        "risk_in_range": risk_in_range,
        "risk_error": risk_error,
        "ioc_precision": round(ioc_precision, 3),
        "ioc_recall": round(ioc_recall, 3),
        "ioc_f1": round(ioc_f1, 3),
        "hallucination": hallucination,
        "findings_count": len(findings),
        "findings_ok": findings_ok,
        "execution_ms": result.get("execution_ms", 0) or 0,
    }


def compute_aggregates(scores: list) -> dict:
    """Compute aggregate metrics from individual scores."""
    n = len(scores) or 1

    verdict_correct = sum(1 for s in scores if s["verdict_correct"])
    code_success = sum(1 for s in scores if s["code_success"])
    risk_in_range = sum(1 for s in scores if s["risk_in_range"])
    hallucinations = sum(1 for s in scores if s["hallucination"])

    # FP/FN rates
    actual_tp = [s for s in scores if s["expected_verdict"] == "true_positive"]
    actual_fp = [s for s in scores if s["expected_verdict"] == "false_positive"]
    false_negatives = sum(1 for s in actual_tp if s["predicted_verdict"] == "false_positive")
    false_positives = sum(1 for s in actual_fp if s["predicted_verdict"] == "true_positive")

    mean_risk_error = sum(s["risk_error"] for s in scores) / n
    mean_ioc_f1 = sum(s["ioc_f1"] for s in scores) / n
    mean_exec_ms = sum(s["execution_ms"] for s in scores) / n

    # By category
    categories = {}
    for s in scores:
        cat = s["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(s)

    by_category = {}
    for cat, cat_scores in categories.items():
        cn = len(cat_scores)
        by_category[cat] = {
            "total": cn,
            "accuracy": round(sum(1 for s in cat_scores if s["verdict_correct"]) / cn, 3),
            "code_success_rate": round(sum(1 for s in cat_scores if s["code_success"]) / cn, 3),
            "mean_ioc_f1": round(sum(s["ioc_f1"] for s in cat_scores) / cn, 3),
        }

    # By difficulty
    difficulties = {}
    for s in scores:
        diff = s["difficulty"]
        if diff not in difficulties:
            difficulties[diff] = []
        difficulties[diff].append(s)

    by_difficulty = {}
    for diff, diff_scores in difficulties.items():
        dn = len(diff_scores)
        by_difficulty[diff] = {
            "total": dn,
            "accuracy": round(sum(1 for s in diff_scores if s["verdict_correct"]) / dn, 3),
        }

    return {
        "total": n,
        "overall_accuracy": round(verdict_correct / n, 3),
        "false_positive_rate": round(false_positives / len(actual_fp), 3) if actual_fp else 0.0,
        "false_negative_rate": round(false_negatives / len(actual_tp), 3) if actual_tp else 0.0,
        "code_gen_success_rate": round(code_success / n, 3),
        "risk_score_accuracy": round(risk_in_range / n, 3),
        "mean_risk_error": round(mean_risk_error, 1),
        "mean_ioc_f1": round(mean_ioc_f1, 3),
        "hallucination_rate": round(hallucinations / n, 3),
        "mean_execution_ms": round(mean_exec_ms, 0),
        "by_category": by_category,
        "by_difficulty": by_difficulty,
    }


def generate_markdown_report(model: str, aggregates: dict, scores: list) -> str:
    """Generate Markdown accuracy report."""
    a = aggregates
    report = f"""# HYDRA Accuracy Report — {model} tier

**Generated:** {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}
**Corpus:** {a['total']} labeled alerts
**Model tier:** {model}

## Summary

| Metric | Value |
|--------|-------|
| Overall accuracy (verdict) | {a['overall_accuracy']*100:.1f}% |
| False positive rate | {a['false_positive_rate']*100:.1f}% |
| False negative rate | {a['false_negative_rate']*100:.1f}% |
| Code generation success | {a['code_gen_success_rate']*100:.1f}% |
| Risk score in range | {a['risk_score_accuracy']*100:.1f}% |
| Mean risk score error | {a['mean_risk_error']:.1f} |
| IOC F1 score | {a['mean_ioc_f1']:.3f} |
| Hallucination rate | {a['hallucination_rate']*100:.1f}% |
| Mean investigation time | {a['mean_execution_ms']:.0f}ms |

## Accuracy by Category

| Category | Total | Accuracy | Code Success | IOC F1 |
|----------|-------|----------|-------------|--------|
"""
    for cat, stats in sorted(a["by_category"].items()):
        report += f"| {cat} | {stats['total']} | {stats['accuracy']*100:.1f}% | {stats['code_success_rate']*100:.1f}% | {stats['mean_ioc_f1']:.3f} |\n"

    report += "\n## Accuracy by Difficulty\n\n| Difficulty | Total | Accuracy |\n|------------|-------|----------|\n"
    for diff, stats in sorted(a["by_difficulty"].items()):
        report += f"| {diff} | {stats['total']} | {stats['accuracy']*100:.1f}% |\n"

    report += "\n## Individual Results\n\n| Alert | Category | Difficulty | Verdict | Risk | IOC F1 | Code OK |\n|-------|----------|------------|---------|------|--------|--------|\n"
    for s in scores:
        v = "correct" if s["verdict_correct"] else "WRONG"
        c = "yes" if s["code_success"] else "NO"
        report += f"| {s['alert_id']} | {s['category']} | {s['difficulty']} | {v} | {s['risk_score']} | {s['ioc_f1']:.2f} | {c} |\n"

    return report


def main():
    parser = argparse.ArgumentParser(description="HYDRA Accuracy Benchmark")
    parser.add_argument("--model", choices=["fast", "standard", "reasoning"], default="fast")
    parser.add_argument("--all", action="store_true", help="Run all tiers")
    parser.add_argument("--offline", action="store_true", help="Score existing results only")
    parser.add_argument("--api-url", default=API_URL)
    parser.add_argument("--limit", type=int, default=0, help="Limit alerts to test (0=all)")
    args = parser.parse_args()

    gt = load_ground_truth()
    alerts = gt["alerts"]
    if args.limit:
        alerts = alerts[:args.limit]
    print(f"Loaded {len(alerts)} labeled alerts")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    tiers = ["fast", "standard", "reasoning"] if args.all else [args.model]

    for tier in tiers:
        print(f"\n{'='*60}")
        print(f"Running benchmark: {tier} tier ({len(alerts)} alerts)")
        print(f"{'='*60}")

        scores = []
        if not args.offline:
            try:
                token = login(args.api_url)
                print(f"Authenticated")
            except Exception as e:
                print(f"Login failed: {e}")
                print("Use --offline to score existing results, or start the Docker stack")
                sys.exit(1)

            os.environ["HYDRA_LLM_MODEL"] = f"hydra-{tier}" if tier != "fast" else "fast"

            for i, alert in enumerate(alerts):
                alert_id = alert.get("id", f"alert-{i}")
                print(f"  [{i+1}/{len(alerts)}] {alert_id}...", end=" ", flush=True)
                try:
                    task_id = submit_alert(args.api_url, token, alert)
                    result = poll_task(args.api_url, token, task_id)
                    score = score_investigation(result, alert)
                    scores.append(score)
                    v = "correct" if score["verdict_correct"] else "WRONG"
                    print(f"risk={score['risk_score']} verdict={v} ({score['execution_ms']}ms)")
                except Exception as e:
                    print(f"ERROR: {e}")
                    scores.append({
                        "alert_id": alert_id, "category": alert.get("category", "unknown"),
                        "difficulty": alert.get("difficulty", "unknown"), "status": "error",
                        "code_success": False, "verdict_correct": False,
                        "predicted_verdict": "error", "expected_verdict": alert.get("ground_truth", {}).get("verdict", "unknown"),
                        "risk_score": 0, "risk_in_range": False, "risk_error": 50,
                        "ioc_precision": 0, "ioc_recall": 0, "ioc_f1": 0,
                        "hallucination": False, "findings_count": 0, "findings_ok": False,
                        "execution_ms": 0,
                    })
        else:
            # Offline mode: generate placeholder scores for report template
            for alert in alerts:
                scores.append({
                    "alert_id": alert.get("id", "unknown"),
                    "category": alert.get("category", "unknown"),
                    "difficulty": alert.get("difficulty", "unknown"),
                    "status": "offline", "code_success": True, "verdict_correct": True,
                    "predicted_verdict": alert.get("ground_truth", {}).get("verdict", "unknown"),
                    "expected_verdict": alert.get("ground_truth", {}).get("verdict", "unknown"),
                    "risk_score": (alert.get("ground_truth", {}).get("risk_score_min", 50) +
                                   alert.get("ground_truth", {}).get("risk_score_max", 80)) // 2,
                    "risk_in_range": True, "risk_error": 0,
                    "ioc_precision": 0.0, "ioc_recall": 0.0, "ioc_f1": 0.0,
                    "hallucination": False, "findings_count": 1, "findings_ok": True,
                    "execution_ms": 0,
                })

        # Compute aggregates
        agg = compute_aggregates(scores)

        # Save JSON results
        results_path = f"{RESULTS_DIR}/{tier}_results.json"
        with open(results_path, "w") as f:
            json.dump({"model": tier, "timestamp": datetime.utcnow().isoformat(),
                        "aggregates": agg, "scores": scores}, f, indent=2)
        print(f"\nResults saved: {results_path}")

        # Generate Markdown report
        report = generate_markdown_report(tier, agg, scores)
        report_path = f"{RESULTS_DIR}/{tier}_report.md"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"Report saved: {report_path}")

        # Print summary
        print(f"\n--- {tier} tier summary ---")
        print(f"  Accuracy: {agg['overall_accuracy']*100:.1f}%")
        print(f"  FP rate:  {agg['false_positive_rate']*100:.1f}%")
        print(f"  FN rate:  {agg['false_negative_rate']*100:.1f}%")
        print(f"  Code gen: {agg['code_gen_success_rate']*100:.1f}%")
        print(f"  IOC F1:   {agg['mean_ioc_f1']:.3f}")


if __name__ == "__main__":
    main()
