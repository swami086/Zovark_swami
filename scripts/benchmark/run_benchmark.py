#!/usr/bin/env python3
"""
HYDRA 200-Alert Accuracy Benchmark Runner.
Submits all alerts from corpus_200.json, polls for completion, scores results.

Usage:
    python scripts/benchmark/run_benchmark.py                    # Full run
    python scripts/benchmark/run_benchmark.py --limit 10         # First 10 only
    python scripts/benchmark/run_benchmark.py --resume            # Resume from progress
    python scripts/benchmark/run_benchmark.py --spacing 30       # 30s between alerts
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from datetime import datetime

API_URL = os.environ.get("HYDRA_API_URL", "http://localhost:8090")
CORPUS_PATH = Path(__file__).parent / "corpus_200.json"
RESULTS_PATH = Path(__file__).parent / "results_raw.json"
PROGRESS_PATH = Path(__file__).parent / "progress.json"


def login(api_url):
    email = os.environ.get("HYDRA_TEST_EMAIL", "admin@test.local")
    password = os.environ.get("HYDRA_TEST_PASSWORD", "TestPass2026")
    payload = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/auth/login", data=payload,
                                 headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())["token"]


def submit_alert(api_url, token, alert):
    payload = json.dumps({
        "task_type": alert["task_type"],
        "input": {
            "prompt": alert.get("prompt", f"Investigate {alert['task_type']}"),
            "severity": alert.get("severity", "high"),
            "siem_event": alert["siem_event"],
        }
    }).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/tasks", data=payload,
                                 headers={"Authorization": f"Bearer {token}",
                                           "Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())


def poll_task(api_url, token, task_id, timeout_s=600):
    start = time.time()
    while time.time() - start < timeout_s:
        try:
            req = urllib.request.Request(f"{api_url}/api/v1/tasks/{task_id}",
                                         headers={"Authorization": f"Bearer {token}"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            status = data.get("status", "unknown")
            if status not in ("pending", "executing"):
                return data
        except Exception:
            pass
        time.sleep(15)
    return {"status": "timeout"}


def save_progress(completed_indices, results, path=PROGRESS_PATH):
    with open(path, "w") as f:
        json.dump({"completed": list(completed_indices), "results": results}, f)


def load_progress(path=PROGRESS_PATH):
    if path.exists():
        with open(path) as f:
            p = json.load(f)
            return set(p.get("completed", [])), p.get("results", [])
    return set(), []


def main():
    parser = argparse.ArgumentParser(description="HYDRA 200-Alert Benchmark Runner")
    parser.add_argument("--limit", type=int, default=0, help="Max alerts to run (0=all)")
    parser.add_argument("--resume", action="store_true", help="Resume from progress file")
    parser.add_argument("--spacing", type=int, default=30, help="Seconds between submissions")
    parser.add_argument("--timeout", type=int, default=600, help="Max seconds per alert")
    parser.add_argument("--api-url", default=API_URL)
    parser.add_argument("--corpus", default=str(CORPUS_PATH))
    args = parser.parse_args()

    with open(args.corpus) as f:
        corpus = json.load(f)

    if args.limit > 0:
        corpus = corpus[:args.limit]

    print(f"HYDRA 200-Alert Accuracy Benchmark")
    print(f"  Corpus:  {len(corpus)} alerts")
    print(f"  Spacing: {args.spacing}s")
    print(f"  Timeout: {args.timeout}s per alert")
    print()

    token = login(args.api_url)
    print("Authenticated.\n")

    completed_set, results = load_progress() if args.resume else (set(), [])

    for idx, alert in enumerate(corpus):
        if idx in completed_set:
            continue

        task_type = alert["task_type"]
        gt_verdict = alert.get("ground_truth", {}).get("verdict", "?")
        print(f"[{idx+1}/{len(corpus)}] {task_type} (expect: {gt_verdict})...", end=" ", flush=True)

        t0 = time.time()
        try:
            resp = submit_alert(args.api_url, token, alert)
            task_id = resp.get("task_id", "")

            if resp.get("status") == "deduplicated":
                elapsed = time.time() - t0
                print(f"DEDUP ({elapsed:.0f}s)")
                results.append({"idx": idx, "task_type": task_type, "status": "deduplicated",
                                "duration": elapsed, "ground_truth": alert.get("ground_truth", {})})
                completed_set.add(idx)
                save_progress(completed_set, results)
                continue

            data = poll_task(args.api_url, token, task_id, args.timeout)
            elapsed = time.time() - t0
            status = data.get("status", "timeout")
            output = data.get("output", {}) or {}

            result_entry = {
                "idx": idx,
                "task_type": task_type,
                "task_id": task_id,
                "status": status,
                "duration": elapsed,
                "ground_truth": alert.get("ground_truth", {}),
                "actual_verdict": output.get("verdict", "unknown"),
                "actual_risk_score": output.get("risk_score", 0),
                "actual_iocs": [ioc.get("value", str(ioc)) if isinstance(ioc, dict) else str(ioc)
                               for ioc in output.get("iocs", [])],
                "actual_summary": output.get("summary", output.get("memory_summary", ""))[:500],
                "difficulty": alert.get("ground_truth", {}).get("difficulty", "medium"),
            }

            print(f"{status.upper()} ({elapsed:.0f}s) verdict={result_entry['actual_verdict']}")
            results.append(result_entry)

        except Exception as e:
            elapsed = time.time() - t0
            print(f"ERROR ({elapsed:.0f}s): {e}")
            results.append({"idx": idx, "task_type": task_type, "status": "error",
                           "duration": elapsed, "error": str(e),
                           "ground_truth": alert.get("ground_truth", {})})

        completed_set.add(idx)
        save_progress(completed_set, results)

        # Refresh token every 5 alerts
        if (idx + 1) % 5 == 0:
            try:
                token = login(args.api_url)
            except Exception:
                pass

        if idx < len(corpus) - 1:
            time.sleep(args.spacing)

    # Save final results
    with open(RESULTS_PATH, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "corpus_size": len(corpus),
            "results": results,
        }, f, indent=2)
    print(f"\nResults saved to {RESULTS_PATH}")

    # Quick summary
    completed = [r for r in results if r["status"] == "completed"]
    correct = sum(1 for r in completed if r.get("actual_verdict") == r.get("ground_truth", {}).get("verdict"))
    print(f"Completed: {len(completed)}/{len(corpus)}")
    print(f"Correct verdicts: {correct}/{len(completed)}")

    # Cleanup progress on full success
    if len(completed_set) == len(corpus) and PROGRESS_PATH.exists():
        PROGRESS_PATH.unlink()


if __name__ == "__main__":
    main()
