#!/usr/bin/env python3
"""ZOVARK 1000-alert benchmark runner. Submits alerts, polls, reports."""
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from collections import defaultdict

API_URL = os.environ.get("ZOVARK_API_URL", "http://localhost:8090")
CORPUS_PATH = os.environ.get("CORPUS_PATH", "corpus_1000.json")

def login(api_url):
    payload = json.dumps({"email": "admin@test.local", "password": "TestPass2026"}).encode()
    req = urllib.request.Request(f"{api_url}/api/v1/auth/login", data=payload,
                                 headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())["token"]

_token_state = {"token": None, "count": 0}

def get_token(api_url):
    _token_state["count"] += 1
    if _token_state["token"] is None or _token_state["count"] % 10 == 0:
        try:
            _token_state["token"] = login(api_url)
        except Exception:
            pass
    return _token_state["token"]

def submit(api_url, token, alert):
    payload = json.dumps({
        "task_type": alert["task_type"],
        "input": {
            "prompt": alert.get("prompt", f"Investigate {alert['task_type']}"),
            "severity": alert.get("severity", "high"),
            "siem_event": alert["siem_event"],
        }
    }).encode()
    for attempt in range(2):
        try:
            req = urllib.request.Request(f"{api_url}/api/v1/tasks", data=payload,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 401 and attempt == 0:
                token = get_token(api_url)
                continue
            return {"error": str(e), "status_code": e.code}
        except Exception as e:
            return {"error": str(e)}

def poll(api_url, token, task_id, timeout_s=600):
    start = time.time()
    while time.time() - start < timeout_s:
        try:
            req = urllib.request.Request(f"{api_url}/api/v1/tasks/{task_id}",
                headers={"Authorization": f"Bearer {token}"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            if data.get("status") not in ("pending", "executing"):
                return data
        except urllib.error.HTTPError as e:
            if e.code == 401:
                token = get_token(api_url)
                continue
        except Exception:
            pass
        time.sleep(15)
    return {"status": "timeout"}

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default=CORPUS_PATH)
    parser.add_argument("--api-url", default=API_URL)
    parser.add_argument("--start", type=int, default=0, help="Start index")
    parser.add_argument("--limit", type=int, default=0, help="Max alerts (0=all)")
    parser.add_argument("--spacing", type=int, default=1, help="Seconds between submissions")
    parser.add_argument("--poll-timeout", type=int, default=600, help="Max seconds to wait per task")
    parser.add_argument("--output", default="results_1000.json")
    args = parser.parse_args()

    with open(args.corpus) as f:
        raw = json.load(f)
    alerts = raw.get("alerts", raw) if isinstance(raw, dict) else raw

    if args.start > 0:
        alerts = alerts[args.start:]
    if args.limit > 0:
        alerts = alerts[:args.limit]

    print(f"ZOVARK 1000-Alert Benchmark")
    print(f"  Corpus: {len(alerts)} alerts (start={args.start})")
    print(f"  Spacing: {args.spacing}s")
    print()

    token = get_token(args.api_url)
    print("Authenticated.\n")

    results = []
    correct = 0
    total_scored = 0

    for idx, alert in enumerate(alerts):
        gt = alert.get("ground_truth", {})
        gt_verdict = gt.get("verdict", "?")
        path = gt.get("path", "?")
        task_type = alert["task_type"]

        token = get_token(args.api_url)
        t0 = time.time()

        resp = submit(args.api_url, token, alert)
        if "error" in resp:
            print(f"[{idx+1}/{len(alerts)}] SUBMIT_ERROR: {resp['error'][:60]}")
            results.append({"idx": idx, "status": "submit_error", "task_type": task_type, "ground_truth": gt})
            time.sleep(args.spacing)
            continue

        task_id = resp.get("task_id", "")
        if resp.get("status") == "deduplicated":
            print(f"[{idx+1}/{len(alerts)}] DEDUP")
            results.append({"idx": idx, "status": "deduplicated", "task_type": task_type, "ground_truth": gt})
            time.sleep(args.spacing)
            continue

        data = poll(args.api_url, token, task_id, args.poll_timeout)
        elapsed = time.time() - t0
        status = data.get("status", "timeout")
        output = data.get("output", {}) or {}
        actual_verdict = output.get("verdict", "unknown")
        is_correct = actual_verdict == gt_verdict
        if status == "completed":
            total_scored += 1
            if is_correct:
                correct += 1

        tag = "OK" if is_correct else "WRONG"
        risk = output.get("risk_score", "?")
        print(f"[{idx+1}/{len(alerts)}] {path} {task_type:30s} {status:10s} verdict={actual_verdict:16s} risk={risk:>3} {tag} ({elapsed:.0f}s)")

        results.append({
            "idx": idx, "task_id": task_id, "task_type": task_type,
            "status": status, "duration": elapsed,
            "ground_truth": gt, "actual_verdict": actual_verdict,
            "actual_risk": output.get("risk_score", 0),
            "ioc_count": len(output.get("iocs", [])),
            "path": path,
        })

        time.sleep(args.spacing)

    # Save results
    with open(args.output, "w") as f:
        json.dump({"results": results, "total": len(alerts), "scored": total_scored,
                    "correct": correct, "accuracy": correct/max(total_scored,1)*100}, f, indent=2)
    print(f"\nResults saved to {args.output}")
    print(f"Completed: {total_scored}/{len(alerts)}")
    print(f"Correct: {correct}/{total_scored} ({correct/max(total_scored,1)*100:.1f}%)")

if __name__ == "__main__":
    main()
