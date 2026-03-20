"""
Batch investigation runner — submits alerts through the real Temporal pipeline.
Polls for completion, tracks results, resume-safe via progress file.

Usage:
    python scripts/batch_runner.py                 # Run all 100
    python scripts/batch_runner.py --limit 10      # Run first 10
    python scripts/batch_runner.py --resume         # Resume from progress
"""
import json, time, os, sys, urllib.request

API = os.environ.get("API_URL", "http://localhost:8090")
CORPUS = os.environ.get("CORPUS", "scripts/alert_corpus_100.json")
PROGRESS_FILE = "batch_progress.json"
RESULTS_FILE = "batch_results_100.json"

# Auth
def get_token():
    payload = json.dumps({"email": "admin@test.local", "password": "TestPass2026"}).encode()
    req = urllib.request.Request(f"{API}/api/v1/auth/login", data=payload,
                                 headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=10)
    return json.loads(resp.read())["token"]


def submit_task(token, alert):
    payload = json.dumps({
        "task_type": alert["task_type"],
        "input": {
            "prompt": alert["prompt"],
            "severity": alert.get("severity", "high"),
            "siem_event": alert["siem_event"],
        }
    }).encode()
    req = urllib.request.Request(f"{API}/api/v1/tasks", data=payload,
                                 headers={"Authorization": f"Bearer {token}",
                                           "Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())


def poll_task(token, task_id, timeout=300, interval=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(f"{API}/api/v1/tasks/{task_id}",
                                         headers={"Authorization": f"Bearer {token}"})
            resp = urllib.request.urlopen(req, timeout=10)
            data = json.loads(resp.read())
            status = data.get("status", "unknown")
            if status not in ("pending", "executing"):
                return status, data
        except Exception:
            pass
        time.sleep(interval)
    return "timeout", {}


def save_progress(completed_indices, results):
    with open(PROGRESS_FILE, "w") as f:
        json.dump({"completed": completed_indices, "results": results}, f)


def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE) as f:
            p = json.load(f)
            return set(p.get("completed", [])), p.get("results", [])
    return set(), []


def main():
    limit = None
    resume = False
    for arg in sys.argv[1:]:
        if arg == "--resume":
            resume = True
        elif arg.startswith("--limit"):
            limit = int(sys.argv[sys.argv.index(arg) + 1]) if "=" not in arg else int(arg.split("=")[1])

    # Handle --limit N (two separate args)
    if "--limit" in sys.argv and limit is None:
        idx = sys.argv.index("--limit")
        if idx + 1 < len(sys.argv):
            limit = int(sys.argv[idx + 1])

    with open(CORPUS) as f:
        alerts = json.load(f)

    if limit:
        alerts = alerts[:limit]

    print(f"=== BATCH RUNNER: {len(alerts)} investigations ===")

    token = get_token()
    print(f"Auth: OK")

    completed_set, results = load_progress() if resume else (set(), [])

    passed = sum(1 for r in results if r["status"] == "completed")
    failed = sum(1 for r in results if r["status"] in ("failed", "timeout"))

    for idx, alert in enumerate(alerts):
        if idx in completed_set:
            continue

        print(f"\n[{idx+1}/{len(alerts)}] {alert['task_type']}: {alert['siem_event']['title']}...")
        t0 = time.time()

        try:
            resp = submit_task(token, alert)
            task_id = resp.get("task_id", "")
            status_initial = resp.get("status", "")

            if status_initial == "deduplicated":
                elapsed = time.time() - t0
                print(f"  DEDUP ({elapsed:.0f}s)")
                results.append({"idx": idx, "task_type": alert["task_type"],
                                "task_id": task_id, "status": "deduplicated", "duration": elapsed})
                completed_set.add(idx)
                save_progress(list(completed_set), results)
                continue

            status, data = poll_task(token, task_id, timeout=900, interval=30)
            elapsed = time.time() - t0

            if status == "completed":
                passed += 1
                print(f"  PASS ({elapsed:.0f}s)")
            elif status == "deduplicated":
                print(f"  DEDUP ({elapsed:.0f}s)")
            else:
                failed += 1
                err = data.get("error_message", "")[:80] if data else ""
                print(f"  {status.upper()} ({elapsed:.0f}s) {err}")

            results.append({
                "idx": idx, "task_type": alert["task_type"],
                "task_id": task_id, "status": status, "duration": elapsed,
            })

        except Exception as e:
            elapsed = time.time() - t0
            failed += 1
            print(f"  ERROR ({elapsed:.0f}s): {e}")
            results.append({"idx": idx, "task_type": alert["task_type"],
                            "task_id": "", "status": "error", "duration": elapsed,
                            "error": str(e)})

        completed_set.add(idx)
        save_progress(list(completed_set), results)
        time.sleep(2)  # Rate limit between submissions

        # Refresh token every 3 tasks (JWT expires in 15 min, tasks take ~5 min each)
        if (idx + 1) % 3 == 0:
            try:
                token = get_token()
            except Exception:
                pass

    # Final summary
    total = len(results)
    n_pass = sum(1 for r in results if r["status"] == "completed")
    n_fail = sum(1 for r in results if r["status"] == "failed")
    n_timeout = sum(1 for r in results if r["status"] == "timeout")
    n_dedup = sum(1 for r in results if r["status"] == "deduplicated")
    n_error = sum(1 for r in results if r["status"] == "error")
    completed_durations = [r["duration"] for r in results if r["status"] == "completed"]

    print(f"\n{'='*50}")
    print(f"BATCH RESULTS: {total} investigations")
    print(f"{'='*50}")
    print(f"Completed:    {n_pass}")
    print(f"Failed:       {n_fail}")
    print(f"Timeout:      {n_timeout}")
    print(f"Deduplicated: {n_dedup}")
    print(f"Error:        {n_error}")
    if completed_durations:
        print(f"Mean duration: {sum(completed_durations)/len(completed_durations):.0f}s")

    # Per-type breakdown
    from collections import defaultdict
    by_type = defaultdict(lambda: {"pass": 0, "fail": 0, "dedup": 0})
    for r in results:
        t = r["task_type"]
        if r["status"] == "completed":
            by_type[t]["pass"] += 1
        elif r["status"] == "deduplicated":
            by_type[t]["dedup"] += 1
        else:
            by_type[t]["fail"] += 1

    print(f"\nPer-type:")
    for t in sorted(by_type):
        b = by_type[t]
        print(f"  {t:30s} pass={b['pass']} fail={b['fail']} dedup={b['dedup']}")

    with open(RESULTS_FILE, "w") as f:
        json.dump({"total": total, "passed": n_pass, "failed": n_fail,
                    "timeout": n_timeout, "dedup": n_dedup, "results": results}, f, indent=2)
    print(f"\nSaved: {RESULTS_FILE}")

    # Cleanup progress file on success
    if n_fail == 0 and n_timeout == 0 and n_error == 0:
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)


if __name__ == "__main__":
    main()
