#!/usr/bin/env python
"""
ZOVARK Load Test Script
Runs FROM inside a container (worker or standalone) against the API.
Usage: python load_test.py --concurrency 10 --total 50
"""
import os
import sys
import time
import json
import asyncio
import argparse
import statistics
from datetime import datetime

import httpx

API_BASE = os.environ.get("ZOVARK_API_URL", "http://zovark-api:8090/api/v1")
DB_URI = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")

SKILLS = ["brute_force", "ransomware", "lateral_movement", "c2", "phishing"]
SKILL_MAP = {
    "brute_force": "Brute Force Investigation",
    "ransomware": "Ransomware Triage",
    "lateral_movement": "Lateral Movement Detection",
    "c2": "C2 Communication Hunt",
    "phishing": "Phishing Investigation",
}
CORPUS_DIR = os.environ.get("CORPUS_DIR", "/app/tests/corpus")

# Stats
results = []
submitted = 0
completed_count = 0
failed_count = 0
running_count = 0
lock = asyncio.Lock()
start_time = None

async def login(client):
    resp = await client.post(f"{API_BASE}/auth/login", json={
        "email": "admin@testcorp.com", "password": "password123"
    }, timeout=10)
    resp.raise_for_status()
    return resp.json()["token"]

async def run_investigation(client, headers, skill, sem, task_num):
    global submitted, completed_count, failed_count, running_count

    async with sem:
        log_path = os.path.join(CORPUS_DIR, skill, "easy.log")
        if not os.path.exists(log_path):
            return

        with open(log_path, "r") as f:
            log_data = f.read()

        payload = {
            "task_type": SKILL_MAP[skill],
            "input": {
                "prompt": f"Analyze this log for {skill} activity.",
                "log_data": log_data,
                "filename": "easy.log"
            }
        }

        t0 = time.time()
        try:
            cr = await client.post(f"{API_BASE}/tasks", headers=headers, json=payload, timeout=30)
            if cr.status_code != 202:
                async with lock:
                    failed_count += 1
                    results.append({"task_num": task_num, "skill": skill, "status": "create_failed", "time_ms": 0, "worker_id": ""})
                return

            task_id = cr.json()["task_id"]
            async with lock:
                submitted += 1
                running_count += 1

            # Poll for completion
            for _ in range(60):  # 120s timeout
                await asyncio.sleep(2)
                try:
                    gr = await client.get(f"{API_BASE}/tasks/{task_id}", headers=headers, timeout=10)
                    if gr.status_code != 200:
                        continue
                    status = gr.json().get("status", "")
                    if status in ("completed", "awaiting_approval"):
                        elapsed = int((time.time() - t0) * 1000)
                        async with lock:
                            completed_count += 1
                            running_count -= 1
                            results.append({"task_num": task_num, "skill": skill, "status": "completed", "time_ms": elapsed, "task_id": task_id, "worker_id": ""})
                        return
                    elif status == "failed":
                        elapsed = int((time.time() - t0) * 1000)
                        async with lock:
                            failed_count += 1
                            running_count -= 1
                            results.append({"task_num": task_num, "skill": skill, "status": "failed", "time_ms": elapsed, "task_id": task_id, "worker_id": ""})
                        return
                except Exception:
                    continue

            # Timeout
            elapsed = int((time.time() - t0) * 1000)
            async with lock:
                failed_count += 1
                running_count -= 1
                results.append({"task_num": task_num, "skill": skill, "status": "timeout", "time_ms": elapsed, "task_id": task_id, "worker_id": ""})

        except Exception as e:
            elapsed = int((time.time() - t0) * 1000)
            async with lock:
                failed_count += 1
                running_count -= 1
                results.append({"task_num": task_num, "skill": skill, "status": f"error: {e}", "time_ms": elapsed, "worker_id": ""})


async def status_printer(total):
    global start_time
    while completed_count + failed_count < total:
        elapsed = int(time.time() - start_time)
        avg = 0
        completed_times = [r["time_ms"] for r in results if r["status"] == "completed"]
        if completed_times:
            avg = statistics.mean(completed_times) / 1000
        print(f"  [{elapsed:03d}s] Submitted: {submitted}/{total} | Completed: {completed_count} | Failed: {failed_count} | Running: {running_count} | Avg: {avg:.1f}s")
        await asyncio.sleep(5)


async def main():
    global start_time

    parser = argparse.ArgumentParser(description="ZOVARK Load Test")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--total", type=int, default=50)
    parser.add_argument("--ramp-up", type=int, default=10)
    parser.add_argument("--api-url", type=str, default=None)
    parser.add_argument("--output", type=str, default="/app/tests/results/load_test_results.json")
    args = parser.parse_args()

    if args.api_url:
        global API_BASE
        API_BASE = args.api_url

    print(f"ZOVARK Load Test: {args.total} investigations, concurrency {args.concurrency}")
    print(f"API: {API_BASE}")

    async with httpx.AsyncClient(timeout=120) as client:
        token = await login(client)
        headers = {"Authorization": f"Bearer {token}"}
        print("Authenticated. Starting load test...")

        sem = asyncio.Semaphore(args.concurrency)
        start_time = time.time()

        # Create tasks cycling through skills
        tasks = []
        printer = asyncio.create_task(status_printer(args.total))

        for i in range(args.total):
            skill = SKILLS[i % len(SKILLS)]
            # Ramp-up delay
            if args.ramp_up > 0 and i < args.concurrency:
                delay = (args.ramp_up / args.concurrency) * i
                await asyncio.sleep(delay)
            task = asyncio.create_task(run_investigation(client, headers, skill, sem, i))
            tasks.append(task)

        await asyncio.gather(*tasks)
        printer.cancel()

    total_time = time.time() - start_time

    # Collect worker distribution from DB
    worker_dist = {}
    try:
        import psycopg2
        conn = psycopg2.connect(DB_URI)
        cur = conn.cursor()
        cur.execute("SELECT worker_id, COUNT(*) FROM agent_tasks WHERE status IN ('completed', 'awaiting_approval') AND worker_id IS NOT NULL GROUP BY worker_id ORDER BY count DESC LIMIT 10;")
        for row in cur.fetchall():
            worker_dist[row[0]] = row[1]
        # Update results with worker_ids
        task_ids = [r.get("task_id") for r in results if r.get("task_id")]
        if task_ids:
            cur.execute("SELECT id::text, worker_id FROM agent_tasks WHERE id::text = ANY(%s)", (task_ids,))
            wid_map = {str(r[0]): r[1] for r in cur.fetchall()}
            for r in results:
                if r.get("task_id") in wid_map:
                    r["worker_id"] = wid_map[r["task_id"]] or ""
        conn.close()
    except Exception as e:
        print(f"Warning: could not fetch worker distribution: {e}")

    # Compute stats
    completed_times = sorted([r["time_ms"] for r in results if r["status"] == "completed"])
    success_count = len(completed_times)
    fail_count = len(results) - success_count

    p50 = p95 = p99 = max_t = 0
    if completed_times:
        p50 = completed_times[int(len(completed_times) * 0.50)] / 1000
        p95 = completed_times[int(min(len(completed_times) * 0.95, len(completed_times) - 1))] / 1000
        p99 = completed_times[int(min(len(completed_times) * 0.99, len(completed_times) - 1))] / 1000
        max_t = completed_times[-1] / 1000

    throughput = success_count / total_time * 60 if total_time > 0 else 0
    error_rate = fail_count / len(results) * 100 if results else 0

    # By skill
    skill_stats = {}
    for skill in SKILLS:
        skill_results = [r for r in results if r["skill"] == skill]
        skill_completed = [r["time_ms"] for r in skill_results if r["status"] == "completed"]
        skill_failed = len([r for r in skill_results if r["status"] != "completed"])
        avg_s = statistics.mean(skill_completed) / 1000 if skill_completed else 0
        skill_stats[skill] = {"count": len(skill_results), "avg_s": avg_s, "failed": skill_failed}

    # Print summary
    print(f"""
{'='*54}
            ZOVARK LOAD TEST RESULTS
{'='*54}
 Total investigations:     {args.total}
 Successful:               {success_count}
 Failed:                   {fail_count}
 Error rate:               {error_rate:.1f}%

 Latency (end-to-end):
   p50:                    {p50:.1f}s
   p95:                    {p95:.1f}s
   p99:                    {p99:.1f}s
   max:                    {max_t:.1f}s

 Throughput:               {throughput:.1f} inv/min

 Worker distribution:""")
    for wid, cnt in worker_dist.items():
        print(f"   {wid}: {cnt} tasks")

    print(f"\n By skill:")
    for skill, st in skill_stats.items():
        print(f"   {skill:20s}: {st['count']:3d} | avg {st['avg_s']:.1f}s | {st['failed']} fail")

    print(f"{'='*54}")

    # Save results
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "config": {"concurrency": args.concurrency, "total": args.total, "ramp_up": args.ramp_up},
        "summary": {
            "total": args.total, "successful": success_count, "failed": fail_count,
            "error_rate": error_rate, "p50_s": p50, "p95_s": p95, "p99_s": p99, "max_s": max_t,
            "throughput_per_min": throughput, "total_time_s": total_time
        },
        "worker_distribution": worker_dist,
        "skill_stats": skill_stats,
        "raw_results": results
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"\nDetailed results saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
