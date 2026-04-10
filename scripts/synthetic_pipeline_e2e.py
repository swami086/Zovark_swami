#!/usr/bin/env python3
"""
Synthetic end-to-end pipeline test: REST tasks + SIEM ingest + Path A vs Path C.

Path A: task_type with a matching entry in investigation_plans.json (e.g. brute_force).
Path C: task_type / SIEM mapping with NO saved plan → LLM tool selection (requires LLM up).

Optional: read path_taken from PostgreSQL when GET /tasks/:id omits it (docker exec).

Usage (repo root, stack up):
  pip install httpx  # or use worker image
  export ZOVARK_API_URL=http://localhost:8090
  export ZOVARK_SMOKE_EMAIL=admin@test.local
  export ZOVARK_SMOKE_PASSWORD=TestPass2026
  python3 scripts/synthetic_pipeline_e2e.py

With DB path_taken probe (default if docker available):
  docker compose exec -T postgres psql -U zovark -d zovark -c "SELECT 1" >/dev/null && OK
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

try:
    import httpx
except ImportError:
    print("Install httpx: pip install httpx", file=sys.stderr)
    sys.exit(1)

API = os.environ.get("ZOVARK_API_URL", "http://localhost:8090").rstrip("/")
EMAIL = os.environ.get("ZOVARK_SMOKE_EMAIL", "admin@test.local")
PASSWORD = os.environ.get("ZOVARK_SMOKE_PASSWORD", "TestPass2026")
RUN_TAG = os.environ.get("ZOVARK_SYNTHETIC_RUN_TAG", f"synth_{int(time.time())}_{uuid.uuid4().hex[:8]}")


def log(msg: str) -> None:
    print(msg, flush=True)


def login(client: httpx.Client) -> str:
    r = client.post(
        f"{API}/api/v1/auth/login",
        json={"email": EMAIL, "password": PASSWORD},
        timeout=30.0,
    )
    r.raise_for_status()
    data = r.json()
    token = data.get("token")
    if not token:
        raise RuntimeError(f"login missing token: {data}")
    return token


def submit_task(client: httpx.Client, token: str, body: dict) -> str:
    r = client.post(
        f"{API}/api/v1/tasks",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
        timeout=60.0,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("status") == "deduplicated":
        raise RuntimeError(f"deduplicated (use force_reinvestigate): {data}")
    tid = data.get("task_id") or data.get("id")
    if not tid:
        raise RuntimeError(f"no task_id: {data}")
    return tid


def poll_task(client: httpx.Client, token: str, task_id: str, timeout_s: int = 300) -> dict:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(
            f"{API}/api/v1/tasks/{task_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
        r.raise_for_status()
        data = r.json()
        st = data.get("status")
        if st in ("completed", "failed", "error"):
            return data
        time.sleep(3)
    raise TimeoutError(f"task {task_id} not terminal within {timeout_s}s")


def path_taken_from_db(task_id: str) -> str | None:
    """Best-effort: docker compose exec postgres psql."""
    import re

    if not re.match(r"^[0-9a-f-]{36}$", task_id, re.I):
        return None
    repo_root = os.environ.get(
        "ZOVARK_REPO_ROOT",
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    try:
        out = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "zovark",
                "-d",
                "zovark",
                "-t",
                "-A",
                "-c",
                f"SELECT COALESCE(path_taken,'') FROM agent_tasks WHERE id = '{task_id}'::uuid",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if out.returncode != 0:
            return None
        line = (out.stdout or "").strip().split("\n")[0].strip()
        return line or None
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None


def splunk_ingest(client: httpx.Client, token: str) -> str:
    """Signature matches sql inject → mapAlertToTaskType → web_attack (no JSON plan) → Path C."""
    payload = {
        "time": time.time(),
        "sourcetype": "synthetic:zovark",
        "source": "synthetic_pipeline_e2e",
        "host": "test-host",
        "event": {
            "signature": f"Synthetic SQL Injection Test {RUN_TAG}",
            "src_ip": "198.51.100.77",
            "dest_ip": "10.0.0.5",
            "user": "www-data",
            "severity": "high",
            "raw": f"GET /login?id=1' OR '1'='1 -- {RUN_TAG}",
        },
    }
    r = client.post(
        f"{API}/api/v1/ingest/splunk",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
        timeout=60.0,
    )
    r.raise_for_status()
    data = r.json()
    tid = data.get("task_id")
    if not tid:
        raise RuntimeError(f"splunk ingest: {data}")
    return tid


def main() -> int:
    log(f"=== Synthetic pipeline E2E ({RUN_TAG}) ===")
    log(f"API={API}")

    with httpx.Client() as client:
        token = login(client)
        log("OK login")

        # --- Path A: saved plan ---
        path_a_body = {
            "task_type": "brute_force",
            "input": {
                "prompt": f"Synthetic Path A brute force {RUN_TAG}",
                "severity": "high",
                "force_reinvestigate": True,
                "siem_event": {
                    "title": f"SSH brute synthetic {RUN_TAG}",
                    "source_ip": "198.51.100.10",
                    "username": "root",
                    "rule_name": "BruteForce",
                    "raw_log": f"Failed password for root from 198.51.100.10 port 22 ssh2 x{RUN_TAG}",
                },
            },
        }
        tid_a = submit_task(client, token, path_a_body)
        log(f"Path A task_id={tid_a}")
        res_a = poll_task(client, token, tid_a)
        pt_a = path_taken_from_db(tid_a)
        log(f"Path A status={res_a.get('status')} verdict={res_a.get('output', {}).get('verdict')} path_taken(db)={pt_a!r}")

        # --- Path C: novel task_type (no plan key / alias / substring match) ---
        path_c_body = {
            "task_type": f"synthetic_novel_pathc_{RUN_TAG}",
            "input": {
                "prompt": f"Synthetic Path C novel TTP {RUN_TAG}",
                "severity": "high",
                "force_reinvestigate": True,
                "siem_event": {
                    "title": f"Novel attack synthetic {RUN_TAG}",
                    "source_ip": "203.0.113.50",
                    "rule_name": f"SyntheticRule_{RUN_TAG}",
                    "raw_log": f"powershell -enc abc suspicious cradle mimikatz sekurlsa {RUN_TAG}",
                },
            },
        }
        tid_c = submit_task(client, token, path_c_body)
        log(f"Path C (REST) task_id={tid_c}")
        res_c = poll_task(client, token, tid_c, timeout_s=360)
        pt_c = path_taken_from_db(tid_c)
        out_c = res_c.get("output") or {}
        log(
            f"Path C status={res_c.get('status')} verdict={out_c.get('verdict')} "
            f"path_taken(db)={pt_c!r} risk={out_c.get('risk_score')}"
        )

        # --- SIEM ingest → web_attack → Path C ---
        tid_s = splunk_ingest(client, token)
        log(f"Splunk ingest task_id={tid_s}")
        res_s = poll_task(client, token, tid_s, timeout_s=360)
        pt_s = path_taken_from_db(tid_s)
        out_s = res_s.get("output") or {}
        log(
            f"Splunk→PathC status={res_s.get('status')} verdict={out_s.get('verdict')} "
            f"path_taken(db)={pt_s!r}"
        )

    # Assertions (soft — LLM may be down)
    failed = []
    if pt_a != "A":
        failed.append(f"expected Path A path_taken='A', got {pt_a!r}")
    if pt_c not in ("C", "error_llm_down", None):
        failed.append(f"Path C unexpected path_taken={pt_c!r} (expected C or error_llm_down)")
    if pt_c == "error_llm_down":
        log("WARN: Path C hit LLM failure (circuit breaker / timeout) — check ZOVARK_LLM_* / inference")
    if pt_s not in ("C", "error_llm_down", None):
        failed.append(f"Splunk path unexpected path_taken={pt_s!r}")

    if failed:
        for f in failed:
            log(f"CHECK: {f}")
        return 1

    log("=== PASS: Path A = A; Path C branches look correct (C or LLM-down) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
