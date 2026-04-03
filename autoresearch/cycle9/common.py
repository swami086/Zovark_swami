"""
Shared utilities for Cycle 9 validation scripts.
Uses only stdlib — no external dependencies required.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

API_URL = os.environ.get("API_URL", "http://localhost:8090")

# ANSI colors
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def api_url(path: str) -> str:
    return f"{API_URL}{path}"


def login(email: str = "admin@test.local", password: str = "TestPass2026") -> str:
    """Login and return JWT token."""
    data = json.dumps({"email": email, "password": password}).encode()
    req = urllib.request.Request(
        api_url("/api/v1/auth/login"),
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        return result.get("token", "")
    except Exception as e:
        print(f"{RED}Login failed: {e}{RESET}")
        sys.exit(1)


def submit_alert(token: str, task_type: str, input_data: dict) -> dict:
    """Submit an alert via POST /api/v1/tasks. Returns response dict."""
    payload = json.dumps({"task_type": task_type, "input": input_data}).encode()
    req = urllib.request.Request(
        api_url("/api/v1/tasks"),
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        return {"error": str(e), "status_code": e.code, "body": body}
    except Exception as e:
        return {"error": str(e)}


def poll_result(token: str, task_id: str, timeout: int = 180, interval: int = 10) -> dict:
    """Poll GET /api/v1/tasks/{id} until completed or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        req = urllib.request.Request(
            api_url(f"/api/v1/tasks/{task_id}"),
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            result = json.loads(resp.read())
            status = result.get("status", "")
            if status in ("completed", "failed", "error"):
                return result
        except Exception:
            pass
        time.sleep(interval)
    return {"status": "timeout", "task_id": task_id}


def get_verdict(result: dict) -> tuple:
    """Extract (verdict, risk_score) from task result."""
    output = result.get("output", {})
    if isinstance(output, dict):
        return output.get("verdict", "unknown"), output.get("risk_score", -1)
    return "unknown", -1


def print_pass(msg: str):
    print(f"  {GREEN}PASS{RESET}: {msg}")


def print_fail(msg: str):
    print(f"  {RED}FAIL{RESET}: {msg}")


def print_warn(msg: str):
    print(f"  {YELLOW}WARN{RESET}: {msg}")
