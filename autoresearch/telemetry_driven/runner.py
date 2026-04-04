"""Test runner — executes generated alerts through the API and collects results."""

import json
import time
import requests
from typing import List, Dict


class TestRunner:
    def __init__(self, api_url=None,
                 email="admin@test.local", password="TestPass2026"):
        if api_url is None:
            # Auto-detect: inside Docker use service name, outside use localhost
            import socket
            try:
                socket.create_connection(("zovark-api", 8090), timeout=2)
                api_url = "http://zovark-api:8090"
            except Exception:
                api_url = "http://localhost:8090"
        self.api = api_url
        self.token = self._login(email, password)

    def _login(self, email, password):
        r = requests.post(f"{self.api}/api/v1/auth/login",
                         json={"email": email, "password": password}, timeout=10)
        r.raise_for_status()
        return r.json()["token"]

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"}

    def run(self, tests: List[Dict], wait_seconds=120, poll_timeout=60) -> List[Dict]:
        results = []
        print(f"\nSubmitting {len(tests)} tests...")
        for test in tests:
            task_id = self._submit(test)
            results.append({"test": test, "task_id": task_id, "submitted": task_id is not None})
            status = "ok" if task_id else "FAIL"
            print(f"  [{status}] {test['name']}: {(task_id or 'none')[:12]}")

        submitted = sum(1 for r in results if r["submitted"])
        print(f"\n{submitted}/{len(tests)} submitted. Waiting {wait_seconds}s...")
        time.sleep(wait_seconds)

        print("Polling results...")
        for result in results:
            if not result["submitted"]:
                result.update({"status": "submit_failed", "verdict": None, "risk_score": None})
                continue
            result.update(self._poll(result["task_id"], timeout=poll_timeout))

        for result in results:
            result["passed"] = self._evaluate(result)
        return results

    def _submit(self, test: Dict):
        try:
            r = requests.post(f"{self.api}/api/v1/tasks",
                            headers=self._headers(),
                            json={"task_type": test["task_type"], "input": test["input"]},
                            timeout=15)
            data = r.json()
            return (data.get("task_id") or data.get("existing_task_id")
                    or data.get("id") or data.get("investigation_id") or "")
        except Exception as e:
            print(f"    Submit error: {e}")
            return None

    def _poll(self, task_id, timeout=60):
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(f"{self.api}/api/v1/tasks/{task_id}",
                               headers=self._headers(), timeout=10)
                data = r.json()
                status = data.get("status", "")
                if status == "completed":
                    output = data.get("output", {})
                    if isinstance(output, str):
                        try: output = json.loads(output)
                        except: output = {}
                    return {
                        "status": "completed",
                        "verdict": output.get("verdict", "unknown"),
                        "risk_score": output.get("risk_score", -1),
                        "path_taken": output.get("path_taken", data.get("path_taken", "?")),
                    }
                if status in ("error", "failed"):
                    return {"status": status, "verdict": "error", "risk_score": -1, "path_taken": "error"}
            except Exception:
                pass
            time.sleep(10)
        return {"status": "timeout", "verdict": "timeout", "risk_score": -1, "path_taken": "timeout"}

    def _evaluate(self, result):
        test = result.get("test", {})
        expect = test.get("expect")
        verdict = result.get("verdict")
        risk = result.get("risk_score", -1) or -1
        if result.get("status") in ("submit_failed", "timeout", "error"):
            return False
        if expect == "attack":
            return verdict in ("true_positive", "suspicious", "needs_manual_review", "needs_analyst_review") and risk >= test.get("min_risk", 65)
        if expect == "benign":
            return verdict == "benign" and risk <= test.get("max_risk", 25)
        return False
