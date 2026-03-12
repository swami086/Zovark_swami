"""End-to-end test: full investigation lifecycle.

1. Register user, login, get JWT
2. Create task via POST /api/v1/tasks
3. Poll GET /api/v1/tasks/:id until complete
4. Verify investigation steps exist
5. Verify audit events logged
"""

import time
import pytest
import requests


class TestFullInvestigationFlow:
    """Full investigation lifecycle — submit, poll, verify."""

    def test_create_task_returns_accepted(self, api_url, admin_headers):
        """POST /api/v1/tasks should return 202 Accepted with task_id."""
        resp = requests.post(
            f"{api_url}/api/v1/tasks",
            headers=admin_headers,
            json={
                "task_type": "log_analysis",
                "input": {
                    "prompt": "Analyze for brute force attacks",
                    "log_data": "2026-03-10 Failed login user=admin src=10.0.0.1\n" * 5,
                },
            },
        )
        assert resp.status_code in (200, 202), f"Unexpected status: {resp.status_code} {resp.text}"
        data = resp.json()
        assert "task_id" in data or "investigation_id" in data

    def test_full_investigation_lifecycle(self, api_url, admin_headers):
        """Create a task, poll until done, check steps and audit."""
        # Step 1: Create task
        create_resp = requests.post(
            f"{api_url}/api/v1/tasks",
            headers=admin_headers,
            json={
                "task_type": "log_analysis",
                "input": {
                    "prompt": "E2E test: look for suspicious SSH activity",
                    "log_data": (
                        "Mar 10 09:14:22 srv sshd[1234]: Failed password for root from 192.168.1.100 port 22\n"
                        "Mar 10 09:14:23 srv sshd[1234]: Failed password for root from 192.168.1.100 port 22\n"
                        "Mar 10 09:14:24 srv sshd[1234]: Accepted password for root from 192.168.1.100 port 22\n"
                    ),
                },
            },
        )
        assert create_resp.status_code in (200, 202), f"Create failed: {create_resp.text}"
        task_id = create_resp.json().get("task_id") or create_resp.json().get("investigation_id")
        assert task_id, "No task_id in response"

        # Step 2: Poll until complete (max 120s)
        deadline = time.time() + 120
        final_status = None
        while time.time() < deadline:
            poll_resp = requests.get(
                f"{api_url}/api/v1/tasks/{task_id}",
                headers=admin_headers,
            )
            assert poll_resp.status_code == 200
            final_status = poll_resp.json().get("status")
            if final_status in ("completed", "failed", "awaiting_approval"):
                break
            time.sleep(3)

        assert final_status in ("completed", "awaiting_approval"), (
            f"Task did not complete in time. Final status: {final_status}"
        )

        # Step 3: Verify investigation steps exist
        steps_resp = requests.get(
            f"{api_url}/api/v1/tasks/{task_id}/steps",
            headers=admin_headers,
        )
        assert steps_resp.status_code == 200
        steps = steps_resp.json().get("steps", [])
        assert len(steps) >= 1, "Expected at least one investigation step"

        # Step 4: Verify audit trail
        audit_resp = requests.get(
            f"{api_url}/api/v1/tasks/{task_id}/audit",
            headers=admin_headers,
        )
        assert audit_resp.status_code == 200
        audit = audit_resp.json().get("audit_trail", [])
        assert len(audit) >= 1, "Expected at least one audit event"
        actions = [a["action"] for a in audit]
        assert "task_created" in actions, "Missing task_created audit event"

    def test_get_nonexistent_task_returns_404(self, api_url, admin_headers):
        """GET a bogus task_id should return 404."""
        resp = requests.get(
            f"{api_url}/api/v1/tasks/00000000-0000-0000-0000-000000000000",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    def test_stats_endpoint(self, api_url, admin_headers):
        """GET /api/v1/stats should return aggregated statistics."""
        resp = requests.get(f"{api_url}/api/v1/stats", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_tasks" in data
        assert "completed" in data

    def test_list_tasks_pagination(self, api_url, admin_headers):
        """GET /api/v1/tasks supports pagination."""
        resp = requests.get(
            f"{api_url}/api/v1/tasks",
            headers=admin_headers,
            params={"page": 1, "limit": 5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "tasks" in data
        assert "total" in data
        assert "pages" in data
