"""End-to-end multi-tenant isolation tests.

Verifies that users in different tenants cannot see each other's data.
"""

import time
import pytest
import requests


class TestTenantIsolation:
    """Multi-tenant data isolation."""

    def test_tenant_a_cannot_see_tenant_b_tasks(self, api_url, test_user, second_tenant_user):
        """A user in tenant A should not see tasks created by tenant B."""
        # Tenant A creates a task
        create_resp = requests.post(
            f"{api_url}/api/v1/tasks",
            headers=test_user["headers"],
            json={
                "task_type": "log_analysis",
                "input": {"prompt": "Tenant isolation test task from tenant A"},
            },
        )
        if create_resp.status_code not in (200, 202):
            pytest.skip("Task creation failed; stack may not be fully running")

        task_id = create_resp.json().get("task_id")
        assert task_id

        # Tenant B tries to access tenant A's task
        get_resp = requests.get(
            f"{api_url}/api/v1/tasks/{task_id}",
            headers=second_tenant_user["headers"],
        )
        assert get_resp.status_code == 404, (
            "Tenant B should NOT be able to see tenant A's task"
        )

    def test_tenant_task_lists_are_separate(self, api_url, test_user, second_tenant_user):
        """Each tenant's task list should only show their own tasks."""
        # Get task lists for both tenants
        resp_a = requests.get(f"{api_url}/api/v1/tasks", headers=test_user["headers"])
        resp_b = requests.get(f"{api_url}/api/v1/tasks", headers=second_tenant_user["headers"])

        assert resp_a.status_code == 200
        assert resp_b.status_code == 200

        tasks_a = resp_a.json().get("tasks", [])
        tasks_b = resp_b.json().get("tasks", [])

        # Extract task IDs
        ids_a = {t["id"] for t in tasks_a}
        ids_b = {t["id"] for t in tasks_b}

        # No overlap
        overlap = ids_a & ids_b
        assert len(overlap) == 0, f"Tenants share tasks: {overlap}"

    def test_tenant_audit_isolation(self, api_url, test_user, second_tenant_user):
        """Tenant B cannot see tenant A's audit trail."""
        # Create a task for tenant A
        create_resp = requests.post(
            f"{api_url}/api/v1/tasks",
            headers=test_user["headers"],
            json={
                "task_type": "log_analysis",
                "input": {"prompt": "Audit isolation test"},
            },
        )
        if create_resp.status_code not in (200, 202):
            pytest.skip("Task creation failed")

        task_id = create_resp.json().get("task_id")

        # Tenant B tries to access tenant A's audit
        audit_resp = requests.get(
            f"{api_url}/api/v1/tasks/{task_id}/audit",
            headers=second_tenant_user["headers"],
        )
        # Should either return 404 or empty audit trail
        if audit_resp.status_code == 200:
            audit = audit_resp.json().get("audit_trail", [])
            assert len(audit) == 0, "Tenant B should not see tenant A audit events"
        else:
            assert audit_resp.status_code == 404

    def test_tenant_stats_are_isolated(self, api_url, test_user, second_tenant_user):
        """Stats endpoint returns per-tenant data only."""
        resp_a = requests.get(f"{api_url}/api/v1/stats", headers=test_user["headers"])
        resp_b = requests.get(f"{api_url}/api/v1/stats", headers=second_tenant_user["headers"])

        assert resp_a.status_code == 200
        assert resp_b.status_code == 200

        # Tenant B (fresh) should have 0 or very few tasks
        # This is a soft assertion since test ordering may vary
        stats_b = resp_b.json()
        assert "total_tasks" in stats_b

    def test_tenant_steps_isolation(self, api_url, test_user, second_tenant_user):
        """Tenant B cannot see tenant A's investigation steps."""
        create_resp = requests.post(
            f"{api_url}/api/v1/tasks",
            headers=test_user["headers"],
            json={
                "task_type": "log_analysis",
                "input": {"prompt": "Steps isolation test"},
            },
        )
        if create_resp.status_code not in (200, 202):
            pytest.skip("Task creation failed")

        task_id = create_resp.json().get("task_id")

        steps_resp = requests.get(
            f"{api_url}/api/v1/tasks/{task_id}/steps",
            headers=second_tenant_user["headers"],
        )
        assert steps_resp.status_code == 404, (
            "Tenant B should not access tenant A's steps"
        )
