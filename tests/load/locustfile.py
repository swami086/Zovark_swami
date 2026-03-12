"""HYDRA Locust Load Test.

Load test scenarios for the HYDRA API gateway. Tests authentication,
task creation, task listing, and stats endpoints under load.

Usage:
    locust -f tests/load/locustfile.py --host http://localhost:8090
    locust -f tests/load/locustfile.py --headless -u 10 -r 2 -t 60s --host http://localhost:8090
"""

import json
import random
import time
from locust import HttpUser, task, between, events


# Sample log data for investigation tasks
SAMPLE_LOGS = [
    # Brute force pattern
    "\n".join([
        f"Mar 10 09:{i:02d}:00 srv sshd[1234]: Failed password for root from 192.168.1.100 port 22"
        for i in range(20)
    ]),
    # C2 beacon pattern
    "\n".join([
        f"2026-03-10T09:{i:02d}:00Z fw ALLOW TCP 10.12.5.34:49{i:03d} -> 185.220.101.42:443 bytes=256"
        for i in range(15)
    ]),
    # Lateral movement pattern
    "\n".join([
        f"2026-03-10T10:{i:02d}:00Z dc EventID=4624 LogonType=3 SourceIP=10.12.5.88 TargetUser=admin{i}"
        for i in range(10)
    ]),
    # Phishing indicator
    "From: cfo@corp-net.com\nTo: finance-team@corpnet.com\nSubject: Urgent Wire Transfer\n"
    "Please review the attached invoice and process payment by EOD.\n"
    "Attachment: Invoice_Q4_2026.xlsm (macro-enabled)\nSPF: fail\nDKIM: none",
]

TASK_TYPES = ["log_analysis", "Brute Force Investigation", "C2 Communication Hunt", "Phishing Investigation"]


class HydraUser(HttpUser):
    """Simulated HYDRA platform user."""

    wait_time = between(1, 5)
    token = None

    def on_start(self):
        """Login on start to get JWT token."""
        resp = self.client.post(
            "/api/v1/auth/login",
            json={"email": "admin@hydra.local", "password": "hydra123"},
            name="/api/v1/auth/login",
        )
        if resp.status_code == 200:
            self.token = resp.json().get("token")
        else:
            # Try registering a test user
            email = f"loadtest-{random.randint(1000, 9999)}@test.local"
            self.client.post(
                "/api/v1/auth/register",
                json={
                    "email": email,
                    "password": "LoadTest123!",
                    "display_name": "Load Test User",
                    "tenant_id": "hydra-dev",
                },
            )
            resp = self.client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "LoadTest123!"},
            )
            if resp.status_code == 200:
                self.token = resp.json().get("token")

    @property
    def auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @task(3)
    def list_tasks(self):
        """List investigations (most common operation)."""
        page = random.randint(1, 3)
        self.client.get(
            f"/api/v1/tasks?page={page}&limit=20",
            headers=self.auth_headers,
            name="/api/v1/tasks",
        )

    @task(2)
    def create_investigation(self):
        """Submit a new investigation task."""
        log_data = random.choice(SAMPLE_LOGS)
        task_type = random.choice(TASK_TYPES)
        self.client.post(
            "/api/v1/tasks",
            headers=self.auth_headers,
            json={
                "task_type": task_type,
                "input": {
                    "prompt": f"Analyze this log for {task_type} activity",
                    "log_data": log_data,
                },
            },
            name="/api/v1/tasks [POST]",
        )

    @task(2)
    def get_stats(self):
        """Fetch platform statistics."""
        self.client.get(
            "/api/v1/stats",
            headers=self.auth_headers,
            name="/api/v1/stats",
        )

    @task(1)
    def get_me(self):
        """Fetch current user profile."""
        self.client.get(
            "/api/v1/me",
            headers=self.auth_headers,
            name="/api/v1/me",
        )

    @task(1)
    def list_playbooks(self):
        """List available playbooks."""
        self.client.get(
            "/api/v1/playbooks",
            headers=self.auth_headers,
            name="/api/v1/playbooks",
        )

    @task(1)
    def list_skills(self):
        """List available skills."""
        self.client.get(
            "/api/v1/skills",
            headers=self.auth_headers,
            name="/api/v1/skills",
        )

    @task(1)
    def health_check(self):
        """Check API health."""
        self.client.get("/health", name="/health")
