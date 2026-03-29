"""Zovark Python SDK client.

Provides a high-level interface to the Zovark SOC automation API.
Uses only stdlib + requests (minimal dependencies).

Usage:
    from zovark import ZovarkClient

    client = ZovarkClient("http://localhost:8090", email="admin@test.local", password="TestPass2026")
    client.login()

    task = client.create_task(
        input={"prompt": "Analyze for brute force", "log_data": "..."},
        task_type="log_analysis",
    )
    result = client.wait_for_completion(task.task_id, timeout=120)
    print(result.status, result.output)
"""

import time
import json
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

from zovark.models import Task, Alert, User, Stats, TaskList
from zovark.exceptions import (
    ZovarkAPIError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
    ForbiddenError,
)


class ZovarkClient:
    """Client for the Zovark SOC automation API.

    Args:
        base_url: API base URL (e.g., "http://localhost:8090")
        api_key: Pre-existing JWT token (optional)
        email: Login email (optional, used with password)
        password: Login password (optional, used with email)
        timeout: Request timeout in seconds (default: 30)
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        email: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self._token = api_key
        self._email = email
        self._password = password
        self._timeout = timeout
        self._user: Optional[User] = None

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make an HTTP request to the API."""
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urlencode(params)

        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")

        req = Request(url, data=body, headers=headers, method=method)

        try:
            with urlopen(req, timeout=self._timeout) as resp:
                resp_body = resp.read().decode("utf-8")
                if resp_body:
                    return json.loads(resp_body)
                return {}
        except HTTPError as e:
            resp_body = e.read().decode("utf-8") if e.fp else ""
            error_msg = resp_body
            try:
                error_data = json.loads(resp_body)
                error_msg = error_data.get("error", resp_body)
            except (json.JSONDecodeError, ValueError):
                pass

            if e.code == 401:
                raise AuthenticationError(error_msg, response_body=resp_body)
            elif e.code == 403:
                raise ForbiddenError(error_msg, response_body=resp_body)
            elif e.code == 404:
                raise NotFoundError(error_msg, response_body=resp_body)
            elif e.code == 429:
                retry_after = e.headers.get("Retry-After")
                raise RateLimitError(
                    error_msg,
                    retry_after=int(retry_after) if retry_after else None,
                    response_body=resp_body,
                )
            else:
                raise ZovarkAPIError(
                    error_msg,
                    status_code=e.code,
                    response_body=resp_body,
                )
        except URLError as e:
            raise ZovarkAPIError(f"Connection failed: {e.reason}")

    # ── Authentication ──────────────────────────────────

    def login(self) -> str:
        """Authenticate and store JWT token.

        Returns:
            JWT token string.

        Raises:
            AuthenticationError: If credentials are invalid.
            ZovarkAPIError: If login fails for another reason.
        """
        if not self._email or not self._password:
            raise AuthenticationError("Email and password are required for login")

        data = self._request("POST", "/api/v1/auth/login", data={
            "email": self._email,
            "password": self._password,
        })

        self._token = data["token"]
        if "user" in data:
            self._user = User.from_dict(data["user"])
        return self._token

    def register(
        self,
        email: str,
        password: str,
        display_name: str,
        tenant_id: str,
    ) -> User:
        """Register a new user.

        Returns:
            User object for the created user.
        """
        data = self._request("POST", "/api/v1/auth/register", data={
            "email": email,
            "password": password,
            "display_name": display_name,
            "tenant_id": tenant_id,
        })
        return User.from_dict(data.get("user", {}))

    @property
    def current_user(self) -> Optional[User]:
        """Get the currently authenticated user."""
        if self._user is None and self._token:
            data = self._request("GET", "/api/v1/me")
            self._user = User.from_dict(data.get("user", {}))
        return self._user

    # ── Tasks ───────────────────────────────────────────

    def create_task(
        self,
        input: Dict[str, Any],
        task_type: str = "log_analysis",
    ) -> Task:
        """Create a new investigation task.

        Args:
            input: Task input dict (must include "prompt" key).
            task_type: Type of task (default: "log_analysis").

        Returns:
            Task object with task_id and initial status.
        """
        data = self._request("POST", "/api/v1/tasks", data={
            "task_type": task_type,
            "input": input,
        })
        return Task.from_dict(data)

    def get_task(self, task_id: str) -> Task:
        """Get task details by ID.

        Args:
            task_id: UUID of the task.

        Returns:
            Task object with full details.

        Raises:
            NotFoundError: If task does not exist.
        """
        data = self._request("GET", f"/api/v1/tasks/{task_id}")
        return Task.from_dict(data)

    def list_tasks(
        self,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
        task_type: Optional[str] = None,
        search: Optional[str] = None,
    ) -> TaskList:
        """List investigation tasks with pagination.

        Args:
            page: Page number (default: 1).
            per_page: Items per page (default: 20, max: 100).
            status: Filter by status (pending, executing, completed, failed).
            task_type: Filter by task type.
            search: Search in prompt text.

        Returns:
            TaskList with paginated results.
        """
        params = {"page": page, "limit": per_page}
        if status:
            params["status"] = status
        if task_type:
            params["task_type"] = task_type
        if search:
            params["search"] = search

        data = self._request("GET", "/api/v1/tasks", params=params)
        return TaskList.from_dict(data)

    def get_task_steps(self, task_id: str) -> List[dict]:
        """Get investigation steps for a task.

        Returns:
            List of step dicts.
        """
        data = self._request("GET", f"/api/v1/tasks/{task_id}/steps")
        return data.get("steps", [])

    def get_task_audit(self, task_id: str) -> List[dict]:
        """Get audit trail for a task.

        Returns:
            List of audit event dicts.
        """
        data = self._request("GET", f"/api/v1/tasks/{task_id}/audit")
        return data.get("audit_trail", [])

    def get_task_timeline(self, task_id: str) -> List[dict]:
        """Get timeline events for a task.

        Returns:
            List of timeline event dicts.
        """
        data = self._request("GET", f"/api/v1/tasks/{task_id}/timeline")
        return data.get("timeline", [])

    def wait_for_completion(
        self,
        task_id: str,
        timeout: int = 120,
        poll_interval: int = 3,
    ) -> Task:
        """Poll a task until it completes or times out.

        Args:
            task_id: UUID of the task.
            timeout: Maximum wait time in seconds (default: 120).
            poll_interval: Seconds between polls (default: 3).

        Returns:
            Task object with final status.

        Raises:
            TimeoutError: If task does not complete within timeout.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            task = self.get_task(task_id)
            if task.is_complete:
                return task
            time.sleep(poll_interval)
        raise TimeoutError(
            f"Task {task_id} did not complete within {timeout}s. "
            f"Last status: {task.status}"
        )

    # ── Alerts ──────────────────────────────────────────

    def list_alerts(self) -> List[Alert]:
        """List SIEM alerts.

        Returns:
            List of Alert objects.
        """
        data = self._request("GET", "/api/v1/siem-alerts")
        alerts_data = data.get("alerts", data.get("siem_alerts", []))
        return [Alert.from_dict(a) for a in alerts_data]

    def investigate_alert(self, alert_id: str) -> Task:
        """Trigger investigation for a SIEM alert.

        Args:
            alert_id: UUID of the SIEM alert.

        Returns:
            Task object for the investigation.
        """
        data = self._request("POST", f"/api/v1/siem-alerts/{alert_id}/investigate")
        return Task.from_dict(data)

    # ── Stats ───────────────────────────────────────────

    def get_stats(self) -> Stats:
        """Get platform statistics.

        Returns:
            Stats object with aggregated metrics.
        """
        data = self._request("GET", "/api/v1/stats")
        return Stats.from_dict(data)

    # ── Health ──────────────────────────────────────────

    def health_check(self) -> dict:
        """Check API health.

        Returns:
            Health status dict.
        """
        return self._request("GET", "/health")

    # ── Playbooks ───────────────────────────────────────

    def list_playbooks(self) -> List[dict]:
        """List available playbooks.

        Returns:
            List of playbook dicts.
        """
        data = self._request("GET", "/api/v1/playbooks")
        return data.get("playbooks", [])

    # ── Skills ──────────────────────────────────────────

    def list_skills(self) -> List[dict]:
        """List available investigation skills.

        Returns:
            List of skill dicts.
        """
        data = self._request("GET", "/api/v1/skills")
        return data.get("skills", [])
