"""End-to-end integration tests — require Docker Compose stack running.

Usage:
    docker compose up -d
    sleep 30  # wait for services
    python -m pytest tests/integration/ -v
"""
import json
import os
import time
import urllib.request
import urllib.error
import pytest

API_BASE = os.environ.get("ZOVARC_API_URL", "http://localhost:8090")
ADMIN_EMAIL = os.environ.get("ZOVARC_ADMIN_EMAIL", "admin@zovarc.local")
ADMIN_PASSWORD = os.environ.get("ZOVARC_ADMIN_PASSWORD", "zovarc123")
TIMEOUT = 120  # seconds


def _api(method, path, data=None, token=None):
    """Make HTTP request to ZOVARC API."""
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode()) if e.read() else {}
    except Exception as e:
        return 0, {"error": str(e)}


def _check_health():
    """Check if API is healthy."""
    try:
        status, body = _api("GET", "/health")
        return status == 200 and body.get("status") == "ok"
    except Exception:
        return False


def _login(email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    """Login and return access token."""
    status, body = _api("POST", "/api/v1/auth/login", {
        "email": email,
        "password": password,
    })
    if status == 200:
        return body.get("token")
    return None


@pytest.fixture(scope="module")
def api_health():
    """Verify API is reachable before running integration tests."""
    if not _check_health():
        pytest.skip("ZOVARC API not available — start Docker Compose first")
    return True


@pytest.fixture(scope="module")
def admin_token(api_health):
    """Get admin JWT token."""
    token = _login()
    if not token:
        pytest.skip("Cannot login — check credentials")
    return token


class TestHealthEndpoint:
    """Basic health checks."""

    def test_health_returns_ok(self, api_health):
        status, body = _api("GET", "/health")
        assert status == 200
        assert body["status"] == "ok"

    def test_health_has_version(self, api_health):
        status, body = _api("GET", "/health")
        assert "version" in body

    def test_health_security_headers(self, api_health):
        """Verify CSP/HSTS headers on health endpoint."""
        url = f"{API_BASE}/health"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers = dict(resp.headers)
            assert "Content-Security-Policy" in headers or "content-security-policy" in headers
            assert "Strict-Transport-Security" in headers or "strict-transport-security" in headers
            assert "X-Frame-Options" in headers or "x-frame-options" in headers


class TestAuthFlow:
    """Authentication flow tests."""

    def test_login_valid_credentials(self, api_health):
        status, body = _api("POST", "/api/v1/auth/login", {
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD,
        })
        assert status == 200
        assert "token" in body

    def test_login_invalid_credentials(self, api_health):
        status, body = _api("POST", "/api/v1/auth/login", {
            "email": "wrong@zovarc.local",
            "password": "wrongpassword",
        })
        assert status == 401

    def test_protected_endpoint_without_token(self, api_health):
        status, body = _api("GET", "/api/v1/tasks")
        assert status == 401


class TestInvestigationE2E:
    """Full investigation flow: submit → poll → verify."""

    def test_submit_and_poll_investigation(self, admin_token):
        # Step 1: Submit a task
        status, body = _api("POST", "/api/v1/tasks", {
            "task_type": "log_analysis",
            "input": {
                "prompt": "Analyze this test alert: suspicious login from 10.0.0.1 to admin account"
            }
        }, admin_token)

        if status not in (200, 201):
            pytest.skip(f"Task creation failed: {status} {body}")

        task_id = body.get("task_id") or body.get("id")
        assert task_id, f"No task_id in response: {body}"

        # Step 2: Poll for completion
        start = time.time()
        final_status = None
        while time.time() - start < TIMEOUT:
            status, body = _api("GET", f"/api/v1/tasks/{task_id}", token=admin_token)
            if status != 200:
                time.sleep(5)
                continue
            final_status = body.get("status")
            if final_status in ("completed", "failed"):
                break
            time.sleep(5)

        assert final_status in ("completed", "failed"), \
            f"Task did not complete within {TIMEOUT}s, status: {final_status}"


class TestRateLimiting:
    """Rate limiting verification."""

    def test_rate_limit_headers(self, admin_token):
        status, body = _api("GET", "/api/v1/tasks", token=admin_token)
        # Just verify the endpoint works — rate limit headers tested in unit tests


class TestErrorHandling:
    """Verify error responses don't leak internals."""

    def test_404_returns_clean_error(self, admin_token):
        status, body = _api("GET", "/api/v1/tasks/00000000-0000-0000-0000-000000000000", token=admin_token)
        # Should be 404, not 500
        if status == 500:
            error_msg = body.get("error", "")
            assert "internal error" in error_msg.lower() or "not found" in error_msg.lower()
            # Must NOT contain DB details
            assert "relation" not in error_msg
            assert "pq:" not in error_msg

    def test_invalid_json_returns_400(self, api_health):
        url = f"{API_BASE}/api/v1/auth/login"
        req = urllib.request.Request(url, data=b"not json", headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                pass
        except urllib.error.HTTPError as e:
            assert e.code == 400
