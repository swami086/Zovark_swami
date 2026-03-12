"""End-to-end auth flow tests: register, login, role checks."""

import time
import pytest
import requests


class TestRegistration:
    """User registration tests."""

    def test_register_new_user(self, api_url):
        """Register a new user and verify response."""
        email = f"reg-test-{int(time.time())}@e2e.local"
        resp = requests.post(
            f"{api_url}/api/v1/auth/register",
            json={
                "email": email,
                "password": "SecurePass123",
                "display_name": "Reg Test User",
                "tenant_id": "hydra-dev",
            },
        )
        assert resp.status_code == 201, f"Registration failed: {resp.text}"
        data = resp.json()
        assert data["user"]["email"] == email
        assert data["user"]["role"] == "analyst"

    def test_register_duplicate_email_fails(self, api_url):
        """Registering the same email twice should fail."""
        email = f"dup-{int(time.time())}@e2e.local"
        payload = {
            "email": email,
            "password": "SecurePass123",
            "display_name": "Dup User",
            "tenant_id": "hydra-dev",
        }
        resp1 = requests.post(f"{api_url}/api/v1/auth/register", json=payload)
        assert resp1.status_code == 201

        resp2 = requests.post(f"{api_url}/api/v1/auth/register", json=payload)
        assert resp2.status_code == 500  # duplicate key error

    def test_register_missing_fields_fails(self, api_url):
        """Registration with missing required fields returns 400."""
        resp = requests.post(
            f"{api_url}/api/v1/auth/register",
            json={"email": "incomplete@test.local"},
        )
        assert resp.status_code == 400

    def test_register_invalid_email_fails(self, api_url):
        """Registration with invalid email format returns 400."""
        resp = requests.post(
            f"{api_url}/api/v1/auth/register",
            json={
                "email": "not-an-email",
                "password": "SecurePass123",
                "display_name": "Bad Email",
                "tenant_id": "hydra-dev",
            },
        )
        assert resp.status_code == 400


class TestLogin:
    """User login tests."""

    def test_login_valid_credentials(self, api_url):
        """Login with valid admin credentials returns token."""
        resp = requests.post(
            f"{api_url}/api/v1/auth/login",
            json={"email": "admin@hydra.local", "password": "hydra123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["user"]["role"] == "admin"

    def test_login_wrong_password_fails(self, api_url):
        """Login with wrong password returns 401."""
        resp = requests.post(
            f"{api_url}/api/v1/auth/login",
            json={"email": "admin@hydra.local", "password": "wrong-password"},
        )
        assert resp.status_code == 401

    def test_login_nonexistent_user_fails(self, api_url):
        """Login with nonexistent email returns 401."""
        resp = requests.post(
            f"{api_url}/api/v1/auth/login",
            json={"email": "nobody@nowhere.com", "password": "anything"},
        )
        assert resp.status_code == 401

    def test_login_missing_fields_fails(self, api_url):
        """Login with missing fields returns 400."""
        resp = requests.post(
            f"{api_url}/api/v1/auth/login",
            json={"email": "admin@hydra.local"},
        )
        assert resp.status_code == 400


class TestRoleAccess:
    """Role-based access control tests."""

    def test_unauthenticated_request_rejected(self, api_url):
        """Requests without JWT are rejected."""
        resp = requests.get(f"{api_url}/api/v1/tasks")
        assert resp.status_code == 401

    def test_invalid_token_rejected(self, api_url):
        """Requests with invalid JWT are rejected."""
        resp = requests.get(
            f"{api_url}/api/v1/tasks",
            headers={"Authorization": "Bearer invalid-jwt-token"},
        )
        assert resp.status_code == 401

    def test_analyst_cannot_access_admin_endpoints(self, api_url, test_user):
        """Analyst role should not access admin-only endpoints."""
        admin_endpoints = [
            ("GET", "/api/v1/tenants"),
            ("GET", "/api/v1/models"),
            ("GET", "/api/v1/feedback/stats"),
        ]
        for method, path in admin_endpoints:
            resp = requests.request(method, f"{api_url}{path}", headers=test_user["headers"])
            assert resp.status_code == 403, (
                f"Expected 403 for analyst on {method} {path}, got {resp.status_code}"
            )

    def test_analyst_can_access_own_endpoints(self, api_url, test_user):
        """Analyst role should access regular endpoints."""
        resp = requests.get(f"{api_url}/api/v1/tasks", headers=test_user["headers"])
        assert resp.status_code == 200

        resp = requests.get(f"{api_url}/api/v1/stats", headers=test_user["headers"])
        assert resp.status_code == 200

        resp = requests.get(f"{api_url}/api/v1/me", headers=test_user["headers"])
        assert resp.status_code == 200

    def test_me_endpoint_returns_user_info(self, api_url, test_user):
        """GET /api/v1/me returns current user info."""
        resp = requests.get(f"{api_url}/api/v1/me", headers=test_user["headers"])
        assert resp.status_code == 200
        data = resp.json()
        assert "user" in data
        assert data["user"]["role"] == "analyst"
