"""Shared fixtures for HYDRA end-to-end tests."""

import os
import time
import pytest
import requests

API_URL = os.environ.get("HYDRA_API_URL", "http://localhost:8090")
ADMIN_EMAIL = "admin@hydra.local"
ADMIN_PASSWORD = "hydra123"
TEST_TENANT_ID = os.environ.get("HYDRA_TEST_TENANT_ID", "hydra-dev")


def wait_for_api(url=API_URL, timeout=120):
    """Wait until the API is healthy before running tests."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{url}/health", timeout=5)
            if resp.status_code == 200:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(2)
    raise TimeoutError(f"API at {url} not healthy after {timeout}s")


@pytest.fixture(scope="session")
def api_url():
    """Return the base API URL and ensure it is reachable."""
    wait_for_api(API_URL)
    return API_URL


@pytest.fixture(scope="session")
def admin_token(api_url):
    """Login with the default admin account and return a JWT token."""
    resp = requests.post(
        f"{api_url}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    data = resp.json()
    assert "token" in data
    return data["token"]


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    """Return authorization headers for the admin user."""
    return {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}


@pytest.fixture(scope="session")
def test_user(api_url):
    """Register a test analyst user and return credentials dict."""
    email = f"e2e-analyst-{int(time.time())}@test.local"
    password = "TestPass123!"
    resp = requests.post(
        f"{api_url}/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "display_name": "E2E Test Analyst",
            "tenant_id": TEST_TENANT_ID,
        },
    )
    # May fail if user exists; that is OK for idempotent runs.
    if resp.status_code == 201:
        user_data = resp.json()["user"]
    else:
        user_data = {"email": email}

    # Login to get token
    login_resp = requests.post(
        f"{api_url}/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200, f"Test user login failed: {login_resp.text}"
    token = login_resp.json()["token"]

    return {
        "email": email,
        "password": password,
        "token": token,
        "headers": {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        **user_data,
    }


@pytest.fixture(scope="session")
def second_tenant_user(api_url):
    """Register a user in a different tenant for isolation tests."""
    tenant_id = f"test-tenant-{int(time.time())}"
    email = f"tenant2-{int(time.time())}@test.local"
    password = "TestPass456!"

    resp = requests.post(
        f"{api_url}/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "display_name": "Tenant 2 Analyst",
            "tenant_id": tenant_id,
        },
    )
    if resp.status_code not in (201, 500):
        pytest.skip(f"Cannot create second tenant user: {resp.text}")

    login_resp = requests.post(
        f"{api_url}/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]

    return {
        "email": email,
        "password": password,
        "tenant_id": tenant_id,
        "token": token,
        "headers": {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    }
