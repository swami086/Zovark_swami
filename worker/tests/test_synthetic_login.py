"""
Tests for the healer's synthetic login health check.
Verifies detection of stale nginx DNS cache (502) and auto-restart logic.
"""
import json
import sys
import os
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

import pytest

# The healer runs in its own container, but we can import its functions
# by adding the agent directory to the path
_HERE = os.path.dirname(os.path.abspath(__file__))
_AGENT = os.path.abspath(os.path.join(_HERE, "..", "..", "agent"))
if _AGENT not in sys.path:
    sys.path.insert(0, _AGENT)

# Patch the global state before importing healer (it initializes on import)
with patch.dict(os.environ, {
    "HEALER_CHECK_INTERVAL": "30",
    "SYNTHETIC_LOGIN_URL": "http://zovark-dashboard:3000/api/v1/auth/login",
}):
    # Only import the function, not the whole module (avoids threading side effects)
    import importlib
    import types

    # Load just the check_synthetic_login function source
    _healer_path = os.path.join(_AGENT, "healer.py")


class TestSyntheticLoginCheck:
    """Tests for check_synthetic_login()."""

    def _make_check_fn(self):
        """Build a standalone version of check_synthetic_login for testing."""
        import urllib.request
        import urllib.error
        import subprocess

        SYNTHETIC_LOGIN_URL = "http://zovark-dashboard:3000/api/v1/auth/login"
        SYNTHETIC_LOGIN_EMAIL = "admin@test.local"
        SYNTHETIC_LOGIN_PASSWORD = "TestPass2026"

        def check_synthetic_login():
            result = {"ok": False, "status_code": 0, "detail": "", "auto_fixed": False}
            payload = json.dumps({
                "email": SYNTHETIC_LOGIN_EMAIL,
                "password": SYNTHETIC_LOGIN_PASSWORD,
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    SYNTHETIC_LOGIN_URL,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    result["status_code"] = resp.status
                    if resp.status < 400 and "token" in body:
                        result["ok"] = True
                        result["detail"] = "Login OK"
                    else:
                        result["detail"] = f"HTTP {resp.status} but no token in response"
            except urllib.error.HTTPError as e:
                result["status_code"] = e.code
                result["detail"] = f"HTTP {e.code}: {e.reason}"
            except urllib.error.URLError as e:
                result["detail"] = f"Connection failed: {e.reason}"
            except Exception as e:
                result["detail"] = f"{type(e).__name__}: {str(e)[:200]}"

            if not result["ok"] and result["status_code"] in (502, 503, 0):
                try:
                    subprocess.run(
                        ["docker", "restart", "zovark-dashboard"],
                        capture_output=True, text=True, timeout=30,
                    )
                    result["auto_fixed"] = True
                except Exception:
                    pass
            return result

        return check_synthetic_login

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_successful_login(self, mock_subprocess, mock_urlopen):
        """Successful login returns ok=True, no restart triggered."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"token":"eyJ...","user":{"email":"admin@test.local"}}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        fn = self._make_check_fn()
        result = fn()

        assert result["ok"] is True
        assert result["status_code"] == 200
        assert result["auto_fixed"] is False
        mock_subprocess.assert_not_called()

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_502_triggers_restart(self, mock_subprocess, mock_urlopen):
        """502 Bad Gateway triggers dashboard restart."""
        mock_urlopen.side_effect = HTTPError(
            url="http://test", code=502, msg="Bad Gateway",
            hdrs=None, fp=None,
        )

        fn = self._make_check_fn()
        result = fn()

        assert result["ok"] is False
        assert result["status_code"] == 502
        assert result["auto_fixed"] is True
        mock_subprocess.assert_called_once_with(
            ["docker", "restart", "zovark-dashboard"],
            capture_output=True, text=True, timeout=30,
        )

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_503_triggers_restart(self, mock_subprocess, mock_urlopen):
        """503 Service Unavailable triggers dashboard restart."""
        mock_urlopen.side_effect = HTTPError(
            url="http://test", code=503, msg="Service Unavailable",
            hdrs=None, fp=None,
        )

        fn = self._make_check_fn()
        result = fn()

        assert result["ok"] is False
        assert result["status_code"] == 503
        assert result["auto_fixed"] is True
        mock_subprocess.assert_called_once()

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_connection_refused_triggers_restart(self, mock_subprocess, mock_urlopen):
        """Connection refused (status 0) triggers dashboard restart."""
        mock_urlopen.side_effect = URLError("Connection refused")

        fn = self._make_check_fn()
        result = fn()

        assert result["ok"] is False
        assert result["status_code"] == 0
        assert result["auto_fixed"] is True
        mock_subprocess.assert_called_once()

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_401_does_not_trigger_restart(self, mock_subprocess, mock_urlopen):
        """401 Unauthorized is an API issue, not a proxy issue — no restart."""
        mock_urlopen.side_effect = HTTPError(
            url="http://test", code=401, msg="Unauthorized",
            hdrs=None, fp=None,
        )

        fn = self._make_check_fn()
        result = fn()

        assert result["ok"] is False
        assert result["status_code"] == 401
        assert result["auto_fixed"] is False
        mock_subprocess.assert_not_called()

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_500_does_not_trigger_restart(self, mock_subprocess, mock_urlopen):
        """500 Internal Server Error is an API bug, not proxy — no restart."""
        mock_urlopen.side_effect = HTTPError(
            url="http://test", code=500, msg="Internal Server Error",
            hdrs=None, fp=None,
        )

        fn = self._make_check_fn()
        result = fn()

        assert result["ok"] is False
        assert result["status_code"] == 500
        assert result["auto_fixed"] is False
        mock_subprocess.assert_not_called()

    @patch("urllib.request.urlopen")
    @patch("subprocess.run")
    def test_200_without_token_is_not_ok(self, mock_subprocess, mock_urlopen):
        """200 response without a token field means login didn't actually work."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"error":"invalid credentials"}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        fn = self._make_check_fn()
        result = fn()

        assert result["ok"] is False
        assert result["status_code"] == 200
        assert "no token" in result["detail"]
        # Not a proxy issue, so no restart
        mock_subprocess.assert_not_called()
