"""Tests for VaultManager and JITCredentials.

All Vault HTTP calls are mocked via patching `_request`.
No real Vault server is required.

Covers:
  - Constructor validation (missing addr / token → VaultUnavailableError)
  - store_credentials, get_credentials, delete_credentials path construction
  - create_jit_token return shape and sequential _request calls
  - revoke_jit_token: happy path and swallowed exception
  - VaultUnavailableError propagation from _request failures
  - JITCredentials async context manager
"""
import sys
import os
import asyncio

_HERE = os.path.dirname(os.path.abspath(__file__))
_WORKER = os.path.abspath(os.path.join(_HERE, ".."))
if _WORKER not in sys.path:
    sys.path.insert(0, _WORKER)

from vault_manager import VaultManager, JITCredentials, VaultUnavailableError
from unittest.mock import MagicMock, patch, call
import pytest


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------

class TestVaultManagerConstructor:

    def test_missing_addr_raises(self):
        with pytest.raises(VaultUnavailableError):
            VaultManager(addr="", token="some-token")

    def test_missing_token_raises(self):
        with pytest.raises(VaultUnavailableError):
            VaultManager(addr="http://vault:8200", token="")

    def test_missing_both_raises(self):
        with pytest.raises(VaultUnavailableError):
            VaultManager(addr="", token="")

    def test_valid_construction_succeeds(self):
        vm = VaultManager(addr="http://vault:8200", token="root")
        assert vm.addr == "http://vault:8200"
        assert vm.token == "root"

    def test_none_addr_raises(self):
        # None is falsy — same as empty string
        with pytest.raises(VaultUnavailableError):
            VaultManager(addr=None, token="some-token")

    def test_none_token_raises(self):
        with pytest.raises(VaultUnavailableError):
            VaultManager(addr="http://vault:8200", token=None)


# ---------------------------------------------------------------------------
# store_credentials
# ---------------------------------------------------------------------------

class TestStoreCredentials:

    def setup_method(self):
        self.vm = VaultManager(addr="http://vault:8200", token="root")
        self.vm._request = MagicMock(return_value={})

    def test_calls_post(self):
        self.vm.store_credentials("int-1", {"api_key": "secret"}, "tenant-1")
        method, path, data = self.vm._request.call_args[0]
        assert method == "POST"

    def test_correct_path(self):
        self.vm.store_credentials("int-1", {"api_key": "secret"}, "tenant-1")
        _, path, _ = self.vm._request.call_args[0]
        assert "int-1" in path
        assert "tenant-1" in path

    def test_credentials_wrapped_in_data_key(self):
        creds = {"api_key": "secret", "url": "https://siem.example.com"}
        self.vm.store_credentials("int-1", creds, "tenant-1")
        _, _, body = self.vm._request.call_args[0]
        assert body == {"data": creds}


# ---------------------------------------------------------------------------
# get_credentials
# ---------------------------------------------------------------------------

class TestGetCredentials:

    def setup_method(self):
        self.vm = VaultManager(addr="http://vault:8200", token="root")

    def test_returns_nested_data(self):
        self.vm._request = MagicMock(
            return_value={"data": {"data": {"api_key": "the-secret"}}}
        )
        result = self.vm.get_credentials("int-1", "tenant-1")
        assert result == {"api_key": "the-secret"}

    def test_calls_get(self):
        self.vm._request = MagicMock(
            return_value={"data": {"data": {}}}
        )
        self.vm.get_credentials("int-1", "tenant-1")
        method = self.vm._request.call_args[0][0]
        assert method == "GET"

    def test_correct_path(self):
        self.vm._request = MagicMock(
            return_value={"data": {"data": {}}}
        )
        self.vm.get_credentials("my-integration", "my-tenant")
        path = self.vm._request.call_args[0][1]
        assert "my-integration" in path
        assert "my-tenant" in path

    def test_vault_error_raises_unavailable(self):
        self.vm._request = MagicMock(side_effect=VaultUnavailableError("down"))
        with pytest.raises(VaultUnavailableError):
            self.vm.get_credentials("int-1", "tenant-1")


# ---------------------------------------------------------------------------
# delete_credentials
# ---------------------------------------------------------------------------

class TestDeleteCredentials:

    def setup_method(self):
        self.vm = VaultManager(addr="http://vault:8200", token="root")
        self.vm._request = MagicMock(return_value={})

    def test_calls_delete(self):
        self.vm.delete_credentials("int-1", "tenant-1")
        method = self.vm._request.call_args[0][0]
        assert method == "DELETE"

    def test_uses_metadata_path(self):
        self.vm.delete_credentials("int-1", "tenant-1")
        path = self.vm._request.call_args[0][1]
        assert "metadata" in path

    def test_does_not_raise_on_success(self):
        # Should complete without raising
        self.vm.delete_credentials("int-1", "tenant-1")


# ---------------------------------------------------------------------------
# create_jit_token
# ---------------------------------------------------------------------------

class TestCreateJITToken:

    def setup_method(self):
        self.vm = VaultManager(addr="http://vault:8200", token="root")

    def test_return_shape(self):
        self.vm._request = MagicMock(side_effect=[
            {"auth": {"client_token": "jit-abc123", "accessor": "acc-456"}},
            {"data": {"data": {"api_key": "svc-key"}}},
        ])
        result = self.vm.create_jit_token("int-1", "tenant-1", ttl_seconds=300)
        assert result["token"] == "jit-abc123"
        assert result["accessor"] == "acc-456"
        assert result["ttl"] == 300
        assert result["credentials"] == {"api_key": "svc-key"}

    def test_default_ttl_is_300(self):
        self.vm._request = MagicMock(side_effect=[
            {"auth": {"client_token": "t", "accessor": "a"}},
            {"data": {"data": {}}},
        ])
        result = self.vm.create_jit_token("int-1", "tenant-1")
        assert result["ttl"] == 300

    def test_custom_ttl_honoured(self):
        self.vm._request = MagicMock(side_effect=[
            {"auth": {"client_token": "t", "accessor": "a"}},
            {"data": {"data": {}}},
        ])
        result = self.vm.create_jit_token("int-1", "tenant-1", ttl_seconds=60)
        assert result["ttl"] == 60

    def test_makes_two_requests(self):
        self.vm._request = MagicMock(side_effect=[
            {"auth": {"client_token": "t", "accessor": "a"}},
            {"data": {"data": {"key": "val"}}},
        ])
        self.vm.create_jit_token("int-1", "tenant-1")
        assert self.vm._request.call_count == 2

    def test_first_request_is_token_create(self):
        self.vm._request = MagicMock(side_effect=[
            {"auth": {"client_token": "t", "accessor": "a"}},
            {"data": {"data": {}}},
        ])
        self.vm.create_jit_token("int-1", "tenant-1")
        first_call = self.vm._request.call_args_list[0][0]
        assert first_call[0] == "POST"
        assert "auth/token/create" in first_call[1]

    def test_vault_error_propagated(self):
        self.vm._request = MagicMock(
            side_effect=VaultUnavailableError("connection refused")
        )
        with pytest.raises(VaultUnavailableError):
            self.vm.create_jit_token("int-1", "tenant-1")


# ---------------------------------------------------------------------------
# revoke_jit_token
# ---------------------------------------------------------------------------

class TestRevokeJITToken:

    def setup_method(self):
        self.vm = VaultManager(addr="http://vault:8200", token="root")

    def test_revoke_calls_request(self):
        self.vm._request = MagicMock(return_value={})
        self.vm.revoke_jit_token("jit-abc123")
        assert self.vm._request.call_count == 1

    def test_revoke_uses_revoke_self_path(self):
        self.vm._request = MagicMock(return_value={})
        self.vm.revoke_jit_token("jit-abc123")
        _, path, _ = self.vm._request.call_args[0]
        assert "revoke" in path

    def test_revoke_exception_swallowed(self):
        """Revocation failure (e.g. token already expired) must not raise."""
        self.vm._request = MagicMock(
            side_effect=VaultUnavailableError("already expired")
        )
        # Should not raise
        self.vm.revoke_jit_token("jit-expired")

    def test_revoke_generic_exception_swallowed(self):
        self.vm._request = MagicMock(side_effect=RuntimeError("network error"))
        self.vm.revoke_jit_token("jit-token")  # Must not raise


# ---------------------------------------------------------------------------
# JITCredentials async context manager
# ---------------------------------------------------------------------------

class TestJITCredentials:

    def _make_vm(self, credentials: dict):
        vm = VaultManager(addr="http://vault:8200", token="root")
        vm.create_jit_token = MagicMock(return_value={
            "token": "jit-ctx-token",
            "accessor": "acc",
            "ttl": 300,
            "credentials": credentials,
        })
        vm.revoke_jit_token = MagicMock()
        return vm

    def test_aenter_returns_credentials(self):
        creds = {"api_key": "ctx-key", "url": "https://siem.example.com"}
        vm = self._make_vm(creds)
        ctx = JITCredentials(vm, "int-1", "tenant-1")

        async def run():
            async with ctx as c:
                return c

        result = asyncio.run(run())
        assert result == creds

    def test_aexit_revokes_token(self):
        vm = self._make_vm({"api_key": "k"})
        ctx = JITCredentials(vm, "int-1", "tenant-1")

        async def run():
            async with ctx:
                pass

        asyncio.run(run())
        vm.revoke_jit_token.assert_called_once_with("jit-ctx-token")

    def test_aexit_revokes_even_on_exception(self):
        vm = self._make_vm({"api_key": "k"})
        ctx = JITCredentials(vm, "int-1", "tenant-1")

        async def run():
            async with ctx:
                raise ValueError("intentional")

        with pytest.raises(ValueError):
            asyncio.run(run())

        # Revocation should still have been called
        vm.revoke_jit_token.assert_called_once()

    def test_custom_ttl_passed_to_create(self):
        vm = self._make_vm({})
        ctx = JITCredentials(vm, "int-1", "tenant-1", ttl=60)

        async def run():
            async with ctx:
                pass

        asyncio.run(run())
        vm.create_jit_token.assert_called_once_with("int-1", "tenant-1", 60)
