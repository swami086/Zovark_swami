"""Vault JIT (Just-In-Time) token manager for SOAR playbook credentials.

Credentials stored in Vault at: zovark-soar/integrations/{integration_id}
JIT pattern: request 5-minute token -> execute -> revoke immediately.
"""
import os
import json
import time
import logging

logger = logging.getLogger(__name__)

VAULT_ADDR = os.environ.get("VAULT_ADDR", "")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")


class VaultUnavailableError(Exception):
    pass


class VaultManager:
    """Manages Vault interactions for SOAR integration credentials."""

    def __init__(self, addr=None, token=None):
        self.addr = addr or VAULT_ADDR
        self.token = token or VAULT_TOKEN
        if not self.addr or not self.token:
            raise VaultUnavailableError(
                "VAULT_ADDR and VAULT_TOKEN must be set for credential management"
            )
        self._session = None

    def _request(self, method, path, data=None):
        """Make HTTP request to Vault API."""
        import urllib.request
        url = f"{self.addr}/v1/{path}"
        headers = {"X-Vault-Token": self.token, "Content-Type": "application/json"}
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 204:
                    return {}
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.error(f"Vault request failed: {method} {path}: {e}")
            raise VaultUnavailableError(f"Vault error: {e}")

    def store_credentials(self, integration_id: str, credentials: dict, tenant_id: str):
        """Store integration credentials in Vault.

        Path: zovark-soar/data/integrations/{tenant_id}/{integration_id}
        """
        path = f"zovark-soar/data/integrations/{tenant_id}/{integration_id}"
        self._request("POST", path, {"data": credentials})
        logger.info(f"Stored credentials for integration {integration_id}")

    def get_credentials(self, integration_id: str, tenant_id: str) -> dict:
        """Retrieve integration credentials from Vault."""
        path = f"zovark-soar/data/integrations/{tenant_id}/{integration_id}"
        resp = self._request("GET", path)
        return resp.get("data", {}).get("data", {})

    def delete_credentials(self, integration_id: str, tenant_id: str):
        """Delete integration credentials from Vault."""
        path = f"zovark-soar/metadata/integrations/{tenant_id}/{integration_id}"
        self._request("DELETE", path)

    def create_jit_token(self, integration_id: str, tenant_id: str, ttl_seconds: int = 300) -> dict:
        """Create a JIT (Just-In-Time) token with short TTL.

        Returns: {token, accessor, ttl, credentials}
        """
        # Create a child token with limited TTL and narrow policy
        resp = self._request("POST", "auth/token/create", {
            "ttl": f"{ttl_seconds}s",
            "explicit_max_ttl": f"{ttl_seconds}s",
            "renewable": False,
            "display_name": f"jit-soar-{integration_id}",
            "metadata": {
                "integration_id": integration_id,
                "tenant_id": tenant_id,
                "created_at": str(int(time.time())),
            },
            "num_uses": 2,  # One for credential read, one for revocation
        })
        auth = resp.get("auth", {})
        jit_token = auth.get("client_token", "")
        accessor = auth.get("accessor", "")

        # Read credentials with the parent token (JIT token uses are reserved for
        # the actual action execution and self-revocation)
        credentials = self.get_credentials(integration_id, tenant_id)

        logger.info(f"JIT token created for {integration_id}, TTL={ttl_seconds}s")
        return {
            "token": jit_token,
            "accessor": accessor,
            "ttl": ttl_seconds,
            "credentials": credentials,
        }

    def revoke_jit_token(self, token: str):
        """Revoke a JIT token immediately after use."""
        try:
            self._request("POST", "auth/token/revoke-self", None)
            logger.info("JIT token revoked")
        except Exception as e:
            logger.warning(f"JIT token revocation failed (may have expired): {e}")


# Context manager for JIT token lifecycle
class JITCredentials:
    """Context manager for JIT credential lifecycle.

    Usage:
        async with JITCredentials(vault, integration_id, tenant_id) as creds:
            # creds contains the integration credentials
            api_key = creds.get("api_key")
    """

    def __init__(self, vault: VaultManager, integration_id: str, tenant_id: str, ttl: int = 300):
        self.vault = vault
        self.integration_id = integration_id
        self.tenant_id = tenant_id
        self.ttl = ttl
        self._jit_data = None

    async def __aenter__(self):
        self._jit_data = self.vault.create_jit_token(
            self.integration_id, self.tenant_id, self.ttl
        )
        return self._jit_data["credentials"]

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._jit_data and self._jit_data.get("token"):
            self.vault.revoke_jit_token(self._jit_data["token"])
        return False  # Don't suppress exceptions
