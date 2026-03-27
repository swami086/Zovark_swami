"""Response action framework — 7 simulated SOAR actions.

All actions are simulated by default (log what they would do).
If a webhook integration exists for the action type + tenant,
the action calls the webhook. Otherwise, log-only mode.

Credential resolution order:
  1. Vault JIT token (if VAULT_ADDR + VAULT_TOKEN are set and vault_path is populated)
  2. Plaintext DB auth_credentials (backward-compatible fallback)
"""

import os
import logging
import httpx
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Lazy import — only fails at runtime if Vault is actually needed but not
# installed. vault_manager has no third-party dependencies (stdlib only).
try:
    from vault_manager import VaultManager, JITCredentials, VaultUnavailableError
    _VAULT_AVAILABLE = True
except ImportError:
    _VAULT_AVAILABLE = False
    VaultUnavailableError = Exception  # fallback sentinel


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
    return psycopg2.connect(db_url)


def _get_webhook(tenant_id: str, action_type: str) -> dict:
    """Check if a webhook integration exists for this action type.

    Returns a dict with at minimum: webhook_url, auth_type, auth_credentials,
    and optionally: id (integration UUID), vault_path, credentials_migrated.
    """
    try:
        conn = _get_db()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id::text, webhook_url, auth_type, auth_credentials,
                           vault_path, credentials_migrated
                    FROM response_integrations
                    WHERE tenant_id = %s AND integration_type = %s AND enabled = true
                    LIMIT 1
                """, (tenant_id, action_type))
                row = cur.fetchone()
                return dict(row) if row else None
        finally:
            conn.close()
    except Exception:
        return None


async def _resolve_credentials(webhook: dict, tenant_id: str) -> str | None:
    """Resolve the auth credential value using Vault JIT when available.

    Resolution order:
      1. Vault JIT token — used when VAULT_ADDR/VAULT_TOKEN are set and
         the integration has a vault_path (credentials_migrated = true).
      2. Plaintext auth_credentials column — backward-compatible fallback.

    Returns the raw credential string, or None if not applicable.
    """
    integration_id = webhook.get("id")
    vault_path = webhook.get("vault_path")
    credentials_migrated = webhook.get("credentials_migrated", False)

    if _VAULT_AVAILABLE and integration_id and vault_path and credentials_migrated:
        try:
            vault = VaultManager()
            async with JITCredentials(vault, integration_id, tenant_id) as creds:
                # Vault creds dict may contain "api_key", "bearer_token", or
                # "password" depending on auth_type.
                auth_type = webhook.get("auth_type", "none")
                if auth_type == "bearer":
                    return creds.get("bearer_token") or creds.get("api_key")
                elif auth_type in ("api_key", "basic"):
                    return creds.get("api_key") or creds.get("password")
                # For any other type return the first value in the dict
                return next(iter(creds.values()), None) if creds else None
        except VaultUnavailableError as exc:
            logger.warning(
                "Vault unavailable for integration %s, falling back to DB credentials: %s",
                integration_id, exc,
            )
        except Exception as exc:
            logger.warning(
                "Vault JIT credential fetch failed for %s, falling back to DB: %s",
                integration_id, exc,
            )

    # Fallback: plaintext credential stored in the DB column
    return webhook.get("auth_credentials")


async def _call_webhook(webhook: dict, payload: dict, tenant_id: str | None = None) -> dict:
    """Call a webhook endpoint with the action payload.

    Credentials are resolved via Vault JIT when available; plaintext DB
    auth_credentials are used as a backward-compatible fallback.
    """
    headers = {"Content-Type": "application/json"}

    credential = await _resolve_credentials(webhook, tenant_id or "")

    if webhook.get("auth_type") == "bearer" and credential:
        headers["Authorization"] = f"Bearer {credential}"
    elif webhook.get("auth_type") == "api_key" and credential:
        headers["X-API-Key"] = credential

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(webhook["webhook_url"], json=payload, headers=headers)
            return {"status": "sent", "status_code": resp.status_code, "response": resp.text[:500]}
    except Exception as e:
        return {"status": "webhook_failed", "error": str(e)}


class ResponseAction:
    """Base class for response actions."""
    action_type = "unknown"

    def validate(self, context: dict) -> bool:
        return True

    async def execute(self, context: dict) -> dict:
        return {"status": "simulated", "action": self.action_type, "message": "No-op (simulated)"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        return {"status": "rollback_simulated", "action": self.action_type}


class BlockIP(ResponseAction):
    action_type = "block_ip"

    def validate(self, context: dict) -> bool:
        return bool(context.get("ip"))

    async def execute(self, context: dict) -> dict:
        ip = context.get("ip", "unknown")
        tenant_id = context.get("tenant_id")
        webhook = _get_webhook(tenant_id, "block_ip") if tenant_id else None
        if webhook:
            result = await _call_webhook(webhook, {"action": "block_ip", "ip": ip}, tenant_id)
            print(f"[BlockIP] Webhook called for {ip}: {result}")
            return {"status": "executed", "ip": ip, "webhook": result}
        print(f"[BlockIP] SIMULATED: Would block IP {ip} on firewall")
        return {"status": "simulated", "ip": ip, "message": f"Would block IP {ip}"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        ip = context.get("ip", "unknown")
        print(f"[BlockIP] ROLLBACK: Would unblock IP {ip}")
        return {"status": "rollback_simulated", "ip": ip}


class DisableUser(ResponseAction):
    action_type = "disable_user"

    def validate(self, context: dict) -> bool:
        return bool(context.get("username"))

    async def execute(self, context: dict) -> dict:
        username = context.get("username", "unknown")
        tenant_id = context.get("tenant_id")
        webhook = _get_webhook(tenant_id, "disable_user") if tenant_id else None
        if webhook:
            result = await _call_webhook(webhook, {"action": "disable_user", "username": username}, tenant_id)
            return {"status": "executed", "username": username, "webhook": result}
        print(f"[DisableUser] SIMULATED: Would disable user {username}")
        return {"status": "simulated", "username": username, "message": f"Would disable user {username}"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        print(f"[DisableUser] ROLLBACK: Would re-enable user {context.get('username')}")
        return {"status": "rollback_simulated", "username": context.get("username")}


class IsolateEndpoint(ResponseAction):
    action_type = "isolate_endpoint"

    def validate(self, context: dict) -> bool:
        return bool(context.get("hostname") or context.get("ip"))

    async def execute(self, context: dict) -> dict:
        target = context.get("hostname") or context.get("ip", "unknown")
        tenant_id = context.get("tenant_id")
        webhook = _get_webhook(tenant_id, "isolate_endpoint") if tenant_id else None
        if webhook:
            result = await _call_webhook(webhook, {"action": "isolate_endpoint", "target": target}, tenant_id)
            return {"status": "executed", "target": target, "webhook": result}
        print(f"[IsolateEndpoint] SIMULATED: Would isolate endpoint {target}")
        return {"status": "simulated", "target": target, "message": f"Would isolate {target}"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        target = context.get("hostname") or context.get("ip", "unknown")
        print(f"[IsolateEndpoint] ROLLBACK: Would un-isolate {target}")
        return {"status": "rollback_simulated", "target": target}


class RotateCredentials(ResponseAction):
    action_type = "rotate_credentials"

    def validate(self, context: dict) -> bool:
        return bool(context.get("username") or context.get("service"))

    async def execute(self, context: dict) -> dict:
        target = context.get("username") or context.get("service", "unknown")
        tenant_id = context.get("tenant_id")
        webhook = _get_webhook(tenant_id, "rotate_credentials") if tenant_id else None
        if webhook:
            result = await _call_webhook(webhook, {"action": "rotate_credentials", "target": target}, tenant_id)
            return {"status": "executed", "target": target, "webhook": result}
        print(f"[RotateCredentials] SIMULATED: Would rotate credentials for {target}")
        return {"status": "simulated", "target": target, "message": f"Would rotate credentials for {target}"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        return {"status": "rollback_not_applicable", "message": "Credential rotation cannot be rolled back"}


class CreateTicket(ResponseAction):
    action_type = "create_ticket"

    def validate(self, context: dict) -> bool:
        return bool(context.get("title"))

    async def execute(self, context: dict) -> dict:
        title = context.get("title", "ZOVARC Alert")
        tenant_id = context.get("tenant_id")
        webhook = _get_webhook(tenant_id, "create_ticket") if tenant_id else None
        if webhook:
            result = await _call_webhook(webhook, {
                "action": "create_ticket", "title": title,
                "description": context.get("description", ""),
                "priority": context.get("priority", "medium"),
            }, tenant_id)
            return {"status": "executed", "title": title, "webhook": result}
        print(f"[CreateTicket] SIMULATED: Would create ticket '{title}'")
        return {"status": "simulated", "title": title, "message": f"Would create ticket: {title}"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        return {"status": "rollback_not_applicable", "message": "Ticket creation cannot be rolled back"}


class SendNotification(ResponseAction):
    action_type = "send_notification"

    def validate(self, context: dict) -> bool:
        return bool(context.get("message") or context.get("channel"))

    async def execute(self, context: dict) -> dict:
        channel = context.get("channel", "security")
        message = context.get("message", "ZOVARC alert triggered")
        tenant_id = context.get("tenant_id")
        webhook = _get_webhook(tenant_id, "send_notification") if tenant_id else None
        if webhook:
            result = await _call_webhook(webhook, {"action": "send_notification", "channel": channel, "message": message}, tenant_id)
            return {"status": "executed", "channel": channel, "webhook": result}
        print(f"[SendNotification] SIMULATED: Would notify #{channel}: {message[:100]}")
        return {"status": "simulated", "channel": channel, "message": f"Would notify #{channel}"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        return {"status": "rollback_not_applicable", "message": "Notifications cannot be rolled back"}


class QuarantineFile(ResponseAction):
    action_type = "quarantine_file"

    def validate(self, context: dict) -> bool:
        return bool(context.get("file_hash") or context.get("file_path"))

    async def execute(self, context: dict) -> dict:
        target = context.get("file_hash") or context.get("file_path", "unknown")
        tenant_id = context.get("tenant_id")
        webhook = _get_webhook(tenant_id, "quarantine_file") if tenant_id else None
        if webhook:
            result = await _call_webhook(webhook, {"action": "quarantine_file", "target": target}, tenant_id)
            return {"status": "executed", "target": target, "webhook": result}
        print(f"[QuarantineFile] SIMULATED: Would quarantine file {target}")
        return {"status": "simulated", "target": target, "message": f"Would quarantine {target}"}

    async def rollback(self, context: dict, execution_result: dict) -> dict:
        target = context.get("file_hash") or context.get("file_path", "unknown")
        print(f"[QuarantineFile] ROLLBACK: Would restore file {target}")
        return {"status": "rollback_simulated", "target": target}


# Registry of action types
ACTION_REGISTRY = {
    "block_ip": BlockIP,
    "disable_user": DisableUser,
    "isolate_endpoint": IsolateEndpoint,
    "rotate_credentials": RotateCredentials,
    "create_ticket": CreateTicket,
    "send_notification": SendNotification,
    "quarantine_file": QuarantineFile,
}


def get_action(action_type: str) -> ResponseAction:
    """Get an action instance by type."""
    cls = ACTION_REGISTRY.get(action_type)
    if cls:
        return cls()
    return ResponseAction()
