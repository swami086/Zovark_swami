"""
LLM Audit Gateway — all LLM calls go through here.
Logs metadata (not prompts/responses) for audit and cost tracking.
"""
import os
import time
import hashlib
import uuid
from typing import Optional

import httpx

LITELLM_URL = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
LITELLM_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")


async def llm_call(
    prompt: str,
    system_prompt: str,
    model_config: dict,
    task_id: str,
    stage: str,
    task_type: str,
    tenant_id: str = "",
    timeout: float = 900.0,
    response_format: Optional[dict] = None,
    prompt_name: str = "",
) -> dict:
    """
    Makes LLM call and logs audit metadata including prompt version.
    Returns: {"content": str, "tokens_in": int, "tokens_out": int, "latency_ms": int, "model": str, "prompt_version": str}
    """
    endpoint = model_config.get("endpoint", LITELLM_URL)
    api_key = model_config.get("api_key", LITELLM_KEY)
    model_name = model_config.get("model", model_config.get("name", "unknown"))

    request_body = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": model_config.get("temperature", 0.1),
        "max_tokens": model_config.get("max_tokens", 4096),
    }
    if response_format:
        request_body["response_format"] = response_format

    prompt_hash = hashlib.sha256(prompt.encode("utf-8", errors="replace")).hexdigest()[:32]
    # Compute prompt version: SHA256 of system_prompt + user_prompt for tracking prompt drift
    combined_prompt = f"{system_prompt}\n---\n{prompt}"
    prompt_version = hashlib.sha256(combined_prompt.encode("utf-8", errors="replace")).hexdigest()[:12]

    t0 = time.time()
    status = "success"
    error_message = None
    tokens_in = 0
    tokens_out = 0
    content = ""

    try:
        # Use explicit timeout config matching original httpx usage
        timeout_config = httpx.Timeout(timeout, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            resp = await client.post(
                endpoint,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=request_body,
            )
            resp.raise_for_status()
            result = resp.json()

        usage = result.get("usage", {})
        tokens_in = usage.get("prompt_tokens", 0)
        tokens_out = usage.get("completion_tokens", 0)
        content = result["choices"][0]["message"]["content"].strip()
    except httpx.TimeoutException as e:
        status = "error"
        error_message = f"LLM timeout after {int(time.time() - t0)}s (limit={timeout}s) endpoint={endpoint}"
        raise RuntimeError(error_message) from e
    except Exception as e:
        status = "error"
        error_message = f"{type(e).__name__}: {e}"[:500]
        raise
    finally:
        latency_ms = int((time.time() - t0) * 1000)
        # Log audit record (best-effort, never block on failure)
        try:
            _log_audit(
                task_id=task_id,
                tenant_id=tenant_id,
                stage=stage,
                task_type=task_type,
                model_name=model_name,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=latency_ms,
                prompt_hash=prompt_hash,
                prompt_version=prompt_version,
                status=status,
                error_message=error_message,
            )
        except Exception:
            pass  # Audit logging must never break the pipeline

    return {
        "content": content,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "latency_ms": latency_ms,
        "model": model_name,
        "prompt_version": prompt_version,
    }


def _log_audit(
    task_id: str,
    tenant_id: str,
    stage: str,
    task_type: str,
    model_name: str,
    tokens_in: int,
    tokens_out: int,
    latency_ms: int,
    prompt_hash: str,
    status: str,
    error_message: Optional[str],
    prompt_version: str = "",
):
    """Insert audit record into llm_audit_log. Best-effort."""
    import psycopg2
    try:
        conn = psycopg2.connect(DATABASE_URL)
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO llm_audit_log
                       (id, task_id, tenant_id, stage, task_type, model_name,
                        tokens_in, tokens_out, latency_ms, prompt_hash, prompt_version,
                        status, error_message)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        str(uuid.uuid4()),
                        task_id or None,
                        tenant_id or None,
                        stage,
                        task_type,
                        model_name,
                        tokens_in,
                        tokens_out,
                        latency_ms,
                        prompt_hash,
                        prompt_version,
                        status,
                        error_message,
                    ),
                )
        conn.close()
    except Exception:
        pass  # Table may not exist yet — never block pipeline
