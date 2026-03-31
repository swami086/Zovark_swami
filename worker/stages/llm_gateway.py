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

ZOVARK_LLM_ENDPOINT = os.environ.get("ZOVARK_LLM_ENDPOINT", "http://host.docker.internal:11434/v1/chat/completions")
try:
    from settings import settings as _settings
    ZOVARK_LLM_KEY = os.environ.get("ZOVARK_LLM_KEY", _settings.llm_key)
    DATABASE_URL = os.environ.get("DATABASE_URL", _settings.database_url)
except ImportError:
    ZOVARK_LLM_KEY = os.environ.get("ZOVARK_LLM_KEY", "sk-zovark-dev-2026")
    DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:hydra_dev_2026@pgbouncer:5432/zovark")

# Two-model routing: American models only (Meta Llama)
# FAST: small model for simple param extraction (Path B)
# CODE: larger model for code generation (Path C) + IOC extraction (Assess)
MODEL_FAST = os.environ.get("ZOVARK_MODEL_FAST", "llama3.2:3b")
MODEL_CODE = os.environ.get("ZOVARK_MODEL_CODE", "llama3.1:8b")

# Dual-endpoint support: route FAST and CODE models to separate Ollama instances
_DEFAULT_ENDPOINT = os.environ.get("ZOVARK_LLM_ENDPOINT",
    "http://host.docker.internal:11434/v1/chat/completions")
ENDPOINT_FAST = os.environ.get("ZOVARK_LLM_ENDPOINT_FAST", _DEFAULT_ENDPOINT)
ENDPOINT_CODE = os.environ.get("ZOVARK_LLM_ENDPOINT_CODE", _DEFAULT_ENDPOINT)


def _get_endpoint_for_model(model: str) -> str:
    """Route model to the correct Ollama instance endpoint."""
    if model == MODEL_FAST:
        return ENDPOINT_FAST
    return ENDPOINT_CODE


def get_model_for_task(stage: str, path: str = "") -> str:
    """Route to appropriate model based on pipeline stage and code path."""
    if stage == "analyze":
        if path in ("C", "path_c", "llm", "llm_gen", "full_llm"):
            return MODEL_CODE
        else:
            return MODEL_FAST
    elif stage == "assess":
        return MODEL_CODE
    else:
        return MODEL_CODE


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
    model_name = model_config.get("model", model_config.get("name", "unknown"))
    endpoint = model_config.get("endpoint") or _get_endpoint_for_model(model_name)
    api_key = model_config.get("api_key", ZOVARK_LLM_KEY)

    request_body = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": model_config.get("temperature", 0.1),
        "max_tokens": model_config.get("max_tokens", 4096),
        "keep_alive": "30m",  # Keep model in VRAM between requests
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

    # Start OTEL span for LLM call
    try:
        from tracing import get_tracer
        _llm_span = get_tracer().start_span("llm.call")
        _llm_span.set_attribute("llm.model", model_name)
        _llm_span.set_attribute("llm.stage", stage)
        _llm_span.set_attribute("llm.task_type", task_type)
        _llm_span.set_attribute("llm.endpoint", endpoint)
    except Exception:
        _llm_span = None

    try:
        # Use explicit timeout config matching original httpx usage
        timeout_config = httpx.Timeout(timeout, connect=10.0)
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            resp = await client.post(
                endpoint,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "X-Zovark-Trace-ID": task_id or "",
                },
                json=request_body,
            )
            resp.raise_for_status()
            result = resp.json()

        usage = result.get("usage", {})
        tokens_in = usage.get("prompt_tokens", 0)
        tokens_out = usage.get("completion_tokens", 0)
        content = result["choices"][0]["message"]["content"].strip()

        if _llm_span:
            try:
                _llm_span.set_attribute("llm.tokens_in", tokens_in)
                _llm_span.set_attribute("llm.tokens_out", tokens_out)
                _llm_span.set_attribute("llm.latency_ms", int((time.time() - t0) * 1000))
                _llm_span.set_attribute("llm.success", True)
                _llm_span.end()
            except Exception:
                pass

    except httpx.TimeoutException as e:
        status = "error"
        error_message = f"LLM timeout after {int(time.time() - t0)}s (limit={timeout}s) endpoint={endpoint}"
        if _llm_span:
            try:
                _llm_span.set_attribute("llm.success", False)
                _llm_span.record_exception(e)
                _llm_span.end()
            except Exception:
                pass
        raise RuntimeError(error_message) from e
    except Exception as e:
        status = "error"
        error_message = f"{type(e).__name__}: {e}"[:500]
        if _llm_span:
            try:
                _llm_span.set_attribute("llm.success", False)
                _llm_span.record_exception(e)
                _llm_span.end()
            except Exception:
                pass
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


def preload_ollama_model():
    """Pre-load CODE and FAST models into VRAM on their respective Ollama instances with 30m keep_alive."""
    import logging
    logger = logging.getLogger(__name__)
    for model, ep in [(MODEL_CODE, ENDPOINT_CODE), (MODEL_FAST, ENDPOINT_FAST)]:
        ollama_url = ep.replace("/v1/chat/completions", "").replace("/v1/models", "")
        try:
            import httpx
            resp = httpx.post(f"{ollama_url}/api/generate", json={
                "model": model, "prompt": "ok", "keep_alive": "30m", "stream": False,
            }, timeout=60.0)
            logger.info(f"Pre-loaded {model} on {ollama_url} (status={resp.status_code})")
        except Exception as e:
            logger.warning(f"Failed to pre-load {model} on {ollama_url}: {e}")
