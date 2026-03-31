"""
Singleton LLM client with concurrency control.

Provides a shared httpx.AsyncClient and asyncio.Semaphore(2)
to limit concurrent LLM requests to Ollama.

Why semaphore(2): Temporal fires up to 8 concurrent activities.
Without limiting, 8 simultaneous LLM calls queue in Ollama and waste
connections. With semaphore(2): 1 processing + 1 queued, other
activities run deterministic tools without blocking.

Path A investigations (no LLM) bypass this entirely.
"""
import asyncio
import time
import logging

import httpx

logger = logging.getLogger(__name__)

try:
    from settings import settings as _settings
    _BASE_URL = _settings.llm_base_url
except ImportError:
    import os
    _BASE_URL = os.environ.get("ZOVARK_LLM_BASE_URL", "http://host.docker.internal:11434")

_client: httpx.AsyncClient | None = None
_semaphore = asyncio.Semaphore(2)


def get_client() -> httpx.AsyncClient:
    """Get or create the singleton httpx.AsyncClient."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=_BASE_URL,
            timeout=httpx.Timeout(
                connect=5.0,
                read=120.0,   # 8B model can take 60s+
                write=5.0,
                pool=10.0,
            ),
        )
    return _client


async def llm_request(
    model: str,
    messages: list[dict],
    temperature: float = 0.1,
    max_tokens: int = 4096,
    stage: str = "unknown",
    response_format: dict | None = None,
) -> dict:
    """Make an LLM request through the semaphore-controlled singleton client.

    Returns the raw response JSON from Ollama's /v1/chat/completions endpoint.
    Raises on timeout or HTTP error (Temporal handles retries at activity level).
    """
    async with _semaphore:
        client = get_client()
        start = time.perf_counter()
        body = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "keep_alive": "30m",
        }
        if response_format:
            body["response_format"] = response_format

        # OTEL span
        _span = None
        try:
            from tracing import get_tracer
            _span = get_tracer().start_span("llm.call")
            _span.set_attribute("llm.model", model)
            _span.set_attribute("llm.stage", stage)
        except Exception:
            pass

        try:
            response = await client.post("/v1/chat/completions", json=body)
            response.raise_for_status()
            duration = round(time.perf_counter() - start, 2)

            result = response.json()
            usage = result.get("usage", {})
            tokens_in = usage.get("prompt_tokens", 0)
            tokens_out = usage.get("completion_tokens", 0)

            logger.info(f"LLM {model} [{stage}] {duration}s tokens={tokens_in}/{tokens_out}")

            if _span:
                try:
                    _span.set_attribute("llm.tokens_in", tokens_in)
                    _span.set_attribute("llm.tokens_out", tokens_out)
                    _span.set_attribute("llm.latency_ms", int(duration * 1000))
                    _span.set_attribute("llm.success", True)
                    _span.end()
                except Exception:
                    pass

            return result

        except httpx.TimeoutException as e:
            duration = round(time.perf_counter() - start, 2)
            logger.error(f"LLM {model} [{stage}] timed out after {duration}s")
            if _span:
                try:
                    _span.set_attribute("llm.success", False)
                    _span.record_exception(e)
                    _span.end()
                except Exception:
                    pass
            raise

        except httpx.HTTPStatusError as e:
            logger.error(f"LLM {model} [{stage}] returned {e.response.status_code}")
            if _span:
                try:
                    _span.set_attribute("llm.success", False)
                    _span.record_exception(e)
                    _span.end()
                except Exception:
                    pass
            raise


async def close_client():
    """Close the singleton client (call on shutdown)."""
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()
        _client = None
