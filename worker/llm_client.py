"""
Singleton LLM client with dual-role concurrency control.

Provides a shared httpx.AsyncClient and split semaphores for FAST and CODE roles:
  - _fast_semaphore(1): tool selection (FAST model, short requests)
  - _code_semaphore(1): assessment (CODE model, longer reasoning)

On dev tier (single container, --parallel 2): prevents GPU contention.
On customer tier (dual containers): each semaphore maps to a different GPU.

Path A investigations (no LLM) bypass this entirely.
"""
import asyncio
import os
import re
import time
import logging

import httpx

logger = logging.getLogger(__name__)

try:
    from settings import settings as _settings
    _BASE_URL = _settings.llm_base_url
except ImportError:
    _BASE_URL = os.environ.get("ZOVARK_LLM_BASE_URL", "http://zovark-inference:8080")

_client: httpx.AsyncClient | None = None
_fast_semaphore = asyncio.Semaphore(1)  # FAST role: tool selection, param fill
_code_semaphore = asyncio.Semaphore(1)  # CODE role: assessment, summary

# Per-role sampling configs (Agent 4)
SAMPLING_CONFIGS = {
    "param_fill":  {"temperature": 0.0, "top_p": 1.0, "top_k": 1},
    "tool_select": {"temperature": 0.1, "top_p": 0.9, "top_k": 40},
    "verdict":     {"temperature": 0.1, "top_p": 0.9, "top_k": 40},
    "summary":     {"temperature": 0.3, "top_p": 0.95, "top_k": 50},
}

# Grammar cache (Agent 3)
_GRAMMAR_DIR = os.path.join(os.path.dirname(__file__), "grammars")
_grammar_cache: dict[str, str | None] = {}


def _load_grammar(name: str) -> str | None:
    """Load a GBNF grammar file. Returns None if not found."""
    if name not in _grammar_cache:
        path = os.path.join(_GRAMMAR_DIR, f"{name}.gbnf")
        try:
            with open(path) as f:
                _grammar_cache[name] = f.read()
        except FileNotFoundError:
            _grammar_cache[name] = None
    return _grammar_cache[name]


# --- LLM output sanitizer (model-agnostic, defense in depth) ---
# Strips control tokens that may leak into grammar-constrained output.
# Covers Gemma 4 thinking blocks, tool call corruption (llama.cpp #21316),
# and turn markers. No-op on models that don't emit these tokens.
_CONTROL_TOKEN_RE = re.compile(
    r'<\|channel>.*?<channel\|>'   # Gemma 4 thinking blocks
    r'|<\|think\|>'                # thinking trigger token
    r'|\[<\|"\|>\]'               # tool call corruption (issue #21316)
    r'|<\|turn\|>'                 # turn markers that leak
    r'|<\|"\|>',                   # quote token corruption
    re.DOTALL
)


def _sanitize_llm_output(text: str) -> str:
    """Strip control tokens that may leak into grammar-constrained output."""
    cleaned = _CONTROL_TOKEN_RE.sub('', text).strip()
    if cleaned != text:
        logger.warning(
            "LLM output contained control tokens — sanitized",
            extra={"original_len": len(text), "cleaned_len": len(cleaned)},
        )
    return cleaned


def get_client() -> httpx.AsyncClient:
    """Get or create the singleton httpx.AsyncClient."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=_BASE_URL,
            timeout=httpx.Timeout(
                connect=5.0,
                read=120.0,
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
    role: str = "tool_select",
    grammar_name: str | None = None,
) -> dict:
    """Make an LLM request through semaphore-controlled singleton client.

    Args:
        role: LLM role — "param_fill", "tool_select", "verdict", "summary".
              Controls which semaphore (fast vs code) and sampling config.
        grammar_name: GBNF grammar file name (without .gbnf). None = no grammar.

    Returns the raw response JSON from the /v1/chat/completions endpoint.
    """
    # Select semaphore based on role
    is_code_role = role in ("verdict", "summary")
    sem = _code_semaphore if is_code_role else _fast_semaphore

    # Merge role-based sampling config
    sampling = SAMPLING_CONFIGS.get(role, SAMPLING_CONFIGS["tool_select"])

    async with sem:
        client = get_client()
        start = time.perf_counter()
        body = {
            "model": model,
            "messages": messages,
            "temperature": temperature if temperature != 0.1 else sampling["temperature"],
            "max_tokens": max_tokens,
            "keep_alive": "30m",
        }
        if sampling.get("top_k"):
            body["top_k"] = sampling["top_k"]
        if response_format:
            body["response_format"] = response_format

        # Grammar-constrained decoding (Agent 3)
        if grammar_name:
            grammar_text = _load_grammar(grammar_name)
            if grammar_text:
                body["grammar"] = grammar_text
                # Remove response_format when using grammar — they conflict
                body.pop("response_format", None)

        # OTEL span
        _span = None
        try:
            from tracing import get_tracer
            _span = get_tracer().start_span("llm.call")
            _span.set_attribute("llm.model", model)
            _span.set_attribute("llm.stage", stage)
            _span.set_attribute("llm.role", role)
            _span.set_attribute("llm.grammar_used", grammar_name is not None)
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

            # Sanitize control tokens before they reach JSON parsing / Pydantic
            raw_content = result["choices"][0]["message"]["content"]
            sanitized = _sanitize_llm_output(raw_content)
            result["choices"][0]["message"]["content"] = sanitized

            logger.info(f"LLM {model} [{stage}/{role}] {duration}s tokens={tokens_in}/{tokens_out}")

            if _span:
                try:
                    _span.set_attribute("llm.tokens_in", tokens_in)
                    _span.set_attribute("llm.tokens_out", tokens_out)
                    _span.set_attribute("llm.e2e_ms", int(duration * 1000))
                    _span.set_attribute("llm.success", True)
                    _span.end()
                except Exception:
                    pass

            return result

        except httpx.TimeoutException as e:
            duration = round(time.perf_counter() - start, 2)
            logger.error(f"LLM {model} [{stage}/{role}] timed out after {duration}s")
            if _span:
                try:
                    _span.set_attribute("llm.success", False)
                    _span.set_attribute("llm.e2e_ms", int(duration * 1000))
                    _span.record_exception(e)
                    _span.end()
                except Exception:
                    pass
            raise

        except httpx.HTTPStatusError as e:
            logger.error(f"LLM {model} [{stage}/{role}] returned {e.response.status_code}")
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
