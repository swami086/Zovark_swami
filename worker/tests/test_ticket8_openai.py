"""Ticket 8 — gated OpenAI validation (real API when OPENAI_API_KEY is set)."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

pytestmark = pytest.mark.openai


def _require_openai_key():
    if not os.environ.get("OPENAI_API_KEY", "").strip():
        pytest.skip("OPENAI_API_KEY is unset")


def test_openai_models_connectivity():
    _require_openai_key()
    key = os.environ["OPENAI_API_KEY"].strip()
    with httpx.Client(timeout=60.0) as client:
        r = client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
        )
    assert r.status_code == 200
    body = r.json()
    ids = [m.get("id", "") for m in body.get("data", [])]
    assert any("gpt-4o-mini" in i for i in ids), "expected gpt-4o-mini in model list"


def test_llm_request_chat_returns_gpt4o_mini():
    _require_openai_key()

    async def _call():
        from llm_client import chat_endpoint_for_model, llm_request, resolve_llm_api_key

        return await llm_request(
            "gpt-4o-mini",
            [
                {"role": "system", "content": "Reply with exactly: OK"},
                {"role": "user", "content": "ping"},
            ],
            temperature=0.0,
            max_tokens=8,
            stage="ticket8_test",
            role="tool_select",
            endpoint_url=chat_endpoint_for_model("gpt-4o-mini"),
            api_key=resolve_llm_api_key(None),
        )

    result = asyncio.run(_call())
    assert "choices" in result
    text = result["choices"][0]["message"]["content"].strip().upper()
    assert "OK" in text or len(text) > 0
    usage = result.get("usage", {})
    assert usage.get("prompt_tokens", 0) > 0


def test_llm_request_verdict_role():
    _require_openai_key()

    async def _call():
        from llm_client import chat_endpoint_for_model, llm_request, resolve_llm_api_key

        return await llm_request(
            "gpt-4o-mini",
            [
                {"role": "system", "content": 'You output only valid JSON: {"x":1}'},
                {"role": "user", "content": "go"},
            ],
            temperature=0.1,
            max_tokens=32,
            stage="ticket8_test",
            role="verdict",
            response_format={"type": "json_object"},
            endpoint_url=chat_endpoint_for_model("gpt-4o-mini"),
            api_key=resolve_llm_api_key(None),
        )

    result = asyncio.run(_call())
    raw = result["choices"][0]["message"]["content"]
    assert "{" in raw


def test_context_budget_truncation_still_returns():
    _require_openai_key()

    async def _call():
        from llm_client import chat_endpoint_for_model, llm_request, resolve_llm_api_key

        huge = "LINE\n" * 8000
        return await llm_request(
            "gpt-4o-mini",
            [
                {"role": "system", "content": "Reply with: OK"},
                {"role": "user", "content": huge},
            ],
            temperature=0.0,
            max_tokens=4,
            stage="ticket8_budget",
            role="tool_select",
            endpoint_url=chat_endpoint_for_model("gpt-4o-mini"),
            api_key=resolve_llm_api_key(None),
        )

    result = asyncio.run(_call())
    assert result.get("choices")


def test_openai_payload_excludes_llama_extensions():
    """No API key required — asserts OpenAI branch omits grammar/keep_alive/top_k."""
    import llm_client

    llm_client._client = None
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = lambda: None
    mock_resp.json = lambda: {
        "choices": [{"message": {"content": "{}"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.is_closed = False

    async def _run():
        with patch.object(llm_client, "_llm_provider", return_value="openai"), patch.object(
            llm_client, "get_client", return_value=mock_client
        ):
            await llm_client.llm_request(
                "gpt-4o-mini",
                [{"role": "user", "content": "x"}],
                endpoint_url="https://api.openai.com/v1/chat/completions",
                api_key="sk-test",
                grammar_name="tool_selection",
                response_format={"type": "json_object"},
                role="tool_select",
            )

    asyncio.run(_run())
    body = mock_client.post.call_args[1]["json"]
    for forbidden in ("grammar", "keep_alive", "top_k"):
        assert forbidden not in body, f"OpenAI payload must not include {forbidden}"
    assert body.get("model") == "gpt-4o-mini"
