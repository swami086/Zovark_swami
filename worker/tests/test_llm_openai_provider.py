"""OpenAI provider branch in llm_client (no network)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def test_openai_llm_request_omits_llama_fields():
    import llm_client

    llm_client._client = None

    async def _run():
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
            )

        call = mock_client.post.call_args
        assert call[0][0] == "https://api.openai.com/v1/chat/completions"
        body = call[1]["json"]
        assert "grammar" not in body
        assert "keep_alive" not in body
        assert "top_k" not in body
        assert body.get("response_format") == {"type": "json_object"}
        assert call[1]["headers"]["Authorization"] == "Bearer sk-test"

    asyncio.run(_run())
