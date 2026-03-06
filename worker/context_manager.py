"""Context manager — model-aware truncation for LLM inputs.

Implements head/tail truncation that preserves the start and end of
content, which are typically the most important parts.

No Pydantic — plain dicts only.
"""

from model_config import get_max_tokens_for_activity

# Rough estimate: 1 token ≈ 4 chars for English text
CHARS_PER_TOKEN = 4

# Reserve tokens for system prompt + response
SYSTEM_PROMPT_RESERVE = 300
RESPONSE_RESERVE = 200


def estimate_tokens(text: str) -> int:
    """Rough token count estimate (chars / 4)."""
    return len(text) // CHARS_PER_TOKEN


def truncate_for_model(text: str, activity_name: str, max_input_chars: int = None) -> str:
    """Truncate text to fit model context window.

    Uses head/tail strategy: keeps first 70% and last 30% of allowed chars.

    Args:
        text: Input text to truncate
        activity_name: Activity name for tier-based max_tokens lookup
        max_input_chars: Override max chars (default: computed from model config)

    Returns:
        Truncated text
    """
    if max_input_chars is None:
        max_tokens = get_max_tokens_for_activity(activity_name)
        # Input budget = max_tokens * 3 (typical context:output ratio) minus reserves
        available_tokens = (max_tokens * 3) - SYSTEM_PROMPT_RESERVE - RESPONSE_RESERVE
        max_input_chars = max(available_tokens * CHARS_PER_TOKEN, 1000)

    if len(text) <= max_input_chars:
        return text

    # Head/tail split: 70% head, 30% tail
    head_chars = int(max_input_chars * 0.7)
    tail_chars = max_input_chars - head_chars - 30  # 30 chars for separator

    head = text[:head_chars]
    tail = text[-tail_chars:] if tail_chars > 0 else ""

    return f"{head}\n... [truncated {len(text) - max_input_chars} chars] ...\n{tail}"


def truncate_log_data(log_data: str, max_chars: int = 50000) -> str:
    """Truncate log data with head/tail preservation.

    Special case for file uploads — larger budget than normal prompts.
    """
    if len(log_data) <= max_chars:
        return log_data

    head_chars = int(max_chars * 0.7)
    tail_chars = max_chars - head_chars - 30

    head = log_data[:head_chars]
    tail = log_data[-tail_chars:] if tail_chars > 0 else ""

    return f"{head}\n... [truncated {len(log_data) - max_chars} chars] ...\n{tail}"
