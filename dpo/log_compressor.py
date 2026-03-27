"""
ZOVARC DPO Log Compressor

Two-stage compression for the DPO training pipeline:
1. compress_alert() — strips noise from SIEM alerts
2. compact_prompt() — builds training-ready prompts under 600 tokens

The compressor runs ONLY at dataset write time.
Kimi API calls always use full uncompressed data.

Token budget:
  Compact system prompt:  ~67 tokens
  Compact invest prompt:  ~100 tokens
  Compressed alert:       ~291 tokens
  Total prompt:           ~454 tokens  (under 600 ceiling)
  Response budget:        ~1594 tokens (at max_seq_length=2048)
"""

import json
import base64
import math
from collections import Counter
from typing import Optional

# Try to use the real tokenizer for exact counts.
# Falls back to char/4 approximation if not installed.
_tokenizer = None


def _get_tokenizer():
    global _tokenizer
    if _tokenizer is None:
        try:
            from transformers import AutoTokenizer
            _tokenizer = AutoTokenizer.from_pretrained(
                "Qwen/Qwen2.5-1.5B-Instruct",
                trust_remote_code=True
            )
        except Exception:
            _tokenizer = "fallback"
    return _tokenizer


def count_tokens(text: str) -> int:
    """Count tokens using the real tokenizer, or estimate at 4 chars/token."""
    tok = _get_tokenizer()
    if tok == "fallback":
        return len(text) // 4
    return len(tok.encode(text))


# ─── ALERT COMPRESSION ───────────────────────────────────────────

# Keys in raw_log that are telemetry noise — not needed for investigation.
STRIP_KEYS = {
    "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel",
    "FileVersion", "Description", "Product", "Company",
    "OriginalFileName", "RuleName", "UtcTime", "CurrentDirectory",
    "AdditionalFields",
}

# Top-level alert keys that are metadata, not evidence.
STRIP_ALERT_KEYS_FOR_TRAINING = {
    "environment", "difficulty", "source_system",
}


def compress_alert(alert: dict, aggressive: bool = False) -> dict:
    """Strip noise from a SIEM alert for DPO training."""
    compressed = {}
    for key, value in alert.items():
        if value is None or value == "" or value == {} or value == []:
            continue
        if aggressive and key in STRIP_ALERT_KEYS_FOR_TRAINING:
            continue
        if key == "raw_log" and isinstance(value, dict):
            compressed_log = {}
            for k, v in value.items():
                if k in STRIP_KEYS:
                    continue
                if v is None or v == "" or v == {} or v == []:
                    continue
                compressed_log[k] = v
            if compressed_log:
                compressed[key] = compressed_log
        else:
            compressed[key] = value
    return compressed


def compress_alert_json(alert: dict, aggressive: bool = False) -> str:
    """Compress alert and return compact JSON string (no indentation)."""
    return json.dumps(compress_alert(alert, aggressive), separators=(",", ":"))


# ─── ENTROPY-AWARE PAYLOAD SUMMARIZATION ─────────────────────────


def calculate_entropy(data: str) -> float:
    """Shannon entropy of a string. High entropy = likely encoded/encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def _try_decode_base64(value: str) -> str | None:
    """Attempt to decode a Base64 string to readable text."""
    cleaned = value.replace("\n", "").replace("\r", "").strip()
    if not all(c in _BASE64_CHARS for c in cleaned):
        return None
    if len(cleaned) < 20:
        return None
    try:
        decoded_bytes = base64.b64decode(cleaned)
        # Try UTF-16LE first (PowerShell -EncodedCommand uses this)
        try:
            text = decoded_bytes.decode("utf-16-le")
            if all(c.isprintable() or c in "\n\r\t" for c in text):
                return text
        except (UnicodeDecodeError, ValueError):
            pass
        # Try UTF-8
        try:
            text = decoded_bytes.decode("utf-8")
            if all(c.isprintable() or c in "\n\r\t" for c in text):
                return text
        except (UnicodeDecodeError, ValueError):
            pass
        return None
    except Exception:
        return None


def _try_decode_hex(value: str) -> str | None:
    """Attempt to decode hex-encoded data."""
    cleaned = value.strip()
    if not all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return None
    if len(cleaned) < 20 or len(cleaned) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(cleaned)
        text = decoded.decode("utf-8", errors="strict")
        if text.isprintable():
            return text
    except Exception:
        pass
    return None


def summarize_payload(value: str, max_chars: int = 150) -> str:
    """
    Intelligently summarize a long payload for DPO training.

    Priority order:
    1. If Base64: decode it — decoded form is shorter AND more informative
    2. If Hex: decode it
    3. If command line: keep command + flags, trim long arguments
    4. If high-entropy blob: replace with entropy descriptor
    5. Default: keep head + tail (never blind middle-truncate)
    """
    if len(value) <= max_chars:
        return value

    # 1. Try Base64 decode
    decoded = _try_decode_base64(value)
    if decoded:
        if len(decoded) <= max_chars - 6:
            return f"[B64→{decoded}]"
        else:
            return f"[B64→{decoded[:max_chars - 12]}...]"

    # 2. Try Hex decode
    decoded = _try_decode_hex(value)
    if decoded:
        if len(decoded) <= max_chars - 6:
            return f"[HEX→{decoded}]"
        else:
            return f"[HEX→{decoded[:max_chars - 12]}...]"

    # 3. Command line — keep command + flags, trim args
    if " " in value and any(
        marker in value.lower()
        for marker in [".exe", "powershell", "cmd.exe", "/bin/", "python"]
    ):
        parts = value.split()
        result = []
        char_count = 0
        for part in parts:
            if char_count + len(part) + 1 > max_chars - 20:
                result.append(f"...+{len(parts) - len(result)} args")
                break
            result.append(part)
            char_count += len(part) + 1
        return " ".join(result)

    # 4. High-entropy blob — describe, don't reproduce
    entropy = calculate_entropy(value)
    if entropy > 5.0:
        return f"[BLOB:len={len(value)},entropy={entropy:.1f},head={value[:40]}]"

    # 5. Default: keep head + tail
    half = (max_chars - 5) // 2
    return f"{value[:half]}...{value[-half:]}"


# ─── PROMPT COMPACTION ────────────────────────────────────────────


def _assemble_prompt(system: str, template: str, alert_json: str) -> str:
    """Assemble the ChatML-formatted prompt."""
    return (
        f"<|im_start|>system\n{system}<|im_end|>\n"
        f"<|im_start|>user\n"
        f"{template.format(alert_json=alert_json)}"
        f"<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )


def compact_prompt(
    alert: dict,
    system_prompt: str,
    investigation_prompt_template: str,
    max_prompt_tokens: int = 600,
) -> str:
    """
    Build a training-ready prompt that fits under the token budget.

    Three stages, progressively more aggressive:
    1. Strip null/empty fields + telemetry noise from raw_log
    2. Also strip top-level metadata (environment, difficulty, source_system)
    3. Entropy-aware payload summarization (decode Base64, trim commands, describe blobs)
    """
    # Stage 1: Normal compression
    compressed_json = compress_alert_json(alert, aggressive=False)
    prompt = _assemble_prompt(system_prompt, investigation_prompt_template, compressed_json)

    tokens = count_tokens(prompt)
    if tokens <= max_prompt_tokens:
        return prompt

    # Stage 2: Aggressive compression (strip metadata)
    compressed_json = compress_alert_json(alert, aggressive=True)
    prompt = _assemble_prompt(system_prompt, investigation_prompt_template, compressed_json)

    tokens = count_tokens(prompt)
    if tokens <= max_prompt_tokens:
        return prompt

    # Stage 3: Entropy-aware payload summarization
    compressed = compress_alert(alert, aggressive=True)
    if "raw_log" in compressed:
        raw_log = compressed["raw_log"]
        for key, value in list(raw_log.items()):
            if isinstance(value, str) and len(value) > 120:
                raw_log[key] = summarize_payload(value, max_chars=150)

    compressed_json = json.dumps(compressed, separators=(",", ":"))
    prompt = _assemble_prompt(system_prompt, investigation_prompt_template, compressed_json)

    tokens = count_tokens(prompt)
    if tokens <= max_prompt_tokens:
        return prompt

    raise ValueError(
        f"Cannot compress prompt to {max_prompt_tokens} tokens. "
        f"Current: {tokens} tokens after entropy-aware compression. "
        f"This alert has unusually large payloads. Skipping."
    )


# ─── DATASET PAIR BUILDER ────────────────────────────────────────


def build_training_pair(
    alert: dict,
    chosen_reasoning: str,
    chosen_code: str,
    rejected_reasoning: str,
    rejected_code: str,
    compact_system: str,
    compact_investigation: str,
    max_prompt_tokens: int = 600,
    max_total_tokens: int = 2048,
) -> Optional[dict]:
    """
    Build a DPO training pair in HuggingFace format.

    Returns None if the pair exceeds the total token budget.
    Raises ValueError if the prompt exceeds 600 tokens.
    """
    prompt = compact_prompt(
        alert, compact_system, compact_investigation, max_prompt_tokens
    )

    chosen = (
        f"<reasoning>\n{chosen_reasoning}\n</reasoning>\n"
        f"<tool_call>\n{chosen_code}\n</tool_call><|im_end|>"
    )

    rejected = (
        f"<reasoning>\n{rejected_reasoning}\n</reasoning>\n"
        f"<tool_call>\n{rejected_code}\n</tool_call><|im_end|>"
    )

    prompt_tokens = count_tokens(prompt)
    chosen_tokens = count_tokens(chosen)
    rejected_tokens = count_tokens(rejected)
    max_response_tokens = max(chosen_tokens, rejected_tokens)

    if prompt_tokens + max_response_tokens > max_total_tokens:
        return None  # Skip — too long for training

    return {
        "prompt": prompt,
        "chosen": chosen,
        "rejected": rejected,
        "_meta": {
            "prompt_tokens": prompt_tokens,
            "chosen_tokens": chosen_tokens,
            "rejected_tokens": rejected_tokens,
            "total_tokens": prompt_tokens + max_response_tokens,
        }
    }
