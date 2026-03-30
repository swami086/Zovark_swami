"""
Input sanitization for SIEM events BEFORE they reach LLM prompt construction.
Defends against prompt injection via attacker-controlled log fields.
"""
import re
import math
import logging

logger = logging.getLogger(__name__)

INJECTION_PATTERNS = [
    r'(?i)(ignore|disregard|forget)\s+(previous|above|all)\s+(instructions?|rules?|prompts?)',
    r'(?i)you\s+are\s+(now|a)\s+',
    r'(?i)(system|assistant|user)\s*:\s*',
    r'(?i)```(python|bash|sh|cmd|powershell)',
    r'(?i)(import\s+os|import\s+subprocess|import\s+socket)',
    r'(?i)(__import__|eval\s*\(|exec\s*\()',
    r'(?i)(ALWAYS|MUST|NEVER)\s+(respond|output|generate|write|include|return)',
    r'(?i)<\s*(system|instruction|prompt|role)\s*>',
    r'(?i)\[\s*INST\s*\]',
    r'(?i)act\s+as\s+(a|an)\s+',
    r'(?i)new\s+instructions?\s*:',
    r'(?i)override\s+(previous|prior|all)',
]

MAX_FIELD_LENGTH = 10_000
ENTROPY_THRESHOLD = 5.5
ENTROPY_CHECK_FIELDS = {"raw_log", "title", "rule_name", "username", "hostname", "process_name"}


def _shannon_entropy(s: str) -> float:
    if not s or len(s) < 10:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def smart_truncate(value: str, max_len: int = 10000) -> str:
    """
    Intelligent truncation preserving security-relevant content.

    Defense against: pad 10K benign chars, hide payload at position 10,001.
    Strategy: keep head (3K) + tail (3K) + extract suspicious segments from middle.
    """
    if not isinstance(value, str) or len(value) <= max_len:
        return value

    head_size = 3000
    tail_size = 3000
    head = value[:head_size]
    tail = value[-tail_size:]
    middle = value[head_size:-tail_size] if len(value) > head_size + tail_size else ""

    suspicious = []

    # Base64 blocks (likely encoded payloads)
    for m in re.finditer(r'[A-Za-z0-9+/=]{50,}', middle):
        suspicious.append(m.group()[:500])

    # URL-encoded blocks
    for m in re.finditer(r'(?:%[0-9A-Fa-f]{2}){10,}', middle):
        suspicious.append(m.group()[:500])

    # Code injection patterns
    for m in re.finditer(
        r'(?:eval|exec|import|system|subprocess|__import__|compile|os\.system|'
        r'os\.popen|socket|requests|urllib|open\s*\(|pickle|ctypes)\s*[\(\.]',
        middle, re.IGNORECASE
    ):
        start = max(0, m.start() - 100)
        end = min(len(middle), m.end() + 200)
        suspicious.append(middle[start:end])

    # Prompt injection patterns
    for m in re.finditer(
        r'(?:ignore previous|new instructions|override|disregard|system:|'
        r'ALWAYS output|act as|forget all|you are now)',
        middle, re.IGNORECASE
    ):
        start = max(0, m.start() - 50)
        end = min(len(middle), m.end() + 150)
        suspicious.append(middle[start:end])

    # High-entropy windows (Shannon > 4.5 in 200-char windows)
    window = 200
    for i in range(0, min(len(middle), 5000), window):
        chunk = middle[i:i + window]
        if len(chunk) > 50:
            entropy = _shannon_entropy(chunk)
            if entropy > 4.5:
                suspicious.append(chunk)

    if suspicious:
        mid_content = " [EXTRACTED] ".join(suspicious[:5])
    else:
        mid_content = "[...TRUNCATED...]"

    result = head + " " + mid_content + " " + tail
    if len(result) > max_len:
        result = result[:max_len]

    return result


def sanitize_siem_event(event: dict) -> dict:
    if not isinstance(event, dict):
        return event

    sanitized = {}
    injection_detected = False
    high_entropy_fields = []

    for key, value in event.items():
        if isinstance(value, str):
            # Check injection patterns on FULL string BEFORE truncation
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, value):
                    injection_detected = True
                    value = re.sub(pattern, '[INJECTION_STRIPPED]', value)
                    logger.warning(f"Prompt injection pattern stripped from field: {key}")

            # Smart truncate AFTER injection checks
            if len(value) > MAX_FIELD_LENGTH:
                value = smart_truncate(value, MAX_FIELD_LENGTH)
                logger.warning(f"Smart-truncated oversized SIEM field: {key}")

            canonical_key = key.split(".")[-1].lower()
            if canonical_key in ENTROPY_CHECK_FIELDS and len(value) > 50:
                entropy = _shannon_entropy(value)
                if entropy > ENTROPY_THRESHOLD:
                    high_entropy_fields.append({"field": key, "entropy": round(entropy, 2)})

            sanitized[key] = value
        elif isinstance(value, dict):
            sanitized[key] = sanitize_siem_event(value)
        else:
            sanitized[key] = value

    if injection_detected:
        sanitized["_injection_warning"] = True
    if high_entropy_fields:
        sanitized["_high_entropy_fields"] = high_entropy_fields
        logger.info(f"High entropy fields detected: {high_entropy_fields}")

    return sanitized
