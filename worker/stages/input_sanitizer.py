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


def sanitize_siem_event(event: dict) -> dict:
    if not isinstance(event, dict):
        return event

    sanitized = {}
    injection_detected = False
    high_entropy_fields = []

    for key, value in event.items():
        if isinstance(value, str):
            if len(value) > MAX_FIELD_LENGTH:
                value = value[:MAX_FIELD_LENGTH] + " [TRUNCATED]"
                logger.warning(f"Truncated oversized SIEM field: {key} ({len(value)} chars)")

            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, value):
                    injection_detected = True
                    value = re.sub(pattern, '[INJECTION_STRIPPED]', value)
                    logger.warning(f"Prompt injection pattern stripped from field: {key}")

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
