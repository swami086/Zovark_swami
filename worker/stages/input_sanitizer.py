"""
Input sanitization for SIEM events BEFORE they reach LLM prompt construction.
Defends against prompt injection via attacker-controlled log fields.
"""
import re
import math
import logging
import unicodedata

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
    # --- Red team patches (Sprint 3) ---
    # Template injection — Jinja2/Mustache double curly braces
    r'\{\{.*?\}\}',
    # Jinja2 block tags
    r'\{%.*?%\}',
    # Code injection variants missed by original patterns
    r'(?i)open\s*\(',
    r'(?i)import\s+sys\b',
    r'(?i)import\s+shutil\b',
    r'(?i)import\s+pathlib\b',
    r'(?i)import\s+glob\b',
    r'(?i)import\s+pickle\b',
    r'(?i)import\s+shelve\b',
    r'(?i)from\s+builtins\s+import',
    # Jinja2/SSTI exploitation
    r'(?i)__globals__',
    r'(?i)__subclasses__',
    r'(?i)__builtins__',
    r'(?i)config\s*\.\s*__class__',
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


def _scan_field_tail(value: str) -> bool:
    """
    Check the tail of long fields for hidden content.
    Attackers pad benign data then append injection near the truncation boundary.
    """
    if len(value) < 1000:
        return False
    tail = value[-200:]
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, tail):
            return True
    return False


# Cyrillic→Latin homoglyph map (visual lookalikes used to bypass regex)
_HOMOGLYPH_MAP = str.maketrans({
    '\u0430': 'a',  # Cyrillic а → Latin a
    '\u0435': 'e',  # Cyrillic е → Latin e
    '\u043e': 'o',  # Cyrillic о → Latin o
    '\u0440': 'p',  # Cyrillic р → Latin p
    '\u0441': 'c',  # Cyrillic с → Latin c
    '\u0443': 'y',  # Cyrillic у → Latin y
    '\u0445': 'x',  # Cyrillic х → Latin x
    '\u0410': 'A',  # Cyrillic А → Latin A
    '\u0412': 'B',  # Cyrillic В → Latin B
    '\u0415': 'E',  # Cyrillic Е → Latin E
    '\u041a': 'K',  # Cyrillic К → Latin K
    '\u041c': 'M',  # Cyrillic М → Latin M
    '\u041d': 'H',  # Cyrillic Н → Latin H
    '\u041e': 'O',  # Cyrillic О → Latin O
    '\u0420': 'P',  # Cyrillic Р → Latin P
    '\u0421': 'C',  # Cyrillic С → Latin C
    '\u0422': 'T',  # Cyrillic Т → Latin T
    '\u0425': 'X',  # Cyrillic Х → Latin X
})


def _normalize_for_scanning(text: str) -> str:
    """Normalize Unicode to catch homoglyph and zero-width character attacks."""
    # Remove zero-width characters
    text = text.replace('\u200b', '').replace('\u200c', '').replace('\u200d', '').replace('\ufeff', '')
    # Remove right-to-left override
    text = text.replace('\u202e', '').replace('\u202d', '')
    # NFKC normalization
    text = unicodedata.normalize('NFKC', text)
    # Cyrillic homoglyph → Latin ASCII
    text = text.translate(_HOMOGLYPH_MAP)
    return text


def sanitize_siem_event(event: dict) -> dict:
    if not isinstance(event, dict):
        return event

    sanitized = {}
    injection_detected = False
    high_entropy_fields = []

    for key, value in event.items():
        if isinstance(value, str):
            # Normalize Unicode BEFORE pattern matching to catch homoglyphs
            scan_value = _normalize_for_scanning(value)

            # Check injection patterns on normalized value BEFORE truncation
            for pattern in INJECTION_PATTERNS:
                if re.search(pattern, scan_value):
                    injection_detected = True
                    value = re.sub(pattern, '[INJECTION_STRIPPED]', scan_value)
                    logger.warning(f"Prompt injection pattern stripped from field: {key}")

            # Smart truncate AFTER injection checks
            if len(value) > MAX_FIELD_LENGTH:
                value = smart_truncate(value, MAX_FIELD_LENGTH)
                logger.warning(f"Smart-truncated oversized SIEM field: {key}")

            # Tail scan for padding attacks (benign padding + attack at end)
            if _scan_field_tail(value):
                injection_detected = True
                value = re.sub(r'.{200}$', '[INJECTION_STRIPPED_TAIL]', value)
                logger.warning(f"Injection pattern detected in tail of field: {key}")

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
