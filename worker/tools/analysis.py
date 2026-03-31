"""Analysis tools — pattern counting, entropy, encoding detection."""
import re
import math
import base64
from collections import Counter
from urllib.parse import unquote


def count_pattern(text: str, pattern: str) -> int:
    """Count regex pattern matches in text."""
    if not text or not pattern:
        return 0
    try:
        return len(re.findall(pattern, text))
    except re.error:
        # Fall back to literal match if pattern is invalid regex
        return text.count(pattern)


def calculate_entropy(text: str) -> float:
    """Shannon entropy of a string. Empty string returns 0.0."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_encoding(text: str) -> dict:
    """Detect if text contains base64, hex, or URL encoding."""
    result = {
        "has_base64": False,
        "has_hex": False,
        "has_url_encoding": False,
        "decoded_samples": [],
    }
    if not text:
        return result

    # Base64 detection: look for -enc flag or long base64 strings
    b64_patterns = [
        r'-[Ee]nc(?:oded(?:Command)?)?[\s]+([A-Za-z0-9+/=]{8,})',
        r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/])',
    ]
    for pat in b64_patterns:
        for match in re.finditer(pat, text):
            candidate = match.group(1) if match.lastindex else match.group()
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
                if any(c.isprintable() for c in decoded[:20]):
                    result["has_base64"] = True
                    result["decoded_samples"].append({"type": "base64", "decoded": decoded[:100]})
                    break
            except Exception:
                continue
        if result["has_base64"]:
            break

    # Hex detection: long hex strings (not hashes)
    hex_match = re.search(r'(?:0x|\\x)([0-9a-fA-F]{8,})', text)
    if hex_match:
        result["has_hex"] = True

    # URL encoding detection
    if re.search(r'%[0-9a-fA-F]{2}', text):
        result["has_url_encoding"] = True
        decoded = unquote(text)
        if decoded != text:
            result["decoded_samples"].append({"type": "url_encoding", "decoded": decoded[:100]})

    return result


def check_base64(text: str) -> list:
    """Find base64 strings in text, decode them, return decoded content."""
    if not text:
        return []

    results = []
    # First: look for base64 after -enc flag (PowerShell encoded command)
    enc_pattern = r'-[Ee]nc(?:oded(?:Command)?)?[\s]+([A-Za-z0-9+/=]{8,})'
    for match in re.finditer(enc_pattern, text):
        candidate = match.group(1)
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(len(decoded), 1)
            if printable_ratio > 0.5:
                results.append({
                    "encoded": candidate,
                    "decoded": decoded[:200],
                    "offset": match.start(1),
                })
        except Exception:
            continue

    # Then: look for standalone base64 strings (at least 16 chars, may end with =)
    pattern = r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])'
    for match in re.finditer(pattern, text):
        candidate = match.group(1)
        # Skip if already found via -enc pattern
        if any(r["encoded"] == candidate for r in results):
            continue
        # Must have mix of cases or digits to be plausible base64
        if not (re.search(r'[A-Z]', candidate) and re.search(r'[a-z]', candidate)):
            continue
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            # Filter out garbage
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(len(decoded), 1)
            if printable_ratio > 0.5:
                results.append({
                    "encoded": candidate,
                    "decoded": decoded[:200],
                    "offset": match.start(),
                })
        except Exception:
            continue
    return results
