"""Pre-embedding alert sanitization — prevents memory poisoning via crafted alerts.

5-stage pipeline:
  1. HTML-escape all string fields
  2. Injection neutralization (prompt injection patterns)
  3. IoC extraction into structured field
  4. Structural normalization (flatten nested)
  5. Integrity hash (SHA-256 of sanitized content)

Target: 1000 alerts/second
"""
import hashlib
import html
import json
import re
from typing import Any, Dict, List, Optional, Tuple


# Stage 2: Injection patterns to neutralize
INJECTION_PATTERNS = [
    # Prompt injection
    (re.compile(r'ignore\s+(all\s+)?previous\s+instructions', re.I), "[SANITIZED:prompt_injection]"),
    (re.compile(r'forget\s+everything', re.I), "[SANITIZED:prompt_injection]"),
    (re.compile(r'you\s+are\s+now\s+', re.I), "[SANITIZED:role_injection]"),
    (re.compile(r'(?:^|\n)\s*system\s*:', re.I | re.MULTILINE), "[SANITIZED:system_prefix]"),
    (re.compile(r'(?:^|\n)\s*assistant\s*:', re.I | re.MULTILINE), "[SANITIZED:assistant_prefix]"),
    (re.compile(r'(?:^|\n)\s*human\s*:', re.I | re.MULTILINE), "[SANITIZED:human_prefix]"),
    (re.compile(r'(?:^|\n)\s*user\s*:', re.I | re.MULTILINE), "[SANITIZED:user_prefix]"),
    # Template injection
    (re.compile(r'\{\{.*?\}\}'), "[SANITIZED:template_injection]"),
    (re.compile(r'\$\{.*?\}'), "[SANITIZED:shell_injection]"),
    # Instruction override
    (re.compile(r'do\s+not\s+follow\s+', re.I), "[SANITIZED:instruction_override]"),
    (re.compile(r'disregard\s+(all\s+)?(previous|above|prior)', re.I), "[SANITIZED:instruction_override]"),
    (re.compile(r'new\s+instructions?\s*:', re.I), "[SANITIZED:instruction_override]"),
    # Data exfil attempts
    (re.compile(r'repeat\s+(back|all|everything)', re.I), "[SANITIZED:data_exfil]"),
    (re.compile(r'output\s+(all|every|the)\s+(data|information|content)', re.I), "[SANITIZED:data_exfil]"),
]

# Stage 3: IoC extraction patterns
IOC_PATTERNS = {
    "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.I),
}

# Known safe domains to exclude from IoC extraction
SAFE_DOMAINS = {"example.com", "localhost", "localhost.localdomain", "zovark.local", "internal"}

# Known malicious patterns for threat level assessment
HIGH_THREAT_PATTERNS = [
    re.compile(r'cobalt\s*strike', re.I),
    re.compile(r'mimikatz', re.I),
    re.compile(r'metasploit', re.I),
    re.compile(r'reverse.{0,5}shell', re.I),
    re.compile(r'c2.{0,5}beacon', re.I),
    re.compile(r'ransomware', re.I),
    re.compile(r'credential.{0,5}dump', re.I),
]


class AlertSanitizer:
    """Multi-stage alert sanitization pipeline."""

    def __init__(self, custom_patterns: Optional[List[Tuple]] = None):
        self.injection_patterns = list(INJECTION_PATTERNS)
        if custom_patterns:
            self.injection_patterns.extend(custom_patterns)
        self._injection_count = 0

    def sanitize(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Run full 5-stage sanitization pipeline.

        Args:
            alert: Raw alert dict from SIEM webhook

        Returns:
            Sanitized alert dict with _iocs_extracted, _sanitized_hash,
            _threat_level, and _injection_detected fields added.
        """
        self._injection_count = 0

        # Stage 1: HTML-escape all string fields
        sanitized = self._html_escape_recursive(alert)

        # Stage 2: Injection neutralization
        sanitized = self._neutralize_injections(sanitized)

        # Stage 3: IoC extraction
        text = json.dumps(sanitized)
        iocs = self._extract_iocs(text)
        sanitized["_iocs_extracted"] = iocs

        # Stage 4: Structural normalization
        sanitized = self._normalize_structure(sanitized)

        # Stage 5: Integrity hash
        canonical = json.dumps(sanitized, sort_keys=True, default=str)
        sanitized["_sanitized_hash"] = hashlib.sha256(canonical.encode()).hexdigest()

        # Assess threat level
        sanitized["_threat_level"] = self._assess_threat(text, iocs)
        sanitized["_injection_detected"] = self._injection_count > 0
        sanitized["_injection_count"] = self._injection_count

        return sanitized

    def _html_escape_recursive(self, obj: Any) -> Any:
        """Stage 1: HTML-escape all string values recursively."""
        if isinstance(obj, str):
            return html.escape(obj, quote=True)
        elif isinstance(obj, dict):
            return {k: self._html_escape_recursive(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._html_escape_recursive(item) for item in obj]
        return obj

    def _neutralize_injections(self, obj: Any) -> Any:
        """Stage 2: Replace injection patterns with safe markers."""
        if isinstance(obj, str):
            result = obj
            for pattern, replacement in self.injection_patterns:
                new_result = pattern.sub(replacement, result)
                if new_result != result:
                    self._injection_count += 1
                result = new_result
            return result
        elif isinstance(obj, dict):
            return {k: self._neutralize_injections(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._neutralize_injections(item) for item in obj]
        return obj

    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Stage 3: Extract IoCs from text."""
        iocs = {}
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = set(pattern.findall(text))
            # Filter safe domains
            if ioc_type == "domain":
                matches = {m for m in matches if m.lower() not in SAFE_DOMAINS}
            if matches:
                iocs[ioc_type] = sorted(matches)
        return iocs

    def _normalize_structure(self, obj: Any, max_depth: int = 5, current_depth: int = 0) -> Any:
        """Stage 4: Flatten deeply nested structures."""
        if current_depth >= max_depth:
            return str(obj) if not isinstance(obj, (str, int, float, bool, type(None))) else obj
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if k.startswith("_"):  # Preserve our metadata fields
                    result[k] = v
                else:
                    result[k] = self._normalize_structure(v, max_depth, current_depth + 1)
            return result
        elif isinstance(obj, list):
            if len(obj) > 100:
                obj = obj[:100]  # Truncate very long arrays
            return [self._normalize_structure(item, max_depth, current_depth + 1) for item in obj]
        return obj

    def _assess_threat(self, text: str, iocs: Dict[str, List[str]]) -> str:
        """Assess threat level based on IoC patterns and known malicious indicators."""
        for pattern in HIGH_THREAT_PATTERNS:
            if pattern.search(text):
                return "high"

        ioc_count = sum(len(v) for v in iocs.values())
        if ioc_count >= 10:
            return "high"
        elif ioc_count >= 5:
            return "medium"
        elif ioc_count >= 1:
            return "low"
        return "informational"


# Module-level singleton
_sanitizer = AlertSanitizer()


def sanitize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function using module-level sanitizer."""
    return _sanitizer.sanitize(alert)
