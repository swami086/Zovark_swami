"""Deterministic regex-based prompt injection detection.

Pure regex, <1ms. If injection detected, flag the investigation but
DON'T strip the payload — an attempted AI subversion IS a threat signal.
"""

import re
from dataclasses import dataclass, field


@dataclass
class InjectionScanResult:
    is_suspicious: bool
    matched_patterns: list  # list of category strings
    confidence_source: str  # 'clean', 'suspicious', 'injection_detected'
    raw_matches: list  # list of dicts with pattern, category, match text, position


# Pattern categories
_PATTERNS = {
    "role_override": [
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
        re.compile(r"override\s+(your\s+)?instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
        re.compile(r"forget\s+(all\s+)?your\s+instructions", re.IGNORECASE),
    ],
    "token_injection": [
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"<\|im_end\|>", re.IGNORECASE),
        re.compile(r"<\|system\|>", re.IGNORECASE),
        re.compile(r"\[INST\]", re.IGNORECASE),
        re.compile(r"<<SYS>>", re.IGNORECASE),
    ],
    "verdict_manipulation": [
        re.compile(r"classify\s+(this\s+)?as\s+false\s+positive", re.IGNORECASE),
        re.compile(r"mark\s+(this\s+)?as\s+benign", re.IGNORECASE),
        re.compile(r"risk\s*_?\s*score\s*=\s*0", re.IGNORECASE),
        re.compile(r"output\s+empty\s+entities", re.IGNORECASE),
        re.compile(r"terminate\s+(the\s+)?task", re.IGNORECASE),
    ],
    "prompt_extraction": [
        re.compile(r"print\s+your\s+(system\s+)?prompt", re.IGNORECASE),
        re.compile(r"what\s+are\s+your\s+instructions", re.IGNORECASE),
        re.compile(r"repeat\s+the\s+above", re.IGNORECASE),
    ],
}


def scan_for_injection(text: str) -> InjectionScanResult:
    """Scan text for prompt injection patterns.

    Returns InjectionScanResult with confidence_source:
    - 'clean': no matches
    - 'suspicious': matches in 1 category
    - 'injection_detected': matches span 2+ categories
    """
    if not text:
        return InjectionScanResult(
            is_suspicious=False,
            matched_patterns=[],
            confidence_source="clean",
            raw_matches=[],
        )

    raw_matches = []
    matched_categories = set()

    for category, patterns in _PATTERNS.items():
        for pattern in patterns:
            for match in pattern.finditer(text):
                matched_categories.add(category)
                raw_matches.append({
                    "pattern": pattern.pattern,
                    "category": category,
                    "match": match.group(),
                    "position": match.start(),
                })

    if not matched_categories:
        confidence_source = "clean"
    elif len(matched_categories) >= 2:
        confidence_source = "injection_detected"
    else:
        confidence_source = "suspicious"

    return InjectionScanResult(
        is_suspicious=len(matched_categories) > 0,
        matched_patterns=sorted(matched_categories),
        confidence_source=confidence_source,
        raw_matches=raw_matches,
    )
