"""ML-based string ranking for malware analysis (StringSifter-inspired).

Extracts ASCII/Unicode strings from binary data, ranks by suspiciousness
using TF-IDF character n-grams + classifier, categorizes top results.
"""
import os
import re
import logging
import math
from typing import List, Dict, Tuple, Optional
from collections import Counter

logger = logging.getLogger(__name__)

STRINGSIFTER_MODEL_PATH = os.environ.get("STRINGSIFTER_MODEL_PATH", "/models/stringsifter.pkl")

# Pre-defined suspicious patterns for rule-based scoring
SUSPICIOUS_PATTERNS = {
    "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.I),
    "ip": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "registry": re.compile(r'HKEY_[A-Z_]+\\', re.I),
    "file_path": re.compile(r'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*', re.I),
    "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "powershell": re.compile(r'(?:powershell|invoke-|iex |downloadstring|encodedcommand)', re.I),
    "cmd_exec": re.compile(r'(?:cmd\.exe|/c |wscript|cscript|mshta|regsvr32)', re.I),
    "crypto": re.compile(r'(?:AES|RSA|DES|SHA256|MD5|base64|encrypt|decrypt)', re.I),
    "c2_indicator": re.compile(r'(?:beacon|callback|heartbeat|exfil|payload|shellcode)', re.I),
    "api_key": re.compile(r'(?:api[_-]?key|secret[_-]?key|access[_-]?token|bearer)\s*[:=]', re.I),
}


class StringSifterAnalyzer:
    """Extract and rank strings from binary data."""

    def __init__(self, model_path: str = None, min_length: int = 4):
        self.min_length = min_length
        self.model = None
        self.vectorizer = None
        self._load_model(model_path or STRINGSIFTER_MODEL_PATH)

    def _load_model(self, path: str):
        """Load pre-trained sklearn model if available."""
        if os.path.exists(path):
            try:
                import pickle
                with open(path, "rb") as f:
                    data = pickle.load(f)
                self.model = data.get("classifier")
                self.vectorizer = data.get("vectorizer")
                logger.info(f"StringSifter model loaded from {path}")
            except Exception as e:
                logger.warning(f"Failed to load StringSifter model: {e}")

    def extract_strings(self, binary_data: bytes, min_length: int = None) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        min_len = min_length or self.min_length
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
        strings = [s.decode("ascii", errors="ignore") for s in re.findall(ascii_pattern, binary_data)]
        # UTF-16LE strings (common in Windows malware)
        utf16_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}'
        for match in re.findall(utf16_pattern, binary_data):
            try:
                decoded = match.decode("utf-16-le").strip()
                if len(decoded) >= min_len:
                    strings.append(decoded)
            except (UnicodeDecodeError, ValueError):
                pass
        return list(set(strings))

    def rank_strings(self, strings: List[str]) -> List[Tuple[str, float]]:
        """Rank strings by suspiciousness.

        Uses ML model if available, otherwise falls back to rule-based scoring.
        Returns list of (string, score) sorted by score descending.
        """
        if not strings:
            return []

        if self.model and self.vectorizer:
            return self._ml_rank(strings)

        return self._rule_based_rank(strings)

    def _ml_rank(self, strings: List[str]) -> List[Tuple[str, float]]:
        """Rank using trained ML model."""
        features = self.vectorizer.transform(strings)
        if hasattr(self.model, "predict_proba"):
            scores = self.model.predict_proba(features)[:, 1]
        else:
            scores = self.model.predict(features)
        ranked = sorted(zip(strings, scores), key=lambda x: x[1], reverse=True)
        return ranked

    def _rule_based_rank(self, strings: List[str]) -> List[Tuple[str, float]]:
        """Fallback: rank using pattern matching and heuristics."""
        scored = []
        for s in strings:
            score = 0.0
            # Length bonus (longer strings are more interesting)
            score += min(len(s) / 100.0, 0.2)
            # Pattern matching
            for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
                if pattern.search(s):
                    score += 0.3
            # Entropy bonus (high-entropy strings may be encoded/encrypted)
            entropy = self._shannon_entropy(s)
            if entropy > 4.5:
                score += 0.15
            # Mixed case with numbers (potential encoded payload)
            if re.search(r'[a-z]', s) and re.search(r'[A-Z]', s) and re.search(r'[0-9]', s):
                score += 0.1
            scored.append((s, min(score, 1.0)))
        return sorted(scored, key=lambda x: x[1], reverse=True)

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def analyze_suspicious_strings(self, binary_data: bytes) -> Dict:
        """Full analysis pipeline: extract, rank, categorize.

        Returns:
            {
                top_strings: [{string, score, categories}],
                iocs: {urls, ips, registry_keys, file_paths, emails},
                risk_score: float (0-1),
                total_strings: int,
            }
        """
        strings = self.extract_strings(binary_data)
        ranked = self.rank_strings(strings)
        top_20 = ranked[:20]

        # Categorize IoCs from ALL strings
        iocs = {
            "urls": [], "ips": [], "registry_keys": [],
            "file_paths": [], "emails": [],
        }
        for s, _ in ranked:
            if SUSPICIOUS_PATTERNS["url"].search(s):
                iocs["urls"].append(s)
            if SUSPICIOUS_PATTERNS["ip"].search(s):
                for ip in SUSPICIOUS_PATTERNS["ip"].findall(s):
                    if not ip.startswith(("0.", "127.", "255.", "10.", "192.168.", "172.")):
                        iocs["ips"].append(ip)
            if SUSPICIOUS_PATTERNS["registry"].search(s):
                iocs["registry_keys"].append(s)
            if SUSPICIOUS_PATTERNS["file_path"].search(s):
                iocs["file_paths"].append(s)
            if SUSPICIOUS_PATTERNS["email"].search(s):
                iocs["emails"].extend(SUSPICIOUS_PATTERNS["email"].findall(s))

        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        # Risk score from top strings
        if top_20:
            risk_score = sum(score for _, score in top_20) / len(top_20)
        else:
            risk_score = 0.0

        return {
            "top_strings": [{"string": s, "score": round(sc, 4)} for s, sc in top_20],
            "iocs": iocs,
            "risk_score": round(risk_score, 4),
            "total_strings": len(strings),
        }


from temporalio import activity


@activity.defn
async def analyze_binary_strings(params: dict) -> dict:
    """Temporal activity: analyze binary file strings.

    Args: {file_path: str, sandbox_id: str}
    Returns: analysis dict from StringSifterAnalyzer
    """
    file_path = params.get("file_path", "")

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except (FileNotFoundError, PermissionError) as e:
        return {"error": str(e), "risk_score": 0, "total_strings": 0}

    analyzer = StringSifterAnalyzer()
    return analyzer.analyze_suspicious_strings(data)
