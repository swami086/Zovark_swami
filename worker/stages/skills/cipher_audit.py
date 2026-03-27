"""
Zovarc Cipher Audit Skill
Deterministic TLS cipher-suite classification per NIST SP 800-57.

Receives (protocol_version, cipher_suite_name) and returns a structured
verdict: risk level, security bits, PFS status, vulnerability class,
remediation guidance, and an optional LLM prompt for narrative generation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    SECURE = "SECURE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Effective security bits for common bulk ciphers (NIST SP 800-57 Table 2)
SECURITY_BITS: dict[str, int] = {
    "AES_256": 256,
    "AES256": 256,
    "AES_128": 128,
    "AES128": 128,
    "CHACHA20": 256,
    "3DES": 64,       # Sweet32 — effective strength reduced
    "DES": 56,
    "RC4": 0,         # Broken
    "NULL": 0,
    "EXPORT": 40,
}

# Remediation guidance keyed by vulnerability class
REMEDIATION: dict[str, str] = {
    "deprecated_protocol": (
        "Upgrade to TLS 1.2 (minimum) or TLS 1.3. Disable SSLv2, SSLv3, "
        "TLSv1.0, and TLSv1.1 in server configuration."
    ),
    "broken_stream_cipher": (
        "Disable RC4 immediately. Use AES-GCM or CHACHA20-POLY1305 suites."
    ),
    "weak_block_cipher": (
        "Disable DES and 3DES (Sweet32 attack). Migrate to AES-128-GCM or "
        "AES-256-GCM cipher suites."
    ),
    "null_cipher": (
        "Disable NULL cipher suites — traffic is sent in plaintext."
    ),
    "export_grade": (
        "Disable EXPORT-grade cipher suites (FREAK/Logjam). These provide "
        "only 40-bit security and are trivially breakable."
    ),
    "anonymous_key_exchange": (
        "Disable anonymous (aNULL/ADH) key exchange — vulnerable to "
        "man-in-the-middle attacks."
    ),
    "weak_mac": (
        "Disable cipher suites using MD5 for message authentication. "
        "Prefer SHA-256 or SHA-384."
    ),
    "no_forward_secrecy": (
        "Prefer ECDHE or DHE key exchange for forward secrecy. Static RSA "
        "key transport means a compromised server key decrypts all past traffic."
    ),
}

# Regex patterns for broken/weak cipher components → (vulnerability_class, risk)
BROKEN_PATTERNS: dict[str, tuple[str, RiskLevel]] = {
    r"(?i)\bRC4\b": ("broken_stream_cipher", RiskLevel.CRITICAL),
    r"(?i)\bDES\b(?!.*CBC3)": ("weak_block_cipher", RiskLevel.CRITICAL),
    r"(?i)\b(DES-CBC3|3DES|DES_EDE)\b": ("weak_block_cipher", RiskLevel.CRITICAL),
    r"(?i)\bNULL\b": ("null_cipher", RiskLevel.CRITICAL),
    r"(?i)\bEXP(ORT)?[-_]": ("export_grade", RiskLevel.CRITICAL),
    r"(?i)\b(ADH|ANON|aNULL)\b": ("anonymous_key_exchange", RiskLevel.CRITICAL),
    r"(?i)\bMD5\b": ("weak_mac", RiskLevel.CRITICAL),
}

# Deprecated protocols (MUST NOT be used per NIST SP 800-52r2)
DEPRECATED_PROTOCOLS: set[str] = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class CipherAuditResult:
    protocol: str
    cipher_suite: str
    risk_level: RiskLevel
    security_bits: int
    has_pfs: bool
    vulnerability_class: Optional[str] = None
    remediation: Optional[str] = None
    llm_prompt: Optional[str] = None


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------

def analyze_cipher(protocol: str, cipher_suite: str) -> CipherAuditResult:
    """
    Deterministic cipher-suite classification per NIST SP 800-57.

    Order of checks:
      1. Deprecated protocol (SSLv2/3, TLS 1.0/1.1) -> CRITICAL
      2. TLS 1.3 -> always SECURE (RFC 8446 mandates ephemeral exchange)
      3. Broken patterns (RC4, DES, 3DES, NULL, EXPORT, ANON, MD5) -> CRITICAL
      4. Forward secrecy (ECDHE/DHE present?) -> no PFS = WARNING
      5. Otherwise -> SECURE
    """
    protocol = protocol.strip()
    cipher_suite = cipher_suite.strip()

    # --- 1. Deprecated protocol ------------------------------------------
    if protocol in DEPRECATED_PROTOCOLS:
        bits = _estimate_bits(cipher_suite)
        return CipherAuditResult(
            protocol=protocol,
            cipher_suite=cipher_suite,
            risk_level=RiskLevel.CRITICAL,
            security_bits=bits,
            has_pfs=_has_pfs(cipher_suite),
            vulnerability_class="deprecated_protocol",
            remediation=REMEDIATION["deprecated_protocol"],
            llm_prompt=build_llm_prompt(protocol, cipher_suite, "deprecated_protocol"),
        )

    # --- 2. TLS 1.3 — always SECURE (RFC 8446) --------------------------
    if protocol == "TLSv1.3":
        bits = _estimate_bits(cipher_suite)
        return CipherAuditResult(
            protocol=protocol,
            cipher_suite=cipher_suite,
            risk_level=RiskLevel.SECURE,
            security_bits=bits,
            has_pfs=True,  # TLS 1.3 mandates ephemeral key exchange
        )

    # --- 3. Broken cipher patterns ---------------------------------------
    for pattern, (vuln_class, risk) in BROKEN_PATTERNS.items():
        if re.search(pattern, cipher_suite):
            bits = _estimate_bits(cipher_suite)
            return CipherAuditResult(
                protocol=protocol,
                cipher_suite=cipher_suite,
                risk_level=risk,
                security_bits=bits,
                has_pfs=_has_pfs(cipher_suite),
                vulnerability_class=vuln_class,
                remediation=REMEDIATION[vuln_class],
                llm_prompt=build_llm_prompt(protocol, cipher_suite, vuln_class),
            )

    # --- 4. Forward secrecy check ----------------------------------------
    pfs = _has_pfs(cipher_suite)
    bits = _estimate_bits(cipher_suite)
    if not pfs:
        return CipherAuditResult(
            protocol=protocol,
            cipher_suite=cipher_suite,
            risk_level=RiskLevel.WARNING,
            security_bits=bits,
            has_pfs=False,
            vulnerability_class="no_forward_secrecy",
            remediation=REMEDIATION["no_forward_secrecy"],
            llm_prompt=build_llm_prompt(protocol, cipher_suite, "no_forward_secrecy"),
        )

    # --- 5. SECURE -------------------------------------------------------
    return CipherAuditResult(
        protocol=protocol,
        cipher_suite=cipher_suite,
        risk_level=RiskLevel.SECURE,
        security_bits=bits,
        has_pfs=True,
    )


# ---------------------------------------------------------------------------
# LLM prompt builder
# ---------------------------------------------------------------------------

def build_llm_prompt(protocol: str, cipher_suite: str, vuln_class: str) -> str:
    """
    Generate a concise prompt for LLM narration on non-secure findings.
    Only called for WARNING or CRITICAL results.
    """
    remediation = REMEDIATION.get(vuln_class, "Review cipher configuration.")
    return (
        f"A TLS connection was observed using protocol {protocol} with cipher "
        f"suite {cipher_suite}. This has been classified as vulnerability class "
        f"'{vuln_class}'. Recommended remediation: {remediation}\n\n"
        f"Write a 2-3 sentence SOC analyst narrative explaining the risk to a "
        f"non-technical stakeholder. Include the specific vulnerability and the "
        f"business impact of not remediating."
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_pfs(cipher_suite: str) -> bool:
    """Check for ephemeral key exchange (ECDHE or DHE)."""
    return bool(re.search(r"(?i)\b(ECDHE|DHE)\b", cipher_suite))


def _estimate_bits(cipher_suite: str) -> int:
    """
    Estimate effective security bits from the cipher suite name.
    Returns the bits for the first matching bulk cipher token.
    """
    upper = cipher_suite.upper()
    # Check specific patterns in priority order
    if "NULL" in upper:
        return 0
    if re.search(r"EXP(ORT)?[-_]", upper):
        return 40
    if "RC4" in upper:
        return 0
    if "CHACHA20" in upper:
        return 256
    if re.search(r"AES[_-]?256", upper):
        return 256
    if re.search(r"AES[_-]?128", upper):
        return 128
    # DES-CBC3 / 3DES before plain DES
    if re.search(r"(DES-CBC3|3DES|DES_EDE)", upper):
        return 64
    if "DES" in upper:
        return 56
    # TLS 1.3 suite names (TLS_AES_256_GCM_SHA384, etc.)
    if "AES_256" in upper:
        return 256
    if "AES_128" in upper:
        return 128
    return 0
