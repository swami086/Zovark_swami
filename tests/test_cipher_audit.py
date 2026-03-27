import pytest
import sys
import os

# Ensure worker modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

try:
    from stages.skills.cipher_audit import analyze_cipher, RiskLevel
except ModuleNotFoundError:
    from worker.stages.skills.cipher_audit import analyze_cipher, RiskLevel


def test_tls13_aes256():
    r = analyze_cipher("TLSv1.3", "TLS_AES_256_GCM_SHA384")
    assert r.risk_level == RiskLevel.SECURE and r.has_pfs and r.security_bits == 256


def test_tls12_ecdhe():
    r = analyze_cipher("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256")
    assert r.risk_level == RiskLevel.SECURE and r.has_pfs


def test_tls12_rsa_no_pfs():
    r = analyze_cipher("TLSv1.2", "AES128-SHA")  # RSA key transport, no ECDHE
    assert r.risk_level == RiskLevel.WARNING and not r.has_pfs


def test_rc4():
    r = analyze_cipher("TLSv1.2", "RC4-SHA")
    assert r.risk_level == RiskLevel.CRITICAL and r.vulnerability_class == "broken_stream_cipher"


def test_des():
    r = analyze_cipher("TLSv1.2", "DES-CBC-SHA")
    assert r.risk_level == RiskLevel.CRITICAL


def test_3des():
    r = analyze_cipher("TLSv1.2", "DES-CBC3-SHA")
    assert r.risk_level == RiskLevel.CRITICAL


def test_export():
    r = analyze_cipher("TLSv1.2", "EXP-RC4-MD5")
    assert r.risk_level == RiskLevel.CRITICAL


def test_sslv3():
    r = analyze_cipher("SSLv3", "ECDHE-RSA-AES128-SHA")
    assert r.risk_level == RiskLevel.CRITICAL and r.vulnerability_class == "deprecated_protocol"


def test_tls10():
    r = analyze_cipher("TLSv1.0", "AES128-SHA")
    assert r.risk_level == RiskLevel.CRITICAL and r.vulnerability_class == "deprecated_protocol"


def test_tls11_ecdhe():
    r = analyze_cipher("TLSv1.1", "ECDHE-RSA-AES128-SHA")
    assert r.risk_level == RiskLevel.CRITICAL  # protocol trumps cipher
