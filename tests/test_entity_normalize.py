"""Unit tests for entity normalization and hashing."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

from entity_normalize import (
    normalize_ip, normalize_domain, normalize_file_hash,
    normalize_url, normalize_email, normalize_entity, compute_entity_hash
)


class TestNormalizeIP:
    def test_ipv4_basic(self):
        assert normalize_ip("192.168.1.1") == "192.168.1.1"

    def test_ipv4_with_port(self):
        assert normalize_ip("10.0.0.1:8080") == "10.0.0.1"

    def test_ipv4_defanged(self):
        assert normalize_ip("192[.]168[.]1[.]1") == "192.168.1.1"

    def test_ipv4_whitespace(self):
        assert normalize_ip("  10.0.0.1  ") == "10.0.0.1"

    def test_ipv6_basic(self):
        result = normalize_ip("::1")
        assert result == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_ipv6_full(self):
        result = normalize_ip("2001:db8::1")
        assert result == "2001:0db8:0000:0000:0000:0000:0000:0001"

    def test_ipv6_bracketed(self):
        result = normalize_ip("[::1]")
        assert result == "0000:0000:0000:0000:0000:0000:0000:0001"

    def test_ipv4_private(self):
        assert normalize_ip("172.16.0.1") == "172.16.0.1"

    def test_invalid_ip(self):
        assert normalize_ip("not-an-ip") == "not-an-ip"


class TestNormalizeDomain:
    def test_basic(self):
        assert normalize_domain("Example.COM") == "example.com"

    def test_strip_www(self):
        assert normalize_domain("www.example.com") == "example.com"

    def test_trailing_dot(self):
        assert normalize_domain("example.com.") == "example.com"

    def test_defanged_hxxp(self):
        assert normalize_domain("hxxps://malware.evil.com/path") == "malware.evil.com"

    def test_defanged_dots(self):
        assert normalize_domain("evil[.]example[.]com") == "evil.example.com"

    def test_subdomain(self):
        assert normalize_domain("sub.example.co.uk") == "sub.example.co.uk"

    def test_with_path(self):
        assert normalize_domain("example.com/some/path") == "example.com"


class TestNormalizeFileHash:
    def test_md5(self):
        h = "D41D8CD98F00B204E9800998ECF8427E"
        assert normalize_file_hash(h) == h.lower()

    def test_sha1(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert normalize_file_hash(h) == h

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert normalize_file_hash(h) == h

    def test_with_prefix(self):
        assert normalize_file_hash("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == \
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_invalid_hash(self):
        assert normalize_file_hash("not-a-hash") == "not-a-hash"

    def test_wrong_length(self):
        assert normalize_file_hash("abcdef1234") == "abcdef1234"


class TestNormalizeURL:
    def test_basic(self):
        result = normalize_url("HTTP://Example.COM/path/")
        assert result == "http://example.com/path"

    def test_defanged(self):
        result = normalize_url("hxxps://evil[.]com/malware")
        assert result == "https://evil.com/malware"

    def test_tracking_params_stripped(self):
        result = normalize_url("https://example.com/page?utm_source=test&id=123")
        assert "utm_source" not in result
        assert "id=123" in result

    def test_trailing_slash_stripped(self):
        result = normalize_url("https://example.com/")
        assert result == "https://example.com"

    def test_all_tracking_stripped(self):
        result = normalize_url("https://example.com/page?utm_source=a&utm_medium=b")
        assert result == "https://example.com/page"


class TestNormalizeEmail:
    def test_basic(self):
        assert normalize_email("User@Example.COM") == "user@example.com"

    def test_plus_addressing(self):
        assert normalize_email("user+tag@example.com") == "user@example.com"

    def test_whitespace(self):
        assert normalize_email("  user@example.com  ") == "user@example.com"

    def test_no_at(self):
        assert normalize_email("notanemail") == "notanemail"


class TestNormalizeEntity:
    def test_dispatches_ip(self):
        assert normalize_entity("ip", "192[.]168[.]1[.]1") == "192.168.1.1"

    def test_dispatches_domain(self):
        assert normalize_entity("domain", "WWW.Example.COM.") == "example.com"

    def test_unknown_type_fallback(self):
        assert normalize_entity("user", "  Admin  ") == "admin"

    def test_device_type(self):
        assert normalize_entity("device", "WORKSTATION-01") == "workstation-01"

    def test_process_type(self):
        assert normalize_entity("process", "  cmd.exe  ") == "cmd.exe"


class TestComputeEntityHash:
    def test_deterministic(self):
        h1 = compute_entity_hash("ip", "192.168.1.1")
        h2 = compute_entity_hash("ip", "192.168.1.1")
        assert h1 == h2

    def test_different_types_different_hash(self):
        h1 = compute_entity_hash("ip", "test")
        h2 = compute_entity_hash("domain", "test")
        assert h1 != h2

    def test_hash_is_sha256(self):
        h = compute_entity_hash("ip", "192.168.1.1")
        assert len(h) == 64
        assert all(c in '0123456789abcdef' for c in h)
