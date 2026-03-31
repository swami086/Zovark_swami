"""Tests for extraction tools."""
import pytest
from tools.extraction import (
    extract_ipv4, extract_ipv6, extract_domains, extract_urls,
    extract_hashes, extract_emails, extract_usernames, extract_cves,
)


class TestExtractIPv4:
    def test_single_ip(self):
        result = extract_ipv4("Failed login from 185.220.101.45 user root")
        values = [r["value"] for r in result]
        assert "185.220.101.45" in values

    def test_no_ips(self):
        assert extract_ipv4("No IPs here") == []

    def test_multiple_ips(self):
        result = extract_ipv4("Multiple: 10.0.1.5 and 192.168.1.100 and 172.16.0.1")
        assert len(result) == 3

    def test_exclude_broadcast_loopback(self):
        result = extract_ipv4("Exclude 255.255.255.255 and 127.0.0.1 and 0.0.0.0")
        assert result == []

    def test_edge_positions(self):
        result = extract_ipv4("10.0.0.1 at start and end 10.0.0.2")
        assert len(result) == 2

    def test_evidence_refs(self):
        result = extract_ipv4("Attack from 10.0.0.5")
        assert result[0]["evidence_refs"][0]["source"] == "text"

    def test_dedup(self):
        result = extract_ipv4("10.0.0.1 and again 10.0.0.1")
        assert len(result) == 1

    def test_empty_string(self):
        assert extract_ipv4("") == []


class TestExtractIPv6:
    def test_full_ipv6(self):
        result = extract_ipv6("Connection from 2001:0db8:85a3::8a2e:0370:7334")
        values = [r["value"] for r in result]
        assert any("2001" in v for v in values)

    def test_exclude_loopback(self):
        assert extract_ipv6("Loopback ::1 excluded") == []

    def test_no_ipv6(self):
        assert extract_ipv6("No IPv6") == []


class TestExtractDomains:
    def test_simple_domain(self):
        result = extract_domains("Query to evil-cdn.net")
        values = [r["value"] for r in result]
        assert "evil-cdn.net" in values

    def test_subdomain(self):
        result = extract_domains("http://secure-login.company-portal.com/verify")
        values = [r["value"] for r in result]
        assert "secure-login.company-portal.com" in values

    def test_exclude_localhost(self):
        result = extract_domains("localhost and test.local excluded")
        assert result == []

    def test_exclude_example(self):
        result = extract_domains("example.com is excluded")
        assert result == []


class TestExtractUrls:
    def test_http_url(self):
        result = extract_urls("Downloaded from http://evil.com/payload.bin")
        values = [r["value"] for r in result]
        assert "http://evil.com/payload.bin" in values

    def test_multiple_urls(self):
        result = extract_urls("https://legit.com and ftp://files.net/data")
        assert len(result) == 2

    def test_no_urls(self):
        assert extract_urls("No URLs") == []


class TestExtractHashes:
    def test_md5(self):
        result = extract_hashes("Hash: d41d8cd98f00b204e9800998ecf8427e")
        assert len(result) == 1
        assert result[0]["type"] == "md5"

    def test_sha256(self):
        result = extract_hashes("SHA256: a948904f2f0f479b8f8564e9e27f63e0f4c8d2d0abc44f1c71d262036c2f5e54")
        assert len(result) == 1
        assert result[0]["type"] == "sha256"

    def test_no_hashes(self):
        assert extract_hashes("No hashes") == []


class TestExtractEmails:
    def test_multiple_emails(self):
        result = extract_emails("From ceo@evil-corp.com to admin@company.org")
        assert len(result) == 2

    def test_no_emails(self):
        assert extract_emails("No emails") == []


class TestExtractUsernames:
    def test_windows_event(self):
        result = extract_usernames("EventID=4625 TargetUserName=admin SubjectUserName=SYSTEM")
        values = [r["value"] for r in result]
        assert "admin" in values
        assert "SYSTEM" in values

    def test_user_equals(self):
        result = extract_usernames("User=root failed login")
        values = [r["value"] for r in result]
        assert "root" in values

    def test_no_usernames(self):
        assert extract_usernames("No username patterns") == []


class TestExtractCves:
    def test_single_cve(self):
        result = extract_cves("Exploit for CVE-2024-1234")
        values = [r["value"] for r in result]
        assert "CVE-2024-1234" in values

    def test_multiple_cves(self):
        result = extract_cves("CVE-2023-44487 and CVE-2024-3400")
        assert len(result) == 2

    def test_no_cves(self):
        assert extract_cves("No CVEs") == []
