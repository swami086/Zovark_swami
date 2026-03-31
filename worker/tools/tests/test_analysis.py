"""Tests for analysis tools."""
import pytest
from tools.analysis import count_pattern, calculate_entropy, detect_encoding, check_base64


class TestCountPattern:
    def test_simple_count(self):
        assert count_pattern("failed failed success failed", "failed") == 3

    def test_event_id_count(self):
        assert count_pattern("EventID=4625 EventID=4625 EventID=4624", "EventID=4625") == 2

    def test_no_match(self):
        assert count_pattern("clean", "malware") == 0

    def test_empty_text(self):
        assert count_pattern("", "anything") == 0

    def test_regex_pattern(self):
        assert count_pattern("cat bat hat", r"[cbh]at") == 3


class TestCalculateEntropy:
    def test_low_entropy(self):
        e = calculate_entropy("aaaaaaaaaa")
        assert 0.0 <= e <= 0.01

    def test_high_entropy(self):
        e = calculate_entropy("abcdefghijklmnopqrstuvwxyz")
        assert 4.5 <= e <= 5.0

    def test_empty_string(self):
        assert calculate_entropy("") == 0.0


class TestDetectEncoding:
    def test_base64(self):
        result = detect_encoding("powershell -enc JABzAD0ATgBlAHcA=")
        assert result["has_base64"] is True

    def test_normal_text(self):
        result = detect_encoding("normal text")
        assert result["has_base64"] is False
        assert result["has_hex"] is False
        assert result["has_url_encoding"] is False

    def test_url_encoding(self):
        result = detect_encoding("%2Fetc%2Fpasswd")
        assert result["has_url_encoding"] is True


class TestCheckBase64:
    def test_encoded_string(self):
        result = check_base64("powershell -enc SGVsbG8gV29ybGQ=")
        assert len(result) >= 1

    def test_no_base64(self):
        assert check_base64("no base64") == []
