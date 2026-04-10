"""Tests for deprecated ZCS normalizer stub (OCSF normalization lives in Go API)."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "worker"))

from stages.normalizer import normalize_siem_event, _detect_field_style, get_zcs_field


class TestDeprecatedPassthrough:
    def test_dict_unchanged(self):
        event = {"src_ip": "10.0.0.1", "class_uid": 2004}
        r = normalize_siem_event(event)
        assert r is event
        assert r["src_ip"] == "10.0.0.1"

    def test_non_dict(self):
        assert normalize_siem_event("string") == "string"
        assert normalize_siem_event(None) is None


class TestFieldStyleDetection:
    def test_splunk_style(self):
        event = {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}
        assert _detect_field_style(event) == "splunk"

    def test_elastic_style(self):
        event = {"source": {"ip": "10.0.0.1"}, "host": {"name": "x"}}
        assert _detect_field_style(event) == "elastic"

    def test_empty_unknown(self):
        assert _detect_field_style({}) == "unknown"


class TestGetZcsField:
    def test_helper(self):
        assert get_zcs_field({"source_ip": "1.1.1.1"}, "source_ip") == "1.1.1.1"
        assert get_zcs_field({}, "missing", "d") == "d"
