"""Tests for Zovark Core log normalizer."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'worker'))

from stages.normalizer import normalize_siem_event, _detect_field_style, get_zcs_field


class TestSplunkNormalization:
    def test_basic_splunk(self):
        event = {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "user": "admin",
                 "host": "srv-01", "rule_name": "BruteForce", "raw_log": "test"}
        r = normalize_siem_event(event)
        assert r["source_ip"] == "10.0.0.1"
        assert r["destination_ip"] == "10.0.0.2"
        assert r["username"] == "admin"
        assert r["hostname"] == "srv-01"
        assert r["_field_style"] == "splunk"

    def test_splunk_alt_fields(self):
        event = {"src": "1.2.3.4", "dst": "5.6.7.8", "src_user": "root"}
        r = normalize_siem_event(event)
        assert r["source_ip"] == "1.2.3.4"
        assert r["destination_ip"] == "5.6.7.8"
        assert r["username"] == "root"


class TestElasticNormalization:
    def test_nested_elastic(self):
        event = {"source": {"ip": "10.0.0.1"}, "user": {"name": "admin"},
                 "host": {"name": "srv-01"}, "rule": {"name": "BruteForce"}, "raw_log": "test"}
        r = normalize_siem_event(event)
        assert r["source_ip"] == "10.0.0.1"
        assert r["username"] == "admin"
        assert r["hostname"] == "srv-01"
        assert r["rule_name"] == "BruteForce"
        assert r["_field_style"] == "elastic"

    def test_deep_nesting(self):
        event = {"source": {"ip": "1.2.3.4", "port": 443},
                 "destination": {"ip": "5.6.7.8", "port": 80}}
        r = normalize_siem_event(event)
        assert r["source_ip"] == "1.2.3.4"
        assert r["destination_ip"] == "5.6.7.8"
        assert r["source_port"] == 443
        assert r["destination_port"] == 80


class TestFirewallNormalization:
    def test_firewall_fields(self):
        event = {"SrcAddr": "10.0.0.1", "DstAddr": "10.0.0.2",
                 "User": "admin", "DeviceName": "fw-01",
                 "SignatureName": "BruteForce", "Proto": "TCP", "Action": "deny"}
        r = normalize_siem_event(event)
        assert r["source_ip"] == "10.0.0.1"
        assert r["hostname"] == "fw-01"
        assert r["protocol"] == "TCP"
        assert r["action"] == "deny"
        assert r["_field_style"] == "firewall"


class TestLegacyNormalization:
    def test_legacy_fields(self):
        event = {"sourceAddress": "10.0.0.1", "accountName": "admin",
                 "computer_name": "ws-01", "alert_name": "BruteForce"}
        r = normalize_siem_event(event)
        assert r["source_ip"] == "10.0.0.1"
        assert r["username"] == "admin"
        assert r["hostname"] == "ws-01"
        assert r["_field_style"] == "legacy"


class TestTypeCoercion:
    def test_port_coercion(self):
        event = {"src_ip": "1.2.3.4", "src_port": "443", "dest_port": "80"}
        r = normalize_siem_event(event)
        assert r["source_port"] == 443
        assert r["destination_port"] == 80

    def test_invalid_port(self):
        event = {"src_ip": "1.2.3.4", "src_port": "99999"}
        r = normalize_siem_event(event)
        assert r["source_port"] is None

    def test_severity_lowercase(self):
        event = {"src_ip": "1.2.3.4", "severity": "CRITICAL"}
        r = normalize_siem_event(event)
        assert r["severity"] == "critical"


class TestEventIdExtraction:
    def test_extract_from_raw_log(self):
        event = {"src_ip": "1.2.3.4", "raw_log": "EventID=4769 ServiceName=MSSQLSvc"}
        r = normalize_siem_event(event)
        assert r["event_id"] == "4769"

    def test_no_event_id(self):
        event = {"src_ip": "1.2.3.4", "raw_log": "simple log message"}
        r = normalize_siem_event(event)
        assert "event_id" not in r or r.get("event_id") is None

    def test_existing_event_id_preserved(self):
        event = {"src_ip": "1.2.3.4", "event_id": "1234", "raw_log": "EventID=5678"}
        r = normalize_siem_event(event)
        assert r["event_id"] == "1234"


class TestMetadata:
    def test_original_fields_audit(self):
        event = {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}
        r = normalize_siem_event(event)
        assert r["_original_fields"]["source_ip"] == "src_ip"
        assert r["_original_fields"]["destination_ip"] == "dest_ip"

    def test_normalizer_version(self):
        event = {"src_ip": "10.0.0.1"}
        r = normalize_siem_event(event)
        assert r["_normalizer_version"] == "1.0"

    def test_unknown_fields_passthrough(self):
        event = {"src_ip": "10.0.0.1", "custom_field": "custom_value"}
        r = normalize_siem_event(event)
        assert r["custom_field"] == "custom_value"

    def test_internal_fields_preserved(self):
        event = {"src_ip": "10.0.0.1", "_sanitized": True}
        r = normalize_siem_event(event)
        assert r["_sanitized"] is True


class TestEdgeCases:
    def test_empty_event(self):
        r = normalize_siem_event({})
        assert r["_field_style"] == "unknown"

    def test_non_dict_input(self):
        assert normalize_siem_event("string") == "string"
        assert normalize_siem_event(None) is None

    def test_get_zcs_field_helper(self):
        event = normalize_siem_event({"src_ip": "10.0.0.1"})
        assert get_zcs_field(event, "source_ip") == "10.0.0.1"
        assert get_zcs_field(event, "missing", "default") == "default"
