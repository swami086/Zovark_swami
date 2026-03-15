"""Tests for PlaybookTemplateResolver."""
import pytest
from response.template_resolver import PlaybookTemplateResolver


@pytest.fixture
def resolver():
    return PlaybookTemplateResolver()


@pytest.fixture
def investigation_data():
    return {
        'investigation': {
            'id': 'inv-001',
            'tenant_id': 'tenant-abc',
            'alert_id': 'alert-123',
            'risk_score': 85,
            'severity': 'critical',
            'mitre_techniques': ['T1566.001', 'T1059'],
            'created_at': '2026-03-15T10:00:00Z',
            'findings_summary': 'Phishing email with malicious attachment detected',
        },
        'entities': [
            {'entity_type': 'ip_address', 'value': '10.0.0.50', 'role': 'attacker'},
            {'entity_type': 'ip_address', 'value': '192.168.1.100', 'role': 'victim'},
            {'entity_type': 'hostname', 'value': 'workstation-42', 'role': 'source'},
            {'entity_type': 'domain', 'value': 'evil-phish.com', 'role': None},
            {'entity_type': 'hash', 'value': 'abc123def456', 'role': None},
            {'entity_type': 'user', 'value': 'jdoe@corp.com', 'role': None},
            {'entity_type': 'user', 'value': 'admin@corp.com', 'role': None},
        ],
    }


def test_simple_ip_resolution(resolver, investigation_data):
    """Variable {{attacker_ip}} resolves to the attacker entity."""
    result = resolver.resolve("Block IP {{attacker_ip}}", investigation_data)
    assert result == "Block IP 10.0.0.50"


def test_multiple_variables(resolver, investigation_data):
    """Multiple variables resolved in one string."""
    template = "Alert {{alert_id}} risk={{risk_score}} technique={{mitre_technique}}"
    result = resolver.resolve(template, investigation_data)
    assert result == "Alert alert-123 risk=85 technique=T1566.001"


def test_missing_variable(resolver, investigation_data):
    """Unknown variable becomes [UNKNOWN:name]."""
    result = resolver.resolve("Host {{nonexistent_var}}", investigation_data)
    assert result == "Host [UNKNOWN:nonexistent_var]"


def test_no_templates(resolver, investigation_data):
    """String without templates passes through unchanged."""
    result = resolver.resolve("No templates here", investigation_data)
    assert result == "No templates here"


def test_nested_context(resolver, investigation_data):
    """resolve_action_context handles nested dicts and lists."""
    action = {
        "type": "block_ip",
        "ip": "{{attacker_ip}}",
        "metadata": {
            "investigation": "{{investigation_id}}",
            "severity": "{{severity}}",
        },
        "tags": ["{{mitre_technique}}", "auto-response"],
        "count": 42,
    }
    result = resolver.resolve_action_context(action, investigation_data)
    assert result["ip"] == "10.0.0.50"
    assert result["metadata"]["investigation"] == "inv-001"
    assert result["metadata"]["severity"] == "critical"
    assert result["tags"] == ["T1566.001", "auto-response"]
    assert result["count"] == 42


def test_csv_list(resolver, investigation_data):
    """IOC list collects ip_address, domain, hash as CSV."""
    result = resolver.resolve("IOCs: {{ioc_list}}", investigation_data)
    assert "10.0.0.50" in result
    assert "evil-phish.com" in result
    assert "abc123def456" in result


def test_injection_in_value_no_reresolution(resolver):
    """Values containing {{ }} are sanitized — no re-resolution."""
    data = {
        'investigation': {
            'id': 'inv-002',
            'findings_summary': 'Attack used {{attacker_ip}} in payload',
        },
        'entities': [],
    }
    result = resolver.resolve("Summary: {{finding_summary}}", data)
    # The {{ }} in the value should be stripped
    assert '{{' not in result
    assert 'attacker_ip' in result  # Text preserved but without braces
    assert result == "Summary: Attack used attacker_ip in payload"
