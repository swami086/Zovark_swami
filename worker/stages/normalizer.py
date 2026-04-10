"""
Zovark Core — Log Normalizer (deprecated).

SIEM payloads are normalized to OCSF 1.3 at the Go API (api/ocsf_normalizer.go).
This module is retained for tests and backward compatibility; normalize_siem_event is a no-op passthrough.
"""
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)
NORMALIZER_VERSION = "1.0"

FIELD_MAPPINGS = {
    # Splunk
    "src_ip": "source_ip", "src": "source_ip", "src_addr": "source_ip",
    "dest_ip": "destination_ip", "dest": "destination_ip", "dst_ip": "destination_ip",
    "dst": "destination_ip", "dest_addr": "destination_ip",
    "user": "username", "src_user": "username", "account_name": "username",
    "host": "hostname", "src_host": "hostname", "dvc": "hostname",
    "src_port": "source_port", "dest_port": "destination_port", "dst_port": "destination_port",
    "process": "process_name", "Image": "process_name",
    "search_name": "rule_name", "ss_name": "rule_name",
    # Elastic (flattened dot notation)
    "source.ip": "source_ip", "source.address": "source_ip",
    "destination.ip": "destination_ip", "destination.address": "destination_ip",
    "user.name": "username", "user.id": "username",
    "host.name": "hostname", "host.hostname": "hostname",
    "source.port": "source_port", "destination.port": "destination_port",
    "process.name": "process_name", "process.executable": "process_name",
    "rule.name": "rule_name", "signal.rule.name": "rule_name",
    # Firewall
    "SrcAddr": "source_ip", "SrcIP": "source_ip",
    "DstAddr": "destination_ip", "DstIP": "destination_ip",
    "User": "username", "DeviceName": "hostname", "Device": "hostname",
    "SrcPort": "source_port", "DstPort": "destination_port",
    "Application": "process_name",
    "SignatureName": "rule_name", "AlertName": "rule_name",
    "Proto": "protocol", "Action": "action",
    # Legacy
    "sourceAddress": "source_ip", "remote_ip": "source_ip",
    "clientip": "source_ip", "client_ip": "source_ip",
    "destinationAddress": "destination_ip", "server_ip": "destination_ip",
    "accountName": "username", "userName": "username", "user_name": "username",
    "computer_name": "hostname", "machine_name": "hostname", "workstation": "hostname",
    "s_port": "source_port", "d_port": "destination_port",
    "exe": "process_name", "alert_name": "rule_name", "signature": "rule_name",
    # Common (passthrough)
    "severity": "severity", "raw_log": "raw_log", "title": "title",
    "message": "raw_log", "msg": "raw_log",
    "rule_name": "rule_name", "process_name": "process_name",
    "event_id": "event_id", "EventID": "event_id", "winlog.event_id": "event_id",
    "source_ip": "source_ip", "destination_ip": "destination_ip",
    "username": "username", "hostname": "hostname",
}


def _flatten_nested(event: dict, prefix: str = "", result: dict = None) -> dict:
    if result is None:
        result = {}
    for key, value in event.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            _flatten_nested(value, full_key, result)
        else:
            result[full_key] = value
    return result


def _detect_field_style(event: dict) -> str:
    keys = set(event.keys())
    has_nested = any(isinstance(v, dict) for v in event.values())
    flat_keys = set(_flatten_nested(event).keys()) if has_nested else keys

    if any(k.startswith(("source.", "destination.", "host.", "user.", "process.")) for k in flat_keys):
        return "elastic"
    if any(k in keys for k in ("src_ip", "dest_ip", "src", "dest")):
        return "splunk"
    if any(k in keys for k in ("SrcAddr", "DstAddr", "SrcIP", "DstIP", "Proto")):
        return "firewall"
    if any(k in keys for k in ("sourceAddress", "destinationAddress", "accountName", "remote_ip")):
        return "legacy"
    return "unknown"


def _coerce_port(value) -> Optional[int]:
    if value is None:
        return None
    try:
        port = int(value)
        return port if 0 < port <= 65535 else None
    except (ValueError, TypeError):
        return None


def _extract_event_id(raw_log: str) -> Optional[str]:
    if not raw_log:
        return None
    match = re.search(r'EventID[=: ]*(\d+)', raw_log, re.IGNORECASE)
    return match.group(1) if match else None


def normalize_siem_event(event: dict) -> dict:
    """Deprecated: API emits OCSF; worker enriches flat fields in ingest. Passthrough only."""
    return event


def get_zcs_field(event: dict, canonical_name: str, default=None):
    return event.get(canonical_name, default)
