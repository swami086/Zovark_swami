import hashlib
import json
import re
from typing import Optional

EXACT_DEDUP_TTL_BY_SEVERITY = {
    'critical': 60,
    'high': 300,
    'medium': 900,
    'low': 3600,
    'info': 7200,
}

TIMESTAMP_PATTERNS = [
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',
    r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
    r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
]


def normalize_raw_log(raw_log: str) -> str:
    for pattern in TIMESTAMP_PATTERNS:
        raw_log = re.sub(pattern, 'TIMESTAMP', raw_log)
    return raw_log


def compute_alert_hash(alert: dict) -> str:
    canonical = {
        'rule_name': alert.get('rule_name', ''),
        'source_ip': alert.get('source_ip', ''),
        'destination_ip': alert.get('destination_ip', ''),
        'hostname': alert.get('hostname', ''),
        'username': alert.get('username', ''),
        'raw_log': normalize_raw_log(alert.get('raw_log', '')),
    }
    content = json.dumps(canonical, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()


def check_exact_dedup(alert: dict, redis_client) -> Optional[str]:
    alert_hash = compute_alert_hash(alert)
    existing = redis_client.get(f'dedup:exact:{alert_hash}')
    return existing.decode() if existing else None


def register_alert(alert: dict, task_id: str, redis_client):
    severity = alert.get('severity', 'high').lower()
    ttl = EXACT_DEDUP_TTL_BY_SEVERITY.get(severity, 300)
    alert_hash = compute_alert_hash(alert)
    redis_client.setex(f'dedup:exact:{alert_hash}', ttl, task_id)
