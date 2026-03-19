import json
import time
from typing import Optional, Tuple

CORRELATION_WINDOW_TTL = 900  # 15 minutes
MAX_MERGED_ALERTS = 20


def _correlation_key(alert: dict) -> str:
    return f"dedup:corr:{alert.get('rule_name', '')}:{alert.get('source_ip', '')}:{alert.get('hostname', '')}"


def check_correlation(alert: dict, redis_client) -> Tuple[Optional[str], int]:
    key = _correlation_key(alert)
    data = redis_client.get(key)
    if not data:
        return None, 0
    record = json.loads(data)
    task_id = record['task_id']
    merged_count = len(record.get('merged_alerts', []))
    if merged_count >= MAX_MERGED_ALERTS:
        return None, merged_count  # Cap exceeded, spawn new investigation
    return task_id, merged_count


def register_correlation(alert: dict, task_id: str, redis_client):
    key = _correlation_key(alert)
    record = {
        'task_id': task_id,
        'merged_alerts': [],
        'created_at': time.time(),
    }
    redis_client.setex(key, CORRELATION_WINDOW_TTL, json.dumps(record))


def merge_alert(alert: dict, existing_task_id: str, redis_client):
    key = _correlation_key(alert)
    data = redis_client.get(key)
    if not data:
        return
    record = json.loads(data)
    record['merged_alerts'].append({
        'source_ip': alert.get('source_ip', ''),
        'timestamp': time.time(),
        'raw_log_snippet': alert.get('raw_log', '')[:200],
    })
    ttl = redis_client.ttl(key)
    if ttl > 0:
        redis_client.setex(key, ttl, json.dumps(record))

    _update_investigation_context(existing_task_id, record['merged_alerts'])


def _update_investigation_context(task_id: str, merged_alerts: list):
    import os
    try:
        import psycopg2
        conn = psycopg2.connect(os.environ.get('DATABASE_URL', ''))
        cur = conn.cursor()
        cur.execute(
            'UPDATE investigations SET merged_context = %s WHERE task_id = %s',
            (json.dumps(merged_alerts), task_id)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Warning: failed to update merged context for {task_id}: {e}")
