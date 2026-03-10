"""Investigation result cache — skip re-investigation for identical indicators.

SHA-256 hash of normalized, sorted indicators → cached verdict + report.
24-hour TTL by default.
"""

import hashlib
import json
import os
import re
import psycopg2


def _normalize_indicators(indicators):
    """Extract and normalize IOCs from input dict."""
    iocs = set()
    text = json.dumps(indicators) if isinstance(indicators, dict) else str(indicators)

    # IPs
    for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text):
        if not ip.startswith(('0.', '127.', '255.')):
            iocs.add(f"ip:{ip}")

    # Domains
    for d in re.findall(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b', text):
        d_lower = d.lower()
        if d_lower not in ('example.com', 'localhost.localdomain'):
            iocs.add(f"domain:{d_lower}")

    # SHA256 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{64}\b', text):
        iocs.add(f"sha256:{h.lower()}")

    # MD5 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{32}\b', text):
        iocs.add(f"md5:{h.lower()}")

    return sorted(iocs)


def compute_cache_key(task_input):
    """Compute SHA-256 cache key from normalized indicators."""
    indicators = _normalize_indicators(task_input)
    if not indicators:
        return None
    payload = json.dumps(indicators, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def check_cache(task_input):
    """Check if a cached result exists for these indicators.

    Returns dict with cached result or None.
    """
    cache_key = compute_cache_key(task_input)
    if not cache_key:
        return None

    try:
        db_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
        )
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT investigation_id, task_id, verdict, risk_score,
                           confidence, entity_count, summary
                    FROM investigation_cache
                    WHERE cache_key = %s AND expires_at > NOW()
                    LIMIT 1
                """, (cache_key,))
                row = cur.fetchone()
                if row:
                    return {
                        'cache_hit': True,
                        'cache_key': cache_key,
                        'investigation_id': str(row[0]),
                        'task_id': str(row[1]) if row[1] else None,
                        'verdict': row[2],
                        'risk_score': row[3],
                        'confidence': row[4],
                        'entity_count': row[5],
                        'summary': row[6],
                    }
        finally:
            conn.close()
    except Exception as e:
        print(f"investigation_cache: check failed (non-fatal): {e}")

    return None


def store_cache(task_input, investigation_id, task_id=None,
                verdict=None, risk_score=None, confidence=None,
                entity_count=None, summary=None, ttl_hours=24):
    """Store investigation result in cache."""
    cache_key = compute_cache_key(task_input)
    if not cache_key:
        return

    try:
        db_url = os.environ.get(
            "DATABASE_URL",
            "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra"
        )
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO investigation_cache
                        (cache_key, investigation_id, task_id, verdict,
                         risk_score, confidence, entity_count, summary,
                         ttl_hours, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                            NOW() + make_interval(hours => %s))
                    ON CONFLICT (cache_key) DO UPDATE SET
                        investigation_id = EXCLUDED.investigation_id,
                        task_id = EXCLUDED.task_id,
                        verdict = EXCLUDED.verdict,
                        risk_score = EXCLUDED.risk_score,
                        confidence = EXCLUDED.confidence,
                        entity_count = EXCLUDED.entity_count,
                        summary = EXCLUDED.summary,
                        expires_at = NOW() + make_interval(hours => EXCLUDED.ttl_hours),
                        created_at = NOW()
                """, (
                    cache_key, investigation_id, task_id, verdict,
                    risk_score, confidence, entity_count, summary,
                    ttl_hours, ttl_hours,
                ))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"investigation_cache: store failed (non-fatal): {e}")
