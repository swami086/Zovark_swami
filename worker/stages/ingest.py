"""
Stage 1: INGEST — Validate, deduplicate, PII mask.
NO LLM calls. Only Redis + DB.

Self-contained: imports psycopg2, redis directly.
Does NOT import from _legacy_activities.py.
"""
import os
import json
import hashlib
import re
import time
from typing import Optional
from dataclasses import asdict

import psycopg2
from psycopg2.extras import RealDictCursor

from stages import IngestOutput

# --- Config ---
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
DEDUP_ENABLED = os.environ.get("DEDUP_ENABLED", "true").lower() == "true"
FAST_FILL = os.environ.get("HYDRA_FAST_FILL", "false").lower() == "true"


# --- DB helper ---
def _get_db():
    return psycopg2.connect(DATABASE_URL)


# --- Dedup (inlined from dedup/stage1_exact.py) ---
TIMESTAMP_PATTERNS = [
    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',
    r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
    r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}',
]
DEDUP_TTL = {'critical': 60, 'high': 300, 'medium': 900, 'low': 3600, 'info': 7200}


def _normalize_raw_log(raw_log: str) -> str:
    for p in TIMESTAMP_PATTERNS:
        raw_log = re.sub(p, 'TIMESTAMP', raw_log)
    return raw_log


def _compute_alert_hash(alert: dict) -> str:
    canonical = {
        'rule_name': alert.get('rule_name', ''),
        'source_ip': alert.get('source_ip', ''),
        'destination_ip': alert.get('destination_ip', ''),
        'hostname': alert.get('hostname', ''),
        'username': alert.get('username', ''),
        'raw_log': _normalize_raw_log(alert.get('raw_log', '')),
    }
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def _check_exact_dedup(alert: dict, redis_client) -> Optional[str]:
    alert_hash = _compute_alert_hash(alert)
    existing = redis_client.get(f'dedup:exact:{alert_hash}')
    return existing.decode() if existing else None


def _register_dedup(alert: dict, task_id: str, redis_client):
    severity = alert.get('severity', 'high').lower()
    ttl = DEDUP_TTL.get(severity, 300)
    alert_hash = _compute_alert_hash(alert)
    redis_client.setex(f'dedup:exact:{alert_hash}', ttl, task_id)


# --- PII masking (simplified — regex-based, no Redis entity map) ---
PII_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS_KEY'),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
    (r'\b(?:sk|pk|api|key|token|secret|bearer)[_-]?[A-Za-z0-9]{20,}\b', 'API_KEY'),
]


def _mask_pii(text: str) -> tuple:
    """Simple regex PII masking. Returns (masked_text, was_masked)."""
    masked = text
    count = 0
    for pattern, label in PII_PATTERNS:
        matches = re.findall(pattern, masked)
        for i, m in enumerate(matches):
            masked = masked.replace(m, f'[{label}_{i}]', 1)
            count += 1
    return masked, count > 0


# --- Skill retrieval (DB only, no LLM) ---
def _retrieve_skill(task_type: str, prompt: str, conn) -> Optional[dict]:
    """Find matching skill template. Pure DB query."""
    tt = task_type.lower().replace(" ", "_")
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Priority 1: exact threat_type match
            cur.execute("""
                SELECT id, skill_name, skill_slug, investigation_methodology,
                       detection_patterns, mitre_techniques, code_template, parameters
                FROM agent_skills
                WHERE is_active = true AND code_template IS NOT NULL
                AND %s = ANY(threat_types)
                ORDER BY times_used DESC LIMIT 1
            """, (tt,))
            row = cur.fetchone()

            # Priority 2: prefix match
            if not row:
                cur.execute("""
                    SELECT id, skill_name, skill_slug, investigation_methodology,
                           detection_patterns, mitre_techniques, code_template, parameters
                    FROM agent_skills
                    WHERE is_active = true AND code_template IS NOT NULL
                    AND EXISTS (SELECT 1 FROM unnest(threat_types) t WHERE t LIKE %s || '%%' OR %s LIKE t || '%%')
                    ORDER BY times_used DESC LIMIT 1
                """, (tt, tt))
                row = cur.fetchone()

            if row:
                cur.execute("UPDATE agent_skills SET times_used = times_used + 1 WHERE id = %s", (row['id'],))
                conn.commit()
                return dict(row)
    except Exception as e:
        print(f"Skill retrieval failed (non-fatal): {e}")
    return None


# --- Main entry point ---
async def ingest_alert(task_data: dict) -> dict:
    """
    Stage 1: Validate, deduplicate, prepare alert for analysis.
    NO LLM calls. Only Redis + DB.

    Returns dict (serializable IngestOutput fields).
    """
    task_id = task_data.get("task_id", "")
    tenant_id = task_data.get("tenant_id", "")
    task_type = task_data.get("task_type", "")
    siem_event = task_data.get("input", {}).get("siem_event", {})
    prompt = task_data.get("input", {}).get("prompt", "")

    result = IngestOutput(
        task_id=task_id,
        tenant_id=tenant_id,
        task_type=task_type,
        siem_event=siem_event,
        prompt=prompt,
    )

    # --- Dedup (Redis) ---
    if DEDUP_ENABLED and siem_event:
        try:
            import redis
            r = redis.from_url(REDIS_URL)
            alert_for_dedup = {**siem_event, "task_type": task_type}
            match = _check_exact_dedup(alert_for_dedup, r)
            if match:
                result.is_duplicate = True
                result.duplicate_of = match
                result.dedup_reason = "exact_duplicate"
                return asdict(result)
            # Register for future dedup
            _register_dedup(alert_for_dedup, task_id, r)
        except Exception as e:
            print(f"Dedup check failed (non-fatal): {e}")

    # --- PII masking ---
    if prompt:
        masked_prompt, was_masked = _mask_pii(prompt)
        if was_masked:
            result.pii_masked = True
            result.prompt = masked_prompt

    # --- Skill retrieval ---
    try:
        conn = _get_db()
        try:
            skill = _retrieve_skill(task_type, prompt, conn)
            if skill:
                result.skill_id = str(skill.get("id", ""))
                result.skill_template = skill.get("code_template")
                result.skill_params = skill.get("parameters", [])
                result.skill_methodology = skill.get("investigation_methodology", "")
        finally:
            conn.close()
    except Exception as e:
        print(f"Skill retrieval failed (non-fatal): {e}")

    return asdict(result)
