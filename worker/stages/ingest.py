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

from temporalio import activity
from stages import IngestOutput
from stages.input_sanitizer import sanitize_siem_event
from stages.normalizer import normalize_siem_event
from stages.smart_batcher import get_batcher

# --- Config ---
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
DEDUP_ENABLED = os.environ.get("DEDUP_ENABLED", "true").lower() == "true"
FAST_FILL = os.environ.get("ZOVARK_FAST_FILL", "false").lower() == "true"


# --- DB helper ---
def _get_db():
    return psycopg2.connect(DATABASE_URL)


# --- Inverted benign detection (recognize attacks, not benign) ---
ATTACK_INDICATORS = [
    "malware", "trojan", "ransomware", "exploit", "vulnerability",
    "injection", "overflow", "brute", "credential_dump", "mimikatz",
    "cobalt", "beacon", "exfiltration", "lateral", "escalation",
    "c2", "command_and_control", "phishing", "suspicious",
    "unauthorized", "anomal", "attack", "intrusion", "compromise",
    "kerberoast", "dcsync", "pass_the_hash", "pass_the_ticket",
    "golden_ticket", "lolbin", "process_injection", "dll_sideload",
    "persistence", "wmi_abuse", "credential_dumping", "rdp_tunnel",
    "dns_exfil", "powershell_obfusc", "office_macro", "webshell",
]


def _has_attack_indicators(task_type: str, rule_name: str, title: str) -> bool:
    """Check if any field contains attack-related terminology."""
    combined = f"{task_type} {rule_name} {title}".lower()
    return any(indicator in combined for indicator in ATTACK_INDICATORS)


# HIGH-CONFIDENCE attack content patterns in raw_log (Red team patch)
# These indicate real attacks regardless of what the metadata says
RAW_LOG_ATTACK_PATTERNS = [
    r'(?i)mimikatz|sekurlsa|lsadump|kerberos::',
    r'(?i)certutil\s+(-urlcache|-split|-f\s+http)',
    r'(?i)bitsadmin.*transfer.*http',
    r'(?i)mshta\s+http',
    r'(?i)rundll32.*javascript',
    r'(?i)wscript.*\.(js|vbs)\b',
    r'(?i)powershell.*(-enc\b|-encodedcommand)',
    r'(?i)invoke-(mimikatz|expression|webrequest)',
    r'(?i)net\s+(user|localgroup)\s+.*(/add|/delete)',
    r'(?i)schtasks.*/create.*(/sc|/tn|/tr)',
    r'(?i)reg\s+add.*\\\\run\b',
    r'(?i)vssadmin.*delete\s+shadows',
    r'(?i)wmic.*process\s+call\s+create',
    r'(?i)psexec|paexec',
    r'(?i)impacket|secretsdump|ntlmrelayx',
    r'(?i)bloodhound|sharphound',
    r'(?i)rubeus\s+(asreproast|kerberoast|hash)',
    r'(?i)\\\\[^\\]+\\(c|admin|ipc)\$',
    r'(?i)CreateRemoteThread|NtMapViewOfSection',
    r'(?i)lsass\.exe|ntds\.dit|sam\s+dump',
]


def _has_raw_log_attack_content(raw_log: str) -> bool:
    """Check if raw_log contains high-confidence attack indicators."""
    if not raw_log or len(raw_log) < 10:
        return False
    for pattern in RAW_LOG_ATTACK_PATTERNS:
        if re.search(pattern, raw_log):
            return True
    return False


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


# --- Fetch task from DB (not @activity.defn — legacy fetch_task is registered) ---
async def fetch_task(task_id: str) -> dict:
    """Load task from agent_tasks table. Shared by V2 workflow."""
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, tenant_id, task_type, input, status, trace_id FROM agent_tasks WHERE id = %s", (task_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Task {task_id} not found")
            row['id'] = str(row['id'])
            row['tenant_id'] = str(row['tenant_id'])
            row['trace_id'] = str(row['trace_id']) if row.get('trace_id') else ""
            return dict(row)
    finally:
        conn.close()


# --- Main entry point ---
@activity.defn
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
    siem_event = sanitize_siem_event(siem_event)
    if siem_event.get("_injection_warning"):
        activity.logger.warning(f"Prompt injection patterns detected in SIEM data for task {task_id}")
    siem_event = normalize_siem_event(siem_event)
    activity.logger.info(f"Normalized: style={siem_event.get('_field_style', 'unknown')}, fields={len(siem_event.get('_original_fields', {}))}")
    prompt = task_data.get("input", {}).get("prompt", "")

    # --- Redis client (shared by smart batcher + dedup) ---
    _redis_client = None
    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL)
    except Exception as e:
        print(f"Redis connection failed (non-fatal, batcher/dedup use fallback): {e}")

    # --- Smart batching: aggregate similar alerts within time window ---
    if siem_event and _redis_client:
        try:
            batcher = get_batcher(_redis_client)
            severity = task_data.get("input", {}).get("severity", "medium")
            should_skip, aggregated = batcher.should_batch(task_type, siem_event, severity)

            if should_skip:
                activity.logger.info(f"Smart batcher: alert absorbed into batch for {task_type}")
                return asdict(IngestOutput(
                    task_id=task_id,
                    tenant_id=tenant_id,
                    task_type=task_type,
                    siem_event=siem_event,
                    prompt="",
                    is_duplicate=True,
                    duplicate_of="batch",
                    dedup_reason="smart_batch",
                ))

            if aggregated:
                siem_event = aggregated
                activity.logger.info(f"Smart batcher: processing aggregated batch of {aggregated.get('_batch_count', 1)} alerts")
        except Exception as e:
            print(f"Smart batching failed (non-fatal): {e}")

    result = IngestOutput(
        task_id=task_id,
        tenant_id=tenant_id,
        task_type=task_type,
        siem_event=siem_event,
        prompt=prompt,
    )

    # --- Dedup (Redis) ---
    if DEDUP_ENABLED and siem_event and _redis_client:
        try:
            alert_for_dedup = {**siem_event, "task_type": task_type}
            match = _check_exact_dedup(alert_for_dedup, _redis_client)
            if match:
                result.is_duplicate = True
                result.duplicate_of = match
                result.dedup_reason = "exact_duplicate"
                return asdict(result)
            # Register for future dedup
            _register_dedup(alert_for_dedup, task_id, _redis_client)
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
                # Red team patch: content-based override
                # If skill routes to benign but raw_log has attack content, block benign routing
                skill_slug = skill.get("skill_slug", "")
                if skill_slug == "benign-system-event":
                    raw_log = siem_event.get("raw_log", "")
                    if _has_raw_log_attack_content(raw_log):
                        activity.logger.warning(
                            f"Classification override: benign metadata but attack content "
                            f"in raw_log for task {task_id}. Forcing investigation."
                        )
                        skill = None  # Clear benign skill — force Path C investigation

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
