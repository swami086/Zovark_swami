"""Suppression rule validation and audit logging for evaluation failures."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def validate_suppression_rule_syntax(rule: str) -> Tuple[bool, str]:
    """Validate suppression rule at write time.

    Rules are treated as case-insensitive regex patterns over alert text/metadata.
    Returns (ok, error_message).
    """
    if rule is None or not str(rule).strip():
        return False, "empty rule"
    text = str(rule).strip()
    if len(text) > 50_000:
        return False, "rule exceeds max length"
    try:
        re.compile(text, re.IGNORECASE | re.DOTALL)
    except re.error as e:
        return False, f"invalid regex: {e}"
    return True, ""


def log_suppression_eval_failure(
    tenant_id: Optional[str],
    rule_id: str,
    message: str,
    *,
    alert_context: Optional[str] = None,
) -> None:
    """Persist suppression evaluation failures to audit_events (never silent)."""
    try:
        import psycopg2
    except ImportError:
        logger.error("suppression audit: psycopg2 missing — %s", message)
        return

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://zovark:zovark_dev_2026@postgres:5432/zovark",
    )
    tid = tenant_id or "00000000-0000-0000-0000-000000000001"
    try:
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_events
                    (tenant_id, event_type, actor_type, resource_type, resource_id, metadata)
                    VALUES (%s::uuid, %s, %s, %s, %s, %s)
                    """,
                    (
                        tid,
                        "suppression_rule_eval_failed",
                        "system",
                        "suppression_rule",
                        None,
                        json.dumps(
                            {
                                "rule_id": rule_id[:500],
                                "error": message[:4000],
                                "alert_context": (alert_context or "")[:2000],
                            }
                        ),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.error("suppression audit insert failed: %s (orig=%s)", e, message)
