"""Per-tenant token quota enforcement.

Checks before LLM calls, updates after. Circuit breaker prevents runaway costs.

Tables used: token_quotas, token_usage_events
"""

import json
import os

import psycopg2
from psycopg2.extras import RealDictCursor
from temporalio import activity

import logger


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn
async def check_token_quota(tenant_id: str) -> dict:
    """Check if a tenant has remaining token quota.

    Args:
        tenant_id: Tenant UUID
    Returns:
        {allowed, reason, pct_used, warning, tokens_remaining}
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT monthly_token_limit, tokens_used, cost_used_usd,
                       warn_threshold_pct, hard_limit_pct, circuit_breaker_open,
                       current_period_start
                FROM token_quotas
                WHERE tenant_id = %s
                LIMIT 1
            """, (tenant_id,))
            row = cur.fetchone()

            if not row:
                # No quota configured — allow by default
                return {"allowed": True, "reason": "no_quota_configured",
                        "pct_used": 0, "warning": None, "tokens_remaining": None}

            if row["circuit_breaker_open"]:
                logger.warn("Token quota circuit breaker open", tenant_id=tenant_id)
                return {"allowed": False, "reason": "circuit_breaker",
                        "pct_used": 100, "warning": None, "tokens_remaining": 0}

            limit = row["monthly_token_limit"] or 0
            used = row["tokens_used"] or 0
            warn_pct = row["warn_threshold_pct"] or 80
            hard_pct = row["hard_limit_pct"] or 100

            if limit <= 0:
                return {"allowed": True, "reason": "unlimited",
                        "pct_used": 0, "warning": None, "tokens_remaining": None}

            pct_used = round((used / limit) * 100, 2)
            tokens_remaining = max(0, limit - used)
            hard_threshold = limit * hard_pct / 100
            warn_threshold = limit * warn_pct / 100

            if used >= hard_threshold:
                logger.warn("Token quota hard limit reached",
                            tenant_id=tenant_id, pct_used=pct_used)
                return {"allowed": False, "reason": "quota_exceeded",
                        "pct_used": pct_used, "warning": None, "tokens_remaining": 0}

            warning = None
            if used >= warn_threshold:
                warning = "approaching_limit"
                logger.info("Token quota warning threshold reached",
                            tenant_id=tenant_id, pct_used=pct_used)

            return {"allowed": True, "reason": "within_quota",
                    "pct_used": pct_used, "warning": warning,
                    "tokens_remaining": tokens_remaining}
    finally:
        conn.close()


@activity.defn
async def record_token_usage(params: dict) -> dict:
    """Record token usage for a tenant and check thresholds.

    Args:
        params: {tenant_id, task_id, model_id, tokens_input, tokens_output, cost_usd}
    Returns:
        {tokens_used_total, cost_used_total, threshold_crossed}
    """
    tenant_id = params["tenant_id"]
    task_id = params.get("task_id")
    model_id = params.get("model_id", "unknown")
    tokens_input = params.get("tokens_input", 0)
    tokens_output = params.get("tokens_output", 0)
    cost_usd = params.get("cost_usd", 0.0)

    total_tokens = tokens_input + tokens_output

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Insert usage event
            cur.execute("""
                INSERT INTO token_usage_events
                    (tenant_id, task_id, model_id, tokens_input, tokens_output, cost_usd)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (tenant_id, task_id, model_id, tokens_input, tokens_output, cost_usd))

            # Atomic update of quota counters
            cur.execute("""
                UPDATE token_quotas
                SET tokens_used = tokens_used + %s,
                    cost_used_usd = cost_used_usd + %s,
                    updated_at = NOW()
                WHERE tenant_id = %s
                RETURNING tokens_used, cost_used_usd, monthly_token_limit,
                          warn_threshold_pct, hard_limit_pct
            """, (total_tokens, cost_usd, tenant_id))
            row = cur.fetchone()

        conn.commit()

        if not row:
            return {"tokens_used_total": total_tokens, "cost_used_total": cost_usd,
                    "threshold_crossed": None}

        tokens_used = row["tokens_used"] or 0
        cost_used = float(row["cost_used_usd"] or 0)
        limit = row["monthly_token_limit"] or 0
        warn_pct = row["warn_threshold_pct"] or 80
        hard_pct = row["hard_limit_pct"] or 100

        threshold_crossed = None
        if limit > 0:
            pct = (tokens_used / limit) * 100
            # Check if we just crossed the hard threshold
            prev_pct = ((tokens_used - total_tokens) / limit) * 100
            if pct >= hard_pct and prev_pct < hard_pct:
                threshold_crossed = "hard"
                logger.warn("Token quota hard threshold crossed",
                            tenant_id=tenant_id, pct=pct)
            elif pct >= warn_pct and prev_pct < warn_pct:
                threshold_crossed = "warn"
                logger.info("Token quota warn threshold crossed",
                            tenant_id=tenant_id, pct=pct)

        return {
            "tokens_used_total": tokens_used,
            "cost_used_total": cost_used,
            "threshold_crossed": threshold_crossed,
        }
    finally:
        conn.close()


@activity.defn
async def reset_monthly_quota(tenant_id: str) -> dict:
    """Reset monthly token quota for a tenant.

    Called by monthly scheduled workflow. Resets tokens_used and cost_used_usd
    to 0 and updates current_period_start.

    Args:
        tenant_id: Tenant UUID
    Returns:
        {reset, previous_tokens_used, previous_cost_used}
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Capture previous values before reset
            cur.execute("""
                UPDATE token_quotas
                SET tokens_used = 0,
                    cost_used_usd = 0,
                    current_period_start = NOW(),
                    circuit_breaker_open = false,
                    updated_at = NOW()
                WHERE tenant_id = %s
                RETURNING tokens_used AS old_tokens, cost_used_usd AS old_cost
            """, (tenant_id,))
            # Note: RETURNING gives the NEW values (0, 0) — we need a different approach
            # Use a CTE to capture old values
            conn.rollback()

            cur.execute("""
                WITH old AS (
                    SELECT tokens_used, cost_used_usd
                    FROM token_quotas WHERE tenant_id = %s
                )
                UPDATE token_quotas
                SET tokens_used = 0,
                    cost_used_usd = 0,
                    current_period_start = NOW(),
                    circuit_breaker_open = false,
                    updated_at = NOW()
                WHERE tenant_id = %s
                RETURNING (SELECT tokens_used FROM old) AS prev_tokens,
                          (SELECT cost_used_usd FROM old) AS prev_cost
            """, (tenant_id, tenant_id))
            row = cur.fetchone()
        conn.commit()

        prev_tokens = row["prev_tokens"] if row else 0
        prev_cost = float(row["prev_cost"]) if row else 0.0

        logger.info("Monthly quota reset",
                    tenant_id=tenant_id, prev_tokens=prev_tokens, prev_cost=prev_cost)

        return {
            "reset": True,
            "previous_tokens_used": prev_tokens or 0,
            "previous_cost_used": prev_cost,
        }
    finally:
        conn.close()


@activity.defn
async def trip_circuit_breaker(params: dict) -> dict:
    """Trip the circuit breaker for a tenant's token quota.

    Immediately blocks all LLM calls for this tenant.

    Args:
        params: {tenant_id, reason, actor_id}
    Returns:
        {tripped, tenant_id, reason}
    """
    tenant_id = params["tenant_id"]
    reason = params.get("reason", "manual")
    actor_id = params.get("actor_id")

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE token_quotas
                SET circuit_breaker_open = true, updated_at = NOW()
                WHERE tenant_id = %s
            """, (tenant_id,))

            # Log audit event
            cur.execute("""
                INSERT INTO audit_events
                    (tenant_id, event_type, actor_id, actor_type, resource_type, resource_id, metadata)
                VALUES (%s, 'circuit_breaker_tripped', %s, %s, 'token_quota', %s, %s)
            """, (
                tenant_id,
                actor_id,
                "user" if actor_id else "system",
                tenant_id,
                json.dumps({"reason": reason}),
            ))
        conn.commit()
    finally:
        conn.close()

    logger.warn("Circuit breaker tripped",
                tenant_id=tenant_id, reason=reason, actor_id=actor_id)

    return {
        "tripped": True,
        "tenant_id": tenant_id,
        "reason": reason,
    }
