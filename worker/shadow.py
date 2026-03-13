"""Shadow Mode: Hydra generates recommendations, humans decide.

30-day protocol: Pure shadow -> Calibrated assistance -> Measured automation.

Tables used: shadow_recommendations, automation_controls
"""

import json
import os
import time
import uuid
from datetime import timedelta

from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    import httpx
    import psycopg2
    from psycopg2.extras import RealDictCursor
    from llm_logger import log_llm_call
    from model_config import get_tier_config
    from prompt_registry import get_version
    import logger


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn
async def generate_recommendation(params: dict) -> dict:
    """Call LLM to generate a shadow-mode recommendation for an alert.

    Args:
        params: {task_id, tenant_id, investigation_data}
    Returns:
        {recommendation_id, recommended_action, severity, confidence, reasoning}
    """
    task_id = params["task_id"]
    tenant_id = params["tenant_id"]
    investigation_data = params.get("investigation_data", {})

    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")

    tier_config = get_tier_config("generate_recommendation")

    system_prompt = (
        "You are a senior SOC analyst reviewing an investigation result. "
        "Generate a JSON object with exactly these keys: "
        "recommended_action (one of: escalate, contain, dismiss, monitor, investigate_further), "
        "severity (one of: critical, high, medium, low, informational), "
        "confidence (float 0.0-1.0), "
        "reasoning (string explaining your recommendation in 2-3 sentences). "
        "Respond with ONLY valid JSON, no markdown fences."
    )

    user_prompt = f"Investigation data:\n{json.dumps(investigation_data, default=str)[:4000]}"

    payload = {
        "model": tier_config["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": tier_config["max_tokens"],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    start_time = time.time()
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(litellm_url, json=payload, headers=headers)
        response.raise_for_status()
        result = response.json()
    execution_ms = int((time.time() - start_time) * 1000)

    usage = result.get("usage", {})
    log_llm_call(
        activity_name="generate_recommendation",
        model_tier=tier_config["tier"],
        model_id=tier_config["model"],
        prompt_name="shadow_recommendation",
        prompt_version=get_version("shadow_recommendation"),
        input_tokens=usage.get("prompt_tokens", 0),
        output_tokens=usage.get("completion_tokens", 0),
        latency_ms=execution_ms,
        temperature=0.2,
        max_tokens=tier_config["max_tokens"],
        tenant_id=tenant_id,
        task_id=task_id,
    )

    raw = result["choices"][0]["message"]["content"].strip()
    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
    if raw.endswith("```"):
        raw = raw[:-3].strip()

    try:
        rec = json.loads(raw)
    except json.JSONDecodeError:
        rec = {
            "recommended_action": "monitor",
            "severity": "medium",
            "confidence": 0.3,
            "reasoning": raw[:500],
        }

    recommendation_id = str(uuid.uuid4())

    conn = _get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO shadow_recommendations
                    (id, tenant_id, task_id, recommended_action, severity,
                     confidence, reasoning, status, investigation_data)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s)
            """, (
                recommendation_id, tenant_id, task_id,
                rec.get("recommended_action", "monitor"),
                rec.get("severity", "medium"),
                rec.get("confidence", 0.5),
                rec.get("reasoning", ""),
                json.dumps(investigation_data, default=str),
            ))
        conn.commit()
    finally:
        conn.close()

    logger.info("Shadow recommendation generated",
                recommendation_id=recommendation_id, tenant_id=tenant_id, task_id=task_id)

    return {
        "recommendation_id": recommendation_id,
        "recommended_action": rec.get("recommended_action", "monitor"),
        "severity": rec.get("severity", "medium"),
        "confidence": rec.get("confidence", 0.5),
        "reasoning": rec.get("reasoning", ""),
    }


@activity.defn
async def check_automation_mode(params: dict) -> dict:
    """Read automation_controls for a tenant and return current mode.

    Args:
        params: {tenant_id, workflow_name}
    Returns:
        {mode, killed, day}
    """
    tenant_id = params["tenant_id"]
    workflow_name = params.get("workflow_name", "investigation")

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT mode, kill_switch, activated_at,
                       EXTRACT(DAY FROM NOW() - activated_at)::int AS day_number
                FROM automation_controls
                WHERE tenant_id = %s AND workflow_name = %s
                LIMIT 1
            """, (tenant_id, workflow_name))
            row = cur.fetchone()

            if not row:
                return {"mode": "shadow", "killed": False, "day": 0}

            killed = bool(row.get("kill_switch", False))
            mode = "disabled" if killed else row.get("mode", "shadow")
            day = row.get("day_number", 0) or 0

            return {"mode": mode, "killed": killed, "day": day}
    finally:
        conn.close()


@activity.defn
async def record_human_decision(params: dict) -> dict:
    """Record the analyst's decision for a shadow recommendation.

    Args:
        params: {recommendation_id, human_action, human_severity, human_reasoning, decided_by}
    Returns:
        {action_match, severity_match, match_category}
    """
    recommendation_id = params["recommendation_id"]
    human_action = params["human_action"]
    human_severity = params["human_severity"]
    human_reasoning = params.get("human_reasoning", "")
    decided_by = params.get("decided_by")

    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Fetch the original recommendation
            cur.execute("""
                SELECT recommended_action, severity FROM shadow_recommendations
                WHERE id = %s
            """, (recommendation_id,))
            rec = cur.fetchone()
            if not rec:
                raise ValueError(f"Recommendation {recommendation_id} not found")

            action_match = (rec["recommended_action"] == human_action)
            severity_match = (rec["severity"] == human_severity)

            if action_match and severity_match:
                match_category = "exact"
            elif action_match:
                match_category = "action_only"
            elif severity_match:
                match_category = "severity_only"
            else:
                match_category = "mismatch"

            cur.execute("""
                UPDATE shadow_recommendations
                SET status = 'decided',
                    human_action = %s,
                    human_severity = %s,
                    human_reasoning = %s,
                    decided_by = %s,
                    decided_at = NOW(),
                    action_match = %s,
                    severity_match = %s,
                    match_category = %s
                WHERE id = %s
            """, (
                human_action, human_severity, human_reasoning, decided_by,
                action_match, severity_match, match_category,
                recommendation_id,
            ))
        conn.commit()
    finally:
        conn.close()

    logger.info("Human decision recorded",
                recommendation_id=recommendation_id, match_category=match_category)

    return {
        "action_match": action_match,
        "severity_match": severity_match,
        "match_category": match_category,
    }


@activity.defn
async def compute_conformance_metrics(tenant_id: str) -> dict:
    """Compute shadow conformance stats for a tenant.

    Queries shadow_conformance_stats materialized view.
    Refreshes if stale (>1 hour).

    Returns:
        {total, matched, match_rate, by_action: {...}}
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Refresh materialized view if stale (best-effort)
            try:
                cur.execute("""
                    SELECT pg_catalog.pg_stat_get_last_analyze_time(c.oid) AS last_refresh
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relname = 'shadow_conformance_stats' AND n.nspname = 'public'
                """)
                row = cur.fetchone()
                should_refresh = True
                if row and row.get("last_refresh"):
                    # If analyzed in last hour, skip refresh
                    should_refresh = False
                if should_refresh:
                    cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY shadow_conformance_stats")
                    conn.commit()
            except Exception:
                # View might not exist yet or CONCURRENTLY not supported — non-fatal
                conn.rollback()

            # Query per-action stats
            cur.execute("""
                SELECT recommended_action,
                       total_count,
                       action_match_count,
                       CASE WHEN total_count > 0
                            THEN ROUND(action_match_count::numeric / total_count * 100, 2)
                            ELSE 0 END AS match_rate
                FROM shadow_conformance_stats
                WHERE tenant_id = %s
            """, (tenant_id,))
            rows = cur.fetchall()

            by_action = {}
            total = 0
            matched = 0
            for r in rows:
                action = r["recommended_action"]
                by_action[action] = {
                    "total": r["total_count"],
                    "matched": r["action_match_count"],
                    "match_rate": float(r["match_rate"]),
                }
                total += r["total_count"]
                matched += r["action_match_count"]

            overall_rate = round((matched / total * 100), 2) if total > 0 else 0.0

            return {
                "total": total,
                "matched": matched,
                "match_rate": overall_rate,
                "by_action": by_action,
            }
    finally:
        conn.close()


@activity.defn
async def check_mode_graduation(tenant_id: str) -> dict:
    """Check if a tenant is eligible to graduate to the next automation mode.

    Day 1-30: Stay in shadow (return {graduate: false})
    Day 31-90: If match_rate > 90%: graduate to 'assisted'
    Day 91+: If match_rate > 95% AND fn_rate = 0: graduate to 'autonomous'

    Returns:
        {graduate, current_mode, new_mode, match_rate, day, reason}
    """
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get current mode and day
            cur.execute("""
                SELECT mode, kill_switch,
                       EXTRACT(DAY FROM NOW() - activated_at)::int AS day_number
                FROM automation_controls
                WHERE tenant_id = %s AND workflow_name = 'investigation'
                LIMIT 1
            """, (tenant_id,))
            ctrl = cur.fetchone()
            if not ctrl:
                return {"graduate": False, "current_mode": "shadow", "new_mode": None,
                        "match_rate": 0, "day": 0, "reason": "No automation control record"}

            day = ctrl.get("day_number", 0) or 0
            current_mode = ctrl.get("mode", "shadow")

            if ctrl.get("kill_switch"):
                return {"graduate": False, "current_mode": current_mode, "new_mode": None,
                        "match_rate": 0, "day": day, "reason": "Kill switch active"}

            # Compute match rate from decided recommendations
            cur.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN action_match THEN 1 ELSE 0 END) AS matched,
                       SUM(CASE WHEN NOT action_match AND human_action = 'escalate' THEN 1 ELSE 0 END) AS false_negatives
                FROM shadow_recommendations
                WHERE tenant_id = %s AND status = 'decided'
            """, (tenant_id,))
            stats = cur.fetchone()
            total = stats["total"] or 0
            matched = stats["matched"] or 0
            fn = stats["false_negatives"] or 0
            match_rate = round((matched / total * 100), 2) if total > 0 else 0.0
            fn_rate = round((fn / total * 100), 2) if total > 0 else 0.0

            if day <= 30:
                return {"graduate": False, "current_mode": current_mode, "new_mode": None,
                        "match_rate": match_rate, "day": day,
                        "reason": f"Shadow period: day {day} of 30"}

            if day <= 90 and current_mode == "shadow":
                if match_rate > 90 and total >= 20:
                    return {"graduate": True, "current_mode": current_mode, "new_mode": "assisted",
                            "match_rate": match_rate, "day": day,
                            "reason": f"Match rate {match_rate}% > 90% with {total} decisions"}
                return {"graduate": False, "current_mode": current_mode, "new_mode": None,
                        "match_rate": match_rate, "day": day,
                        "reason": f"Match rate {match_rate}% (need >90% with >=20 decisions)"}

            if day > 90 and current_mode == "assisted":
                if match_rate > 95 and fn_rate == 0 and total >= 50:
                    return {"graduate": True, "current_mode": current_mode, "new_mode": "autonomous",
                            "match_rate": match_rate, "day": day,
                            "reason": f"Match rate {match_rate}%, FN rate {fn_rate}%, {total} decisions"}
                return {"graduate": False, "current_mode": current_mode, "new_mode": None,
                        "match_rate": match_rate, "day": day,
                        "reason": f"Match {match_rate}%, FN {fn_rate}% (need >95%, 0% FN, >=50 decisions)"}

            return {"graduate": False, "current_mode": current_mode, "new_mode": None,
                    "match_rate": match_rate, "day": day, "reason": "Already at target mode"}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------

@workflow.defn
class ShadowInvestigationWorkflow:
    """Shadow mode workflow: generate recommendation, wait for human decision."""

    def __init__(self):
        self._alert_data = None
        self._human_decision = None

    @workflow.signal
    async def submit_alert(self, data: dict):
        """Signal to submit an alert for shadow investigation."""
        self._alert_data = data

    @workflow.signal
    async def human_decision(self, data: dict):
        """Signal with the analyst's decision on the recommendation."""
        self._human_decision = data

    @workflow.run
    async def run(self, params: dict) -> dict:
        """Run shadow investigation workflow.

        Args:
            params: {tenant_id, task_id, investigation_data}
        """
        tenant_id = params.get("tenant_id")
        task_id = params.get("task_id")
        investigation_data = params.get("investigation_data", {})

        # Step 1: Check automation mode
        mode_result = await workflow.execute_activity(
            check_automation_mode,
            {"tenant_id": tenant_id, "workflow_name": "investigation"},
            schedule_to_close_timeout=timedelta(seconds=10),
        )

        if mode_result["killed"] or mode_result["mode"] == "disabled":
            workflow.logger.info(f"Shadow workflow aborted: mode={mode_result['mode']}, killed={mode_result['killed']}")
            return {"status": "aborted", "reason": "disabled_or_killed"}

        # Step 2: Generate recommendation
        rec_result = await workflow.execute_activity(
            generate_recommendation,
            {"task_id": task_id, "tenant_id": tenant_id, "investigation_data": investigation_data},
            schedule_to_close_timeout=timedelta(minutes=5),
        )
        recommendation_id = rec_result["recommendation_id"]

        workflow.logger.info(
            f"Shadow recommendation: {rec_result['recommended_action']} "
            f"(confidence={rec_result['confidence']})"
        )

        # Step 3: If mode is autonomous, skip human wait
        if mode_result["mode"] == "autonomous":
            return {
                "status": "auto_executed",
                "recommendation_id": recommendation_id,
                "action": rec_result["recommended_action"],
            }

        # Step 4: Wait for human decision signal (4 hour timeout)
        self._human_decision = None
        try:
            await workflow.wait_condition(
                lambda: self._human_decision is not None,
                timeout=timedelta(hours=4),
            )
        except TimeoutError:
            workflow.logger.info(f"Shadow workflow timed out waiting for human decision: {recommendation_id}")
            return {
                "status": "timeout",
                "recommendation_id": recommendation_id,
                "timeout_hours": 4,
            }

        # Step 5: Record human decision
        decision = self._human_decision
        match_result = await workflow.execute_activity(
            record_human_decision,
            {
                "recommendation_id": recommendation_id,
                "human_action": decision.get("action", "monitor"),
                "human_severity": decision.get("severity", "medium"),
                "human_reasoning": decision.get("reasoning", ""),
                "decided_by": decision.get("decided_by"),
            },
            schedule_to_close_timeout=timedelta(seconds=10),
        )

        # Step 6: Check graduation eligibility
        graduation = await workflow.execute_activity(
            check_mode_graduation,
            tenant_id,
            schedule_to_close_timeout=timedelta(seconds=10),
        )

        return {
            "status": "completed",
            "recommendation_id": recommendation_id,
            "match_category": match_result["match_category"],
            "graduation": graduation,
        }
