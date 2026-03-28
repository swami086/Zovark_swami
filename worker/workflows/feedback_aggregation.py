"""Daily feedback aggregation workflow.

Temporal cron schedule: 0 2 * * * (daily at 2 AM UTC)

Aggregates analyst feedback into actionable signals:
- Per-source FP rates
- Per-rule accuracy
- Flags underperforming detection rules
- Refreshes materialized views
- Emits summary event via NATS
"""
import os
import json
import logging
from datetime import datetime, timedelta

from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    from database.pool_manager import pooled_connection

logger = logging.getLogger(__name__)


@activity.defn
async def aggregate_feedback_stats(params: dict) -> dict:
    """Aggregate feedback statistics per source and per rule.

    Returns: {
        total_feedback: int,
        sources: [{source, total, fp_count, fp_rate}],
        rules: [{rule_name, total, correct, accuracy}],
        period_days: int,
    }
    """
    tenant_id = params.get("tenant_id")
    period_days = params.get("period_days", 90)
    cutoff = datetime.utcnow() - timedelta(days=period_days)

    with pooled_connection("background") as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Per-source FP rates
            cur.execute("""
                SELECT
                    COALESCE(t.task_type, 'unknown') AS source,
                    COUNT(*) AS total,
                    SUM(CASE WHEN f.false_positive THEN 1 ELSE 0 END) AS fp_count,
                    ROUND(AVG(CASE WHEN f.false_positive THEN 1.0 ELSE 0.0 END)::numeric, 3) AS fp_rate
                FROM investigation_feedback f
                JOIN agent_tasks t ON t.id::text = f.investigation_id::text
                WHERE f.tenant_id = %s AND f.created_at >= %s
                GROUP BY t.task_type
                ORDER BY fp_rate DESC
            """, (tenant_id, cutoff))
            sources = [dict(r) for r in cur.fetchall()]
            for s in sources:
                s['fp_rate'] = float(s['fp_rate'] or 0)

            # Per-rule accuracy (based on alert_name from investigations)
            cur.execute("""
                SELECT
                    COALESCE(t.input->>'rule_name', t.input->>'alert_name', 'unknown') AS rule_name,
                    COUNT(*) AS total,
                    SUM(CASE WHEN f.verdict_correct THEN 1 ELSE 0 END) AS correct,
                    ROUND(AVG(CASE WHEN f.verdict_correct THEN 1.0 ELSE 0.0 END)::numeric, 3) AS accuracy
                FROM investigation_feedback f
                JOIN agent_tasks t ON t.id::text = f.investigation_id::text
                WHERE f.tenant_id = %s AND f.created_at >= %s
                GROUP BY rule_name
                HAVING COUNT(*) >= 3
                ORDER BY accuracy ASC
            """, (tenant_id, cutoff))
            rules = [dict(r) for r in cur.fetchall()]
            for r in rules:
                r['accuracy'] = float(r['accuracy'] or 0)

            # Total feedback count
            cur.execute(
                "SELECT COUNT(*) FROM investigation_feedback WHERE tenant_id = %s AND created_at >= %s",
                (tenant_id, cutoff)
            )
            total = cur.fetchone()['count']

    return {
        'total_feedback': total,
        'sources': sources,
        'rules': rules,
        'period_days': period_days,
    }


@activity.defn
async def flag_underperforming_rules(params: dict) -> dict:
    """Flag detection rules with accuracy < 30% over 10+ samples.

    Updates detection_candidates status to 'needs_review' for matching rules.
    Returns: {flagged_count: int, flagged_rules: [str]}
    """
    tenant_id = params.get("tenant_id")
    rules = params.get("rules", [])
    threshold = params.get("accuracy_threshold", 0.3)
    min_samples = params.get("min_samples", 10)

    flagged = []
    with pooled_connection("background") as conn:
        with conn.cursor() as cur:
            for rule in rules:
                if rule['total'] >= min_samples and rule['accuracy'] < threshold:
                    flagged.append(rule['rule_name'])
                    cur.execute("""
                        UPDATE detection_candidates
                        SET status = 'needs_review',
                            updated_at = NOW()
                        WHERE tenant_id = %s
                          AND (sigma_rule ILIKE %s OR technique_id = %s)
                          AND status NOT IN ('rejected', 'needs_review')
                    """, (tenant_id, f'%{rule["rule_name"]}%', rule['rule_name']))

    return {'flagged_count': len(flagged), 'flagged_rules': flagged}


@activity.defn
async def refresh_materialized_views(params: dict) -> dict:
    """Refresh feedback-related materialized views."""
    with pooled_connection("background") as conn:
        with conn.cursor() as cur:
            cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY feedback_accuracy")
            # Also refresh cross-tenant views if they exist
            try:
                cur.execute("REFRESH MATERIALIZED VIEW CONCURRENTLY cross_tenant_entity_summary")
            except Exception:
                pass  # View may not exist

    return {'refreshed': True}


@activity.defn
async def emit_feedback_summary(params: dict) -> dict:
    """Emit feedback summary as a NATS event (if NATS configured)."""
    nats_url = os.environ.get("NATS_URL")
    if not nats_url:
        return {'emitted': False, 'reason': 'NATS not configured'}

    summary = {
        'type': 'feedback.daily_summary',
        'tenant_id': params.get('tenant_id'),
        'total_feedback': params.get('total_feedback', 0),
        'source_count': len(params.get('sources', [])),
        'flagged_rules': params.get('flagged_rules', []),
        'timestamp': datetime.utcnow().isoformat(),
    }

    try:
        import socket
        host, port = nats_url.replace('nats://', '').split(':')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, int(port)))
        # NATS protocol: PUB subject length\r\npayload\r\n
        payload = json.dumps(summary)
        msg = f"PUB zovark.feedback.summary {len(payload)}\r\n{payload}\r\n"
        sock.sendall(msg.encode())
        sock.close()
        return {'emitted': True}
    except Exception as e:
        logger.warning(f"Failed to emit feedback summary via NATS: {e}")
        return {'emitted': False, 'reason': str(e)}


@workflow.defn
class FeedbackAggregationWorkflow:
    """Daily feedback aggregation — cron scheduled at 0 2 * * *."""

    @workflow.run
    async def run(self, params: dict) -> dict:
        tenant_id = params.get("tenant_id")
        period_days = params.get("period_days", 90)

        # Step 1: Aggregate stats
        stats = await workflow.execute_activity(
            aggregate_feedback_stats,
            {"tenant_id": tenant_id, "period_days": period_days},
            start_to_close_timeout=timedelta(minutes=5),
        )

        # Step 2: Flag underperforming rules
        flag_result = await workflow.execute_activity(
            flag_underperforming_rules,
            {
                "tenant_id": tenant_id,
                "rules": stats.get("rules", []),
                "accuracy_threshold": 0.3,
                "min_samples": 10,
            },
            start_to_close_timeout=timedelta(minutes=2),
        )

        # Step 3: Refresh materialized views
        await workflow.execute_activity(
            refresh_materialized_views,
            {"tenant_id": tenant_id},
            start_to_close_timeout=timedelta(minutes=5),
        )

        # Step 4: Emit NATS event
        await workflow.execute_activity(
            emit_feedback_summary,
            {
                "tenant_id": tenant_id,
                "total_feedback": stats.get("total_feedback", 0),
                "sources": stats.get("sources", []),
                "flagged_rules": flag_result.get("flagged_rules", []),
            },
            start_to_close_timeout=timedelta(minutes=1),
        )

        return {
            "total_feedback": stats.get("total_feedback", 0),
            "sources_analyzed": len(stats.get("sources", [])),
            "rules_analyzed": len(stats.get("rules", [])),
            "rules_flagged": flag_result.get("flagged_count", 0),
        }
