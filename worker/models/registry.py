"""Model registry — dynamic model selection and routing.

Supports:
- Per-tenant model overrides
- Per-task-type model routing
- A/B traffic splitting
- Default model fallback
"""

import os
import random
import psycopg2
import logger

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")

# Cache: refreshed every 60s by worker
_model_cache = {}
_cache_ts = 0


def _get_db():
    return psycopg2.connect(DATABASE_URL)


def refresh_model_cache():
    """Refresh the in-memory model cache from DB."""
    global _model_cache, _cache_ts
    import time

    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, name, model_id, provider, status, is_default, config, routing_rules, eval_score
            FROM model_registry WHERE status IN ('active', 'testing', 'promoted')
        """)

        models = {}
        for row in cur.fetchall():
            mid, name, model_id, provider, status, is_default, config, routing_rules, eval_score = row
            models[str(mid)] = {
                "id": str(mid),
                "name": name,
                "model_id": model_id,
                "provider": provider,
                "status": status,
                "is_default": is_default,
                "config": config or {},
                "routing_rules": routing_rules or {},
                "eval_score": float(eval_score) if eval_score else None,
            }

        cur.close()
        conn.close()
        _model_cache = models
        _cache_ts = time.time()
    except Exception as e:
        logger.warn("Model cache refresh failed", error=str(e))


def get_model_for_task(tenant_id: str = None, task_type: str = None) -> str:
    """Resolve which model to use for a given task.

    Priority:
    1. Active A/B test (random split)
    2. Tenant-specific routing rule
    3. Task-type-specific routing rule
    4. Default model
    5. Fallback to env var ZOVARC_LLM_MODEL
    """
    import time

    # Refresh cache if stale (>60s)
    if time.time() - _cache_ts > 60:
        refresh_model_cache()

    if not _model_cache:
        return os.environ.get("ZOVARC_LLM_MODEL", "fast")

    # Check A/B tests
    ab_model = _check_ab_test(tenant_id, task_type)
    if ab_model:
        return ab_model

    # Check tenant-specific routing
    for model in _model_cache.values():
        rules = model.get("routing_rules", {})
        tenant_ids = rules.get("tenant_ids", [])
        if tenant_id and tenant_id in tenant_ids:
            logger.info("Model routed by tenant", model=model["model_id"], tenant_id=tenant_id)
            return model["model_id"]

    # Check task-type routing
    for model in _model_cache.values():
        rules = model.get("routing_rules", {})
        task_types = rules.get("task_types", [])
        if task_type and task_type in task_types:
            logger.info("Model routed by task_type", model=model["model_id"], task_type=task_type)
            return model["model_id"]

    # Default model
    for model in _model_cache.values():
        if model.get("is_default"):
            return model["model_id"]

    return os.environ.get("ZOVARC_LLM_MODEL", "fast")


def _check_ab_test(tenant_id: str = None, task_type: str = None) -> str:
    """Check if there's an active A/B test and randomly assign."""
    try:
        conn = _get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT ab.id, ab.traffic_split,
                   ma.model_id as model_a, mb.model_id as model_b
            FROM model_ab_tests ab
            JOIN model_registry ma ON ab.model_a_id = ma.id
            JOIN model_registry mb ON ab.model_b_id = mb.id
            WHERE ab.status = 'running'
            LIMIT 1
        """)
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row:
            ab_id, split, model_a, model_b = row
            if random.random() < split:
                logger.info("A/B test: assigned model B", ab_test=str(ab_id), model=model_b)
                return model_b
            else:
                logger.info("A/B test: assigned model A", ab_test=str(ab_id), model=model_a)
                return model_a
    except Exception:
        pass

    return None


def promote_model(model_id: str) -> bool:
    """Promote a model to default, deprecating the current default."""
    try:
        conn = _get_db()
        cur = conn.cursor()

        # Deprecate current default
        cur.execute("UPDATE model_registry SET is_default = false, status = 'deprecated', updated_at = NOW() WHERE is_default = true")

        # Promote new model
        cur.execute("UPDATE model_registry SET is_default = true, status = 'promoted', updated_at = NOW() WHERE id = %s", (model_id,))

        conn.commit()
        cur.close()
        conn.close()

        logger.info("Model promoted to default", model_id=model_id)
        refresh_model_cache()
        return True
    except Exception as e:
        logger.error("Model promotion failed", error=str(e))
        return False
