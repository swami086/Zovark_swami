"""LLM call logger — non-blocking logging of all LLM API calls.

Logs to llm_call_log table with model tier, prompt version, tokens, latency, cost.
Fire-and-forget: errors are printed but never raised.

No Pydantic — plain dicts only.
"""

import os
import psycopg2

from cost_calculator import calculate_cost


def estimate_cost(input_tokens: int, output_tokens: int, model: str = None) -> float:
    """Estimate USD cost from token counts using per-model rates."""
    if model:
        return round(calculate_cost(model, input_tokens, output_tokens), 6)
    # Fallback: conservative default
    return round(calculate_cost("zovarc-standard", input_tokens, output_tokens), 6)


def log_llm_call(
    activity_name: str,
    model_tier: str,
    model_id: str,
    prompt_name: str = None,
    prompt_version: str = None,
    input_tokens: int = 0,
    output_tokens: int = 0,
    latency_ms: int = 0,
    status: str = "success",
    error_message: str = None,
    temperature: float = None,
    max_tokens: int = None,
    tenant_id: str = None,
    task_id: str = None,
) -> None:
    """Log an LLM call to the database. Fire-and-forget.

    Args:
        activity_name: Name of the Temporal activity
        model_tier: fast/standard/reasoning
        model_id: Actual model ID used
        prompt_name: Registered prompt name
        prompt_version: SHA256[:12] version hash
        input_tokens: Prompt tokens used
        output_tokens: Completion tokens used
        latency_ms: Call duration in milliseconds
        status: success/error/timeout/fallback
        error_message: Error details if status != success
        temperature: Temperature used
        max_tokens: Max tokens setting
        tenant_id: Tenant UUID
        task_id: Task UUID
    """
    try:
        db_url = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@postgres:5432/zovarc")
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cost = estimate_cost(input_tokens, output_tokens, model=model_id)
                cur.execute("""
                    INSERT INTO llm_call_log
                    (tenant_id, task_id, activity_name, model_tier, model_id,
                     prompt_name, prompt_version, input_tokens, output_tokens,
                     estimated_cost_usd, cost_usd, latency_ms, status, error_message,
                     temperature, max_tokens)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    tenant_id, task_id, activity_name, model_tier, model_id,
                    prompt_name, prompt_version, input_tokens, output_tokens,
                    cost, cost,
                    latency_ms, status, error_message,
                    temperature, max_tokens,
                ))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"llm_logger: failed to log call (non-fatal): {e}")
