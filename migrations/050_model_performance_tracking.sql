-- Sprint 1I: Prompt versioning + model performance tracking
-- Adds prompt_version column to llm_audit_log and creates materialized view
-- for aggregated model performance metrics.

-- Add prompt_version to audit log
ALTER TABLE llm_audit_log ADD COLUMN IF NOT EXISTS prompt_version TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_llm_audit_prompt_version ON llm_audit_log(prompt_version);

-- Materialized view: model performance aggregated by day
-- Refresh via: REFRESH MATERIALIZED VIEW CONCURRENTLY model_performance;
CREATE MATERIALIZED VIEW IF NOT EXISTS model_performance AS
SELECT
    model_name                                          AS model_id,
    COALESCE(prompt_version, '')                        AS prompt_version,
    stage                                               AS call_type,
    COUNT(*)                                            AS total_calls,
    ROUND(AVG(latency_ms), 1)                           AS avg_latency_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_latency_ms,
    ROUND(AVG(tokens_in), 1)                            AS avg_input_tokens,
    ROUND(AVG(tokens_out), 1)                           AS avg_output_tokens,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END)::FLOAT
        / NULLIF(COUNT(*), 0)                           AS success_rate,
    DATE_TRUNC('day', created_at)                       AS day
FROM llm_audit_log
GROUP BY model_name, prompt_version, stage, DATE_TRUNC('day', created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_model_perf_unique
    ON model_performance(model_id, prompt_version, call_type, day);
