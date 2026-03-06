-- Sprint 1I: Model Tiering + Prompt Versioning + LLM Call Logging
-- Migration 007
-- Adds llm_call_log table and model_performance materialized view

-- ============================================================
-- LLM CALL LOG
-- ============================================================

CREATE TABLE IF NOT EXISTS llm_call_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    task_id UUID,
    activity_name VARCHAR(100) NOT NULL,
    model_tier VARCHAR(20) NOT NULL CHECK (model_tier IN ('fast', 'standard', 'reasoning')),
    model_id VARCHAR(200) NOT NULL,
    prompt_name VARCHAR(100),
    prompt_version VARCHAR(20),
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER GENERATED ALWAYS AS (input_tokens + output_tokens) STORED,
    estimated_cost_usd NUMERIC(10,6) DEFAULT 0,
    latency_ms INTEGER DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'error', 'timeout', 'fallback')),
    error_message TEXT,
    temperature NUMERIC(3,2),
    max_tokens INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_llm_call_log_tenant ON llm_call_log(tenant_id);
CREATE INDEX idx_llm_call_log_activity ON llm_call_log(activity_name);
CREATE INDEX idx_llm_call_log_model ON llm_call_log(model_id);
CREATE INDEX idx_llm_call_log_prompt ON llm_call_log(prompt_name, prompt_version);
CREATE INDEX idx_llm_call_log_created ON llm_call_log(created_at DESC);
CREATE INDEX idx_llm_call_log_status ON llm_call_log(status) WHERE status != 'success';

-- ============================================================
-- MODEL PERFORMANCE MATERIALIZED VIEW
-- ============================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS model_performance AS
SELECT
    model_id,
    activity_name,
    prompt_name,
    COUNT(*) as call_count,
    AVG(latency_ms) as avg_latency_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95_latency_ms,
    SUM(total_tokens) as total_tokens,
    SUM(estimated_cost_usd) as total_cost_usd,
    AVG(input_tokens) as avg_input_tokens,
    AVG(output_tokens) as avg_output_tokens,
    COUNT(*) FILTER (WHERE status = 'error') as error_count,
    COUNT(*) FILTER (WHERE status = 'timeout') as timeout_count,
    COUNT(*) FILTER (WHERE status = 'fallback') as fallback_count,
    MIN(created_at) as first_seen,
    MAX(created_at) as last_seen
FROM llm_call_log
GROUP BY model_id, activity_name, prompt_name;

CREATE UNIQUE INDEX IF NOT EXISTS idx_model_perf_key
    ON model_performance(model_id, activity_name, prompt_name);

-- Add prompt_version column to investigations if not present
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'investigations' AND column_name = 'prompt_version'
    ) THEN
        ALTER TABLE investigations ADD COLUMN prompt_version VARCHAR(50);
    END IF;
END $$;
