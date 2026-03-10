-- Migration 018: Investigation cost tracking (Sprint 7D)

ALTER TABLE llm_call_log ADD COLUMN IF NOT EXISTS cost_usd DECIMAL(10,6);

-- Per-investigation cost rollup view
CREATE OR REPLACE VIEW investigation_costs AS
SELECT
    task_id,
    COUNT(*) as llm_calls,
    SUM(input_tokens) as total_input_tokens,
    SUM(output_tokens) as total_output_tokens,
    SUM(cost_usd) as total_cost_usd
FROM llm_call_log
WHERE task_id IS NOT NULL
GROUP BY task_id;
