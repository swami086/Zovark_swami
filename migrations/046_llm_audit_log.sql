-- LLM Audit Log — tracks all LLM calls for cost and compliance
-- Does NOT store prompts or responses (privacy by design)
CREATE TABLE IF NOT EXISTS llm_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID,
    tenant_id UUID,
    stage TEXT NOT NULL,
    task_type TEXT,
    model_name TEXT NOT NULL,
    tokens_in INTEGER DEFAULT 0,
    tokens_out INTEGER DEFAULT 0,
    latency_ms INTEGER DEFAULT 0,
    prompt_hash TEXT,
    status TEXT NOT NULL DEFAULT 'success',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_llm_audit_task ON llm_audit_log(task_id);
CREATE INDEX IF NOT EXISTS idx_llm_audit_tenant ON llm_audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_llm_audit_created ON llm_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_llm_audit_model ON llm_audit_log(model_name);
