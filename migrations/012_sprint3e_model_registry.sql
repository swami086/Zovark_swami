-- Sprint 3E: Proprietary Model Integration
-- Model registry for tracking model versions, routing, and A/B testing

CREATE TABLE IF NOT EXISTS model_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,  -- openrouter, vllm, ollama, litellm
    model_id VARCHAR(255) NOT NULL,  -- e.g., "qwen/qwen-2.5-coder-32b-instruct"
    version VARCHAR(50) DEFAULT '1.0',
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'testing', 'promoted', 'deprecated')),
    is_default BOOLEAN DEFAULT false,
    config JSONB DEFAULT '{}',  -- max_tokens, temperature, etc.
    routing_rules JSONB DEFAULT '{}',  -- tenant_ids, task_types, traffic_pct
    eval_score FLOAT,
    eval_results JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_model_registry_default ON model_registry(is_default) WHERE is_default = true;
CREATE INDEX IF NOT EXISTS idx_model_registry_status ON model_registry(status);
CREATE INDEX IF NOT EXISTS idx_model_registry_provider ON model_registry(provider);

-- A/B test records
CREATE TABLE IF NOT EXISTS model_ab_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    model_a_id UUID NOT NULL REFERENCES model_registry(id),
    model_b_id UUID NOT NULL REFERENCES model_registry(id),
    traffic_split FLOAT DEFAULT 0.5,  -- fraction going to model B
    status VARCHAR(20) DEFAULT 'running' CHECK (status IN ('running', 'completed', 'cancelled')),
    results_a JSONB DEFAULT '{}',
    results_b JSONB DEFAULT '{}',
    winner_id UUID REFERENCES model_registry(id),
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ab_tests_status ON model_ab_tests(status);
