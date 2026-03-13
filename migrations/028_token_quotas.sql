-- Migration 028: Token Quotas (Sprint v0.10.0)
-- Per-tenant token quotas and usage tracking

CREATE TABLE IF NOT EXISTS token_quotas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) UNIQUE,
    -- Monthly limits
    monthly_token_limit BIGINT NOT NULL DEFAULT 10000000, -- 10M tokens default
    monthly_cost_limit_usd NUMERIC(10,2) DEFAULT 500.00,
    -- Current period usage (reset monthly)
    current_period_start DATE NOT NULL DEFAULT date_trunc('month', CURRENT_DATE)::date,
    tokens_used BIGINT NOT NULL DEFAULT 0,
    cost_used_usd NUMERIC(10,2) NOT NULL DEFAULT 0.00,
    -- Alert thresholds
    warn_threshold_pct INTEGER NOT NULL DEFAULT 80, -- alert at 80% usage
    hard_limit_pct INTEGER NOT NULL DEFAULT 100, -- block at 100%
    -- Circuit breaker
    circuit_breaker_open BOOLEAN NOT NULL DEFAULT false,
    circuit_breaker_reason TEXT,
    circuit_breaker_opened_at TIMESTAMPTZ,
    circuit_breaker_opened_by UUID REFERENCES users(id),
    -- Metadata
    last_reset_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_token_quotas_tenant ON token_quotas(tenant_id);
CREATE INDEX idx_token_quotas_circuit ON token_quotas(circuit_breaker_open) WHERE circuit_breaker_open = true;

-- Token usage events (append-only audit trail)
CREATE TABLE IF NOT EXISTS token_usage_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    task_id UUID REFERENCES agent_tasks(id),
    model_id VARCHAR(100),
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    tokens_total INTEGER GENERATED ALWAYS AS (tokens_input + tokens_output) STORED,
    cost_usd NUMERIC(10,6) NOT NULL DEFAULT 0,
    quota_pct_after NUMERIC(5,2), -- % of quota used after this event
    throttled BOOLEAN NOT NULL DEFAULT false, -- was this request throttled?
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_token_usage_tenant_period ON token_usage_events(tenant_id, created_at);
