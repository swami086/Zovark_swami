-- Migration 032: Stampede Protection (Sprint v0.10.0)
-- Request coalescing, cache stampede protection, and tenant shadow mode settings

CREATE TABLE IF NOT EXISTS coalescing_locks (
    cache_key VARCHAR(500) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    locked_by VARCHAR(100) NOT NULL, -- worker_id
    locked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    -- Waiters
    waiter_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_coalescing_expires ON coalescing_locks(expires_at);

-- Add approval_mode and shadow_mode settings to tenants
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS approval_mode VARCHAR(20) NOT NULL DEFAULT 'shadow';
-- 'shadow' = all recommendations, human decides
-- 'assisted' = suggested actions, human clicks to execute
-- 'autonomous' = auto-approve informational (Phase 2+)
-- 'disabled' = no automation

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS shadow_mode_start DATE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS shadow_mode_day INTEGER GENERATED ALWAYS AS (
    CASE WHEN shadow_mode_start IS NOT NULL
    THEN EXTRACT(DAY FROM (CURRENT_DATE - shadow_mode_start))::integer
    ELSE NULL END
) STORED;
