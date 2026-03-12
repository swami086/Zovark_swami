-- Migration 024: Scheduled workflows (Issue #52)
-- Cron-based workflow scheduling configuration

CREATE TABLE IF NOT EXISTS scheduled_workflows (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    workflow_type VARCHAR(100) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    params JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scheduled_workflows_active ON scheduled_workflows(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_scheduled_workflows_type ON scheduled_workflows(workflow_type);

-- Seed default schedules
INSERT INTO scheduled_workflows (workflow_type, cron_expression, params, is_active) VALUES
    ('DetectionGenerationWorkflow', '0 2 * * *', '{"min_investigations": 2}', true),
    ('SelfHealingWorkflow', '*/30 * * * *', '{"lookback_minutes": 30, "dry_run": true}', true),
    ('CrossTenantRefreshWorkflow', '0 * * * *', '{}', true)
ON CONFLICT DO NOTHING;
