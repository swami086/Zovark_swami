-- Migration 026: SLA events table (Issue #54)
-- Investigation SLA monitoring and breach tracking

CREATE TABLE IF NOT EXISTS sla_events (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    task_id UUID NOT NULL,
    severity VARCHAR(20) NOT NULL,
    sla_threshold_minutes INTEGER NOT NULL,
    actual_duration_minutes FLOAT NOT NULL,
    breached BOOLEAN DEFAULT false,
    breach_ratio FLOAT,
    webhook_sent BOOLEAN DEFAULT false,
    webhook_status INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sla_events_tenant ON sla_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sla_events_breached ON sla_events(breached) WHERE breached = true;
CREATE INDEX IF NOT EXISTS idx_sla_events_created ON sla_events(created_at DESC);
