-- Migration 025: Incidents table (Issue #53)
-- Alert correlation engine — merged incident records

CREATE TABLE IF NOT EXISTS incidents (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    alert_ids UUID[] DEFAULT '{}',
    alert_count INTEGER DEFAULT 0,
    correlation_rule VARCHAR(100),
    mitre_techniques TEXT[],
    source_ips TEXT[],
    target_users TEXT[],
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'closed', 'false_positive')),
    investigation_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
