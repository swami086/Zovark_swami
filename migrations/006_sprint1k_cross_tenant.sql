-- Sprint 1K: Cross-Tenant Entity Resolution
-- Materialized view for cross-tenant intelligence + privacy-safe public view

-- Materialized view: entity threat scores aggregated across tenants
CREATE MATERIALIZED VIEW IF NOT EXISTS cross_tenant_intel AS
SELECT
    e.entity_hash,
    e.entity_type,
    COUNT(DISTINCT e.tenant_id) as tenant_count,
    COUNT(DISTINCT eo.investigation_id) as investigation_count,
    MAX(e.observation_count) as max_observations,
    MAX(e.threat_score) as max_threat_score,
    array_agg(DISTINCT e.tenant_id) as tenant_ids,
    MAX(e.last_seen) as last_seen_globally
FROM entities e
JOIN entity_observations eo ON eo.entity_id = e.id
JOIN investigations i ON i.id = eo.investigation_id
WHERE NOT COALESCE(i.injection_detected, false)
GROUP BY e.entity_hash, e.entity_type
HAVING COUNT(DISTINCT e.tenant_id) >= 2;

CREATE UNIQUE INDEX IF NOT EXISTS idx_cross_tenant_hash ON cross_tenant_intel(entity_hash);
CREATE INDEX IF NOT EXISTS idx_cross_tenant_type ON cross_tenant_intel(entity_type);
CREATE INDEX IF NOT EXISTS idx_cross_tenant_tenants ON cross_tenant_intel(tenant_count DESC);

-- Privacy-safe view: strips tenant_ids, only shows aggregate counts
CREATE OR REPLACE VIEW cross_tenant_public AS
SELECT
    entity_hash,
    entity_type,
    tenant_count,
    investigation_count,
    max_observations,
    max_threat_score,
    last_seen_globally
FROM cross_tenant_intel;

-- Add threat_score and tenant_count columns to entities if not exists
ALTER TABLE entities ADD COLUMN IF NOT EXISTS threat_score INTEGER DEFAULT 0;
ALTER TABLE entities ADD COLUMN IF NOT EXISTS tenant_count INTEGER DEFAULT 1;

-- Add analyst_feedback column to investigations for FP loop
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS analyst_feedback JSONB;

-- Add cross_tenant_hit and injection_detected to audit_events event_type CHECK
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (
    event_type IN (
        'investigation_started', 'investigation_completed', 'code_executed',
        'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
        'entity_extracted', 'detection_generated', 'user_login', 'user_registered',
        'injection_detected', 'cross_tenant_hit', 'threat_score_updated'
    )
);
