-- Migration 050: Sprint 1K — Cross-Tenant Entity Resolution
-- Adds cross_tenant_entities table for privacy-preserving aggregation.
-- Existing cross_tenant_intel materialized view (migration 006) is complemented
-- by this persistent table that stores computed threat scores and metadata.

CREATE TABLE IF NOT EXISTS cross_tenant_entities (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,
    entity_value TEXT NOT NULL,
    entity_hash VARCHAR(64) NOT NULL,  -- SHA256 for privacy
    tenant_count INTEGER DEFAULT 1,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    threat_score NUMERIC(5,2) DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    UNIQUE(entity_hash)
);

CREATE INDEX IF NOT EXISTS idx_cte_hash ON cross_tenant_entities(entity_hash);
CREATE INDEX IF NOT EXISTS idx_cte_score ON cross_tenant_entities(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_cte_type ON cross_tenant_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_cte_last_seen ON cross_tenant_entities(last_seen DESC);

-- Add playbook_auto_triggered to audit_events event_type check (if not already present)
-- Drop and re-add constraint to include new event types needed for cross-tenant intelligence
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (
    event_type IN (
        'investigation_started', 'investigation_completed', 'code_executed',
        'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
        'entity_extracted', 'detection_generated', 'user_login', 'user_registered',
        'injection_detected', 'cross_tenant_hit', 'threat_score_updated',
        'playbook_auto_triggered', 'cross_tenant_intelligence', 'entity_enriched',
        'detection_rule_created', 'playbook_executed'
    )
);
