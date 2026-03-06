-- Migration 014: Sprint 4A — Self-Healing SRE Agent
-- Adds self_healing_events table and extends audit_events CHECK constraint

-- Update audit_events CHECK to add self_healing event types
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (event_type IN (
    'investigation_started', 'investigation_completed', 'code_executed',
    'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
    'entity_extracted', 'detection_generated', 'user_login', 'user_registered',
    'injection_detected', 'cross_tenant_hit', 'threat_score_updated',
    'self_healing_scan', 'self_healing_diagnosis', 'self_healing_patch_applied',
    'self_healing_patch_failed', 'self_healing_rollback'
));

-- Self-healing event tracking
CREATE TABLE IF NOT EXISTS self_healing_events (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    failure_id TEXT,
    workflow_id TEXT,
    activity_name VARCHAR(100),
    error_category VARCHAR(30) CHECK (error_category IN (
        'dependency_missing', 'logic_bug', 'llm_malformed', 'resource_exhaustion', 'unknown'
    )),
    diagnosis JSONB,
    patch_type VARCHAR(30),
    patch_content TEXT,
    test_result JSONB,
    applied BOOLEAN DEFAULT false,
    rolled_back BOOLEAN DEFAULT false,
    file_path TEXT,
    backup_path TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_self_healing_created ON self_healing_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_self_healing_category ON self_healing_events(error_category);
