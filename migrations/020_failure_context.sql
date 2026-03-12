-- Migration 020: Failure context for investigation hardening
-- Sprint 8: Contextual error logging for 4 failure modes
-- Adds: blocked_credentials status, 4 failure audit event types

-- 1. Add 'blocked_credentials' to agent_tasks status CHECK
ALTER TABLE agent_tasks DROP CONSTRAINT IF EXISTS agent_tasks_status_check;
ALTER TABLE agent_tasks ADD CONSTRAINT agent_tasks_status_check CHECK (
    status IN (
        'pending', 'planning', 'approved', 'executing',
        'completed', 'failed', 'cancelled',
        'awaiting_approval', 'rejected',
        'blocked_credentials'
    )
);

-- 2. Add 4 failure mode event types to audit_events CHECK
-- Must update on parent + all partitions (partitioned table)
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (
    event_type IN (
        -- Existing event types
        'investigation_started', 'investigation_completed', 'code_executed',
        'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
        'entity_extracted', 'detection_generated',
        'user_login', 'user_registered',
        'injection_detected', 'cross_tenant_hit', 'threat_score_updated',
        'self_healing_scan', 'self_healing_diagnosis',
        'self_healing_patch_applied', 'self_healing_patch_failed', 'self_healing_rollback',
        'dry_run_validation_failed', 'memory_enrichment_applied',
        -- New failure mode event types (Sprint 8)
        'model_timeout',
        'telemetry_access_denied',
        'schema_validation_error',
        'postgres_lock'
    )
);

-- 3. Add 'credential_rotation_required' to common webhook event types
-- (No schema change needed — event_types is a text[] column, values are freeform)

-- 4. Create index for failure mode audit queries
CREATE INDEX IF NOT EXISTS idx_audit_events_failure_modes
    ON audit_events (event_type, created_at DESC)
    WHERE event_type IN ('model_timeout', 'telemetry_access_denied', 'schema_validation_error', 'postgres_lock');

-- 5. Create index for blocked_credentials task lookup
CREATE INDEX IF NOT EXISTS idx_agent_tasks_blocked
    ON agent_tasks (tenant_id, status)
    WHERE status = 'blocked_credentials';
