-- Extend audit_events.event_type (union of prior migrations + new governance / platform types)
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (
    event_type IN (
        'investigation_started', 'investigation_completed', 'code_executed',
        'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
        'entity_extracted', 'detection_generated', 'user_login', 'user_registered',
        'injection_detected', 'cross_tenant_hit', 'threat_score_updated',
        'playbook_auto_triggered', 'cross_tenant_intelligence', 'entity_enriched',
        'detection_rule_created', 'playbook_executed',
        'self_healing_scan', 'self_healing_diagnosis', 'self_healing_patch_applied',
        'self_healing_patch_failed', 'self_healing_rollback',
        'dry_run_validation_failed', 'memory_enrichment_applied',
        'model_timeout', 'telemetry_access_denied', 'schema_validation_error', 'postgres_lock',
        'platform_data_ready',
        'suppression_rule_eval_failed',
        'retrain_check'
    )
);
