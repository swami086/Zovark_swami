-- Ticket 4: MCP API keys, optional server-side sessions, governance audit event type

CREATE TABLE IF NOT EXISTS mcp_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, key_hash)
);

CREATE INDEX IF NOT EXISTS idx_mcp_api_keys_tenant ON mcp_api_keys (tenant_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_api_keys_hash ON mcp_api_keys (key_hash) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

-- Authoritative superset after 067: every event_type emitted by INSERT INTO audit_events
-- in api/*.go and worker/**/*.py (incl. breakglass_login_attempt, circuit_breaker_tripped).
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
        'retrain_check',
        'governance_config_updated',
        'breakglass_login_attempt',
        'circuit_breaker_tripped'
    )
);

-- ── Session expiry purge (bounded table growth) ───────────────────────────
-- 1) Callable function: run from any scheduler (systemd timer, K8s CronJob,
--    external cron) when pg_cron is NOT available:
--       SELECT zovark_purge_expired_sessions();
-- 2) When pg_cron extension exists, register a nightly job idempotently.

CREATE OR REPLACE FUNCTION zovark_purge_expired_sessions()
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
  deleted bigint;
BEGIN
  DELETE FROM sessions WHERE expires_at < NOW();
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END;
$$;

COMMENT ON FUNCTION zovark_purge_expired_sessions() IS
  'Deletes expired rows from sessions. Schedule nightly via pg_cron (see migration) or host cron: psql -c "SELECT zovark_purge_expired_sessions();"';

DO $cron$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    IF NOT EXISTS (
      SELECT 1 FROM cron.job WHERE jobname = 'zovark_purge_expired_sessions'
    ) THEN
      PERFORM cron.schedule(
        'zovark_purge_expired_sessions',
        '0 3 * * *',
        'SELECT zovark_purge_expired_sessions();'
      );
    END IF;
  ELSE
    RAISE NOTICE 'pg_cron not installed: schedule zovark_purge_expired_sessions() via host cron or Kubernetes CronJob (see COMMENT on function).';
  END IF;
END;
$cron$;
