-- Row-Level Security (RLS) — defense-in-depth tenant isolation (Security P2#27)
--
-- These policies enforce tenant isolation at the database level.
-- The application must SET app.current_tenant_id = '<uuid>' at the
-- start of each request/activity for RLS to take effect.
--
-- NOTE: RLS is additive to application-level checks. If app.current_tenant_id
-- is not set, current_setting returns '' which won't match any UUID,
-- effectively denying all access (fail-closed).

BEGIN;

-- Enable RLS on tenant-scoped tables
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE siem_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_cache ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY tenant_isolation_investigations ON investigations
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY tenant_isolation_tasks ON agent_tasks
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY tenant_isolation_entities ON entities
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY tenant_isolation_edges ON entity_edges
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY tenant_isolation_siem ON siem_alerts
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY tenant_isolation_cache ON investigation_cache
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- The hydra superuser bypasses RLS by default (BYPASSRLS role attribute).
-- Application connections via PgBouncer use the hydra user which has BYPASSRLS,
-- so RLS acts as defense-in-depth only when app.current_tenant_id is set.
-- To fully enforce RLS, create a restricted application user without BYPASSRLS.

COMMIT;
