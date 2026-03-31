-- Mission 3: PostgreSQL Row-Level Security
-- Enforces tenant isolation at the database level.
-- Application sets: SET LOCAL app.current_tenant = '<tenant_uuid>';

-- Helper function to get current tenant
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
  SELECT NULLIF(current_setting('app.current_tenant', true), '')::UUID;
$$ LANGUAGE SQL STABLE;

-- Apply RLS to core tenant-scoped tables
DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOR tbl IN
        SELECT unnest(ARRAY[
            'agent_tasks',
            'investigations',
            'llm_audit_log',
            'audit_events',
            'analyst_feedback',
            'entities',
            'entity_edges',
            'response_playbooks',
            'users',
            'cipher_audit_events'
        ])
    LOOP
        -- Only enable RLS if table exists
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = tbl AND table_schema = 'public') THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);

            -- Drop existing policy if it exists (idempotent)
            EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', tbl);

            -- Create tenant isolation policy
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I
                 FOR ALL
                 USING (tenant_id = current_tenant_id())
                 WITH CHECK (tenant_id = current_tenant_id())',
                tbl
            );
        END IF;
    END LOOP;
END $$;

-- Note: The zovark DB user is NOT a superuser, so RLS applies to it.
-- For admin operations, use: SET LOCAL app.current_tenant = '<tenant_id>';
