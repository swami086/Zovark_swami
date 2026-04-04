BEGIN;
CREATE TABLE IF NOT EXISTS system_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    config_key TEXT NOT NULL,
    config_value TEXT NOT NULL,
    is_secret BOOLEAN NOT NULL DEFAULT false,
    description TEXT,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, config_key)
);
ALTER TABLE system_configs ENABLE ROW LEVEL SECURITY;
CREATE POLICY system_configs_tenant_isolation ON system_configs
    USING (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));
CREATE INDEX IF NOT EXISTS idx_system_configs_tenant_key ON system_configs(tenant_id, config_key);

CREATE TABLE IF NOT EXISTS system_config_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    config_key TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'rollback')),
    changed_by UUID,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_config_audit_tenant ON system_config_audit(tenant_id, changed_at DESC);

CREATE OR REPLACE FUNCTION update_system_configs_timestamp() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_system_configs_updated_at
    BEFORE UPDATE ON system_configs
    FOR EACH ROW EXECUTE FUNCTION update_system_configs_timestamp();

GRANT SELECT, INSERT, UPDATE, DELETE ON system_configs TO zovark_app;
GRANT SELECT, INSERT ON system_config_audit TO zovark_app;
COMMIT;
