BEGIN;
ALTER TABLE model_registry ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE model_registry ADD COLUMN IF NOT EXISTS is_global BOOLEAN NOT NULL DEFAULT false;
UPDATE model_registry SET is_global = true WHERE tenant_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_model_registry_tenant ON model_registry (tenant_id) WHERE tenant_id IS NOT NULL;

ALTER TABLE ab_tests ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE ab_tests SET tenant_id = (SELECT id FROM tenants ORDER BY created_at LIMIT 1) WHERE tenant_id IS NULL;
ALTER TABLE ab_tests ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ab_tests_tenant ON ab_tests (tenant_id);

ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
UPDATE retention_policies SET tenant_id = (SELECT id FROM tenants ORDER BY created_at LIMIT 1) WHERE tenant_id IS NULL;
ALTER TABLE retention_policies ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_retention_policies_tenant ON retention_policies (tenant_id);
COMMIT;
