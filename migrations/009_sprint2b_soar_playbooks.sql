-- Sprint 2B: SOAR Response Playbooks
-- Migration 009
-- Adds response_playbooks, response_executions, response_integrations tables

CREATE TABLE IF NOT EXISTS response_playbooks (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger_conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    requires_approval BOOLEAN DEFAULT true,
    enabled BOOLEAN DEFAULT true,
    tenant_id UUID REFERENCES tenants(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS response_executions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    playbook_id UUID REFERENCES response_playbooks(id),
    investigation_id UUID,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    trigger_data JSONB,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN (
        'pending', 'awaiting_approval', 'executing', 'completed',
        'failed', 'rolled_back', 'cancelled'
    )),
    actions_executed JSONB DEFAULT '[]',
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS response_integrations (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    integration_type VARCHAR(50) NOT NULL,
    name VARCHAR(255),
    webhook_url TEXT NOT NULL,
    auth_type VARCHAR(20) CHECK (auth_type IN ('none', 'bearer', 'api_key', 'basic')),
    auth_credentials TEXT,  -- TODO: migrate to Vault for production
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbooks_tenant ON response_playbooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON response_playbooks(enabled);
CREATE INDEX IF NOT EXISTS idx_response_exec_tenant ON response_executions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_response_exec_status ON response_executions(status);
CREATE INDEX IF NOT EXISTS idx_response_exec_investigation ON response_executions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON response_integrations(tenant_id);
