-- Migration 029: Kill Switch (Sprint v0.10.0)
-- Per-tenant, per-workflow automation controls

CREATE TABLE IF NOT EXISTS automation_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    -- Scope
    scope VARCHAR(30) NOT NULL DEFAULT 'tenant', -- 'tenant', 'workflow', 'activity', 'playbook'
    scope_target VARCHAR(200), -- workflow name, activity name, or playbook ID (NULL = all)
    -- Control
    enabled BOOLEAN NOT NULL DEFAULT true,
    mode VARCHAR(20) NOT NULL DEFAULT 'shadow', -- 'shadow', 'assisted', 'autonomous', 'disabled'
    -- Kill switch
    killed BOOLEAN NOT NULL DEFAULT false,
    killed_by UUID REFERENCES users(id),
    killed_at TIMESTAMPTZ,
    kill_reason TEXT,
    -- Auto-resume
    auto_resume_at TIMESTAMPTZ, -- optional: auto-re-enable after cooldown
    -- Audit
    last_changed_by UUID REFERENCES users(id),
    last_changed_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Ensure unique scope per tenant
    UNIQUE(tenant_id, scope, scope_target)
);

CREATE INDEX idx_automation_controls_tenant ON automation_controls(tenant_id);
CREATE INDEX idx_automation_controls_killed ON automation_controls(killed) WHERE killed = true;

-- Kill switch audit log
CREATE TABLE IF NOT EXISTS kill_switch_audit (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    control_id UUID NOT NULL REFERENCES automation_controls(id),
    action VARCHAR(20) NOT NULL, -- 'kill', 'resume', 'mode_change', 'create', 'update'
    old_state JSONB,
    new_state JSONB,
    actor_id UUID REFERENCES users(id),
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kill_audit_tenant ON kill_switch_audit(tenant_id, created_at);
CREATE INDEX idx_kill_audit_control ON kill_switch_audit(control_id);
