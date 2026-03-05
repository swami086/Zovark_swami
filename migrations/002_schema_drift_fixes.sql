-- Migration 002: Schema drift fixes
-- Resolves mismatches between Go API / Python worker and init.sql
-- Safe to re-run (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS guards)

-- ============================================================
-- 0. Fix agent_tasks status CHECK constraint (add awaiting_approval, rejected)
-- ============================================================
ALTER TABLE agent_tasks DROP CONSTRAINT IF EXISTS agent_tasks_status_check;
ALTER TABLE agent_tasks ADD CONSTRAINT agent_tasks_status_check
    CHECK (status IN ('pending', 'planning', 'approved', 'executing', 'completed', 'failed', 'cancelled', 'awaiting_approval', 'rejected'));

-- ============================================================
-- 1. Add password_hash to users table
-- ============================================================
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- ============================================================
-- 2. Add parameters to agent_skills table
-- ============================================================
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS parameters JSONB;

-- ============================================================
-- 3. Add severity and worker_id to agent_tasks table
-- ============================================================
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS severity VARCHAR(20);
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS worker_id VARCHAR(255);

-- ============================================================
-- 4. Fix audit_log FK cascade (ON DELETE CASCADE -> ON DELETE SET NULL)
--    The append-only trigger blocks DELETE, so CASCADE will fail.
-- ============================================================
-- Drop and re-add tenant_id FK on agent_audit_log
ALTER TABLE agent_audit_log ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE agent_audit_log DROP CONSTRAINT IF EXISTS agent_audit_log_tenant_id_fkey;
ALTER TABLE agent_audit_log
    ADD CONSTRAINT agent_audit_log_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL;

-- Fix user_id FK on agent_audit_log
ALTER TABLE agent_audit_log DROP CONSTRAINT IF EXISTS agent_audit_log_user_id_fkey;
ALTER TABLE agent_audit_log
    ADD CONSTRAINT agent_audit_log_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

-- Fix usage_records FKs (also has immutable trigger)
ALTER TABLE usage_records ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_tenant_id_fkey;
ALTER TABLE usage_records
    ADD CONSTRAINT usage_records_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL;

ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_user_id_fkey;
ALTER TABLE usage_records
    ADD CONSTRAINT usage_records_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE usage_records DROP CONSTRAINT IF EXISTS usage_records_task_id_fkey;
ALTER TABLE usage_records
    ADD CONSTRAINT usage_records_task_id_fkey
    FOREIGN KEY (task_id) REFERENCES agent_tasks(id) ON DELETE SET NULL;

-- ============================================================
-- 5. Create investigation_steps table
-- ============================================================
CREATE TABLE IF NOT EXISTS investigation_steps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id UUID NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL,
    step_type VARCHAR(50) NOT NULL DEFAULT 'analysis',
    summary_prompt TEXT,
    generated_code TEXT,
    output TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    tokens_used_input INTEGER DEFAULT 0,
    tokens_used_output INTEGER DEFAULT 0,
    execution_ms INTEGER DEFAULT 0,
    execution_mode VARCHAR(20) DEFAULT 'sandbox',
    parameters_used JSONB,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(task_id, step_number)
);
CREATE INDEX IF NOT EXISTS idx_investigation_steps_task ON investigation_steps(task_id);

-- ============================================================
-- 6. Create approval_requests table
-- ============================================================
CREATE TABLE IF NOT EXISTS approval_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id UUID NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'medium',
    action_summary TEXT,
    generated_code TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ,
    decided_by UUID REFERENCES users(id),
    decision_comment TEXT
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_task ON approval_requests(task_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status);

-- ============================================================
-- 7. Create playbooks table
-- ============================================================
CREATE TABLE IF NOT EXISTS playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    task_type VARCHAR(100) NOT NULL,
    is_template BOOLEAN NOT NULL DEFAULT false,
    system_prompt_override TEXT,
    steps JSONB NOT NULL DEFAULT '[]',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant ON playbooks(tenant_id);
