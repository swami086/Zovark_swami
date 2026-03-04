-- Hydra MVP Database Schema
-- Version: 1.1.1
-- 14 tables, 1 view, 14 indexes, 2 append-only enforcement rules

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================
-- TENANT & AUTH
-- ============================================================

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    tier VARCHAR(50) NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'professional', 'enterprise')),
    settings JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    role VARCHAR(20) NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
    external_auth_id VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- ============================================================
-- AGENT CONFIGURATION
-- ============================================================

CREATE TABLE agent_personas (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    system_prompt TEXT NOT NULL,
    model_name VARCHAR(100) NOT NULL DEFAULT 'fast',
    temperature NUMERIC(3,2) NOT NULL DEFAULT 0.7 CHECK (temperature >= 0 AND temperature <= 2),
    max_tokens INTEGER NOT NULL DEFAULT 2048,
    tools_enabled JSONB NOT NULL DEFAULT '[]',
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SKILLS (Code Generation & Execution)
-- ============================================================

CREATE TABLE agent_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),  -- NULL = community/global
    skill_name VARCHAR(100) NOT NULL,
    skill_slug VARCHAR(100) NOT NULL,
    version INTEGER DEFAULT 1,
    is_community BOOLEAN DEFAULT true,
    threat_types TEXT[] NOT NULL,
    mitre_tactics TEXT[] NOT NULL,
    mitre_techniques TEXT[] NOT NULL,
    severity_default VARCHAR(20) DEFAULT 'medium',
    applicable_log_sources TEXT[],
    investigation_methodology TEXT NOT NULL,
    detection_patterns TEXT NOT NULL,
    code_template TEXT,
    example_prompt TEXT NOT NULL,
    expected_output_schema JSONB,
    follow_up_chain JSONB,
    embedding vector(768),
    keywords TEXT[],
    times_used INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, skill_slug, version)
);

-- ============================================================
-- TASKS & EXECUTION
-- ============================================================

CREATE TABLE agent_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    persona_id UUID REFERENCES agent_personas(id),
    task_type VARCHAR(100) NOT NULL,
    input JSONB NOT NULL DEFAULT '{}',
    output JSONB,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'planning', 'approved', 'executing', 'completed', 'failed', 'cancelled')),
    error_message TEXT,
    workflow_id VARCHAR(255),
    workflow_run_id VARCHAR(255),
    skill_id UUID REFERENCES agent_skills(id),
    tokens_used_input INTEGER NOT NULL DEFAULT 0,
    tokens_used_output INTEGER NOT NULL DEFAULT 0,
    execution_ms INTEGER,
    sandbox_container_id VARCHAR(255),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_task_steps (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id UUID NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL,
    step_type VARCHAR(50) NOT NULL CHECK (step_type IN ('plan', 'llm_call', 'skill_exec', 'tool_call', 'human_approval', 'sandbox_exec')),
    input JSONB,
    output JSONB,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    error_message TEXT,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    execution_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- MEMORY (Episodic + Semantic via pgvector + Investigation Memory)
-- ============================================================

CREATE TABLE investigation_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    task_id UUID NOT NULL REFERENCES agent_tasks(id),
    skill_used_id UUID REFERENCES agent_skills(id),
    threat_type VARCHAR(100),
    memory_summary TEXT NOT NULL,
    key_findings JSONB NOT NULL,
    key_iocs JSONB,
    risk_score INTEGER,
    effective_patterns TEXT[],
    embedding vector(768),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE agent_memory_episodic (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    persona_id UUID REFERENCES agent_personas(id),
    task_id UUID REFERENCES agent_tasks(id),
    memory_type VARCHAR(50) NOT NULL DEFAULT 'task_outcome' CHECK (memory_type IN ('task_outcome', 'error_lesson', 'user_preference', 'skill_feedback')),
    content TEXT NOT NULL,
    embedding vector(768),
    importance_score NUMERIC(3,2) NOT NULL DEFAULT 0.5 CHECK (importance_score >= 0 AND importance_score <= 1),
    access_count INTEGER NOT NULL DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- USAGE METERING
-- ============================================================

CREATE TABLE usage_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    task_id UUID REFERENCES agent_tasks(id),
    record_type VARCHAR(50) NOT NULL CHECK (record_type IN ('llm_call', 'embedding', 'skill_exec', 'storage')),
    model_name VARCHAR(100),
    tokens_input INTEGER NOT NULL DEFAULT 0,
    tokens_output INTEGER NOT NULL DEFAULT 0,
    cost_usd NUMERIC(10,6) NOT NULL DEFAULT 0,
    execution_ms INTEGER,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- AUDIT LOG (Immutable, append-only)
-- ============================================================

CREATE TABLE agent_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- OBJECT STORAGE REFERENCES
-- ============================================================

CREATE TABLE object_refs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bucket VARCHAR(100) NOT NULL,
    object_key VARCHAR(500) NOT NULL,
    content_type VARCHAR(255),
    size_bytes BIGINT,
    checksum_sha256 VARCHAR(64),
    uploaded_by UUID REFERENCES users(id),
    task_id UUID REFERENCES agent_tasks(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(bucket, object_key)
);

-- ============================================================
-- WORKING MEMORY (Redis-backed, but schema for overflow/persistence)
-- ============================================================

CREATE TABLE working_memory_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    snapshot_data JSONB NOT NULL,
    token_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SIEM INTEGRATION
-- ============================================================

CREATE TABLE log_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    connection_config JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_event_at TIMESTAMPTZ,
    event_count INTEGER DEFAULT 0,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE siem_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    log_source_id UUID NOT NULL REFERENCES log_sources(id),
    task_id UUID REFERENCES agent_tasks(id),
    alert_name VARCHAR(500) NOT NULL,
    severity VARCHAR(20),
    source_ip VARCHAR(45),
    dest_ip VARCHAR(45),
    rule_name VARCHAR(500),
    raw_event JSONB NOT NULL,
    normalized_event JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'new',
    auto_investigate BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_agent_personas_tenant ON agent_personas(tenant_id);
CREATE INDEX idx_skills_tenant ON agent_skills(tenant_id);
CREATE INDEX idx_skills_threat ON agent_skills USING GIN(threat_types);
CREATE INDEX idx_skills_mitre ON agent_skills USING GIN(mitre_techniques);
CREATE INDEX idx_skills_keywords ON agent_skills USING GIN(keywords);
CREATE INDEX idx_skills_embedding ON agent_skills USING hnsw (embedding vector_cosine_ops);
CREATE INDEX idx_memory_tenant ON investigation_memory(tenant_id);
CREATE INDEX idx_investigation_memory_embedding ON investigation_memory USING hnsw (embedding vector_cosine_ops);
CREATE INDEX idx_agent_tasks_tenant_status ON agent_tasks(tenant_id, status);
CREATE INDEX idx_agent_tasks_workflow ON agent_tasks(workflow_id);
CREATE INDEX idx_agent_task_steps_task ON agent_task_steps(task_id);
CREATE INDEX idx_agent_memory_tenant ON agent_memory_episodic(tenant_id);
CREATE INDEX idx_agent_memory_type ON agent_memory_episodic(tenant_id, memory_type);
CREATE INDEX idx_usage_records_tenant ON usage_records(tenant_id);
CREATE INDEX idx_usage_records_created ON usage_records(tenant_id, created_at);
CREATE INDEX idx_audit_log_tenant ON agent_audit_log(tenant_id);
CREATE INDEX idx_audit_log_created ON agent_audit_log(tenant_id, created_at);
CREATE INDEX idx_audit_log_action ON agent_audit_log(action);
CREATE INDEX idx_object_refs_tenant ON object_refs(tenant_id);
CREATE INDEX idx_log_sources_tenant ON log_sources(tenant_id);
CREATE INDEX idx_siem_alerts_tenant ON siem_alerts(tenant_id);
CREATE INDEX idx_siem_alerts_status ON siem_alerts(status);
CREATE INDEX idx_siem_alerts_source ON siem_alerts(log_source_id);
CREATE INDEX idx_siem_alerts_created ON siem_alerts(created_at DESC);

-- Vector similarity index for episodic memory
CREATE INDEX idx_memory_embedding ON agent_memory_episodic
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- ============================================================
-- APPEND-ONLY ENFORCEMENT (audit_log + usage_records)
-- ============================================================

CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: modifications are not permitted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_immutable
    BEFORE UPDATE OR DELETE ON agent_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER usage_records_immutable
    BEFORE UPDATE OR DELETE ON usage_records
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- ============================================================
-- VIEW: Task summary with cost
-- ============================================================

CREATE OR REPLACE VIEW v_task_summary AS
SELECT
    t.id AS task_id,
    t.tenant_id,
    tn.name AS tenant_name,
    t.task_type,
    t.status,
    t.tokens_used_input,
    t.tokens_used_output,
    t.execution_ms,
    COALESCE(SUM(u.cost_usd), 0) AS total_cost_usd,
    t.created_at,
    t.completed_at
FROM agent_tasks t
JOIN tenants tn ON tn.id = t.tenant_id
LEFT JOIN usage_records u ON u.task_id = t.id
GROUP BY t.id, tn.name;

-- ============================================================
-- SEED DATA (Development only)
-- ============================================================

INSERT INTO tenants (name, slug, tier) VALUES
    ('Hydra Dev', 'hydra-dev', 'enterprise')
ON CONFLICT (slug) DO NOTHING;
