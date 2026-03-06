-- Hydra MVP Database Schema
-- Version: 1.2.0
-- 21 tables (14 base + 3 new + 4 entity graph), 1 view, append-only enforcement

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
    password_hash TEXT,
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
    parameters JSONB,
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
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'planning', 'approved', 'executing', 'completed', 'failed', 'cancelled', 'awaiting_approval', 'rejected')),
    error_message TEXT,
    workflow_id VARCHAR(255),
    workflow_run_id VARCHAR(255),
    skill_id UUID REFERENCES agent_skills(id),
    tokens_used_input INTEGER NOT NULL DEFAULT 0,
    tokens_used_output INTEGER NOT NULL DEFAULT 0,
    execution_ms INTEGER,
    sandbox_container_id VARCHAR(255),
    severity VARCHAR(20),
    worker_id VARCHAR(255),
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
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    task_id UUID REFERENCES agent_tasks(id) ON DELETE SET NULL,
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
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
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
-- INVESTIGATION STEPS
-- ============================================================

CREATE TABLE investigation_steps (
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

-- ============================================================
-- APPROVAL REQUESTS
-- ============================================================

CREATE TABLE approval_requests (
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

-- ============================================================
-- PLAYBOOKS
-- ============================================================

CREATE TABLE playbooks (
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
CREATE INDEX idx_investigation_steps_task ON investigation_steps(task_id);
CREATE INDEX idx_approval_requests_task ON approval_requests(task_id);
CREATE INDEX idx_approval_requests_status ON approval_requests(status);
CREATE INDEX idx_playbooks_tenant ON playbooks(tenant_id);

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

-- ============================================================
-- ENTITY GRAPH (Sprint 1G)
-- ============================================================

-- Investigations (partitioned by month)
CREATE TABLE investigations (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id UUID REFERENCES agent_tasks(id) ON DELETE CASCADE,
    alert_source VARCHAR(255),
    alert_type VARCHAR(100),
    skill_id UUID REFERENCES agent_skills(id),
    skill_version INTEGER,
    attack_techniques TEXT[],
    verdict VARCHAR(20) CHECK (verdict IN (
        'true_positive', 'false_positive', 'benign', 'suspicious', 'inconclusive'
    )),
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence NUMERIC(3,2) CHECK (confidence >= 0.0 AND confidence <= 1.0),
    timeline JSONB,
    summary TEXT,
    summary_embedding vector(768),
    model_id VARCHAR(100),
    model_version VARCHAR(100),
    prompt_version VARCHAR(50),
    analyst_feedback JSONB,
    source VARCHAR(20) NOT NULL DEFAULT 'production' CHECK (source IN (
        'production', 'bootstrap', 'synthetic'
    )),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE investigations_2026_01 PARTITION OF investigations
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE investigations_2026_02 PARTITION OF investigations
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE investigations_2026_03 PARTITION OF investigations
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE investigations_2026_04 PARTITION OF investigations
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE investigations_2026_05 PARTITION OF investigations
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE investigations_2026_06 PARTITION OF investigations
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE investigations_2026_07 PARTITION OF investigations
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE investigations_2026_08 PARTITION OF investigations
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE investigations_2026_09 PARTITION OF investigations
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE investigations_2026_10 PARTITION OF investigations
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE investigations_2026_11 PARTITION OF investigations
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE investigations_2026_12 PARTITION OF investigations
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE investigations_default PARTITION OF investigations DEFAULT;

CREATE INDEX idx_investigations_attack_techniques
    ON investigations USING GIN (attack_techniques);
CREATE INDEX idx_investigations_verdict_source
    ON investigations (verdict, source);
CREATE INDEX idx_investigations_risk_score
    ON investigations (risk_score DESC);
CREATE INDEX idx_investigations_created_at
    ON investigations (created_at);
CREATE INDEX idx_investigations_tenant
    ON investigations (tenant_id);
CREATE INDEX idx_investigations_task
    ON investigations (task_id);
CREATE INDEX idx_investigations_summary_embedding
    ON investigations USING ivfflat (summary_embedding vector_cosine_ops) WITH (lists = 100);

-- Entities (normalized IOCs with cross-tenant dedup)
CREATE TABLE entities (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    entity_hash VARCHAR(64) NOT NULL,
    entity_type VARCHAR(20) NOT NULL CHECK (entity_type IN (
        'ip', 'domain', 'file_hash', 'url', 'user', 'device', 'process', 'email'
    )),
    value TEXT NOT NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    threat_score INTEGER DEFAULT 0 CHECK (threat_score >= 0 AND threat_score <= 100),
    observation_count INTEGER DEFAULT 1,
    tenant_count INTEGER DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    UNIQUE(entity_hash, tenant_id)
);

CREATE INDEX idx_entities_type_threat ON entities (entity_type, threat_score DESC);
CREATE INDEX idx_entities_last_seen ON entities (last_seen DESC);
CREATE INDEX idx_entities_tenant ON entities (tenant_id);
CREATE INDEX idx_entities_hash ON entities (entity_hash);

-- Entity edges (relationships between entities)
CREATE TABLE entity_edges (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    source_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    edge_type VARCHAR(30) NOT NULL CHECK (edge_type IN (
        'communicates_with', 'resolved_to', 'logged_into',
        'executed', 'downloaded', 'contains', 'parent_of',
        'accessed', 'sent_to', 'received_from', 'associated_with'
    )),
    investigation_id UUID,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    mitre_technique VARCHAR(20),
    confidence NUMERIC(3,2) DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_entity_edges_source_type ON entity_edges (source_entity_id, edge_type);
CREATE INDEX idx_entity_edges_target ON entity_edges (target_entity_id);
CREATE INDEX idx_entity_edges_investigation ON entity_edges (investigation_id);
CREATE INDEX idx_entity_edges_tenant ON entity_edges (tenant_id);
CREATE INDEX idx_entity_edges_mitre ON entity_edges (mitre_technique) WHERE mitre_technique IS NOT NULL;

-- Entity observations (entity sightings per investigation)
CREATE TABLE entity_observations (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    investigation_id UUID,
    role VARCHAR(20) NOT NULL CHECK (role IN (
        'source', 'destination', 'attacker', 'victim',
        'indicator', 'artifact', 'infrastructure', 'target'
    )),
    context TEXT,
    mitre_technique VARCHAR(20),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_entity_observations_entity ON entity_observations (entity_id);
CREATE INDEX idx_entity_observations_investigation ON entity_observations (investigation_id);
CREATE INDEX idx_entity_observations_role ON entity_observations (role);
CREATE INDEX idx_entity_observations_mitre ON entity_observations (mitre_technique) WHERE mitre_technique IS NOT NULL;

-- ============================================================
-- AUDIT EVENTS (Structured, partitioned, append-only)
-- Sprint 1E-4
-- ============================================================

CREATE TABLE audit_events (
    id BIGSERIAL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'investigation_started', 'investigation_completed', 'code_executed',
        'approval_requested', 'approval_granted', 'approval_denied', 'approval_timeout',
        'entity_extracted', 'detection_generated', 'user_login', 'user_registered'
    )),
    actor_id UUID,
    actor_type VARCHAR(20) CHECK (actor_type IN ('user', 'worker', 'system')),
    resource_type VARCHAR(50),
    resource_id UUID,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE audit_events_2026_01 PARTITION OF audit_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE audit_events_2026_02 PARTITION OF audit_events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit_events_2026_03 PARTITION OF audit_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE audit_events_2026_04 PARTITION OF audit_events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE audit_events_2026_05 PARTITION OF audit_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_events_2026_06 PARTITION OF audit_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE audit_events_2026_07 PARTITION OF audit_events
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE audit_events_2026_08 PARTITION OF audit_events
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE audit_events_2026_09 PARTITION OF audit_events
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE audit_events_2026_10 PARTITION OF audit_events
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE audit_events_2026_11 PARTITION OF audit_events
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE audit_events_2026_12 PARTITION OF audit_events
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;

CREATE INDEX idx_audit_events_tenant ON audit_events (tenant_id);
CREATE INDEX idx_audit_events_type ON audit_events (event_type);
CREATE INDEX idx_audit_events_created ON audit_events (created_at);
CREATE INDEX idx_audit_events_resource ON audit_events (resource_type, resource_id);

-- ============================================================
-- MITRE ATT&CK TECHNIQUES (Sprint 1F)
-- ============================================================

CREATE TABLE mitre_techniques (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    technique_id VARCHAR(20) NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    tactics TEXT[],
    platforms TEXT[],
    data_sources TEXT[],
    detection TEXT,
    url TEXT,
    embedding vector(768),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_mitre_technique_id ON mitre_techniques (technique_id);
CREATE INDEX idx_mitre_tactics ON mitre_techniques USING GIN (tactics);
CREATE INDEX idx_mitre_embedding ON mitre_techniques USING ivfflat (embedding vector_cosine_ops) WITH (lists = 50);

-- ============================================================
-- BOOTSTRAP CORPUS (Sprint 1F)
-- ============================================================

CREATE TABLE bootstrap_corpus (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    source VARCHAR(20) NOT NULL CHECK (source IN ('mitre', 'cisa', 'synthetic')),
    source_id VARCHAR(50),
    title TEXT,
    description TEXT,
    generated_investigation TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'generating', 'completed', 'failed')),
    entity_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_bootstrap_source ON bootstrap_corpus (source, status);
CREATE INDEX idx_bootstrap_source_id ON bootstrap_corpus (source_id);
