-- Sprint 1G: Entity Graph Schema + Canonical Investigation Schema
-- Migration: 001_sprint1g_entity_graph.sql
-- Standalone migration for existing databases (idempotent with IF NOT EXISTS)

-- ============================================================
-- INVESTIGATIONS (Partitioned by month)
-- ============================================================

CREATE TABLE IF NOT EXISTS investigations (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
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

-- Monthly partitions for 2026
CREATE TABLE IF NOT EXISTS investigations_2026_01 PARTITION OF investigations
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS investigations_2026_02 PARTITION OF investigations
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS investigations_2026_03 PARTITION OF investigations
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE IF NOT EXISTS investigations_2026_04 PARTITION OF investigations
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS investigations_2026_05 PARTITION OF investigations
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE IF NOT EXISTS investigations_2026_06 PARTITION OF investigations
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE IF NOT EXISTS investigations_2026_07 PARTITION OF investigations
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE IF NOT EXISTS investigations_2026_08 PARTITION OF investigations
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE IF NOT EXISTS investigations_2026_09 PARTITION OF investigations
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE IF NOT EXISTS investigations_2026_10 PARTITION OF investigations
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE IF NOT EXISTS investigations_2026_11 PARTITION OF investigations
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE IF NOT EXISTS investigations_2026_12 PARTITION OF investigations
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
CREATE TABLE IF NOT EXISTS investigations_default PARTITION OF investigations DEFAULT;

-- Investigations indexes
CREATE INDEX IF NOT EXISTS idx_investigations_attack_techniques
    ON investigations USING GIN (attack_techniques);
CREATE INDEX IF NOT EXISTS idx_investigations_verdict_source
    ON investigations (verdict, source);
CREATE INDEX IF NOT EXISTS idx_investigations_risk_score
    ON investigations (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_investigations_created_at
    ON investigations (created_at);
CREATE INDEX IF NOT EXISTS idx_investigations_tenant
    ON investigations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_investigations_task
    ON investigations (task_id);
CREATE INDEX IF NOT EXISTS idx_investigations_summary_embedding
    ON investigations USING ivfflat (summary_embedding vector_cosine_ops) WITH (lists = 100);

-- ============================================================
-- ENTITIES (Normalized IOCs with cross-tenant dedup)
-- ============================================================

CREATE TABLE IF NOT EXISTS entities (
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

CREATE INDEX IF NOT EXISTS idx_entities_type_threat
    ON entities (entity_type, threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_entities_last_seen
    ON entities (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_entities_tenant
    ON entities (tenant_id);
CREATE INDEX IF NOT EXISTS idx_entities_hash
    ON entities (entity_hash);

-- ============================================================
-- ENTITY EDGES (Relationships between entities)
-- ============================================================

CREATE TABLE IF NOT EXISTS entity_edges (
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

CREATE INDEX IF NOT EXISTS idx_entity_edges_source_type
    ON entity_edges (source_entity_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_entity_edges_target
    ON entity_edges (target_entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_edges_investigation
    ON entity_edges (investigation_id);
CREATE INDEX IF NOT EXISTS idx_entity_edges_tenant
    ON entity_edges (tenant_id);
CREATE INDEX IF NOT EXISTS idx_entity_edges_mitre
    ON entity_edges (mitre_technique) WHERE mitre_technique IS NOT NULL;

-- ============================================================
-- ENTITY OBSERVATIONS (Entity sightings per investigation)
-- ============================================================

CREATE TABLE IF NOT EXISTS entity_observations (
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

CREATE INDEX IF NOT EXISTS idx_entity_observations_entity
    ON entity_observations (entity_id);
CREATE INDEX IF NOT EXISTS idx_entity_observations_investigation
    ON entity_observations (investigation_id);
CREATE INDEX IF NOT EXISTS idx_entity_observations_role
    ON entity_observations (role);
CREATE INDEX IF NOT EXISTS idx_entity_observations_mitre
    ON entity_observations (mitre_technique) WHERE mitre_technique IS NOT NULL;
