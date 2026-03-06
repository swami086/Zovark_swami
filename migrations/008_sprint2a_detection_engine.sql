-- Sprint 2A: Self-Generating Detection Engine
-- Migration 008
-- Adds detection_candidates and detection_rules tables

CREATE TABLE IF NOT EXISTS detection_candidates (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    technique_id VARCHAR(20) NOT NULL,
    pattern_signature VARCHAR(64) NOT NULL UNIQUE,
    pattern_description TEXT,
    entity_types TEXT[],
    edge_patterns TEXT[],
    investigation_count INTEGER,
    tenant_spread INTEGER,
    avg_risk_score FLOAT,
    status VARCHAR(20) DEFAULT 'candidate' CHECK (status IN (
        'candidate', 'generating', 'validating', 'approved', 'deployed', 'rejected', 'retired'
    )),
    sigma_rule TEXT,
    validation_result JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    deployed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    candidate_id UUID REFERENCES detection_candidates(id),
    technique_id VARCHAR(20) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    rule_version INTEGER NOT NULL DEFAULT 1,
    sigma_yaml TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'testing', 'retired')),
    tp_rate FLOAT,
    fp_rate FLOAT,
    investigations_matched INTEGER,
    tenant_spread INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    retired_at TIMESTAMPTZ,
    UNIQUE(technique_id, rule_version)
);

CREATE INDEX IF NOT EXISTS idx_candidates_technique ON detection_candidates(technique_id);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON detection_candidates(status);
CREATE INDEX IF NOT EXISTS idx_rules_technique ON detection_rules(technique_id);
CREATE INDEX IF NOT EXISTS idx_rules_status ON detection_rules(status);
