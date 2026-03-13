-- Migration 027: Shadow Mode (Sprint v0.10.0)
-- Recommendations & human decisions for shadow mode evaluation

CREATE TABLE IF NOT EXISTS shadow_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    task_id UUID REFERENCES agent_tasks(id),
    investigation_id UUID REFERENCES investigations(id),
    alert_type VARCHAR(100),
    alert_source VARCHAR(100),
    -- Hydra's recommendation
    recommended_action VARCHAR(50) NOT NULL, -- 'isolate', 'block', 'quarantine', 'escalate', 'dismiss', 'investigate_further'
    recommended_severity VARCHAR(20), -- 'critical', 'high', 'medium', 'low', 'informational'
    recommendation_reasoning TEXT,
    confidence FLOAT CHECK (confidence >= 0 AND confidence <= 1),
    recommended_playbook_id UUID REFERENCES response_playbooks(id),
    -- Human decision
    human_action VARCHAR(50), -- what the analyst actually did
    human_severity VARCHAR(20),
    human_reasoning TEXT,
    decided_by UUID REFERENCES users(id),
    decided_at TIMESTAMPTZ,
    -- Match analysis
    action_match BOOLEAN, -- did human agree with Hydra?
    severity_match BOOLEAN,
    match_category VARCHAR(20), -- 'exact_match', 'partial_match', 'override', 'rejection'
    mismatch_reason TEXT, -- analyst's reason for disagreeing
    -- Metadata
    model_id VARCHAR(100),
    prompt_version VARCHAR(20),
    processing_time_ms INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'decided', 'expired'
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_shadow_rec_tenant ON shadow_recommendations(tenant_id);
CREATE INDEX idx_shadow_rec_status ON shadow_recommendations(status) WHERE status = 'pending';
CREATE INDEX idx_shadow_rec_match ON shadow_recommendations(tenant_id, action_match) WHERE human_action IS NOT NULL;
CREATE INDEX idx_shadow_rec_created ON shadow_recommendations(created_at);
CREATE INDEX idx_shadow_rec_task ON shadow_recommendations(task_id);

-- Conformance metrics materialized view
CREATE MATERIALIZED VIEW IF NOT EXISTS shadow_conformance_stats AS
SELECT
    tenant_id,
    alert_type,
    COUNT(*) AS total_recommendations,
    COUNT(*) FILTER (WHERE human_action IS NOT NULL) AS total_decided,
    COUNT(*) FILTER (WHERE action_match = true) AS exact_matches,
    COUNT(*) FILTER (WHERE severity_match = true) AS severity_matches,
    COUNT(*) FILTER (WHERE match_category = 'override') AS overrides,
    COUNT(*) FILTER (WHERE match_category = 'rejection') AS rejections,
    ROUND(AVG(CASE WHEN action_match THEN 1.0 ELSE 0.0 END)::numeric, 4) AS action_match_rate,
    ROUND(AVG(confidence)::numeric, 4) AS avg_confidence,
    ROUND(AVG(processing_time_ms)::numeric, 0) AS avg_processing_ms,
    MAX(created_at) AS last_recommendation_at
FROM shadow_recommendations
WHERE human_action IS NOT NULL
GROUP BY tenant_id, alert_type
WITH NO DATA;

CREATE UNIQUE INDEX idx_shadow_conformance_tenant_alert ON shadow_conformance_stats(tenant_id, alert_type);
