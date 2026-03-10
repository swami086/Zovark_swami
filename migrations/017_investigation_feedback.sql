-- Migration 017: Investigation feedback collection (Sprint 7C)
-- The data moat — analyst feedback on investigation quality

CREATE TABLE IF NOT EXISTS investigation_feedback (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    investigation_id UUID NOT NULL,  -- logical ref to investigations(id), no FK due to partitioning
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    analyst_id UUID REFERENCES users(id),
    verdict_correct BOOLEAN,
    corrected_verdict VARCHAR(30),
    false_positive BOOLEAN DEFAULT false,
    missed_threat BOOLEAN DEFAULT false,
    notes TEXT,
    analyst_confidence FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feedback_investigation ON investigation_feedback(investigation_id);
CREATE INDEX IF NOT EXISTS idx_feedback_tenant ON investigation_feedback(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON investigation_feedback(verdict_correct);

-- Materialized view for feedback accuracy aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS feedback_accuracy AS
SELECT
    COUNT(*) as total_feedback,
    SUM(CASE WHEN verdict_correct THEN 1 ELSE 0 END) as correct,
    SUM(CASE WHEN NOT verdict_correct THEN 1 ELSE 0 END) as incorrect,
    SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) as false_positives,
    SUM(CASE WHEN missed_threat THEN 1 ELSE 0 END) as missed_threats,
    ROUND(AVG(CASE WHEN verdict_correct THEN 1.0 ELSE 0.0 END)::numeric, 3) as accuracy_rate,
    ROUND(AVG(analyst_confidence)::numeric, 3) as avg_analyst_confidence
FROM investigation_feedback;

CREATE UNIQUE INDEX IF NOT EXISTS idx_feedback_accuracy_unique ON feedback_accuracy(total_feedback);
