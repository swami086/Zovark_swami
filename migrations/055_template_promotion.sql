-- Migration 055: Template Promotion Flywheel
-- Enables Path C -> analyst review -> template promotion -> Path A

-- agent_skills columns for auto-promoted templates
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS auto_promoted BOOLEAN DEFAULT false;
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS source_task_id UUID;
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS promoted_at TIMESTAMPTZ;
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS promoted_by TEXT;
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS promotion_status TEXT DEFAULT 'active' CHECK (promotion_status IN ('active', 'disabled', 'retired'));

-- agent_tasks columns for path tracking
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS path_taken TEXT;
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS generated_code TEXT;

-- Analyst feedback table
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    analyst_email TEXT NOT NULL,
    analyst_verdict TEXT NOT NULL CHECK (analyst_verdict IN ('true_positive', 'false_positive', 'suspicious', 'benign')),
    analyst_risk_score INTEGER CHECK (analyst_risk_score BETWEEN 0 AND 100),
    analyst_notes TEXT,
    original_verdict TEXT,
    original_risk_score INTEGER,
    promote BOOLEAN DEFAULT false,
    promoted_slug TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analyst_feedback_task ON analyst_feedback(task_id);
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_tenant ON analyst_feedback(tenant_id);

-- Promotion queue view
CREATE OR REPLACE VIEW promotion_queue AS
SELECT
    t.id as task_id,
    t.tenant_id,
    t.task_type,
    t.path_taken,
    t.generated_code,
    t.output->>'risk_score' as risk_score,
    t.output->>'verdict' as verdict,
    t.output->'findings' as findings,
    t.output->'iocs' as iocs,
    t.output->'mitre_attack' as mitre_attack,
    t.input->'siem_event' as siem_event,
    t.created_at,
    t.execution_ms
FROM agent_tasks t
WHERE t.path_taken = 'C'
AND t.output->>'verdict' = 'needs_analyst_review'
AND NOT EXISTS (
    SELECT 1 FROM analyst_feedback af WHERE af.task_id = t.id
)
ORDER BY t.created_at DESC;

-- Index for fast promotion queue lookup
CREATE INDEX IF NOT EXISTS idx_agent_tasks_path_verdict ON agent_tasks(path_taken, (output->>'verdict')) WHERE path_taken = 'C';
