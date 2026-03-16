-- Migration 040: Human review flags for investigation quality gating
-- Sprint: Accuracy benchmark & detection threshold

ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS needs_human_review BOOLEAN DEFAULT FALSE;
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS review_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_tasks_human_review
    ON agent_tasks(needs_human_review)
    WHERE needs_human_review = TRUE;
