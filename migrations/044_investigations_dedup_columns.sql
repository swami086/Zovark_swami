-- Migration 044: Add dedup tracking columns to agent_tasks
-- Supports 3-stage dedup pipeline (exact, correlate, semantic)

-- Add dedup columns
ALTER TABLE agent_tasks
  ADD COLUMN IF NOT EXISTS dedup_reason VARCHAR(50),
  ADD COLUMN IF NOT EXISTS existing_task_id VARCHAR(255);

-- Add 'deduplicated' to the status CHECK constraint
ALTER TABLE agent_tasks DROP CONSTRAINT IF EXISTS agent_tasks_status_check;
ALTER TABLE agent_tasks ADD CONSTRAINT agent_tasks_status_check
  CHECK (status IN (
    'pending', 'planning', 'approved', 'executing', 'completed',
    'failed', 'cancelled', 'awaiting_approval', 'rejected',
    'blocked_credentials', 'deduplicated'
  ));

-- Index for finding deduplicated tasks
CREATE INDEX IF NOT EXISTS idx_agent_tasks_dedup
  ON agent_tasks (existing_task_id) WHERE dedup_reason IS NOT NULL;
