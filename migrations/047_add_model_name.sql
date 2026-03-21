-- Add model_name tracking to investigations and tasks
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS model_name TEXT DEFAULT 'unknown';
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS model_name TEXT DEFAULT 'unknown';

CREATE INDEX IF NOT EXISTS idx_investigations_model ON investigations(model_name);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_model ON agent_tasks(model_name);
