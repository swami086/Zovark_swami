-- Mission 4: Global Request Tracing
-- Adds trace_id for end-to-end correlation through the pipeline.

ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS trace_id UUID;
CREATE INDEX IF NOT EXISTS idx_agent_tasks_trace_id ON agent_tasks(trace_id);

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS trace_id UUID;
CREATE INDEX IF NOT EXISTS idx_audit_events_trace_id ON audit_events(trace_id);
