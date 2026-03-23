-- Migration 053: IOC evidence_refs support
-- Each IOC in output.iocs[] now includes evidence_refs[] linking it to the source log line or SIEM field.

-- Add GIN index on iocs for faster querying
CREATE INDEX IF NOT EXISTS idx_agent_tasks_iocs ON agent_tasks USING gin((output->'iocs'));

-- Add comment documenting the IOC schema with evidence_refs
COMMENT ON COLUMN agent_tasks.output IS 'Investigation output JSON. IOCs in output.iocs[] now include evidence_refs[] linking each IOC to its source log line or SIEM field.';
