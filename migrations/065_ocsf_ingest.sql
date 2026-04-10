-- Migration 065: OCSF ingest — immutable vendor payload + API-computed dedup hash
-- SIEM normalization runs in Go; worker reads OCSF from agent_tasks.input.siem_event.

ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS raw_input JSONB;
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS dedup_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_tasks_dedup_hash ON agent_tasks (dedup_hash)
  WHERE dedup_hash IS NOT NULL;

COMMENT ON COLUMN agent_tasks.raw_input IS 'Immutable ingest bytes stored as JSONB: JSON endpoints keep the exact HTTP body bytes; CEF/LEEF store json.Marshal(exact line) (JSON string value).';
COMMENT ON COLUMN agent_tasks.dedup_hash IS 'SHA-256 hex of OCSF canonical dedup fields; computed only in Go API.';
