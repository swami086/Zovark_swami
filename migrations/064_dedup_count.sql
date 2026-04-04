-- Migration 064: Add dedup_count column to agent_tasks
-- Tracks how many duplicate alerts were absorbed by this investigation.
-- SAFE: ADD COLUMN IF NOT EXISTS, no data loss.

ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS dedup_count INTEGER DEFAULT 0;
