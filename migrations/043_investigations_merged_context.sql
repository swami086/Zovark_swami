-- Migration 043: Add merged_context column for correlated alert merging
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS merged_context JSONB;
