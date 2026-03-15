-- Migration 038: CISA KEV processing columns
-- Sprint v0.15.0 — KEV corpus processing support

ALTER TABLE bootstrap_corpus ADD COLUMN IF NOT EXISTS processed_at TIMESTAMP;
ALTER TABLE bootstrap_corpus ADD COLUMN IF NOT EXISTS embedding_id UUID;

CREATE INDEX IF NOT EXISTS idx_kev_unprocessed
    ON bootstrap_corpus(created_at)
    WHERE source = 'cisa' AND processed_at IS NULL;
