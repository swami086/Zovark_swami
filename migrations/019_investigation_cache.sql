-- Migration 019: Investigation result cache (Sprint 7E)
-- Same indicators → return cached verdict instead of re-investigating

CREATE TABLE IF NOT EXISTS investigation_cache (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    cache_key VARCHAR(64) NOT NULL,  -- SHA-256 of normalized indicators
    investigation_id UUID NOT NULL,
    task_id UUID,
    verdict VARCHAR(30),
    risk_score FLOAT,
    confidence FLOAT,
    entity_count INTEGER,
    summary TEXT,
    ttl_hours INTEGER DEFAULT 24,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cache_key ON investigation_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON investigation_cache(expires_at);
