-- Migration 042: Investigation fingerprints for semantic dedup
CREATE TABLE IF NOT EXISTS investigation_fingerprints (
    id SERIAL PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL,
    fingerprint_text TEXT NOT NULL,
    embedding vector(384),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fingerprints_embedding
    ON investigation_fingerprints
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE INDEX IF NOT EXISTS idx_fingerprints_created_at
    ON investigation_fingerprints (created_at);
