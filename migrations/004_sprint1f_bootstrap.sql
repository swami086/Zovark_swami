-- Sprint 1F: Bootstrap Corpus — MITRE ATT&CK + CISA KEV
-- Apply with: docker compose exec -T postgres psql -U hydra -d hydra < migrations/004_sprint1f_bootstrap.sql

-- ============================================================
-- MITRE ATT&CK Techniques
-- ============================================================

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    technique_id VARCHAR(20) NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    tactics TEXT[],
    platforms TEXT[],
    data_sources TEXT[],
    detection TEXT,
    url TEXT,
    embedding vector(768),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mitre_technique_id ON mitre_techniques (technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_tactics ON mitre_techniques USING GIN (tactics);
CREATE INDEX IF NOT EXISTS idx_mitre_embedding ON mitre_techniques USING ivfflat (embedding vector_cosine_ops) WITH (lists = 50);

-- ============================================================
-- Bootstrap Corpus (synthetic investigations from MITRE/CISA)
-- ============================================================

CREATE TABLE IF NOT EXISTS bootstrap_corpus (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    source VARCHAR(20) NOT NULL CHECK (source IN ('mitre', 'cisa', 'synthetic')),
    source_id VARCHAR(50),
    title TEXT,
    description TEXT,
    generated_investigation TEXT,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'generating', 'completed', 'failed')),
    entity_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bootstrap_source ON bootstrap_corpus (source, status);
CREATE INDEX IF NOT EXISTS idx_bootstrap_source_id ON bootstrap_corpus (source_id);

-- ============================================================
-- Make investigations.task_id nullable (bootstrap has no agent_task)
-- ============================================================

ALTER TABLE investigations ALTER COLUMN task_id DROP NOT NULL;
