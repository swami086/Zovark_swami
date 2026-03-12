-- Migration 021: pgvector HNSW indexes for vector similarity search
-- Sprint 9A — Issue #32

-- Set default search parameters for HNSW
SET hnsw.ef_search = 100;

-- Drop existing IVFFlat indexes if they exist (upgrading to HNSW)
DROP INDEX IF EXISTS idx_skills_embedding;
DROP INDEX IF EXISTS idx_investigation_memory_embedding;
DROP INDEX IF EXISTS idx_memory_embedding;
DROP INDEX IF EXISTS idx_investigations_summary_embedding;

-- HNSW index on entities (entity_hash dedup + semantic search)
-- entities table does not have an embedding column yet; add it
ALTER TABLE entities ADD COLUMN IF NOT EXISTS embedding vector(768);

CREATE INDEX IF NOT EXISTS idx_entities_embedding_hnsw
    ON entities USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 200);

-- HNSW index on entity_edges
ALTER TABLE entity_edges ADD COLUMN IF NOT EXISTS embedding vector(768);

CREATE INDEX IF NOT EXISTS idx_entity_edges_embedding_hnsw
    ON entity_edges USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 200);

-- HNSW index on agent_skills.embedding (replacing IVFFlat)
CREATE INDEX IF NOT EXISTS idx_skills_embedding_hnsw
    ON agent_skills USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 200);

-- HNSW index on investigation_memory.embedding (replacing IVFFlat)
CREATE INDEX IF NOT EXISTS idx_investigation_memory_embedding_hnsw
    ON investigation_memory USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 200);

-- HNSW index on agent_memory_episodic.embedding (replacing IVFFlat)
CREATE INDEX IF NOT EXISTS idx_memory_episodic_embedding_hnsw
    ON agent_memory_episodic USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 200);

-- HNSW index on investigations.summary_embedding (replacing IVFFlat)
CREATE INDEX IF NOT EXISTS idx_investigations_summary_embedding_hnsw
    ON investigations USING hnsw (summary_embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 200);

-- HNSW index on mitre_techniques.embedding (replacing IVFFlat)
DROP INDEX IF EXISTS idx_mitre_embedding;

CREATE INDEX IF NOT EXISTS idx_mitre_embedding_hnsw
    ON mitre_techniques USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 200);
