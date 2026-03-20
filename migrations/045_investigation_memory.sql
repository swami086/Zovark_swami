-- Migration 045: Investigation memory — stores successful investigation patterns
-- Foundation for prompt enrichment with past learnings

CREATE TABLE IF NOT EXISTS investigation_memory (
    id SERIAL PRIMARY KEY,
    task_type VARCHAR(100) NOT NULL,
    alert_signature TEXT NOT NULL,
    code_template TEXT,
    iocs_found JSONB DEFAULT '[]',
    findings_found JSONB DEFAULT '[]',
    risk_score INTEGER,
    success BOOLEAN DEFAULT true,
    error_type VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memory_task_type
    ON investigation_memory(task_type);
CREATE INDEX IF NOT EXISTS idx_memory_success
    ON investigation_memory(success);
CREATE INDEX IF NOT EXISTS idx_memory_created
    ON investigation_memory(created_at);
