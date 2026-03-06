-- Sprint 3D: Fine-Tuning Data Pipeline
-- Tracks fine-tuning jobs: data export, quality scoring, evaluation results

CREATE TABLE IF NOT EXISTS finetuning_jobs (
    id VARCHAR(100) PRIMARY KEY,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'exporting', 'scoring', 'evaluating', 'completed', 'failed', 'skipped')),
    config JSONB DEFAULT '{}',
    training_examples INT DEFAULT 0,
    quality_stats JSONB DEFAULT '{}',
    evaluation_results JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_finetuning_jobs_status ON finetuning_jobs(status);
CREATE INDEX IF NOT EXISTS idx_finetuning_jobs_created ON finetuning_jobs(created_at DESC);
