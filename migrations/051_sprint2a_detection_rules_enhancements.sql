-- Migration 051: Sprint 2A — Self-Generating Detection Engine Enhancements
-- Adds tenant_id, confidence, tp_count, fp_count, status enhancements to detection_rules.
-- detection_candidates and detection_rules base tables already exist (migration 008).

-- Add tenant_id to detection_rules for tenant-scoped rule access
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);

-- Add confidence score to detection_rules
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS confidence NUMERIC(5,2) DEFAULT 0;

-- Add tp_count and fp_count integer counters
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS tp_count INTEGER DEFAULT 0;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS fp_count INTEGER DEFAULT 0;

-- Add source_technique and source_pattern_id to detection_rules
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS source_technique VARCHAR(20);
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS source_pattern_id UUID;

-- Add validated_at and last_matched timestamps
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS validated_at TIMESTAMPTZ;
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS last_matched TIMESTAMPTZ;

-- Expand detection_rules status check to include candidate/validated
ALTER TABLE detection_rules DROP CONSTRAINT IF EXISTS detection_rules_status_check;
ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_status_check
    CHECK (status IN ('candidate', 'validated', 'active', 'testing', 'retired'));

-- Index on tenant_id for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_detection_rules_tenant ON detection_rules(tenant_id);

-- Add pattern_description column to detection_candidates if missing
ALTER TABLE detection_candidates ADD COLUMN IF NOT EXISTS pattern_description TEXT;
