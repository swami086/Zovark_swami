-- v3 tool-calling architecture migration
-- Investigation plans, governance config, institutional knowledge

-- Investigation plans for v3 tool-calling architecture
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS investigation_plan JSONB;
ALTER TABLE agent_skills ADD COLUMN IF NOT EXISTS execution_mode VARCHAR(20) DEFAULT 'sandbox';

-- Governance config (autonomy slider)
CREATE TABLE IF NOT EXISTS governance_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    task_type VARCHAR(100) DEFAULT '*',
    autonomy_level VARCHAR(20) DEFAULT 'observe' CHECK (autonomy_level IN ('observe', 'assist', 'autonomous')),
    consecutive_correct INT DEFAULT 0,
    upgrade_threshold INT DEFAULT 20,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, task_type)
);

CREATE INDEX IF NOT EXISTS idx_governance_tenant ON governance_config(tenant_id);

-- Institutional knowledge (analyst-provided baselines)
CREATE TABLE IF NOT EXISTS institutional_knowledge (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    entity_value VARCHAR(500) NOT NULL,
    entity_type VARCHAR(50),
    description TEXT,
    expected_behavior TEXT,
    hours_active VARCHAR(20),
    analyst_notes TEXT,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_ik_tenant ON institutional_knowledge(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ik_entity ON institutional_knowledge(entity_value);

-- Expanded analyst feedback for knowledge capture
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'analyst_feedback' AND column_name = 'investigation_notes') THEN
        ALTER TABLE analyst_feedback ADD COLUMN investigation_notes TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'analyst_feedback' AND column_name = 'environment_baseline') THEN
        ALTER TABLE analyst_feedback ADD COLUMN environment_baseline JSONB;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'analyst_feedback' AND column_name = 'missing_context') THEN
        ALTER TABLE analyst_feedback ADD COLUMN missing_context TEXT;
    END IF;
EXCEPTION
    WHEN undefined_table THEN
        NULL; -- analyst_feedback may not exist yet
END $$;
