-- Sprint 1L: Golden Path — MSSP Demo Sprint
-- Apply with: docker compose exec -T postgres psql -U hydra -d hydra < migrations/005_sprint1l_golden_path.sql

-- ============================================================
-- Entity observation confidence tracking
-- ============================================================

ALTER TABLE entity_observations ADD COLUMN IF NOT EXISTS confidence_source VARCHAR(20) DEFAULT 'clean' CHECK (confidence_source IN ('clean', 'suspicious', 'injection_detected'));
CREATE INDEX IF NOT EXISTS idx_entity_obs_confidence ON entity_observations(confidence_source);

-- ============================================================
-- Investigation injection flag
-- ============================================================

ALTER TABLE investigations ADD COLUMN IF NOT EXISTS injection_detected BOOLEAN DEFAULT FALSE;

-- ============================================================
-- Investigation Reports
-- ============================================================

CREATE TABLE IF NOT EXISTS investigation_reports (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    investigation_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    report_format VARCHAR(10) NOT NULL CHECK (report_format IN ('markdown', 'pdf')),
    executive_summary TEXT,
    technical_timeline TEXT,
    remediation_steps TEXT,
    full_report TEXT,
    pdf_data BYTEA,
    generated_by VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_investigation ON investigation_reports(investigation_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON investigation_reports(tenant_id);
