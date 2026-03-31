-- Template promotion now requires 2 approvals from different analysts
-- Mission 2: Template Promotion Quorum

ALTER TABLE analyst_feedback ADD COLUMN IF NOT EXISTS promotion_approved_by UUID;
ALTER TABLE analyst_feedback ADD COLUMN IF NOT EXISTS promotion_approved_at TIMESTAMPTZ;

-- Track promotion approvals separately
CREATE TABLE IF NOT EXISTS template_promotion_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feedback_id UUID NOT NULL REFERENCES analyst_feedback(id),
    approved_by UUID NOT NULL REFERENCES users(id),
    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id UUID NOT NULL,
    UNIQUE(feedback_id, approved_by)  -- Same person can't approve twice
);

CREATE INDEX IF NOT EXISTS idx_tpa_feedback ON template_promotion_approvals(feedback_id);
CREATE INDEX IF NOT EXISTS idx_tpa_tenant ON template_promotion_approvals(tenant_id);
