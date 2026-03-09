-- migrations/016_alert_fingerprints.sql
-- Sprint 5: Alert deduplication via composite fingerprinting
-- Layer 1: Exact-match SHA-256 fingerprint on normalized alert fields

CREATE TABLE IF NOT EXISTS alert_fingerprints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    fingerprint     VARCHAR(64) NOT NULL,  -- SHA-256 hex
    alert_type      VARCHAR(100) NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_count     INTEGER NOT NULL DEFAULT 1,
    investigation_id UUID,  -- references investigations(id) logically, no FK due to partitioned table
    dedup_window_seconds INTEGER NOT NULL DEFAULT 900,  -- 15 min default
    raw_sample      JSONB,  -- first alert payload for reference
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Regular unique index (dedup window enforced at application layer)
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_fp_tenant_hash
    ON alert_fingerprints(tenant_id, fingerprint);

CREATE INDEX IF NOT EXISTS idx_alert_fp_last_seen
    ON alert_fingerprints(last_seen);

COMMENT ON TABLE alert_fingerprints IS 'Layer 1 alert deduplication. SHA-256 fingerprint of normalized alert fields. Dedup window configurable per tenant.';
