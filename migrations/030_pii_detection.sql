-- Migration 030: PII Detection (Sprint v0.10.0)
-- PII detection audit log and masking rules

CREATE TABLE IF NOT EXISTS pii_detections (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    task_id UUID REFERENCES agent_tasks(id),
    -- Detection details
    field_path VARCHAR(200), -- e.g., 'alert.description', 'investigation.summary'
    pii_type VARCHAR(50) NOT NULL, -- 'email', 'ip_address', 'hostname', 'ssn', 'credit_card', 'phone', 'api_key', 'password'
    detection_method VARCHAR(30) NOT NULL DEFAULT 'regex', -- 'regex', 'model', 'dictionary'
    -- Masking
    original_hash VARCHAR(64), -- SHA-256 of original value (for dedup, never store original)
    masked_value VARCHAR(200), -- e.g., '[EMAIL_1]', '[IP_ADDR_3]'
    entity_map_id VARCHAR(100), -- reference to entity mapping in memory (for unmasking)
    -- Context
    direction VARCHAR(10) NOT NULL, -- 'inbound' (alert data) or 'outbound' (sent to LLM)
    blocked BOOLEAN NOT NULL DEFAULT false, -- was the request blocked due to PII?
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pii_tenant ON pii_detections(tenant_id, created_at);
CREATE INDEX idx_pii_type ON pii_detections(pii_type);
CREATE INDEX idx_pii_blocked ON pii_detections(blocked) WHERE blocked = true;

-- PII masking rules per tenant (customizable)
CREATE TABLE IF NOT EXISTS pii_masking_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id), -- NULL = global default
    pii_type VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL DEFAULT 'mask', -- 'mask', 'redact', 'hash', 'allow', 'block'
    pattern TEXT, -- custom regex override
    priority INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pii_rules_tenant ON pii_masking_rules(tenant_id);
