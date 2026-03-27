CREATE TABLE IF NOT EXISTS cipher_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    task_id UUID,
    server_hostname VARCHAR(255),
    client_ip INET,
    ssl_protocol VARCHAR(20) NOT NULL,
    ssl_cipher VARCHAR(255) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    risk_level VARCHAR(10) NOT NULL CHECK (risk_level IN ('secure','warning','critical')),
    has_pfs BOOLEAN NOT NULL,
    security_bits INTEGER,
    vulnerability_class VARCHAR(100),
    affected_component VARCHAR(50),
    raw_finding TEXT,
    remediation_steps JSONB,
    llm_headline TEXT,
    llm_technical_explanation TEXT,
    llm_attack_scenario TEXT,
    llm_blast_radius TEXT,
    mitre_techniques JSONB DEFAULT '["T1040","T1600"]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cipher_audit_tenant_risk ON cipher_audit_events(tenant_id, risk_level, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_cipher_audit_server ON cipher_audit_events(tenant_id, server_hostname, observed_at DESC);

CREATE MATERIALIZED VIEW IF NOT EXISTS cipher_audit_summary AS
SELECT tenant_id, server_hostname, DATE_TRUNC('day', observed_at) AS audit_date,
    COUNT(*) AS total_connections,
    SUM(CASE WHEN has_pfs THEN 1 ELSE 0 END) AS pfs_connections,
    ROUND(SUM(CASE WHEN has_pfs THEN 1 ELSE 0 END)::numeric/NULLIF(COUNT(*),0)*100,1) AS pfs_percentage,
    SUM(CASE WHEN risk_level='critical' THEN 1 ELSE 0 END) AS critical_count,
    SUM(CASE WHEN risk_level='warning' THEN 1 ELSE 0 END) AS warning_count,
    MIN(security_bits) AS min_security_bits
FROM cipher_audit_events
GROUP BY tenant_id, server_hostname, DATE_TRUNC('day', observed_at);
