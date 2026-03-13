-- Migration 031: NATS JetStream Tracking (Sprint v0.10.0)
-- Stream offset monitoring and alert surge detection

CREATE TABLE IF NOT EXISTS alert_stream_offsets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    stream_name VARCHAR(100) NOT NULL, -- e.g., 'ALERTS.tenant-slug'
    consumer_name VARCHAR(100) NOT NULL,
    last_sequence BIGINT NOT NULL DEFAULT 0,
    last_processed_at TIMESTAMPTZ,
    lag INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, stream_name, consumer_name)
);

CREATE INDEX idx_stream_offsets_tenant ON alert_stream_offsets(tenant_id);

-- Alert buffer stats (for surge monitoring)
CREATE TABLE IF NOT EXISTS alert_surge_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    -- Surge detection
    alerts_per_second NUMERIC(10,2),
    queue_depth INTEGER,
    processing_lag_ms INTEGER,
    -- Actions taken
    throttle_applied BOOLEAN NOT NULL DEFAULT false,
    backpressure_applied BOOLEAN NOT NULL DEFAULT false,
    alerts_dropped INTEGER NOT NULL DEFAULT 0,
    -- Context
    source VARCHAR(100), -- SIEM source
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_surge_tenant ON alert_surge_events(tenant_id, created_at);
