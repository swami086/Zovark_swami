-- Migration 037: Performance indexes for v0.13.0
-- NOTE: CREATE INDEX CONCURRENTLY cannot run inside a transaction block.
-- Each statement executes independently.

-- Alert ingestion: time-range queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_siem_alerts_created_at ON siem_alerts(created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_siem_alerts_tenant_created ON siem_alerts(tenant_id, created_at DESC);

-- JSONB lookups on raw SIEM event data
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_siem_alerts_source_ip ON siem_alerts(source_ip);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_siem_alerts_dest_ip ON siem_alerts(dest_ip);

-- Graph traversal: entity edges
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entity_edges_source ON entity_edges(source_entity_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entity_edges_target ON entity_edges(target_entity_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entity_edges_type ON entity_edges(edge_type);

-- Entity lookups: fast value/type matching (IoC matching)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entities_value_type ON entities(value, entity_type);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entities_first_seen ON entities(first_seen DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entities_hash_tenant ON entities(entity_hash, tenant_id);

-- Partial index: high-severity alerts only (hot path)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_siem_alerts_high_severity
ON siem_alerts(created_at DESC)
WHERE severity IN ('critical', 'high');

-- Task filtering: pending/executing tasks only (hot path)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tasks_status_created
ON agent_tasks(status, created_at DESC)
WHERE status IN ('pending', 'executing');

-- Full-text search on alert names
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_siem_alerts_fts ON siem_alerts
USING gin(to_tsvector('english', alert_name));
