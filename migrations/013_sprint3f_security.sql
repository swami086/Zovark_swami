-- Sprint 3F: Security Hardening + Compliance
-- Data retention policies and audit enhancements

-- Data retention policies
CREATE TABLE IF NOT EXISTS data_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL UNIQUE,
    retention_days INT NOT NULL DEFAULT 90,
    delete_strategy VARCHAR(20) DEFAULT 'soft' CHECK (delete_strategy IN ('soft', 'hard', 'archive')),
    is_active BOOLEAN DEFAULT true,
    last_cleanup_at TIMESTAMPTZ,
    rows_cleaned INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default retention policies
INSERT INTO data_retention_policies (table_name, retention_days, delete_strategy) VALUES
    ('agent_audit_log', 365, 'archive'),
    ('webhook_deliveries', 30, 'hard'),
    ('usage_records', 90, 'hard'),
    ('investigation_steps', 180, 'archive'),
    ('siem_alerts', 90, 'soft')
ON CONFLICT (table_name) DO NOTHING;

-- Add indexes for efficient cleanup queries
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON agent_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_usage_records_created ON usage_records(created_at);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_created ON siem_alerts(created_at);

-- Security: add login attempt tracking
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
