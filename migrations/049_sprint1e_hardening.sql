-- Migration 049: Sprint 1E Production Hardening
-- 1E-2: Synchronous commit (handled in application code, store.py)
-- 1E-3: SCRAM-SHA-256 auth (verify + re-hash password)
-- 1E-4: Audit events wiring (table exists in init.sql, partitions verified)
-- 1E-5: FK constraint on agent_tasks.tenant_id (verify exists)

-- ============================================================
-- 1E-3: Re-hash hydra user password with SCRAM-SHA-256
-- postgresql.conf already has password_encryption = scram-sha-256
-- pg_hba.conf already enforces scram-sha-256 for remote connections
-- This forces the stored password hash to use SCRAM format
-- ============================================================
-- Re-set the password so PostgreSQL stores it with scram-sha-256 hash.
-- password_encryption = scram-sha-256 is already set in postgresql.conf,
-- so this ALTER ROLE will produce a SCRAM hash.
-- In production, replace 'hydra_dev_2026' with the actual production password.
ALTER ROLE hydra PASSWORD 'hydra_dev_2026';

-- ============================================================
-- 1E-4: Verify audit_events partitions exist for current + next months
-- Table and 2026 partitions already exist in init.sql
-- Add 2027-Q1 partitions for forward coverage
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_events_2027_01 PARTITION OF audit_events
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
CREATE TABLE IF NOT EXISTS audit_events_2027_02 PARTITION OF audit_events
    FOR VALUES FROM ('2027-02-01') TO ('2027-03-01');
CREATE TABLE IF NOT EXISTS audit_events_2027_03 PARTITION OF audit_events
    FOR VALUES FROM ('2027-03-01') TO ('2027-04-01');

-- ============================================================
-- 1E-5: Verify FK constraint on agent_tasks.tenant_id → tenants(id)
-- The FK already exists in init.sql (line 95):
--   tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
-- This block is a safety net for databases created before that FK was added
-- ============================================================
DO $$
BEGIN
    -- Check if FK already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'agent_tasks'::regclass
          AND contype = 'f'
          AND confrelid = 'tenants'::regclass
    ) THEN
        ALTER TABLE agent_tasks
            ADD CONSTRAINT fk_agent_tasks_tenant
            FOREIGN KEY (tenant_id)
            REFERENCES tenants(id)
            ON DELETE CASCADE;
        RAISE NOTICE 'FK constraint fk_agent_tasks_tenant added';
    ELSE
        RAISE NOTICE 'FK constraint agent_tasks → tenants already exists';
    END IF;
END $$;

-- Verify investigations table also has FK to tenants
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'investigations'::regclass
          AND contype = 'f'
          AND confrelid = 'tenants'::regclass
    ) THEN
        ALTER TABLE investigations
            ADD CONSTRAINT fk_investigations_tenant
            FOREIGN KEY (tenant_id)
            REFERENCES tenants(id)
            ON DELETE CASCADE;
        RAISE NOTICE 'FK constraint fk_investigations_tenant added';
    ELSE
        RAISE NOTICE 'FK constraint investigations → tenants already exists';
    END IF;
END $$;
