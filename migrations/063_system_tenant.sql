-- Migration 063: Create system tenant for break-glass and admin operations
-- This tenant is used by break-glass auth and system-level audit events.
-- SAFE: INSERT with ON CONFLICT DO NOTHING. No table alterations.

BEGIN;

-- Insert system tenant if not exists
INSERT INTO tenants (id, name, slug, tier, is_active, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'SYSTEM',
    'system',
    'enterprise',
    true,
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

COMMIT;
