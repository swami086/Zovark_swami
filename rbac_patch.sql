ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'analyst';
ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(20);

UPDATE users SET role = 'admin' WHERE email = 'admin@testcorp.com';
UPDATE users SET role = 'analyst' WHERE email = 'demouser2@testcorp.com';

-- Enforce the new check constraint AFTER updating existing values
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'analyst', 'viewer'));

INSERT INTO users (id, tenant_id, email, password_hash, role)
SELECT gen_random_uuid(), tenant_id, 'viewer@testcorp.com', password_hash, 'viewer'
FROM users WHERE email = 'demouser2@testcorp.com'
ON CONFLICT (tenant_id, email) DO NOTHING;
