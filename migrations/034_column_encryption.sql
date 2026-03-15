BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- TOTP secrets are now encrypted at the application level (AES-256-GCM)
-- before storage. The column type remains VARCHAR to hold the "enc:base64..." format.
-- Legacy plaintext values are handled transparently by the decryptSecret() function.

-- Add encrypted column for future migration of existing plaintext secrets
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_encrypted BYTEA;

-- Index for faster TOTP lookups
CREATE INDEX IF NOT EXISTS idx_users_totp_enabled ON users (id) WHERE totp_enabled = true;
COMMIT;
