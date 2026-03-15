BEGIN;
-- Add vault_path column for Vault-managed credentials
ALTER TABLE response_integrations ADD COLUMN IF NOT EXISTS vault_path VARCHAR(255);
-- Mark existing rows as needing migration
ALTER TABLE response_integrations ADD COLUMN IF NOT EXISTS credentials_migrated BOOLEAN NOT NULL DEFAULT false;
-- NOTE: auth_credentials column is NOT dropped yet.
-- It will be dropped after all credentials are migrated to Vault.
-- Migration script should be run separately to move existing creds.
COMMIT;
