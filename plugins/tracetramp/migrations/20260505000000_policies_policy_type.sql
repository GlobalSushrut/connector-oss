-- Older lab volumes created `policies` from init.sql only; enterprise_admin's
-- CREATE TABLE IF NOT EXISTS skipped the new shape. Align with PolicyRow / admin API.
ALTER TABLE IF EXISTS policies
    ADD COLUMN IF NOT EXISTS policy_type VARCHAR(50) NOT NULL DEFAULT 'custom';
