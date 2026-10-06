ALTER TABLE witness_manual_attestations
    ADD COLUMN IF NOT EXISTS attestor_subject TEXT,
    ADD COLUMN IF NOT EXISTS attestor_token_jti TEXT;

ALTER TABLE witness_sessions
    ADD COLUMN IF NOT EXISTS tsa_verified BOOLEAN,
    ADD COLUMN IF NOT EXISTS tsa_policy_oid TEXT;
