ALTER TABLE witness_sessions
    ADD COLUMN IF NOT EXISTS tsa_status TEXT,
    ADD COLUMN IF NOT EXISTS tsa_token TEXT,
    ADD COLUMN IF NOT EXISTS tsa_timestamped_at TIMESTAMPTZ;
