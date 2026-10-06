ALTER TABLE witness_pii_hits
    ADD COLUMN IF NOT EXISTS original_preview TEXT,
    ADD COLUMN IF NOT EXISTS redacted_preview TEXT;

