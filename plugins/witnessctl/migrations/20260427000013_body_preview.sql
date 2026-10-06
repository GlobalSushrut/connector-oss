-- Add request/response body preview columns to witness_captures
-- Stores first 600 chars of the raw body (never stored full PII; used for audit UX)
ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS request_body_preview TEXT,
    ADD COLUMN IF NOT EXISTS response_body_preview TEXT,
    ADD COLUMN IF NOT EXISTS prompt_preview         TEXT,
    ADD COLUMN IF NOT EXISTS response_preview       TEXT,
    ADD COLUMN IF NOT EXISTS risk_level             TEXT,
    ADD COLUMN IF NOT EXISTS risk_score             FLOAT,
    ADD COLUMN IF NOT EXISTS tracetramp_risk_level  TEXT,
    ADD COLUMN IF NOT EXISTS tracetramp_policy_verdict TEXT;
