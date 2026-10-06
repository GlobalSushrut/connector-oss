-- Structured HITL / soft-block context for TUI, SIEM, and audit exports (machine-readable).
ALTER TABLE approval_queue ADD COLUMN IF NOT EXISTS hold_metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
