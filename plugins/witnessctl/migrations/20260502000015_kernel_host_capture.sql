-- Connector host kernel attachment snapshot per capture (Phase B audit trail).
ALTER TABLE witness_captures ADD COLUMN IF NOT EXISTS kernel_host JSONB;
