-- Normalized gate snapshot per capture (admission + firewall + kernel_host) for exports / SIEM.
ALTER TABLE witness_captures ADD COLUMN IF NOT EXISTS decision_digest JSONB;
