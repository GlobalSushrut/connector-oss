ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS firewall_checked BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS firewall_status TEXT;

CREATE INDEX IF NOT EXISTS idx_witness_captures_firewall_checked
    ON witness_captures(firewall_checked);
