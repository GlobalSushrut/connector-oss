-- P6.4 / I-17: optional forensic flow id on captures (from X-Connector-FNI / CFNI header).
ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS fni_flow_id TEXT;

CREATE INDEX IF NOT EXISTS idx_witness_captures_fni_flow_id
    ON witness_captures (fni_flow_id)
    WHERE fni_flow_id IS NOT NULL;
