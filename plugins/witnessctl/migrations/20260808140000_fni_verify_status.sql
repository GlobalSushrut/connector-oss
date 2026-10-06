-- P6.4 / I-17: FNI verify status on captures (unverified until CFNI verify call).
ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS fni_verify_status TEXT;

ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS fni_cfni_wire TEXT;

COMMENT ON COLUMN witness_captures.fni_verify_status IS
    'unverified | verified | invalid | secret_unavailable — never decorative verified';

COMMENT ON COLUMN witness_captures.fni_cfni_wire IS
    'Raw CFNI header (base64url JSON) when present; required for independent verify';
