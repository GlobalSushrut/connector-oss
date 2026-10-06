CREATE TABLE IF NOT EXISTS witness_manual_attestations (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id    UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    control_name  TEXT NOT NULL,
    evidence_url  TEXT NOT NULL,
    attestor      TEXT NOT NULL,
    notes         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_manual_attestations_session
    ON witness_manual_attestations(session_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_witness_manual_attestations_unique
    ON witness_manual_attestations(session_id, control_name, attestor);
