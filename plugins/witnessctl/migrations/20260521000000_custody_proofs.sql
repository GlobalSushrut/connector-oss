-- Custody node proofs for quorum verification (production readiness Phase 2).

CREATE TABLE IF NOT EXISTS witness_custody_proofs (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id    UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    node_id       TEXT NOT NULL,
    capture_hash  TEXT NOT NULL,
    signature     TEXT NOT NULL,
    proof_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_custody_proofs_session
    ON witness_custody_proofs(session_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_witness_custody_proofs_node_hash
    ON witness_custody_proofs(session_id, node_id, capture_hash);
