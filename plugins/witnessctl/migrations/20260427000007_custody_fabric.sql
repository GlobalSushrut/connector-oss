ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS ingest_idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_witness_captures_idempotency
    ON witness_captures(session_id, ingest_idempotency_key)
    WHERE ingest_idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS witness_custody_queue (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id       UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    capture_id       UUID,
    receipt_seq      BIGINT,
    payload_hash     TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending', -- pending | replicated | failed
    attempts         INT NOT NULL DEFAULT 0,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_witness_custody_queue_idempotency
    ON witness_custody_queue(idempotency_key);

CREATE TABLE IF NOT EXISTS witness_custody_checkpoints (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id         UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    local_chain_head   TEXT,
    replicated_head    TEXT,
    pending_count      BIGINT NOT NULL DEFAULT 0,
    failed_count       BIGINT NOT NULL DEFAULT 0,
    quorum_status      TEXT NOT NULL DEFAULT 'local_only', -- local_only | replicated_partial | replicated_quorum
    signed_hash        TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_custody_checkpoints_session
    ON witness_custody_checkpoints(session_id, created_at DESC);
