CREATE TABLE IF NOT EXISTS witness_hitl_queue (
    id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id         UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    control_name       TEXT NOT NULL,
    severity           TEXT NOT NULL DEFAULT 'medium',
    status             TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected | escalated
    primary_reviewer   TEXT NOT NULL,
    secondary_reviewer TEXT,
    due_at             TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at        TIMESTAMPTZ,
    resolution_note    TEXT
);

CREATE INDEX IF NOT EXISTS idx_witness_hitl_queue_session ON witness_hitl_queue(session_id);
CREATE INDEX IF NOT EXISTS idx_witness_hitl_queue_status ON witness_hitl_queue(status, due_at);

CREATE TABLE IF NOT EXISTS witness_reviewer_actions (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id   UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    queue_id     UUID REFERENCES witness_hitl_queue(id) ON DELETE SET NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    signature    TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_reviewer_actions_session ON witness_reviewer_actions(session_id, created_at DESC);
