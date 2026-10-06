CREATE TABLE IF NOT EXISTS witness_webhook_queue (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    session_id      UUID REFERENCES witness_sessions(id) ON DELETE CASCADE,
    endpoint        TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending', -- pending | retry | delivered | dead
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_webhook_queue_pending
    ON witness_webhook_queue(status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_witness_webhook_queue_session
    ON witness_webhook_queue(session_id, created_at DESC);

