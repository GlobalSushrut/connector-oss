-- Operation-scoped enforcement: block specific work types (e.g. llm.chat, tool:bash)
-- for a tenant/actor without full agent quarantine.

CREATE TABLE IF NOT EXISTS operation_blocks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    operation_key   TEXT NOT NULL,
    reason          TEXT NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_operation_blocks_scope
    ON operation_blocks (tenant_id, actor_id, operation_key);

CREATE INDEX IF NOT EXISTS idx_operation_blocks_lookup
    ON operation_blocks (tenant_id, actor_id, active);
