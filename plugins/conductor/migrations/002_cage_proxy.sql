-- Conductor Migration 002: Cage policies and proxy intercept log
-- Cage = OS-level sandbox policy per pipeline/agent
-- ProxyIntercept = every action API call that passed through the cage proxy

-- ── Cage policies ─────────────────────────────────────────────────────────────
-- One cage policy per pipeline. Defines the allowed envelope for every
-- action API call made by agents during a run of that pipeline.
CREATE TABLE IF NOT EXISTS conductor_cages (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pipeline_id         UUID NOT NULL REFERENCES conductor_pipelines(id) ON DELETE CASCADE,
    -- OS-level resource limits
    max_cpu_ms          BIGINT   NOT NULL DEFAULT 30000,    -- wall-clock ms per action call
    max_memory_bytes    BIGINT   NOT NULL DEFAULT 134217728, -- 128 MiB
    max_file_size_bytes BIGINT   NOT NULL DEFAULT 10485760,  -- 10 MiB
    max_open_files      INTEGER  NOT NULL DEFAULT 64,
    max_processes       INTEGER  NOT NULL DEFAULT 8,
    -- Network policy
    allow_network       BOOLEAN  NOT NULL DEFAULT TRUE,
    allowed_hosts       TEXT[]   NOT NULL DEFAULT '{}',     -- empty = all allowed
    blocked_hosts       TEXT[]   NOT NULL DEFAULT '{}',     -- always blocked even if in allowed_hosts
    allowed_ports       INT[]    NOT NULL DEFAULT '{}',     -- empty = all ports allowed
    -- Filesystem policy
    allowed_read_paths  TEXT[]   NOT NULL DEFAULT '{}',     -- empty = none
    allowed_write_paths TEXT[]   NOT NULL DEFAULT '{}',     -- empty = none
    -- Syscall policy (applied if running in subprocess mode)
    syscall_policy      TEXT     NOT NULL DEFAULT 'default', -- default | strict | permissive
    -- Action type allow-list
    allowed_action_types TEXT[]  NOT NULL DEFAULT '{}',     -- empty = all allowed; e.g. {"http","sql"}
    blocked_action_types TEXT[]  NOT NULL DEFAULT '{}',
    -- Enforcement mode
    enforcement         TEXT     NOT NULL DEFAULT 'enforce', -- enforce | audit | disabled
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (pipeline_id)
);

CREATE INDEX idx_conductor_cages_pipeline ON conductor_cages(pipeline_id);

-- ── Proxy intercept log ───────────────────────────────────────────────────────
-- Every action API call that passes through the cage proxy is recorded here.
-- This is the audit log for the cage — immutable append-only.
CREATE TABLE IF NOT EXISTS conductor_proxy_intercepts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id          UUID NOT NULL REFERENCES conductor_runs(id) ON DELETE CASCADE,
    step_index      INTEGER NOT NULL,
    agent_id        TEXT NOT NULL,
    cage_id         UUID REFERENCES conductor_cages(id),
    -- Request details
    action_type     TEXT NOT NULL,          -- http | sql | file | subprocess | tool
    method          TEXT,                   -- GET | POST | etc. for http actions
    target_host     TEXT,                   -- destination host
    target_port     INTEGER,
    target_path     TEXT,
    request_body_hash TEXT,                 -- SHA-256 of request body (never store raw body)
    request_size_bytes BIGINT NOT NULL DEFAULT 0,
    -- Cage verdict
    cage_verdict    TEXT NOT NULL DEFAULT 'allow', -- allow | deny | redact | audit
    deny_reason     TEXT,
    policy_matched  TEXT,                   -- which rule triggered
    -- Forwarded response
    response_status INTEGER,                -- HTTP status from upstream
    response_size_bytes BIGINT NOT NULL DEFAULT 0,
    response_body_hash TEXT,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    -- Integrity
    receipt_hmac    TEXT,                   -- HMAC-SHA256 chaining this record to prev
    prev_receipt_id UUID REFERENCES conductor_proxy_intercepts(id),
    -- Metadata
    request_id      TEXT,                   -- X-Request-ID from the proxy call
    intercepted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_conductor_proxy_run ON conductor_proxy_intercepts(run_id);
CREATE INDEX idx_conductor_proxy_verdict ON conductor_proxy_intercepts(cage_verdict);
CREATE INDEX idx_conductor_proxy_agent ON conductor_proxy_intercepts(agent_id);
CREATE INDEX idx_conductor_proxy_time ON conductor_proxy_intercepts(intercepted_at DESC);
