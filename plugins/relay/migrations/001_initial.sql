-- Relay: initial schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Registered agent functions
CREATE TABLE IF NOT EXISTS relay_functions (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name             TEXT NOT NULL UNIQUE,
    uri              TEXT NOT NULL,               -- http://localhost:3000/run
    description      TEXT,
    policy_json      JSONB NOT NULL DEFAULT '{}',
    instructions     TEXT,                        -- system prompt injection
    status           TEXT NOT NULL DEFAULT 'healthy'
                     CHECK (status IN ('healthy', 'degraded', 'unreachable', 'suspended', 'quarantined')),
    health_status    TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (health_status IN ('healthy', 'degraded', 'unreachable', 'unknown')),
    health_latency_ms INT,
    last_health_at   TIMESTAMPTZ,
    agent_did        TEXT,                        -- AgentPassport DID
    api_key          TEXT,                        -- Connector API key for this function
    invocation_count BIGINT NOT NULL DEFAULT 0,
    total_cost_usd   FLOAT  NOT NULL DEFAULT 0.0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_relay_functions_name   ON relay_functions (name);
CREATE INDEX IF NOT EXISTS idx_relay_functions_status ON relay_functions (status);

-- Per-invocation audit records
CREATE TABLE IF NOT EXISTS relay_invocations (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    function_id      UUID NOT NULL REFERENCES relay_functions (id) ON DELETE CASCADE,
    function_name    TEXT NOT NULL,
    caller_key       TEXT,                        -- API key used to invoke
    input_hash       TEXT NOT NULL,               -- sha256(request body)
    output_hash      TEXT,                        -- sha256(response body)
    model_used       TEXT,                        -- gpt-4o, claude-sonnet-4, etc.
    tokens_in        INT  NOT NULL DEFAULT 0,
    tokens_out       INT  NOT NULL DEFAULT 0,
    cost_usd         FLOAT NOT NULL DEFAULT 0.0,
    latency_ms       INT,
    status_code      INT,
    outcome          TEXT NOT NULL DEFAULT 'success'
                     CHECK (outcome IN ('success', 'denied', 'budget_exceeded', 'timeout', 'error', 'quarantined')),
    deny_reason      TEXT,
    audit_cid        TEXT,                        -- WitnessCtl chain CID
    trace_id         TEXT,                        -- TraceTramp trace ID
    invoked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_relay_invocations_fn   ON relay_invocations (function_id, invoked_at DESC);
CREATE INDEX IF NOT EXISTS idx_relay_invocations_time ON relay_invocations (invoked_at DESC);

-- Health check history (rolling 48h)
CREATE TABLE IF NOT EXISTS relay_health_checks (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    function_id  UUID NOT NULL REFERENCES relay_functions (id) ON DELETE CASCADE,
    status       TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'unreachable')),
    latency_ms   INT,
    error_msg    TEXT,
    checked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_relay_health_fn_time
    ON relay_health_checks (function_id, checked_at DESC);

-- Async job queue
CREATE TABLE IF NOT EXISTS relay_async_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    function_name   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    callback_url    TEXT,
    attempt_count   INT  NOT NULL DEFAULT 0,
    max_attempts    INT  NOT NULL DEFAULT 3,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    result          JSONB,
    error_msg       TEXT,
    scheduled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_relay_async_jobs_status
    ON relay_async_jobs (status, scheduled_at ASC);
