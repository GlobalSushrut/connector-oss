-- Conductor: DB schema for governed multi-agent orchestration
-- Migration 001 — initial tables

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Pipeline definitions (versioned, compiled)
CREATE TABLE IF NOT EXISTS conductor_pipelines (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name             TEXT NOT NULL,
    version          INTEGER NOT NULL DEFAULT 1,
    yaml_source      TEXT NOT NULL,
    compiled_json    JSONB NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'active',   -- active | archived
    fingerprint      TEXT NOT NULL,                    -- SHA-256 of yaml_source
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, version)
);

CREATE INDEX idx_conductor_pipelines_name ON conductor_pipelines(name);
CREATE INDEX idx_conductor_pipelines_status ON conductor_pipelines(status);

-- Pipeline runs
CREATE TABLE IF NOT EXISTS conductor_runs (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pipeline_id         UUID NOT NULL REFERENCES conductor_pipelines(id),
    connector_run_id    TEXT,                          -- returned by Connector multiagent API
    status              TEXT NOT NULL DEFAULT 'pending', -- pending | running | paused | completed | failed | aborted
    inputs              JSONB NOT NULL DEFAULT '{}',
    outputs             JSONB,
    budget_used_tokens  BIGINT NOT NULL DEFAULT 0,
    budget_used_usd     FLOAT8 NOT NULL DEFAULT 0,
    parent_run_id       UUID REFERENCES conductor_runs(id), -- set on replay
    replay_from_step    INTEGER,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at            TIMESTAMPTZ,
    error_message       TEXT
);

CREATE INDEX idx_conductor_runs_pipeline ON conductor_runs(pipeline_id);
CREATE INDEX idx_conductor_runs_status ON conductor_runs(status);
CREATE INDEX idx_conductor_runs_started ON conductor_runs(started_at DESC);

-- Individual step executions within a run
CREATE TABLE IF NOT EXISTS conductor_steps (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id          UUID NOT NULL REFERENCES conductor_runs(id),
    step_index      INTEGER NOT NULL,
    step_name       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending', -- pending | running | waiting_approval | completed | failed | skipped
    input_json      JSONB NOT NULL DEFAULT '{}',
    output_json     JSONB,
    schema_valid    BOOLEAN,
    cost_tokens     INTEGER NOT NULL DEFAULT 0,
    cost_usd        FLOAT8 NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    error_message   TEXT
);

CREATE UNIQUE INDEX idx_conductor_steps_run_step ON conductor_steps(run_id, step_index);
CREATE INDEX idx_conductor_steps_run ON conductor_steps(run_id);
CREATE INDEX idx_conductor_steps_status ON conductor_steps(status);

-- HITL approval requests
CREATE TABLE IF NOT EXISTS conductor_approvals (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id          UUID NOT NULL REFERENCES conductor_runs(id),
    step_id         UUID NOT NULL REFERENCES conductor_steps(id),
    step_index      INTEGER NOT NULL,
    step_name       TEXT NOT NULL,
    required_if     TEXT,                  -- condition string that triggered HITL
    reviewers       TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected | expired
    reviewer        TEXT,                  -- who actually acted
    reason          TEXT,                  -- reviewer's reason
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ            -- optional timeout
);

CREATE INDEX idx_conductor_approvals_run ON conductor_approvals(run_id);
CREATE INDEX idx_conductor_approvals_status ON conductor_approvals(status);

-- Cron and webhook schedules
CREATE TABLE IF NOT EXISTS conductor_schedules (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pipeline_id     UUID NOT NULL REFERENCES conductor_pipelines(id),
    name            TEXT NOT NULL,
    trigger_type    TEXT NOT NULL DEFAULT 'cron', -- cron | webhook | event
    cron_expr       TEXT,                  -- e.g. "0 9 * * MON"
    webhook_token   TEXT,                  -- random token for webhook trigger URL
    default_inputs  JSONB NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_conductor_schedules_pipeline ON conductor_schedules(pipeline_id);
CREATE INDEX idx_conductor_schedules_next ON conductor_schedules(next_run_at) WHERE enabled = TRUE;

-- Gate policies for version promotion
CREATE TABLE IF NOT EXISTS conductor_gates (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pipeline_id     UUID NOT NULL REFERENCES conductor_pipelines(id),
    gate_type       TEXT NOT NULL, -- regression_test | budget_variance | approval_count | custom
    config_json     JSONB NOT NULL DEFAULT '{}',
    required        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_conductor_gates_pipeline ON conductor_gates(pipeline_id);
