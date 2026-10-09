-- AgentLoop: DB schema for the agent lifecycle platform
-- Migration 001 — initial tables
-- Covers all four modules: Design · Ship · Debug · Optimize

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Shared: Agents ────────────────────────────────────────────────────────────
-- Central agent entity shared by all four modules.
CREATE TABLE IF NOT EXISTS al_agents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id    TEXT,                          -- Connector kernel agent ID
    name            TEXT NOT NULL,
    description     TEXT,
    team            TEXT,
    tags            TEXT[]  NOT NULL DEFAULT '{}',
    status          TEXT    NOT NULL DEFAULT 'active', -- active | archived | quarantined
    metadata        JSONB   NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_agents_status ON al_agents(status);
CREATE INDEX idx_al_agents_team   ON al_agents(team);

-- ── Shared: Runs ──────────────────────────────────────────────────────────────
-- Local mirror of Connector run history — populated by the sync worker.
CREATE TABLE IF NOT EXISTS al_runs (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_run_id    TEXT NOT NULL UNIQUE,       -- Connector history run ID
    agent_id            UUID REFERENCES al_agents(id),
    prompt_id           UUID,                       -- FK to al_prompts (set after Design module)
    prompt_version      INTEGER,
    experiment_id       UUID,                       -- FK to al_experiments (set after Ship module)
    status              TEXT NOT NULL DEFAULT 'unknown', -- running | completed | failed | aborted
    inputs              JSONB NOT NULL DEFAULT '{}',
    outputs             JSONB,
    model               TEXT,
    provider            TEXT,
    total_tokens        INTEGER NOT NULL DEFAULT 0,
    prompt_tokens       INTEGER NOT NULL DEFAULT 0,
    completion_tokens   INTEGER NOT NULL DEFAULT 0,
    cost_usd            FLOAT8  NOT NULL DEFAULT 0.0,
    latency_ms          INTEGER NOT NULL DEFAULT 0,
    error_message       TEXT,
    cid                 TEXT,                       -- CID from Connector history
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at            TIMESTAMPTZ
);
CREATE INDEX idx_al_runs_agent      ON al_runs(agent_id);
CREATE INDEX idx_al_runs_status     ON al_runs(status);
CREATE INDEX idx_al_runs_started    ON al_runs(started_at DESC);
CREATE INDEX idx_al_runs_prompt     ON al_runs(prompt_id);
CREATE INDEX idx_al_runs_experiment ON al_runs(experiment_id);

-- ── Shared: Steps ─────────────────────────────────────────────────────────────
-- Individual steps within a run (tool calls, sub-agent calls, etc.)
CREATE TABLE IF NOT EXISTS al_steps (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_id          UUID NOT NULL REFERENCES al_runs(id) ON DELETE CASCADE,
    step_index      INTEGER NOT NULL,
    step_type       TEXT NOT NULL DEFAULT 'llm', -- llm | tool | retrieval | code | handoff
    name            TEXT,
    inputs          JSONB NOT NULL DEFAULT '{}',
    outputs         JSONB,
    model           TEXT,
    tokens          INTEGER NOT NULL DEFAULT 0,
    cost_usd        FLOAT8  NOT NULL DEFAULT 0.0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    UNIQUE (run_id, step_index)
);
CREATE INDEX idx_al_steps_run ON al_steps(run_id);

-- ── MODULE: Design ────────────────────────────────────────────────────────────

-- Prompt registry: one prompt entity, many versioned snapshots
CREATE TABLE IF NOT EXISTS al_prompts (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID REFERENCES al_agents(id),
    name            TEXT NOT NULL,
    description     TEXT,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT   NOT NULL DEFAULT 'active', -- active | archived | deprecated
    current_version INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, name)
);
CREATE INDEX idx_al_prompts_agent  ON al_prompts(agent_id);
CREATE INDEX idx_al_prompts_status ON al_prompts(status);

-- Prompt versions: immutable snapshots of prompt content
CREATE TABLE IF NOT EXISTS al_prompt_versions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    prompt_id       UUID NOT NULL REFERENCES al_prompts(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    system_prompt   TEXT,
    user_template   TEXT,
    variables       JSONB   NOT NULL DEFAULT '[]',   -- [{name, type, required}]
    model_config    JSONB   NOT NULL DEFAULT '{}',   -- {model, temperature, max_tokens, ...}
    lint_score      INTEGER,                         -- 0-100 quality lint score
    lint_issues     JSONB   NOT NULL DEFAULT '[]',
    fingerprint     TEXT    NOT NULL,                -- SHA-256 of content
    author          TEXT,
    commit_message  TEXT,
    approval_status TEXT    NOT NULL DEFAULT 'draft', -- draft | pending | approved | rejected
    approved_by     TEXT,
    approved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (prompt_id, version)
);
CREATE INDEX idx_al_pv_prompt   ON al_prompt_versions(prompt_id);
CREATE INDEX idx_al_pv_approval ON al_prompt_versions(approval_status);

-- Golden datasets: test cases for prompt evaluation
CREATE TABLE IF NOT EXISTS al_datasets (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id    UUID REFERENCES al_agents(id),
    name        TEXT NOT NULL,
    description TEXT,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    row_count   INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS al_dataset_rows (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_id  UUID NOT NULL REFERENCES al_datasets(id) ON DELETE CASCADE,
    inputs      JSONB NOT NULL DEFAULT '{}',
    expected    JSONB,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_dataset_rows_dataset ON al_dataset_rows(dataset_id);

-- ── MODULE: Ship ──────────────────────────────────────────────────────────────

-- Experiments: A/B or canary comparisons between prompt versions
CREATE TABLE IF NOT EXISTS al_experiments (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id            UUID REFERENCES al_agents(id),
    name                TEXT NOT NULL,
    description         TEXT,
    status              TEXT NOT NULL DEFAULT 'draft', -- draft | running | paused | concluded | rolled_back
    variant_control_id  UUID REFERENCES al_prompt_versions(id),
    variant_treatment_id UUID REFERENCES al_prompt_versions(id),
    traffic_split_pct   INTEGER NOT NULL DEFAULT 50, -- % of traffic to treatment
    significance_threshold FLOAT8 NOT NULL DEFAULT 0.95,
    auto_promote        BOOLEAN NOT NULL DEFAULT FALSE,
    winning_variant     TEXT,                        -- 'control' | 'treatment' | null
    concluded_at        TIMESTAMPTZ,
    promoted_at         TIMESTAMPTZ,
    rolled_back_at      TIMESTAMPTZ,
    rollback_reason     TEXT,
    metrics             JSONB NOT NULL DEFAULT '{}', -- {quality_delta, cost_delta, latency_delta, p_value}
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_experiments_agent  ON al_experiments(agent_id);
CREATE INDEX idx_al_experiments_status ON al_experiments(status);

-- Canary rollouts: gradual traffic shifting
CREATE TABLE IF NOT EXISTS al_canaries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    experiment_id   UUID NOT NULL REFERENCES al_experiments(id) ON DELETE CASCADE,
    stage           INTEGER NOT NULL DEFAULT 1,    -- 1=5%, 2=25%, 3=50%, 4=100%
    pct_traffic     INTEGER NOT NULL DEFAULT 5,
    status          TEXT NOT NULL DEFAULT 'active', -- active | paused | promoted | rolled_back
    error_rate      FLOAT8,
    latency_p99_ms  INTEGER,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ
);

-- ── MODULE: Debug ─────────────────────────────────────────────────────────────

-- Replay sessions: reproduce a past run deterministically
CREATE TABLE IF NOT EXISTS al_replays (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_run_id       UUID NOT NULL REFERENCES al_runs(id),
    agent_id            UUID REFERENCES al_agents(id),
    status              TEXT NOT NULL DEFAULT 'pending', -- pending | running | completed | failed
    substitutions       JSONB NOT NULL DEFAULT '{}',    -- {step_index: {model, prompt, inputs}}
    replay_run_id       UUID REFERENCES al_runs(id),    -- the new run created by replay
    diverged_at_step    INTEGER,                        -- first step that differed from source
    diff_summary        JSONB,                          -- high-level diff result
    created_by          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ
);
CREATE INDEX idx_al_replays_source ON al_replays(source_run_id);
CREATE INDEX idx_al_replays_status ON al_replays(status);

-- Diffs: structured diff between two runs or two prompt versions
CREATE TABLE IF NOT EXISTS al_diffs (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    diff_type   TEXT NOT NULL, -- run_vs_run | prompt_vs_prompt | step_vs_step
    left_id     TEXT NOT NULL, -- UUID as text (run or prompt version)
    right_id    TEXT NOT NULL,
    diff_json   JSONB NOT NULL DEFAULT '{}',
    summary     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_diffs_left  ON al_diffs(left_id);
CREATE INDEX idx_al_diffs_right ON al_diffs(right_id);

-- ── MODULE: Optimize ──────────────────────────────────────────────────────────

-- SLOs: service level objectives per agent
CREATE TABLE IF NOT EXISTS al_slos (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES al_agents(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    metric          TEXT NOT NULL, -- error_rate | latency_p99 | cost_per_run | quality_score
    threshold       FLOAT8 NOT NULL,
    window_hours    INTEGER NOT NULL DEFAULT 24,
    status          TEXT NOT NULL DEFAULT 'healthy', -- healthy | warning | breached
    current_value   FLOAT8,
    last_checked_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, name)
);
CREATE INDEX idx_al_slos_agent  ON al_slos(agent_id);
CREATE INDEX idx_al_slos_status ON al_slos(status);

-- Recommendations: auto-generated optimization suggestions
CREATE TABLE IF NOT EXISTS al_recommendations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID REFERENCES al_agents(id),
    rec_type        TEXT NOT NULL, -- rightsize_model | update_prompt | fix_drift | reduce_tokens | cost_saving
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    impact_tokens   INTEGER,       -- projected token savings per run
    impact_cost_usd FLOAT8,        -- projected $ savings per run
    impact_quality  FLOAT8,        -- projected quality delta (-1 to +1)
    status          TEXT NOT NULL DEFAULT 'open', -- open | applied | dismissed | snoozed
    action_payload  JSONB NOT NULL DEFAULT '{}',  -- machine-readable action to apply
    applied_by      TEXT,
    applied_at      TIMESTAMPTZ,
    dismissed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_rec_agent  ON al_recommendations(agent_id);
CREATE INDEX idx_al_rec_status ON al_recommendations(status);
CREATE INDEX idx_al_rec_type   ON al_recommendations(rec_type);

-- Drift events: detected behavioral drift from baseline
CREATE TABLE IF NOT EXISTS al_drift_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES al_agents(id),
    drift_type      TEXT NOT NULL, -- output_distribution | cost | latency | error_rate | token_usage
    severity        TEXT NOT NULL DEFAULT 'low', -- low | medium | high | critical
    description     TEXT NOT NULL,
    baseline_value  FLOAT8,
    current_value   FLOAT8,
    delta_pct       FLOAT8,
    run_id          UUID REFERENCES al_runs(id),
    acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_drift_agent    ON al_drift_events(agent_id);
CREATE INDEX idx_al_drift_severity ON al_drift_events(severity);
CREATE INDEX idx_al_drift_time     ON al_drift_events(detected_at DESC);
