-- Engram: CoT Anchor sessions and per-step grounding records

CREATE TABLE IF NOT EXISTS engram_cot_sessions (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_name   TEXT,
    namespace_id   UUID NOT NULL REFERENCES engram_namespaces (id) ON DELETE CASCADE,
    agent_id       TEXT NOT NULL,
    threshold      FLOAT NOT NULL DEFAULT 0.75,
    on_fail        TEXT NOT NULL DEFAULT 'retry' CHECK (on_fail IN ('retry', 'block', 'flag')),
    started_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    concluded_at   TIMESTAMPTZ,
    proof_cid      TEXT,       -- bundle CID written to WitnessCtl after conclude
    step_count     INT NOT NULL DEFAULT 0,
    passed_count   INT NOT NULL DEFAULT 0,
    failed_count   INT NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'concluded', 'aborted'))
);

CREATE INDEX IF NOT EXISTS idx_engram_cot_sessions_ns
    ON engram_cot_sessions (namespace_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_engram_cot_sessions_agent
    ON engram_cot_sessions (agent_id, started_at DESC);

CREATE TABLE IF NOT EXISTS engram_cot_steps (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id       UUID NOT NULL REFERENCES engram_cot_sessions (id) ON DELETE CASCADE,
    step_number      INT  NOT NULL,
    claim_text       TEXT NOT NULL,
    grounding_score  FLOAT,
    source_cids      JSONB NOT NULL DEFAULT '[]',   -- array of mem1-sha256-* CIDs
    source_namespaces JSONB NOT NULL DEFAULT '[]',
    outcome          TEXT NOT NULL DEFAULT 'pending'
                     CHECK (outcome IN ('pending', 'passed', 'failed', 'retried', 'blocked')),
    retry_count      INT NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (session_id, step_number)
);

CREATE INDEX IF NOT EXISTS idx_engram_cot_steps_session
    ON engram_cot_steps (session_id, step_number);
