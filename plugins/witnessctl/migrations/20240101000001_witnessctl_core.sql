-- WitnessCtl core schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Sessions ────────────────────────────────────────────────────────────────
CREATE TABLE witness_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upstream        TEXT NOT NULL,
    role            TEXT NOT NULL,
    agent_pid       TEXT,
    mode            TEXT NOT NULL DEFAULT 'proxy',   -- proxy | sdk_shim | webhook
    status          TEXT NOT NULL DEFAULT 'active',  -- active | sealed
    frameworks      TEXT[] NOT NULL DEFAULT ARRAY['hipaa','soc2'],
    policy          JSONB NOT NULL DEFAULT '{}',
    session_token   TEXT UNIQUE NOT NULL,
    chain_head_hmac TEXT,                            -- HMAC of last receipt in chain
    receipt_seq     BIGINT NOT NULL DEFAULT 0,
    total_calls     BIGINT NOT NULL DEFAULT 0,
    total_blocked   BIGINT NOT NULL DEFAULT 0,
    total_pii_hits  BIGINT NOT NULL DEFAULT 0,
    cost_usd        NUMERIC(18,8) NOT NULL DEFAULT 0,
    proof_id        TEXT,
    bundle_path     TEXT,
    tsa_status      TEXT,
    tsa_token       TEXT,
    tsa_timestamped_at TIMESTAMPTZ,
    sealed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_witness_sessions_token  ON witness_sessions(session_token);
CREATE INDEX idx_witness_sessions_status ON witness_sessions(status);
CREATE INDEX idx_witness_sessions_created ON witness_sessions(created_at DESC);

-- ── Captures (one row per API call) ─────────────────────────────────────────
CREATE TABLE witness_captures (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id          UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    seq                 BIGINT NOT NULL,
    method              TEXT NOT NULL,
    url                 TEXT NOT NULL,
    host                TEXT NOT NULL,
    path                TEXT NOT NULL,
    request_hash        TEXT NOT NULL,   -- SHA-256 of request body
    response_hash       TEXT,            -- SHA-256 of response body
    response_status     INT,
    latency_ms          INT,
    admission_verdict   TEXT NOT NULL DEFAULT 'allow',  -- allow | deny | hold
    admission_reason    TEXT,
    firewall_blocked    BOOLEAN NOT NULL DEFAULT FALSE,
    firewall_checked    BOOLEAN NOT NULL DEFAULT TRUE,
    firewall_status     TEXT,
    firewall_reason     TEXT,
    pii_in_request      BOOLEAN NOT NULL DEFAULT FALSE,
    pii_in_response     BOOLEAN NOT NULL DEFAULT FALSE,
    schema_drift        BOOLEAN NOT NULL DEFAULT FALSE,
    drift_fields        TEXT[],
    receipt_id          UUID,
    receipt_hmac        TEXT,
    cost_usd            NUMERIC(18,8),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(session_id, seq)
);

CREATE INDEX idx_witness_captures_session ON witness_captures(session_id, seq);
CREATE INDEX idx_witness_captures_url     ON witness_captures(session_id, host, path);
CREATE INDEX idx_witness_captures_created ON witness_captures(created_at DESC);

-- ── Receipt chain (HMAC-linked per session) ──────────────────────────────────
CREATE TABLE witness_receipts (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id  UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    capture_id  UUID REFERENCES witness_captures(id),
    event_type  TEXT NOT NULL,    -- session.open | api.call | session.close
    seq         BIGINT NOT NULL,
    payload     JSONB NOT NULL,
    hmac        TEXT NOT NULL,    -- HMAC-SHA256(payload_json + prev_hmac)
    prev_hmac   TEXT,             -- NULL for first receipt
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(session_id, seq)
);

CREATE INDEX idx_witness_receipts_session ON witness_receipts(session_id, seq);

-- ── PII hits (field-level, per capture) ─────────────────────────────────────
CREATE TABLE witness_pii_hits (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id  UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    capture_id  UUID NOT NULL REFERENCES witness_captures(id) ON DELETE CASCADE,
    location    TEXT NOT NULL,    -- request | response
    field_path  TEXT NOT NULL,    -- e.g. "body.patient.ssn"
    pii_type    TEXT NOT NULL,    -- email | phone | ssn | credit_card | phi | ip | api_key
    action      TEXT NOT NULL,    -- detected | blocked | redacted
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_witness_pii_session  ON witness_pii_hits(session_id);
CREATE INDEX idx_witness_pii_type     ON witness_pii_hits(pii_type);

-- ── Schema snapshots (per endpoint per session) ──────────────────────────────
CREATE TABLE witness_schemas (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    path            TEXT NOT NULL,
    method          TEXT NOT NULL,
    schema_version  INT NOT NULL DEFAULT 1,
    request_schema  JSONB NOT NULL DEFAULT '{}',
    response_schema JSONB NOT NULL DEFAULT '{}',
    status_codes    INT[] NOT NULL DEFAULT '{}',
    drift_log       JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(session_id, host, path, method)
);

CREATE INDEX idx_witness_schemas_session ON witness_schemas(session_id);

-- ── Compliance verdicts (per framework per session) ──────────────────────────
CREATE TABLE witness_compliance (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID NOT NULL REFERENCES witness_sessions(id) ON DELETE CASCADE,
    framework       TEXT NOT NULL,   -- hipaa | soc2 | gdpr | eu_ai_act
    passed          BOOLEAN NOT NULL,
    score           INT NOT NULL DEFAULT 0,   -- 0-100
    controls        JSONB NOT NULL DEFAULT '{}',
    failed_controls TEXT[] NOT NULL DEFAULT '{}',
    evaluated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(session_id, framework)
);

CREATE INDEX idx_witness_compliance_session ON witness_compliance(session_id);
