-- Engram: initial schema
-- Namespaces, entropy snapshots, knowledge shares

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS engram_namespaces (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    path           TEXT NOT NULL UNIQUE,        -- "acme/support-agent"
    team           TEXT,
    retention_days INT  NOT NULL DEFAULT 90,
    entropy_alert  FLOAT NOT NULL DEFAULT 0.7,
    entropy_halt   FLOAT NOT NULL DEFAULT 0.95,
    hipaa          BOOLEAN NOT NULL DEFAULT false,
    auto_consolidate BOOLEAN NOT NULL DEFAULT true,
    stale_days     INT  NOT NULL DEFAULT 30,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_engram_namespaces_path   ON engram_namespaces (path);
CREATE INDEX IF NOT EXISTS idx_engram_namespaces_team   ON engram_namespaces (team);

-- One entropy snapshot per namespace per background sweep
CREATE TABLE IF NOT EXISTS engram_entropy_snapshots (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    namespace_id         UUID NOT NULL REFERENCES engram_namespaces (id) ON DELETE CASCADE,
    entropy_score        FLOAT NOT NULL,
    contradiction_count  INT   NOT NULL DEFAULT 0,
    redundancy_count     INT   NOT NULL DEFAULT 0,
    stale_count          INT   NOT NULL DEFAULT 0,
    knot_score           FLOAT NOT NULL DEFAULT 0.0,
    threads_detected     INT   NOT NULL DEFAULT 0,
    action_taken         TEXT,   -- "none" | "alerted" | "consolidated" | "halted"
    snapped_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_engram_entropy_ns_time
    ON engram_entropy_snapshots (namespace_id, snapped_at DESC);

-- Cross-agent knowledge shares
CREATE TABLE IF NOT EXISTS engram_knowledge_shares (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_ns      TEXT NOT NULL,
    target_pattern TEXT NOT NULL,    -- "acme/*" or exact namespace path
    shared_path    TEXT NOT NULL,    -- "/k/acme/legal-summaries/"
    permission     TEXT NOT NULL CHECK (permission IN ('read_only', 'read_write')),
    ucan_cid       TEXT,             -- UCAN capability CID from AgentPassport
    active         BOOLEAN NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_engram_shares_source ON engram_knowledge_shares (source_ns);
CREATE INDEX IF NOT EXISTS idx_engram_shares_active ON engram_knowledge_shares (active);

-- Entropy consolidation audit trail
CREATE TABLE IF NOT EXISTS engram_consolidations (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    namespace_id   UUID NOT NULL REFERENCES engram_namespaces (id) ON DELETE CASCADE,
    merged_count   INT  NOT NULL DEFAULT 0,
    expired_count  INT  NOT NULL DEFAULT 0,
    flagged_count  INT  NOT NULL DEFAULT 0,
    before_entropy FLOAT NOT NULL,
    after_entropy  FLOAT,
    initiated_by   TEXT NOT NULL DEFAULT 'background',  -- "background" | "api" | "threshold"
    completed_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_engram_consolidations_ns
    ON engram_consolidations (namespace_id, created_at DESC);
