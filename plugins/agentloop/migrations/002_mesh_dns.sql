-- AgentLoop: Migration 002 — Agent DNS + Mesh infrastructure
-- Adds: agent endpoints, DNS records, mesh hop log, workers, worker invocations, tunnels

-- ── Agent Endpoints ───────────────────────────────────────────────────────────
-- An agent can have multiple live endpoints (multi-region, blue/green, etc.)
CREATE TABLE IF NOT EXISTS al_agent_endpoints (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES al_agents(id) ON DELETE CASCADE,
    endpoint_url    TEXT NOT NULL,
    region          TEXT,                              -- e.g. us-east-1, eu-west-1
    weight          INTEGER NOT NULL DEFAULT 100,      -- for weighted routing (0–100)
    health_status   TEXT NOT NULL DEFAULT 'unknown',   -- healthy | degraded | unhealthy | unknown
    last_health_at  TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    metadata        JSONB NOT NULL DEFAULT '{}',       -- custom tags, capabilities
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_ep_agent   ON al_agent_endpoints(agent_id);
CREATE INDEX idx_al_ep_health  ON al_agent_endpoints(health_status);
CREATE INDEX idx_al_ep_region  ON al_agent_endpoints(region);

-- ── DNS Records ───────────────────────────────────────────────────────────────
-- The agent:// address space. Maps a name+version+team to one or more endpoints.
CREATE TABLE IF NOT EXISTS al_dns_records (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES al_agents(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,                     -- e.g. "summarizer"
    version_label   TEXT NOT NULL DEFAULT 'latest',    -- "latest" | "stable" | "canary" | "v2" | "blue"
    team            TEXT,
    org             TEXT,
    fqan            TEXT NOT NULL UNIQUE,              -- fully-qualified agent name: name.version.team.org
    routing_policy  TEXT NOT NULL DEFAULT 'round_robin', -- round_robin | weighted | canary | blue_green | failover
    canary_weight   INTEGER NOT NULL DEFAULT 0,        -- % of traffic to canary variant (0 = off)
    canary_target_id UUID REFERENCES al_agent_endpoints(id),
    ttl_secs        INTEGER NOT NULL DEFAULT 30,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    agent_card      JSONB NOT NULL DEFAULT '{}',       -- A2A AgentCard JSON
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_dns_fqan    ON al_dns_records(fqan);
CREATE INDEX idx_al_dns_agent   ON al_dns_records(agent_id);
CREATE INDEX idx_al_dns_team    ON al_dns_records(team);

-- ── Mesh Hop Log ──────────────────────────────────────────────────────────────
-- Append-only record of every agent-to-agent call proxied through the mesh.
CREATE TABLE IF NOT EXISTS al_mesh_hops (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    caller_agent_id     UUID REFERENCES al_agents(id),
    callee_fqan         TEXT NOT NULL,                 -- the agent:// address called
    callee_agent_id     UUID REFERENCES al_agents(id),
    callee_endpoint_id  UUID REFERENCES al_agent_endpoints(id),
    resolved_url        TEXT,                          -- the actual URL forwarded to
    method              TEXT NOT NULL DEFAULT 'POST',
    status_code         INTEGER,
    verdict             TEXT NOT NULL DEFAULT 'allow', -- allow | deny | error
    deny_reason         TEXT,
    request_body_hash   TEXT,                          -- SHA-256, never raw content
    response_body_hash  TEXT,
    latency_ms          INTEGER,
    request_id          TEXT NOT NULL,
    prev_hop_id         UUID REFERENCES al_mesh_hops(id), -- for chain linking
    receipt_hmac        TEXT,                          -- HMAC-SHA256 chained receipt
    hop_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_al_hop_caller  ON al_mesh_hops(caller_agent_id);
CREATE INDEX idx_al_hop_callee  ON al_mesh_hops(callee_agent_id);
CREATE INDEX idx_al_hop_fqan    ON al_mesh_hops(callee_fqan);
CREATE INDEX idx_al_hop_time    ON al_mesh_hops(hop_at DESC);
CREATE INDEX idx_al_hop_verdict ON al_mesh_hops(verdict);

-- ── Workers ───────────────────────────────────────────────────────────────────
-- Agent Workers — stateless edge compute units registered in the mesh.
CREATE TABLE IF NOT EXISTS al_workers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID REFERENCES al_agents(id),
    name            TEXT NOT NULL,
    description     TEXT,
    worker_type     TEXT NOT NULL DEFAULT 'request',   -- request | response | event | schedule | a2a | tunnel
    trigger_config  JSONB NOT NULL DEFAULT '{}',       -- {cron_expr, event_type, path_pattern, ...}
    handler_url     TEXT,                              -- external HTTP handler (or null for inline)
    handler_inline  TEXT,                              -- inline JSON/script config
    mcp_capabilities JSONB NOT NULL DEFAULT '[]',      -- MCP tools this worker exposes
    fqan            TEXT,                              -- auto-set: name.workers.team
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    invoke_count    BIGINT NOT NULL DEFAULT 0,
    last_invoked_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, name)
);
CREATE INDEX idx_al_workers_type    ON al_workers(worker_type);
CREATE INDEX idx_al_workers_agent   ON al_workers(agent_id);
CREATE INDEX idx_al_workers_enabled ON al_workers(enabled);

-- ── Worker Invocations ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS al_worker_invocations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    worker_id       UUID NOT NULL REFERENCES al_workers(id) ON DELETE CASCADE,
    trigger_source  TEXT,                              -- hop_id, event_type, cron, etc.
    status          TEXT NOT NULL DEFAULT 'pending',   -- pending | running | completed | failed | timeout
    input_hash      TEXT,
    output_hash     TEXT,
    error_message   TEXT,
    latency_ms      INTEGER,
    invoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);
CREATE INDEX idx_al_wi_worker ON al_worker_invocations(worker_id);
CREATE INDEX idx_al_wi_status ON al_worker_invocations(status);
CREATE INDEX idx_al_wi_time   ON al_worker_invocations(invoked_at DESC);

-- ── Tunnels ───────────────────────────────────────────────────────────────────
-- Persistent outbound connections from private agents into the mesh.
CREATE TABLE IF NOT EXISTS al_tunnels (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES al_agents(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    token           TEXT NOT NULL UNIQUE,              -- secret token for tunnel auth
    status          TEXT NOT NULL DEFAULT 'disconnected', -- connected | disconnected | error
    private_addr    TEXT,                              -- what the tunnel is forwarding to
    public_fqan     TEXT,                              -- agent:// address exposed in mesh
    last_connected_at TIMESTAMPTZ,
    last_ping_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, name)
);
CREATE INDEX idx_al_tunnels_agent  ON al_tunnels(agent_id);
CREATE INDEX idx_al_tunnels_status ON al_tunnels(status);
CREATE INDEX idx_al_tunnels_token  ON al_tunnels(token);
