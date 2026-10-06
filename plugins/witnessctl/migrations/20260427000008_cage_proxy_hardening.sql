ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS observed_via_witness_route BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS witness_proxy_watchdog (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name            TEXT NOT NULL,
    route_profile           TEXT NOT NULL,
    healthy                 BOOLEAN NOT NULL DEFAULT TRUE,
    active_session_count    BIGINT NOT NULL DEFAULT 0,
    note                    TEXT,
    heartbeat_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_proxy_watchdog_heartbeat
    ON witness_proxy_watchdog(service_name, heartbeat_at DESC);
