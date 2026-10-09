-- Connector License Server — Initial schema (Postgres)
-- Migrated from SQLite; all types promoted to native PG equivalents.
-- Run automatically by sqlx::migrate! on startup.

CREATE TABLE IF NOT EXISTS license_keys (
    key_id              TEXT        PRIMARY KEY,
    key_secret          TEXT        NOT NULL UNIQUE,
    tier                TEXT        NOT NULL,
    customer_email      TEXT        NOT NULL,
    customer_name       TEXT        NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,
    max_activations     INTEGER     NOT NULL DEFAULT 3,
    revoked             BOOLEAN     NOT NULL DEFAULT FALSE,
    stripe_sub_id       TEXT,
    signature           TEXT        NOT NULL,
    active_instances    JSONB       NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS activations (
    instance_id         TEXT        PRIMARY KEY,
    key_id              TEXT        NOT NULL REFERENCES license_keys(key_id) ON DELETE CASCADE,
    machine_id          TEXT        NOT NULL,
    hostname            TEXT        NOT NULL,
    activated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat      TIMESTAMPTZ,
    deactivated_at      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS usage_records (
    id                  BIGSERIAL   PRIMARY KEY,
    instance_id         TEXT        NOT NULL,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    agents_active       INTEGER     NOT NULL DEFAULT 0,
    packets_stored      INTEGER     NOT NULL DEFAULT 0,
    audit_entries       INTEGER     NOT NULL DEFAULT 0,
    total_tokens        BIGINT      NOT NULL DEFAULT 0,
    total_cost_usd      NUMERIC(12,6) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS revocation_log (
    id                  BIGSERIAL   PRIMARY KEY,
    key_id              TEXT        NOT NULL,
    revoked_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason              TEXT
);

CREATE TABLE IF NOT EXISTS customers (
    customer_id         TEXT        PRIMARY KEY,
    email               TEXT        NOT NULL UNIQUE,
    name                TEXT        NOT NULL,
    stripe_customer_id  TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    payment_status      TEXT        NOT NULL DEFAULT 'Trial',
    last_payment_at     TIMESTAMPTZ,
    total_paid_cents    BIGINT      NOT NULL DEFAULT 0,
    key_ids             JSONB       NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS instances (
    instance_id         TEXT        PRIMARY KEY,
    key_id              TEXT        NOT NULL,
    customer_id         TEXT        NOT NULL,
    machine_id          TEXT        NOT NULL,
    hostname            TEXT        NOT NULL,
    binary_hash         TEXT        NOT NULL,
    binary_id           TEXT        NOT NULL,
    license_address     TEXT        NOT NULL,
    tier                TEXT        NOT NULL,
    permissions         JSONB       NOT NULL DEFAULT '[]',
    activated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat      TIMESTAMPTZ,
    last_usage_report   TIMESTAMPTZ,
    status              TEXT        NOT NULL DEFAULT 'Active',
    agents_last         INTEGER     NOT NULL DEFAULT 0,
    packets_last        INTEGER     NOT NULL DEFAULT 0,
    trust_score_last    INTEGER     NOT NULL DEFAULT 0,
    total_tokens        BIGINT      NOT NULL DEFAULT 0,
    total_cost          NUMERIC(12,6) NOT NULL DEFAULT 0,
    warnings_issued     INTEGER     NOT NULL DEFAULT 0,
    grace_period_ends   TIMESTAMPTZ,
    kill_issued         BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS surveillance_events (
    id                  BIGSERIAL   PRIMARY KEY,
    event_id            TEXT        NOT NULL UNIQUE,
    instance_id         TEXT        NOT NULL,
    event_type          TEXT        NOT NULL,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    details             JSONB       NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS blocked_hashes (
    hash                TEXT        PRIMARY KEY,
    blocked_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason              TEXT
);

CREATE TABLE IF NOT EXISTS binary_issuances (
    binary_id           TEXT        PRIMARY KEY,
    role_id             TEXT        NOT NULL,
    secret_id           TEXT        NOT NULL UNIQUE,
    secret_id_used      BOOLEAN     NOT NULL DEFAULT FALSE,
    key_id              TEXT        NOT NULL,
    tier                TEXT        NOT NULL,
    locked_machine_id   TEXT,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,
    auth_count          INTEGER     NOT NULL DEFAULT 0,
    active_token_ids    JSONB       NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS rpc_tokens (
    token_id            TEXT        PRIMARY KEY,
    instance_id         TEXT        NOT NULL,
    binary_id           TEXT        NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          BIGINT      NOT NULL,
    revoked             BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMPTZ,
    revoke_reason       TEXT
);

CREATE TABLE IF NOT EXISTS portal_users (
    user_id             TEXT        PRIMARY KEY,
    email               TEXT        NOT NULL UNIQUE,
    name                TEXT        NOT NULL,
    password_hash       TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login          TIMESTAMPTZ,
    totp_secret         TEXT,
    totp_enabled        BOOLEAN     NOT NULL DEFAULT FALSE,
    api_keys            JSONB       NOT NULL DEFAULT '[]',
    license_key_id      TEXT,
    tier                TEXT        NOT NULL DEFAULT 'Community',
    locked              BOOLEAN     NOT NULL DEFAULT FALSE,
    email_verified      BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_codes        JSONB       NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS pilot_grants (
    grant_id                TEXT        PRIMARY KEY,
    customer_id             TEXT        NOT NULL,
    granted_by              TEXT        NOT NULL,
    granted_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,
    status                  TEXT        NOT NULL DEFAULT 'Active',
    tier_override           TEXT,
    agent_limit_override    INTEGER,
    packet_limit_override   INTEGER,
    features_override       JSONB       NOT NULL DEFAULT '[]',
    reason                  TEXT        NOT NULL,
    notes                   TEXT        NOT NULL DEFAULT ''
);

-- ── Indexes ──────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_activations_key         ON activations(key_id);
CREATE INDEX IF NOT EXISTS idx_usage_instance          ON usage_records(instance_id);
CREATE INDEX IF NOT EXISTS idx_usage_recorded_at       ON usage_records(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_instance         ON surveillance_events(instance_id);
CREATE INDEX IF NOT EXISTS idx_events_occurred_at      ON surveillance_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_instances_customer      ON instances(customer_id);
CREATE INDEX IF NOT EXISTS idx_instances_status        ON instances(status);
CREATE INDEX IF NOT EXISTS idx_issuances_key           ON binary_issuances(key_id);
CREATE INDEX IF NOT EXISTS idx_issuances_role          ON binary_issuances(role_id);
CREATE INDEX IF NOT EXISTS idx_tokens_instance         ON rpc_tokens(instance_id);
CREATE INDEX IF NOT EXISTS idx_tokens_expires          ON rpc_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_portal_users_email      ON portal_users(email);
CREATE INDEX IF NOT EXISTS idx_pilot_grants_customer   ON pilot_grants(customer_id);
CREATE INDEX IF NOT EXISTS idx_pilot_grants_status     ON pilot_grants(status);
CREATE INDEX IF NOT EXISTS idx_customers_stripe        ON customers(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_license_keys_email      ON license_keys(customer_email);
CREATE INDEX IF NOT EXISTS idx_license_keys_secret     ON license_keys(key_secret);
