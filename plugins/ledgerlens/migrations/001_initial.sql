-- LedgerLens — Initial Schema
-- AI FinOps: tag attribution, budget envelopes, anomaly events,
-- unit economics, forecast snapshots, recommendations, exports.
--
-- ConnectorOS is the source of truth for raw usage records.
-- LedgerLens adds: tags, budget enforcement, analytics, exports.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────
-- 1. COST TAGS  (business context on every ConnectorOS usage record)
-- ─────────────────────────────────────────────────────────────────

-- Tag definitions: what tags are valid in this tenant
CREATE TABLE IF NOT EXISTS ll_tag_keys (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    key         TEXT        NOT NULL UNIQUE,          -- e.g. "feature", "bu", "customer", "workflow"
    description TEXT,
    required    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A usage record received from ConnectorOS with tags applied
CREATE TABLE IF NOT EXISTS ll_usage_records (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- ConnectorOS identifiers
    connector_record_id TEXT        UNIQUE,           -- raw ID from ConnectorOS billing record
    agent_id            TEXT        NOT NULL,
    model               TEXT        NOT NULL,
    provider            TEXT        NOT NULL DEFAULT 'openai',
    call_type           TEXT        NOT NULL DEFAULT 'llm',  -- llm | tool | mcp
    -- Costs (USD, 8 decimal places for sub-cent precision)
    input_tokens        BIGINT      NOT NULL DEFAULT 0,
    output_tokens       BIGINT      NOT NULL DEFAULT 0,
    total_tokens        BIGINT      NOT NULL DEFAULT 0,
    cost_usd            NUMERIC(18,8) NOT NULL DEFAULT 0,
    -- Business tags (denormalized for fast pivot queries)
    tag_feature         TEXT,
    tag_bu              TEXT,
    tag_customer        TEXT,
    tag_workflow        TEXT,
    tag_team            TEXT,
    tags                JSONB       NOT NULL DEFAULT '{}',   -- all tags, including custom
    -- Timing
    called_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_agent         ON ll_usage_records(agent_id);
CREATE INDEX IF NOT EXISTS idx_usage_called_at     ON ll_usage_records(called_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_tag_feature   ON ll_usage_records(tag_feature);
CREATE INDEX IF NOT EXISTS idx_usage_tag_bu        ON ll_usage_records(tag_bu);
CREATE INDEX IF NOT EXISTS idx_usage_tag_customer  ON ll_usage_records(tag_customer);
CREATE INDEX IF NOT EXISTS idx_usage_tag_workflow  ON ll_usage_records(tag_workflow);
CREATE INDEX IF NOT EXISTS idx_usage_model         ON ll_usage_records(model);
CREATE INDEX IF NOT EXISTS idx_usage_cost          ON ll_usage_records(cost_usd DESC);

-- ─────────────────────────────────────────────────────────────────
-- 2. BUDGET ENVELOPES
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ll_budgets (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT        NOT NULL,
    -- Scope: exactly ONE of these should be set
    scope_type      TEXT        NOT NULL,             -- bu | feature | customer | workflow | agent | global
    scope_value     TEXT,                             -- the actual value (e.g. "marketing", "checkout")
    -- Limits
    period          TEXT        NOT NULL DEFAULT 'monthly',  -- hourly | daily | weekly | monthly | custom
    limit_usd       NUMERIC(18,4) NOT NULL,
    -- On-breach policy
    breach_policy   TEXT        NOT NULL DEFAULT 'alert_only',
    -- alert_only | downgrade | hard_stop | cap_and_queue
    downgrade_model TEXT,                             -- model to downgrade to on breach (e.g. "gpt-4o-mini")
    -- State
    current_spend   NUMERIC(18,8) NOT NULL DEFAULT 0,
    period_start    TIMESTAMPTZ NOT NULL DEFAULT date_trunc('month', NOW()),
    period_end      TIMESTAMPTZ NOT NULL DEFAULT (date_trunc('month', NOW()) + INTERVAL '1 month'),
    breached        BOOLEAN     NOT NULL DEFAULT FALSE,
    breach_at       TIMESTAMPTZ,
    -- Notifications
    alert_emails    JSONB       NOT NULL DEFAULT '[]',
    alert_webhooks  JSONB       NOT NULL DEFAULT '[]',
    alert_pct       INTEGER     NOT NULL DEFAULT 80,  -- alert at this % of limit
    -- Meta
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_budget_scope   ON ll_budgets(scope_type, scope_value);
CREATE INDEX IF NOT EXISTS idx_budget_enabled ON ll_budgets(enabled) WHERE enabled = TRUE;

-- Budget breach events (immutable log)
CREATE TABLE IF NOT EXISTS ll_budget_events (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    budget_id   UUID        NOT NULL REFERENCES ll_budgets(id),
    event_type  TEXT        NOT NULL,  -- breach | warn | reset | policy_applied | cap_lifted
    spend_usd   NUMERIC(18,8) NOT NULL,
    limit_usd   NUMERIC(18,8) NOT NULL,
    pct_used    NUMERIC(6,2) NOT NULL,
    policy      TEXT,
    detail      JSONB       NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_budget_events_budget ON ll_budget_events(budget_id, occurred_at DESC);

-- ─────────────────────────────────────────────────────────────────
-- 3. ANOMALY EVENTS
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ll_anomalies (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- What triggered it
    dimension_type  TEXT        NOT NULL,             -- feature | bu | customer | agent | model | global
    dimension_value TEXT,
    -- Spend data
    observed_spend  NUMERIC(18,8) NOT NULL,
    baseline_spend  NUMERIC(18,8) NOT NULL,
    multiplier      NUMERIC(8,2) NOT NULL,            -- observed / baseline
    window_hours    INTEGER     NOT NULL DEFAULT 1,
    -- Root cause (from ConnectorOS causal analysis)
    root_cause      TEXT,
    top_agents      JSONB       NOT NULL DEFAULT '[]',
    top_models      JSONB       NOT NULL DEFAULT '[]',
    -- State
    status          TEXT        NOT NULL DEFAULT 'open',  -- open | acknowledged | resolved | false_positive
    severity        TEXT        NOT NULL DEFAULT 'medium', -- low | medium | high | critical
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    detail          JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomaly_status    ON ll_anomalies(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_dimension ON ll_anomalies(dimension_type, dimension_value);

-- ─────────────────────────────────────────────────────────────────
-- 4. UNIT ECONOMICS  (cost × revenue linkage)
-- ─────────────────────────────────────────────────────────────────

-- Revenue import: link customer / feature to revenue data
CREATE TABLE IF NOT EXISTS ll_revenue_records (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    period_start    DATE        NOT NULL,
    period_end      DATE        NOT NULL,
    dimension_type  TEXT        NOT NULL,             -- customer | feature | bu | workflow
    dimension_value TEXT        NOT NULL,
    revenue_usd     NUMERIC(18,4) NOT NULL,
    source          TEXT        NOT NULL DEFAULT 'manual',  -- manual | stripe | import
    source_ref      TEXT,                             -- Stripe invoice ID, CSV row, etc.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (period_start, dimension_type, dimension_value)
);

CREATE INDEX IF NOT EXISTS idx_revenue_dim    ON ll_revenue_records(dimension_type, dimension_value);
CREATE INDEX IF NOT EXISTS idx_revenue_period ON ll_revenue_records(period_start);

-- ─────────────────────────────────────────────────────────────────
-- 5. FORECAST SNAPSHOTS
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ll_forecasts (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    dimension_type  TEXT        NOT NULL DEFAULT 'global',
    dimension_value TEXT,
    horizon_days    INTEGER     NOT NULL,             -- 30 | 60 | 90
    -- Point estimates (USD)
    p50_usd         NUMERIC(18,4) NOT NULL,
    p80_usd         NUMERIC(18,4) NOT NULL,
    p95_usd         NUMERIC(18,4) NOT NULL,
    -- Model inputs
    trailing_30d_usd NUMERIC(18,4),
    trailing_7d_usd  NUMERIC(18,4),
    daily_avg_usd    NUMERIC(18,4),
    growth_rate_pct  NUMERIC(8,4),
    -- Scenario adjustments
    scenarios       JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_forecast_dim ON ll_forecasts(dimension_type, dimension_value, created_at DESC);

-- ─────────────────────────────────────────────────────────────────
-- 6. OPTIMIZATION RECOMMENDATIONS
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ll_recommendations (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    rec_type        TEXT        NOT NULL,
    -- rightsize_model | enable_cache | terminate_zombie |
    -- dedup_prompts   | shift_traffic | budget_cap
    title           TEXT        NOT NULL,
    description     TEXT        NOT NULL,
    -- What it applies to
    agent_id        TEXT,
    model_current   TEXT,
    model_suggested TEXT,
    workflow        TEXT,
    feature         TEXT,
    -- Impact
    monthly_savings_usd NUMERIC(18,4) NOT NULL DEFAULT 0,
    quality_impact  TEXT        NOT NULL DEFAULT 'none',  -- none | minimal | moderate | significant
    confidence      NUMERIC(4,2) NOT NULL DEFAULT 0.8,    -- 0-1
    -- Evidence
    evidence        JSONB       NOT NULL DEFAULT '{}',
    -- Lifecycle
    status          TEXT        NOT NULL DEFAULT 'open',  -- open | applied | dismissed | expired
    applied_by      TEXT,
    applied_at      TIMESTAMPTZ,
    dismissed_by    TEXT,
    dismissed_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rec_status ON ll_recommendations(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rec_type   ON ll_recommendations(rec_type);

-- ─────────────────────────────────────────────────────────────────
-- 7. EXPORT JOBS  (chargeback / CFO packages / BI exports)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ll_exports (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    export_type     TEXT        NOT NULL,
    -- chargeback | unit_economics | waste_report | forecast_report | full_cfo_package
    format          TEXT        NOT NULL DEFAULT 'json', -- json | csv | xlsx | parquet
    period_start    DATE        NOT NULL,
    period_end      DATE        NOT NULL,
    filters         JSONB       NOT NULL DEFAULT '{}',
    -- Result
    status          TEXT        NOT NULL DEFAULT 'pending', -- pending | running | done | failed
    row_count       INTEGER,
    size_bytes      BIGINT,
    download_url    TEXT,
    error           TEXT,
    hmac_sig        TEXT,                             -- signed with LEDGERLENS_HMAC_KEY
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_exports_status ON ll_exports(status, created_at DESC);

-- ─────────────────────────────────────────────────────────────────
-- 8. NOTIFICATION CHANNELS
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ll_notification_channels (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT        NOT NULL,
    channel_type    TEXT        NOT NULL,             -- slack | pagerduty | opsgenie | webhook | email
    config          JSONB       NOT NULL DEFAULT '{}',  -- webhook_url, email, routing_key, etc.
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Which channels fire on which event types
CREATE TABLE IF NOT EXISTS ll_notification_rules (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id      UUID        NOT NULL REFERENCES ll_notification_channels(id) ON DELETE CASCADE,
    event_type      TEXT        NOT NULL,
    -- budget_breach | budget_warn | anomaly_critical | anomaly_high |
    -- recommendation_new | export_done | export_failed
    min_severity    TEXT        NOT NULL DEFAULT 'medium',
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notif_rules_channel ON ll_notification_rules(channel_id);
CREATE INDEX IF NOT EXISTS idx_notif_rules_event   ON ll_notification_rules(event_type);

-- ─────────────────────────────────────────────────────────────────
-- 9. AUDIT LOG  (immutable, append-only)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ll_audit_log (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor       TEXT        NOT NULL DEFAULT 'system',
    action      TEXT        NOT NULL,
    resource    TEXT        NOT NULL,
    resource_id TEXT,
    before_json JSONB,
    after_json  JSONB,
    ip_addr     TEXT,
    request_id  TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_resource ON ll_audit_log(resource, resource_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor    ON ll_audit_log(actor, occurred_at DESC);
