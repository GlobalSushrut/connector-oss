-- Scale tiered storage: rollup tables and tier management

-- Hourly aggregates for fast metrics queries
CREATE TABLE IF NOT EXISTS hourly_rollups (
    tenant_id VARCHAR(36) NOT NULL,
    hour TIMESTAMPTZ NOT NULL,
    model VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    decision_count BIGINT NOT NULL DEFAULT 0,
    total_input_tokens BIGINT NOT NULL DEFAULT 0,
    total_output_tokens BIGINT NOT NULL DEFAULT 0,
    total_cost_usd NUMERIC(18,6) NOT NULL DEFAULT 0,
    p50_latency_ms BIGINT DEFAULT 0,
    p95_latency_ms BIGINT DEFAULT 0,
    p99_latency_ms BIGINT DEFAULT 0,
    error_count BIGINT DEFAULT 0,
    policy_blocks BIGINT DEFAULT 0,
    policy_redactions BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, hour, model, provider)
);

CREATE INDEX idx_hourly_rollups_tenant ON hourly_rollups(tenant_id, hour DESC);
CREATE INDEX idx_hourly_rollups_hour ON hourly_rollups(hour DESC);

-- Daily rollups (aggregated from hourly)
CREATE TABLE IF NOT EXISTS daily_rollups (
    tenant_id VARCHAR(36) NOT NULL,
    day DATE NOT NULL,
    decision_count BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    total_cost_usd NUMERIC(18,6) NOT NULL DEFAULT 0,
    by_model JSONB DEFAULT '{}',
    by_app JSONB DEFAULT '{}',
    by_actor JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, day)
);

CREATE INDEX idx_daily_rollups_tenant ON daily_rollups(tenant_id, day DESC);

-- Add tier-management columns to decision_trees
ALTER TABLE decision_trees ADD COLUMN IF NOT EXISTS compressed BOOLEAN DEFAULT FALSE;
ALTER TABLE decision_trees ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT FALSE;
ALTER TABLE decision_trees ADD COLUMN IF NOT EXISTS s3_location TEXT;
ALTER TABLE decision_trees ADD COLUMN IF NOT EXISTS input_hash VARCHAR(64);
ALTER TABLE decision_trees ADD COLUMN IF NOT EXISTS output_hash VARCHAR(64);

-- Index for efficient tier-migration queries
CREATE INDEX IF NOT EXISTS idx_decision_trees_compression 
    ON decision_trees(created_at) WHERE compressed = FALSE;
CREATE INDEX IF NOT EXISTS idx_decision_trees_archive 
    ON decision_trees(created_at) WHERE archived = FALSE;

-- Partition decision_trees by month for scalability
-- (Requires existing table to be converted to partitioned)
COMMENT ON TABLE decision_trees IS 'Consider converting to partitioned table for >100M rows: partition by month on created_at';

-- Function to create monthly partitions (execute for future scale)
CREATE OR REPLACE FUNCTION create_monthly_partition(table_name TEXT, month_date DATE)
RETURNS VOID AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    start_date := date_trunc('month', month_date);
    end_date := start_date + INTERVAL '1 month';
    partition_name := table_name || '_' || to_char(start_date, 'YYYY_MM');
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
        partition_name, table_name, start_date, end_date
    );
END;
$$ LANGUAGE plpgsql;

-- Storage tier tracking
CREATE TABLE IF NOT EXISTS storage_tier_stats (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL,
    tier VARCHAR(20) NOT NULL, -- hot, warm, cold
    record_count BIGINT NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, tier)
);

CREATE INDEX idx_storage_tier_tenant ON storage_tier_stats(tenant_id);
