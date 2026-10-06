-- Workflow schedules and trigger logs

CREATE TABLE IF NOT EXISTS workflow_schedules (
    workflow_id VARCHAR(36) PRIMARY KEY REFERENCES workflows(id) ON DELETE CASCADE,
    cron VARCHAR(100) NOT NULL,
    next_run_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_workflow_schedules_next_run ON workflow_schedules(next_run_at) WHERE is_active = true;

CREATE TABLE IF NOT EXISTS workflow_trigger_logs (
    id VARCHAR(36) PRIMARY KEY,
    workflow_id VARCHAR(36) NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    trigger_type VARCHAR(50) NOT NULL,
    event_data JSONB,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_trigger_logs_workflow ON workflow_trigger_logs(workflow_id);
CREATE INDEX idx_trigger_logs_time ON workflow_trigger_logs(triggered_at);

-- API Keys for function authentication
CREATE TABLE IF NOT EXISTS function_api_keys (
    id VARCHAR(36) PRIMARY KEY,
    function_id VARCHAR(36) NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    UNIQUE(key_prefix)
);

CREATE INDEX idx_function_api_keys_function ON function_api_keys(function_id);
