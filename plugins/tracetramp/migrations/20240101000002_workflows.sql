-- Workflow and tool registry schema additions

-- Workflows table
CREATE TABLE IF NOT EXISTS workflows (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL DEFAULT '1.0',
    description TEXT,
    definition JSONB NOT NULL,
    triggers JSONB DEFAULT '[]',
    variables JSONB DEFAULT '{}',
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workflows_tenant_id ON workflows(tenant_id);

-- Workflow runs table
CREATE TABLE IF NOT EXISTS workflow_runs (
    id VARCHAR(36) PRIMARY KEY,
    workflow_id VARCHAR(36) NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    tenant_id VARCHAR(36) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    input JSONB NOT NULL DEFAULT '{}',
    output JSONB,
    step_results JSONB NOT NULL DEFAULT '{}',
    current_step VARCHAR(36),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workflow_runs_workflow_id ON workflow_runs(workflow_id);
CREATE INDEX idx_workflow_runs_status ON workflow_runs(status);
CREATE INDEX idx_workflow_runs_started_at ON workflow_runs(started_at);

-- Workflow checkpoints for recovery
CREATE TABLE IF NOT EXISTS workflow_checkpoints (
    id VARCHAR(36) PRIMARY KEY,
    run_id VARCHAR(36) NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_workflow_checkpoints_run_id ON workflow_checkpoints(run_id);

-- Tools registry table
CREATE TABLE IF NOT EXISTS tools (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    tool_type VARCHAR(50) NOT NULL,
    definition JSONB NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tools_tenant_id ON tools(tenant_id);
CREATE INDEX idx_tools_tool_type ON tools(tool_type);

-- Functions table (for OpenFaaS, Lambda, etc.)
CREATE TABLE IF NOT EXISTS functions (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    backend VARCHAR(50) NOT NULL, -- openfaas, lambda, docker, wasm
    runtime VARCHAR(100),
    memory_mb INTEGER DEFAULT 256,
    timeout_seconds INTEGER DEFAULT 30,
    config JSONB NOT NULL DEFAULT '{}',
    env_vars JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_functions_tenant_id ON functions(tenant_id);

-- Function execution logs
CREATE TABLE IF NOT EXISTS function_executions (
    id BIGSERIAL PRIMARY KEY,
    function_id VARCHAR(36) NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
    run_id VARCHAR(36),
    input JSONB,
    output JSONB,
    status VARCHAR(50) NOT NULL,
    execution_time_ms INTEGER,
    cold_start BOOLEAN DEFAULT FALSE,
    logs TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_function_executions_function_id ON function_executions(function_id);
CREATE INDEX idx_function_executions_created_at ON function_executions(created_at);

-- Add trigger for updated_at
CREATE TRIGGER update_workflows_updated_at BEFORE UPDATE ON workflows
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tools_updated_at BEFORE UPDATE ON tools
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_functions_updated_at BEFORE UPDATE ON functions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
