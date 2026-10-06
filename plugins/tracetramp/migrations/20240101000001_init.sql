-- Initial TraceTramp schema
-- Creates tables for tenants, actors, API keys, traces, costs, policies, etc.

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    default_mode VARCHAR(50) NOT NULL DEFAULT 'control',
    policy_bundle VARCHAR(255) NOT NULL DEFAULT 'default',
    budget_tier VARCHAR(50) NOT NULL DEFAULT 'standard',
    providers TEXT[] NOT NULL DEFAULT ARRAY['openai'],
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Actors table (users/systems making requests)
CREATE TABLE IF NOT EXISTS actors (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_id VARCHAR(255) NOT NULL,
    role VARCHAR(100) NOT NULL DEFAULT 'user',
    clearance_level INTEGER NOT NULL DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ,
    UNIQUE(tenant_id, external_id)
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_prefix VARCHAR(50) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    actor_id VARCHAR(36) NOT NULL,
    actor_role VARCHAR(100) NOT NULL DEFAULT 'user',
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    UNIQUE(key_prefix)
);

-- Trace Events table (execution timeline)
CREATE TABLE IF NOT EXISTS trace_events (
    id BIGSERIAL PRIMARY KEY,
    trace_id VARCHAR(36) NOT NULL,
    request_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    step VARCHAR(100) NOT NULL,
    result VARCHAR(100) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for trace queries
CREATE INDEX idx_trace_events_trace_id ON trace_events(trace_id);
CREATE INDEX idx_trace_events_request_id ON trace_events(request_id);
CREATE INDEX idx_trace_events_created_at ON trace_events(created_at);

-- Cost Records table
CREATE TABLE IF NOT EXISTS cost_records (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(36) NOT NULL,
    trace_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model VARCHAR(100) NOT NULL,
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT GENERATED ALWAYS AS (input_tokens + output_tokens) STORED,
    cost_usd DECIMAL(12, 6) NOT NULL DEFAULT 0,
    tags JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for cost queries
CREATE INDEX idx_cost_records_tenant_id ON cost_records(tenant_id);
CREATE INDEX idx_cost_records_created_at ON cost_records(created_at);
CREATE INDEX idx_cost_records_request_id ON cost_records(request_id);

-- Providers table
CREATE TABLE IF NOT EXISTS providers (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    api_base VARCHAR(500) NOT NULL,
    provider_type VARCHAR(50) NOT NULL, -- openai, anthropic, azure, ollama
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rules JSONB NOT NULL DEFAULT '[]',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Budgets table
CREATE TABLE IF NOT EXISTS budgets (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    budget_type VARCHAR(50) NOT NULL, -- monthly, per_request, per_user
    limit_amount DECIMAL(12, 2) NOT NULL,
    alert_threshold DECIMAL(5, 2) NOT NULL DEFAULT 0.8, -- 80%
    current_spend DECIMAL(12, 2) NOT NULL DEFAULT 0,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Approvals queue table
CREATE TABLE IF NOT EXISTS approvals (
    id VARCHAR(36) PRIMARY KEY,
    request_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id VARCHAR(36) NOT NULL,
    requested_action TEXT NOT NULL,
    approvers TEXT[] NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, approved, rejected
    approved_by VARCHAR(36),
    approved_at TIMESTAMPTZ,
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

-- Create indexes for approval queries
CREATE INDEX idx_approvals_status ON approvals(status);
CREATE INDEX idx_approvals_tenant_id ON approvals(tenant_id);

-- RBAC Roles table
CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RBAC User-Role assignments
CREATE TABLE IF NOT EXISTS user_roles (
    id BIGSERIAL PRIMARY KEY,
    actor_id VARCHAR(36) NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    role_id VARCHAR(36) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by VARCHAR(36),
    UNIQUE(actor_id, role_id)
);

-- Sessions table (for context preservation)
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id VARCHAR(36) NOT NULL,
    context JSONB NOT NULL DEFAULT '{}',
    memory_references TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default tenant
INSERT INTO tenants (id, name, environment, default_mode, policy_bundle, budget_tier, providers)
VALUES ('default', 'Default Tenant', 'production', 'control', 'default', 'standard', ARRAY['openai'])
ON CONFLICT (id) DO NOTHING;

-- Insert default provider
INSERT INTO providers (id, name, api_base, provider_type)
VALUES ('openai-default', 'OpenAI', 'https://api.openai.com/v1', 'openai')
ON CONFLICT (id) DO NOTHING;

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_providers_updated_at BEFORE UPDATE ON providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_budgets_updated_at BEFORE UPDATE ON budgets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
