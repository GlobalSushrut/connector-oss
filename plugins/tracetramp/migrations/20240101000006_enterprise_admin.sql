-- Enterprise admin tables: RBAC, budgets, policies, approvals, logging, compliance

-- RBAC: Roles
CREATE TABLE IF NOT EXISTS rbac_roles (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_rbac_roles_tenant ON rbac_roles(tenant_id);

-- RBAC: Users  
CREATE TABLE IF NOT EXISTS rbac_users (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    roles TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_rbac_users_tenant ON rbac_users(tenant_id);
CREATE INDEX idx_rbac_users_email ON rbac_users(email);

-- Budgets (already exists in init but ensure columns)
ALTER TABLE IF EXISTS budgets 
    ADD COLUMN IF NOT EXISTS current_spend_usd NUMERIC(18,6) DEFAULT 0,
    ADD COLUMN IF NOT EXISTS alert_threshold NUMERIC(5,4) DEFAULT 0.8,
    ADD COLUMN IF NOT EXISTS scope VARCHAR(50) DEFAULT 'tenant',
    ADD COLUMN IF NOT EXISTS scope_id VARCHAR(255);

-- If budgets table doesn't exist yet
CREATE TABLE IF NOT EXISTS budgets (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    period VARCHAR(50) NOT NULL, -- monthly, daily, hourly
    limit_usd NUMERIC(18,6) NOT NULL,
    alert_threshold NUMERIC(5,4) DEFAULT 0.8,
    scope VARCHAR(50) DEFAULT 'tenant',
    scope_id VARCHAR(255),
    current_spend_usd NUMERIC(18,6) DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_budgets_tenant ON budgets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_budgets_active ON budgets(is_active) WHERE is_active = TRUE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_budgets_tenant_name ON budgets(tenant_id, name);

-- Policies: add missing columns (table already created in migration 1)
ALTER TABLE IF EXISTS policies
    ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 0;
ALTER TABLE IF EXISTS policies
    ADD COLUMN IF NOT EXISTS enforcement_mode VARCHAR(50) DEFAULT 'monitor';

CREATE TABLE IF NOT EXISTS policies (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    policy_type VARCHAR(50) NOT NULL,
    rules JSONB NOT NULL DEFAULT '{}',
    enforcement_mode VARCHAR(50) NOT NULL DEFAULT 'monitor',
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(is_active, priority DESC) WHERE is_active = TRUE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_tenant_name ON policies(tenant_id, name);

-- Cleanup duplicate records created before unique index constraints.
DELETE FROM budgets
WHERE id NOT IN (
    SELECT MIN(id) FROM budgets GROUP BY tenant_id, name
);

DELETE FROM policies
WHERE id NOT IN (
    SELECT MIN(id) FROM policies GROUP BY tenant_id, name
);

-- Approval Queue
CREATE TABLE IF NOT EXISTS approval_queue (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id VARCHAR(36) NOT NULL,
    trace_id VARCHAR(36) NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, approved, rejected, expired
    approvers TEXT[] NOT NULL DEFAULT '{}',
    resolved_by VARCHAR(255),
    resolved_at TIMESTAMPTZ,
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_queue(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approval_queue(tenant_id);

-- Log Destinations
CREATE TABLE IF NOT EXISTS log_destinations (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    destination_type VARCHAR(50) NOT NULL, -- splunk, s3, datadog, cloudwatch, elasticsearch
    config JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_destinations_tenant ON log_destinations(tenant_id);

-- Compliance Export Jobs
CREATE TABLE IF NOT EXISTS compliance_exports (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ NOT NULL,
    format VARCHAR(20) NOT NULL,
    delivery VARCHAR(50) NOT NULL, -- download, s3, email
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, processing, ready, failed
    download_url TEXT,
    file_size_bytes BIGINT,
    record_count BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_compliance_exports_tenant ON compliance_exports(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_exports_status ON compliance_exports(status);

-- Providers table enhancement
ALTER TABLE IF EXISTS providers
    ADD COLUMN IF NOT EXISTS api_key_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS config JSONB DEFAULT '{}';

-- Create providers if missing
CREATE TABLE IF NOT EXISTS providers (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    api_base VARCHAR(500) NOT NULL,
    provider_type VARCHAR(50) NOT NULL, -- openai, anthropic, azure, ollama, mistral, cohere, bedrock, vertex
    api_key_encrypted TEXT,
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_providers_tenant ON providers(tenant_id);

-- Add update triggers
DO $$
BEGIN
    -- Only create triggers if function exists
    IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'update_updated_at_column') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_rbac_roles_updated_at') THEN
            CREATE TRIGGER update_rbac_roles_updated_at BEFORE UPDATE ON rbac_roles
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_rbac_users_updated_at') THEN
            CREATE TRIGGER update_rbac_users_updated_at BEFORE UPDATE ON rbac_users
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_budgets_updated_at') THEN
            CREATE TRIGGER update_budgets_updated_at BEFORE UPDATE ON budgets
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_policies_updated_at') THEN
            CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        END IF;
    END IF;
END $$;
