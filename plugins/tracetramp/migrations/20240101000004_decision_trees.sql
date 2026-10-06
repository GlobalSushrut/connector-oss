-- Decision Trees - The True Moat
-- Captures raw LLM decision-making process with complete evidence

CREATE TABLE IF NOT EXISTS decision_trees (
    id BIGSERIAL PRIMARY KEY,
    trace_id VARCHAR(36) NOT NULL UNIQUE,
    request_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tree_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX idx_decision_trees_tenant_id ON decision_trees(tenant_id);
CREATE INDEX idx_decision_trees_request_id ON decision_trees(request_id);
CREATE INDEX idx_decision_trees_created_at ON decision_trees(created_at);

-- GIN index for JSONB queries (e.g., searching by model, action, etc.)
CREATE INDEX idx_decision_trees_data_gin ON decision_trees USING GIN (tree_data);

-- Trigger to update updated_at
CREATE TRIGGER update_decision_trees_updated_at BEFORE UPDATE ON decision_trees
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- View for quick decision statistics
CREATE OR REPLACE VIEW decision_stats AS
SELECT 
    tenant_id,
    DATE(created_at) as date,
    COUNT(*) as total_decisions,
    SUM((tree_data->'metadata'->>'total_cost_usd')::numeric) as total_cost_usd,
    SUM((tree_data->'metadata'->>'total_tokens')::bigint) as total_tokens,
    AVG((tree_data->'metadata'->>'node_count')::int) as avg_nodes_per_tree
FROM decision_trees
GROUP BY tenant_id, DATE(created_at);
