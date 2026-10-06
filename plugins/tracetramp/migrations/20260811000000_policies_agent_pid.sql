-- B18: first-class agent_pid on TT policies (nullable; tenant policies remain valid).
ALTER TABLE IF EXISTS policies
    ADD COLUMN IF NOT EXISTS agent_pid TEXT;

CREATE INDEX IF NOT EXISTS idx_policies_agent_pid ON policies(agent_pid)
    WHERE agent_pid IS NOT NULL;
