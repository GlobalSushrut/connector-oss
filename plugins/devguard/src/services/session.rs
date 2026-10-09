use serde::{Deserialize, Serialize};

/// Extracted DevGuard session domain model.
/// This keeps session semantics in the DevGuard plugin boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevGuardSession {
    pub session_id: String,
    pub agent_pid: String,
    pub role: String,
    pub workspace: String,
    pub tool: String,
    pub policy_path: String,
    pub created_at: String,
    pub active: bool,
    pub stats: SessionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionStats {
    pub llm_calls: u64,
    pub files_read: u64,
    pub files_written: u64,
    pub commands_executed: u64,
    pub commands_denied: u64,
    pub secrets_redacted: u64,
    pub approvals_requested: u64,
    pub tokens_consumed: u64,
    pub cost_usd: f64,
}

pub fn build_session_instructions(tool: &str, session_token: &str) -> String {
    match tool {
        "claude_code" => format!(
            "Run: ANTHROPIC_BASE_URL=http://localhost:9091 ANTHROPIC_API_KEY={} claude \"your task\"",
            session_token
        ),
        "cursor" => format!(
            "Set in Cursor: Override OpenAI Base URL = http://localhost:9091, API Key = {}",
            session_token
        ),
        "windsurf" => format!(
            "Add to .windsurf/mcp_config.json or set OpenAI Base URL = http://localhost:9091, Key = {}",
            session_token
        ),
        _ => format!(
            "Set OPENAI_BASE_URL=http://localhost:9091 OPENAI_API_KEY={} or ANTHROPIC_BASE_URL=http://localhost:9091 ANTHROPIC_API_KEY={}",
            session_token, session_token
        ),
    }
}
