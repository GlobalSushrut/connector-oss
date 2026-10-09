//! Canonical Action Model — DevGuard's internal language.
//!
//! Every coding tool action (Claude tool_use, Cursor file op, Windsurf MCP call, etc.)
//! is translated into one of these canonical actions by the tool adapter.
//!
//! Connector OS does NOT know this type exists. It's DevGuard's internal contract.
//! When DevGuard submits actions to Connector, it translates them into generic
//! Connector API calls (admission check, audit record, etc.).

use std::path::PathBuf;
use serde::{Serialize, Deserialize};

// ── Canonical Action ──────────────────────────────────────────────────────

/// Every coding tool action reduces to one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CanonicalAction {
    // ── Session lifecycle ──
    SessionStart {
        tool: ToolId,
        role: String,
        workspace: PathBuf,
        identity: String,
    },
    SessionStop {
        session_id: String,
    },

    // ── File operations ──
    FileRead {
        path: PathBuf,
    },
    FileWrite {
        path: PathBuf,
        content_hash: String,
        lines_changed: u32,
    },
    FileDelete {
        path: PathBuf,
    },
    FileRename {
        from: PathBuf,
        to: PathBuf,
    },
    PatchApply {
        path: PathBuf,
        diff_hash: String,
        lines_added: u32,
        lines_removed: u32,
    },

    // ── Code search ──
    SearchCode {
        query: String,
        scope: Vec<String>,
    },

    // ── Command execution ──
    CommandExec {
        command: String,
        cwd: PathBuf,
        background: bool,
    },

    // ── Network ──
    NetworkRequest {
        host: String,
        port: u16,
        method: String,
        path: String,
    },

    // ── Secrets ──
    SecretAccess {
        key_name: String,
        operation: SecretOp,
    },

    // ── Git ──
    GitOp {
        operation: GitOperation,
        args: Vec<String>,
    },

    // ── Package management ──
    PackageInstall {
        manager: String,
        package: String,
        version: Option<String>,
    },

    // ── CI/CD ──
    DeployAction {
        tool: String,
        command: String,
        target: String,
    },

    // ── LLM call (proxied through Connector gateway) ──
    LlmCall {
        model: String,
        input_tokens: u32,
        cost_usd: f64,
    },

    // ── Generic tool invocation ──
    ToolInvoke {
        tool_name: String,
        input_hash: String,
    },

    // ── Context assembly ──
    ContextRequest {
        scope: Vec<String>,
        budget_tokens: u64,
    },
}

// ── Supporting types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ToolId {
    ClaudeCode,
    Kiro,
    Cursor,
    Windsurf,
    Aider,
    Continue,
    Cline,
    RooCode,
    Copilot,
    Zed,
    Generic,
}

impl ToolId {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().replace('-', "_").as_str() {
            "claude_code" | "claude" => Self::ClaudeCode,
            "kiro" => Self::Kiro,
            "cursor" => Self::Cursor,
            "windsurf" => Self::Windsurf,
            "aider" => Self::Aider,
            "continue" => Self::Continue,
            "cline" => Self::Cline,
            "roo_code" | "roo" => Self::RooCode,
            "copilot" => Self::Copilot,
            "zed" => Self::Zed,
            _ => Self::Generic,
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Kiro => "Kiro",
            Self::Cursor => "Cursor",
            Self::Windsurf => "Windsurf",
            Self::Aider => "Aider",
            Self::Continue => "Continue",
            Self::Cline => "Cline",
            Self::RooCode => "Roo Code",
            Self::Copilot => "Copilot",
            Self::Zed => "Zed",
            Self::Generic => "Generic",
        }
    }
}

impl std::fmt::Display for ToolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecretOp {
    Read,
    Inject,
    Rotate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GitOperation {
    Commit,
    Push,
    ForcePush,
    Rebase,
    Merge,
    BranchCreate,
    BranchDelete,
    Tag,
    Reset,
    Checkout,
}

// ── Risk ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub score: u8,
    pub reasons: Vec<String>,
    pub affected_paths: Vec<PathBuf>,
    pub requires_approval: bool,
    pub approval_from: Vec<String>,
}

// ── Decision ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny { reason: String },
    RequireApproval { from: Vec<String>, reason: String },
    HoldForReview { reason: String },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub action: CanonicalAction,
    pub verdict: Verdict,
    pub risk: RiskAssessment,
    pub policy_fingerprint: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub session_id: String,
    pub identity: String,
    pub role: String,
}

// ── Support level ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SupportLevel {
    /// Level 0: Total enforcement — all actions intercepted
    Total,
    /// Level 1: Strong enforcement — sandbox controls FS/Net/Cmd, some tool actions not interceptable
    Strong,
    /// Level 2: Protocol governance — MCP or proxy-based, most actions governed
    Protocol,
    /// Level 3: Proxy only — LLM traffic audited, file/command ops not interceptable
    ProxyOnly,
}
