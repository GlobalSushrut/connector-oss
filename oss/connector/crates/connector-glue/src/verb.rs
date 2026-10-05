//! Canonical GLUE verbs

use serde::{Deserialize, Serialize};

/// Canonical verbs for GLUE operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    // Execution
    Run,
    Start,
    Stop,
    Pause,
    Resume,
    Restart,
    // Data
    Remember,
    Recall,
    Search,
    // CRUD
    Create,
    Delete,
    Show,
    List,
    // Governance
    Verify,
    Audit,
    Prove,
    // Binding
    Bind,
    Attach,
    Detach,
    Use,
}

impl Verb {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Restart => "restart",
            Self::Remember => "remember",
            Self::Recall => "recall",
            Self::Search => "search",
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Show => "show",
            Self::List => "list",
            Self::Verify => "verify",
            Self::Audit => "audit",
            Self::Prove => "prove",
            Self::Bind => "bind",
            Self::Attach => "attach",
            Self::Detach => "detach",
            Self::Use => "use",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "run" | "execute" => Some(Self::Run),
            "start" => Some(Self::Start),
            "stop" | "kill" => Some(Self::Stop),
            "pause" | "suspend" => Some(Self::Pause),
            "resume" | "continue" => Some(Self::Resume),
            "restart" => Some(Self::Restart),
            "remember" | "store" | "write" => Some(Self::Remember),
            "recall" | "read" | "get" => Some(Self::Recall),
            "search" | "find" | "query" => Some(Self::Search),
            "create" | "new" | "add" => Some(Self::Create),
            "delete" | "remove" | "rm" => Some(Self::Delete),
            "show" | "inspect" | "describe" => Some(Self::Show),
            "list" | "ls" => Some(Self::List),
            "verify" | "check" => Some(Self::Verify),
            "audit" | "trace" => Some(Self::Audit),
            "prove" | "certify" => Some(Self::Prove),
            "bind" | "connect" => Some(Self::Bind),
            "attach" => Some(Self::Attach),
            "detach" => Some(Self::Detach),
            "use" | "set" => Some(Self::Use),
            _ => None,
        }
    }
}

impl std::fmt::Display for Verb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
