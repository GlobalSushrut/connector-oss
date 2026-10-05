//! Selectors for targeting resources (@agent, #session, ns:...)

use serde::{Deserialize, Serialize};

/// Selector for targeting specific resources
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Selector {
    /// @agent - target specific agent
    Agent(String),
    /// #session - target specific session
    Session(String),
    /// ns:namespace - target namespace
    Namespace(String),
    /// :run - target specific run/execution
    Run(String),
    /// current - the current context
    Current,
    /// last - the most recent
    Last,
    /// default - the default resource
    Default,
    /// all - all matching resources
    All,
    /// active - only active resources
    Active,
}

impl Selector {
    /// Parse a selector from string
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.starts_with('@') {
            Some(Self::Agent(s[1..].to_string()))
        } else if s.starts_with('#') {
            Some(Self::Session(s[1..].to_string()))
        } else if s.starts_with("ns:") {
            Some(Self::Namespace(s[3..].to_string()))
        } else if s.starts_with(':') {
            Some(Self::Run(s[1..].to_string()))
        } else {
            match s.to_lowercase().as_str() {
                "current" | "this" => Some(Self::Current),
                "last" | "latest" | "recent" => Some(Self::Last),
                "default" => Some(Self::Default),
                "all" | "*" => Some(Self::All),
                "active" | "running" => Some(Self::Active),
                _ => None,
            }
        }
    }

    /// Convert to canonical string
    pub fn to_canonical(&self) -> String {
        match self {
            Self::Agent(a) => format!("@{}", a),
            Self::Session(s) => format!("#{}", s),
            Self::Namespace(n) => format!("ns:{}", n),
            Self::Run(r) => format!(":{}", r),
            Self::Current => "current".to_string(),
            Self::Last => "last".to_string(),
            Self::Default => "default".to_string(),
            Self::All => "all".to_string(),
            Self::Active => "active".to_string(),
        }
    }
}

impl std::fmt::Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_canonical())
    }
}

impl From<&str> for Selector {
    fn from(s: &str) -> Self {
        Self::parse(s).unwrap_or(Self::Default)
    }
}
