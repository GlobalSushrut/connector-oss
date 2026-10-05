//! Canonical GLUE nouns (resource types)

use serde::{Deserialize, Serialize};

/// Canonical nouns for GLUE resources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Noun {
    // Core resources
    Agent,
    Contract,
    Session,
    Execution,
    // Data resources
    Memory,
    Knowledge,
    Asset,
    // Governance
    Policy,
    Proof,
    Receipt,
    Audit,
    Compliance,
    // Infrastructure
    Tool,
    Protocol,
    Namespace,
    Capability,
    // System
    Runtime,
    Node,
    Cluster,
}

impl Noun {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Contract => "contract",
            Self::Session => "session",
            Self::Execution => "execution",
            Self::Memory => "memory",
            Self::Knowledge => "knowledge",
            Self::Asset => "asset",
            Self::Policy => "policy",
            Self::Proof => "proof",
            Self::Receipt => "receipt",
            Self::Audit => "audit",
            Self::Compliance => "compliance",
            Self::Tool => "tool",
            Self::Protocol => "protocol",
            Self::Namespace => "namespace",
            Self::Capability => "capability",
            Self::Runtime => "runtime",
            Self::Node => "node",
            Self::Cluster => "cluster",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "agent" | "agents" => Some(Self::Agent),
            "contract" | "contracts" => Some(Self::Contract),
            "session" | "sessions" => Some(Self::Session),
            "execution" | "executions" | "run" | "runs" => Some(Self::Execution),
            "memory" | "memories" | "mem" => Some(Self::Memory),
            "knowledge" | "kb" => Some(Self::Knowledge),
            "asset" | "assets" | "file" | "files" => Some(Self::Asset),
            "policy" | "policies" => Some(Self::Policy),
            "proof" | "proofs" => Some(Self::Proof),
            "receipt" | "receipts" => Some(Self::Receipt),
            "audit" | "audits" => Some(Self::Audit),
            "compliance" => Some(Self::Compliance),
            "tool" | "tools" => Some(Self::Tool),
            "protocol" | "protocols" => Some(Self::Protocol),
            "namespace" | "namespaces" | "ns" => Some(Self::Namespace),
            "capability" | "capabilities" | "cap" | "caps" => Some(Self::Capability),
            "runtime" => Some(Self::Runtime),
            "node" | "nodes" => Some(Self::Node),
            "cluster" | "clusters" => Some(Self::Cluster),
            _ => None,
        }
    }

    /// Get the namespace prefix for this noun type
    pub fn namespace_prefix(&self) -> &'static str {
        match self {
            Self::Memory => "/m/",
            Self::Knowledge => "/k/",
            Self::Asset => "/v/",
            Self::Tool => "/x/",
            Self::Agent => "/a/",
            Self::Namespace => "/s/",
            _ => "/",
        }
    }
}

impl std::fmt::Display for Noun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&str> for Noun {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap_or(Self::Agent)
    }
}

impl From<String> for Noun {
    fn from(s: String) -> Self {
        Self::from_str(&s).unwrap_or(Self::Agent)
    }
}
