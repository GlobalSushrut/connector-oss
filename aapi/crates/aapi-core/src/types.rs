//! Common types used across AAPI

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Semantic version for protocol versioning
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemanticVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    pub fn v0_1_0() -> Self {
        Self::new(0, 1, 0)
    }
}

impl std::fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Default for SemanticVersion {
    fn default() -> Self {
        Self::v0_1_0()
    }
}

/// Principal identifier for actors in the system
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Resource identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId(pub String);

impl ResourceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Namespace for organizing resources and actions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace(pub String);

impl Namespace {
    pub fn new(ns: impl Into<String>) -> Self {
        Self(ns.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this namespace contains another namespace
    pub fn contains(&self, other: &Namespace) -> bool {
        other.0.starts_with(&self.0)
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trace context for distributed tracing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceContext {
    /// Unique trace ID spanning multiple requests
    pub trace_id: String,
    /// Span ID for this specific operation
    pub span_id: String,
    /// Parent span ID if this is a child operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    /// Sampling decision
    #[serde(default)]
    pub sampled: bool,
}

impl TraceContext {
    pub fn new() -> Self {
        Self {
            trace_id: Uuid::new_v4().to_string(),
            span_id: Uuid::new_v4().to_string(),
            parent_span_id: None,
            sampled: true,
        }
    }

    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: Uuid::new_v4().to_string(),
            parent_span_id: Some(self.span_id.clone()),
            sampled: self.sampled,
        }
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamp with timezone (always UTC)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn from_millis(millis: i64) -> Self {
        Self(DateTime::from_timestamp_millis(millis).unwrap_or_else(Utc::now))
    }

    pub fn as_millis(&self) -> i64 {
        self.0.timestamp_millis()
    }

    pub fn is_expired(&self) -> bool {
        self.0 < Utc::now()
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

/// Budget tracking for resource limits
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    /// Budget identifier
    pub id: String,
    /// Resource type (e.g., "api_calls", "tokens", "cost_usd")
    pub resource: String,
    /// Maximum allowed value
    pub limit: u64,
    /// Currently used value
    #[serde(default)]
    pub used: u64,
    /// Reset period in seconds (0 = never resets)
    #[serde(default)]
    pub reset_period_secs: u64,
    /// Last reset timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reset: Option<Timestamp>,
}

impl Budget {
    pub fn new(id: impl Into<String>, resource: impl Into<String>, limit: u64) -> Self {
        Self {
            id: id.into(),
            resource: resource.into(),
            limit,
            used: 0,
            reset_period_secs: 0,
            last_reset: None,
        }
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn is_exhausted(&self) -> bool {
        self.used >= self.limit
    }

    pub fn consume(&mut self, amount: u64) -> bool {
        if self.used + amount <= self.limit {
            self.used += amount;
            true
        } else {
            false
        }
    }
}

/// Approval lane for human-in-the-loop workflows
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLane {
    /// No approval required
    None,
    /// Async approval (can proceed, but may be revoked)
    Async,
    /// Sync approval required before execution
    Sync,
    /// Multi-party approval required
    MultiParty { required: u32, approvers: Vec<PrincipalId> },
}

impl Default for ApprovalLane {
    fn default() -> Self {
        Self::None
    }
}

/// Effect bucket types for categorizing action effects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectBucket {
    /// No effect (pure computation)
    #[default]
    None,
    /// State was created
    Create,
    /// State was read (no mutation)
    Read,
    /// State was updated
    Update,
    /// State was deleted
    Delete,
    /// External side effect (email, API call, etc.)
    External,
}

impl EffectBucket {
    pub fn is_mutating(&self) -> bool {
        matches!(self, Self::Create | Self::Update | Self::Delete | Self::External)
    }

    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::Read | Self::None)
    }
}

/// Hash algorithm used for content hashing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

/// Content hash with algorithm identifier
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentHash {
    pub algorithm: HashAlgorithm,
    pub value: String,
}

impl ContentHash {
    pub fn sha256(value: impl Into<String>) -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            value: value.into(),
        }
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}:{}", self.algorithm, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_version() {
        let v = SemanticVersion::v0_1_0();
        assert_eq!(v.to_string(), "0.1.0");
    }

    #[test]
    fn test_namespace_contains() {
        let parent = Namespace::new("org.example");
        let child = Namespace::new("org.example.service");
        let other = Namespace::new("com.other");

        assert!(parent.contains(&child));
        assert!(!parent.contains(&other));
    }

    #[test]
    fn test_budget_consume() {
        let mut budget = Budget::new("test", "api_calls", 100);
        assert!(budget.consume(50));
        assert_eq!(budget.remaining(), 50);
        assert!(!budget.consume(60));
        assert_eq!(budget.remaining(), 50);
    }

    #[test]
    fn test_trace_context_child() {
        let parent = TraceContext::new();
        let child = parent.child();
        
        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }
}
