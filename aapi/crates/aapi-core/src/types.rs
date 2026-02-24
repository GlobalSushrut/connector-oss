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

// =============================================================================
// Agent Memory Context — Cross-system linkage between AAPI actions and VAC memory
//
// Every AAPI action exists in the context of an agent's memory. These types
// connect the action layer (AAPI) to the memory layer (VAC), enabling:
// - Full provenance: action → decision → evidence → raw data
// - Multi-agent coordination with namespace isolation
// - Machine-world interaction logging for audit
// =============================================================================

/// Agent context — identifies the agent and its memory namespace
///
/// Attached to every VĀKYA to establish which agent is acting,
/// in which namespace, and with what memory session context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    /// Agent identifier (e.g., "agent:healthcare-bot-v2")
    pub agent_id: String,
    /// Agent type/role (e.g., "triage", "analyst", "executor")
    pub agent_role: Option<String>,
    /// Memory namespace for isolation (e.g., "org:hospital/team:er")
    pub namespace: String,
    /// Active session ID in VAC memory
    pub session_id: Option<String>,
    /// Pipeline ID grouping related actions
    pub pipeline_id: Option<String>,
    /// Parent agent ID (for delegated sub-agents)
    pub parent_agent_id: Option<String>,
    /// Model being used (e.g., "gpt-4o", "deepseek-chat")
    pub model: Option<String>,
    /// Agent framework (e.g., "langchain", "crewai", "autogen", "custom")
    pub framework: Option<String>,
}

/// Interaction log entry — records every machine-world interaction
///
/// Every API call, database query, file access, or external service
/// invocation by an agent is logged as an InteractionLog. This provides:
/// - Complete audit trail for regulatory compliance
/// - Cost tracking across LLM providers
/// - Performance monitoring and debugging
/// - Replay capability for incident investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionLog {
    /// Unique interaction ID
    pub interaction_id: String,
    /// Associated VĀKYA ID (if this interaction was part of an authorized action)
    pub vakya_id: Option<String>,
    /// Agent context
    pub agent_id: String,
    /// Interaction type
    pub interaction_type: InteractionType,
    /// Target service/resource
    pub target: String,
    /// HTTP method or operation type
    pub operation: String,
    /// Request payload (may be redacted for sensitive data)
    pub request_payload: Option<serde_json::Value>,
    /// Response payload (may be redacted)
    pub response_payload: Option<serde_json::Value>,
    /// Status (success, error, timeout)
    pub status: InteractionStatus,
    /// HTTP status code or service-specific code
    pub status_code: Option<i32>,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Token usage (for LLM interactions)
    pub tokens: Option<InteractionTokens>,
    /// Estimated cost in USD
    pub cost_usd: Option<f64>,
    /// Error details (if failed)
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: Timestamp,
    /// VAC MemPacket CID (if this interaction was stored as a memory packet)
    pub packet_cid: Option<String>,
    /// Trace context for distributed tracing
    pub trace: Option<TraceContext>,
}

/// Type of machine-world interaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InteractionType {
    /// LLM inference call (OpenAI, Anthropic, DeepSeek, etc.)
    LlmInference,
    /// Tool/function call
    ToolCall,
    /// Database query (SQL, NoSQL, vector DB)
    DatabaseQuery,
    /// HTTP API call
    HttpApi,
    /// File system operation
    FileSystem,
    /// Message queue publish/consume
    MessageQueue,
    /// Email/notification send
    Notification,
    /// Search engine query
    Search,
    /// Custom/other
    Custom,
}

/// Status of an interaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InteractionStatus {
    Success,
    Error,
    Timeout,
    RateLimited,
    Cancelled,
}

/// Token usage for LLM interactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionTokens {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub model: String,
    /// Cache hit tokens (for prompt caching)
    #[serde(default)]
    pub cached_tokens: u64,
}

/// Action record — complete documentation of an agent action end-to-end
///
/// This is the "receipt" that documents everything about an action:
/// what was intended, how it was authorized, what happened, and what evidence exists.
/// This is the unit of audit documentation — one ActionRecord per agent action.
///
/// Satisfies: EU AI Act Art. 12 (decision logging), HIPAA audit trail,
/// FINRA supervision records, FDA electronic records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecord {
    /// Unique action record ID
    pub record_id: String,

    // --- Intent ---
    /// What the agent intended to do (human-readable)
    pub intent: String,
    /// Action domain and verb (e.g., "ehr.update_allergy")
    pub action: String,
    /// Target resource
    pub target_resource: String,
    /// Reasoning chain (why this action was chosen)
    pub reasoning: Option<String>,
    /// Confidence in the decision (0.0 - 1.0)
    pub confidence: Option<f64>,

    // --- Authorization ---
    /// AAPI VĀKYA ID that authorized this action
    pub vakya_id: Option<String>,
    /// Actor who authorized
    pub authorized_by: Option<String>,
    /// Capability reference used
    pub capability_ref: Option<String>,
    /// Whether human approval was obtained
    #[serde(default)]
    pub human_approved: bool,
    /// Human approver ID
    pub approver_id: Option<String>,

    // --- Execution ---
    /// Agent that executed the action
    pub agent_id: String,
    /// Agent namespace
    pub namespace: String,
    /// Session ID during execution
    pub session_id: Option<String>,
    /// Pipeline ID
    pub pipeline_id: Option<String>,
    /// Execution status
    pub outcome: ActionOutcome,
    /// Error details (if failed)
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,

    // --- Evidence ---
    /// VAC MemPacket CIDs that document this action
    #[serde(default)]
    pub evidence_cids: Vec<String>,
    /// Input packet CID (what data was used)
    pub input_cid: Option<String>,
    /// Output packet CID (what was produced)
    pub output_cid: Option<String>,
    /// State snapshot CID (before/after state)
    pub state_snapshot_cid: Option<String>,
    /// Tool interaction CIDs
    #[serde(default)]
    pub tool_interaction_cids: Vec<String>,

    // --- Provenance ---
    /// Prolly tree root at time of action
    pub prolly_root: Option<String>,
    /// Merkle tree root at time of action
    pub merkle_root: Option<String>,
    /// Block number in VAC chain
    pub block_no: Option<u64>,

    // --- Compliance ---
    /// Applicable regulations
    #[serde(default)]
    pub regulations: Vec<String>,
    /// Data classification
    pub data_classification: Option<String>,
    /// Retention period in days
    #[serde(default)]
    pub retention_days: u64,
    /// Whether this action is reversible
    #[serde(default)]
    pub reversible: bool,

    // --- Timestamps ---
    /// When the action was initiated
    pub initiated_at: Timestamp,
    /// When the action completed
    pub completed_at: Option<Timestamp>,
}

/// Outcome of an agent action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    /// Action completed successfully
    Success,
    /// Action partially completed
    Partial,
    /// Action failed
    Failed,
    /// Action was denied by access control
    Denied,
    /// Action was rolled back
    RolledBack,
    /// Action is pending human approval
    PendingApproval,
    /// Action was cancelled
    Cancelled,
}

impl std::fmt::Display for ActionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionOutcome::Success => write!(f, "success"),
            ActionOutcome::Partial => write!(f, "partial"),
            ActionOutcome::Failed => write!(f, "failed"),
            ActionOutcome::Denied => write!(f, "denied"),
            ActionOutcome::RolledBack => write!(f, "rolled_back"),
            ActionOutcome::PendingApproval => write!(f, "pending_approval"),
            ActionOutcome::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[cfg(test)]
mod agent_context_tests {
    use super::*;

    #[test]
    fn test_agent_context_creation() {
        let ctx = AgentContext {
            agent_id: "agent:healthcare-bot".to_string(),
            agent_role: Some("triage".to_string()),
            namespace: "org:hospital/team:er".to_string(),
            session_id: Some("session:abc123".to_string()),
            pipeline_id: Some("pipeline:intake-001".to_string()),
            parent_agent_id: None,
            model: Some("gpt-4o".to_string()),
            framework: Some("langchain".to_string()),
        };

        assert_eq!(ctx.agent_id, "agent:healthcare-bot");
        assert_eq!(ctx.agent_role.as_deref(), Some("triage"));
        assert_eq!(ctx.namespace, "org:hospital/team:er");
    }

    #[test]
    fn test_interaction_log_llm() {
        let log = InteractionLog {
            interaction_id: "int:001".to_string(),
            vakya_id: Some("vakya:v-001".to_string()),
            agent_id: "agent:bot".to_string(),
            interaction_type: InteractionType::LlmInference,
            target: "api.openai.com".to_string(),
            operation: "chat.completions".to_string(),
            request_payload: Some(serde_json::json!({"model": "gpt-4o"})),
            response_payload: None,
            status: InteractionStatus::Success,
            status_code: Some(200),
            duration_ms: 1500,
            tokens: Some(InteractionTokens {
                prompt_tokens: 500,
                completion_tokens: 200,
                total_tokens: 700,
                model: "gpt-4o".to_string(),
                cached_tokens: 100,
            }),
            cost_usd: Some(0.0105),
            error: None,
            timestamp: Timestamp::now(),
            packet_cid: Some("bafy2bzace...".to_string()),
            trace: None,
        };

        assert_eq!(log.interaction_type, InteractionType::LlmInference);
        assert_eq!(log.status, InteractionStatus::Success);
        assert_eq!(log.tokens.as_ref().unwrap().total_tokens, 700);
        assert_eq!(log.tokens.as_ref().unwrap().cached_tokens, 100);
    }

    #[test]
    fn test_interaction_log_tool_call() {
        let log = InteractionLog {
            interaction_id: "int:002".to_string(),
            vakya_id: None,
            agent_id: "agent:bot".to_string(),
            interaction_type: InteractionType::DatabaseQuery,
            target: "postgres://ehr-db".to_string(),
            operation: "SELECT".to_string(),
            request_payload: Some(serde_json::json!({"query": "SELECT * FROM patients WHERE id = $1"})),
            response_payload: Some(serde_json::json!({"rows": 1})),
            status: InteractionStatus::Success,
            status_code: None,
            duration_ms: 12,
            tokens: None,
            cost_usd: None,
            error: None,
            timestamp: Timestamp::now(),
            packet_cid: None,
            trace: None,
        };

        assert_eq!(log.interaction_type, InteractionType::DatabaseQuery);
        assert_eq!(log.duration_ms, 12);
    }

    #[test]
    fn test_action_record_full_lifecycle() {
        let record = ActionRecord {
            record_id: "ar:001".to_string(),
            intent: "Update patient allergy record with penicillin allergy".to_string(),
            action: "ehr.update_allergy".to_string(),
            target_resource: "ehr:patient:P-44291".to_string(),
            reasoning: Some("LLM extracted allergy from clinical note with 0.95 confidence".to_string()),
            confidence: Some(0.95),
            vakya_id: Some("vakya:v-001".to_string()),
            authorized_by: Some("did:key:z6MkDoctor".to_string()),
            capability_ref: Some("cap:ehr-write".to_string()),
            human_approved: true,
            approver_id: Some("dr.smith@hospital.org".to_string()),
            agent_id: "agent:healthcare-bot".to_string(),
            namespace: "org:hospital/team:er".to_string(),
            session_id: Some("session:abc".to_string()),
            pipeline_id: Some("pipeline:intake-001".to_string()),
            outcome: ActionOutcome::Success,
            error: None,
            duration_ms: Some(2500),
            evidence_cids: vec!["bafy...input".to_string(), "bafy...extraction".to_string()],
            input_cid: Some("bafy...input".to_string()),
            output_cid: Some("bafy...output".to_string()),
            state_snapshot_cid: Some("bafy...snapshot".to_string()),
            tool_interaction_cids: vec!["bafy...llm-call".to_string()],
            prolly_root: Some("bafy...prolly".to_string()),
            merkle_root: Some("bafy...merkle".to_string()),
            block_no: Some(42),
            regulations: vec!["hipaa".to_string(), "eu_ai_act".to_string()],
            data_classification: Some("phi".to_string()),
            retention_days: 2555,
            reversible: true,
            initiated_at: Timestamp::now(),
            completed_at: Some(Timestamp::now()),
        };

        assert_eq!(record.outcome, ActionOutcome::Success);
        assert!(record.human_approved);
        assert_eq!(record.evidence_cids.len(), 2);
        assert_eq!(record.regulations.len(), 2);
        assert!(record.reversible);
    }

    #[test]
    fn test_action_outcome_display() {
        assert_eq!(ActionOutcome::Success.to_string(), "success");
        assert_eq!(ActionOutcome::Denied.to_string(), "denied");
        assert_eq!(ActionOutcome::RolledBack.to_string(), "rolled_back");
        assert_eq!(ActionOutcome::PendingApproval.to_string(), "pending_approval");
    }
}
