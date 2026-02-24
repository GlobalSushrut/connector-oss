//! VĀKYA - The Agentic Action Request (AAR) Schema
//!
//! VĀKYA is the core request envelope for AAPI, based on the 7 Vibhakti
//! (Sanskrit grammatical cases) that capture the complete semantics of an action.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::*;
use crate::error::{AapiError, AapiResult};

/// VĀKYA - The complete Agentic Action Request envelope
/// 
/// The 7 slots correspond to Sanskrit Vibhakti cases:
/// - V1 Kartā (कर्ता) - Nominative: WHO is acting
/// - V2 Karma (कर्म) - Accusative: WHAT is being acted upon
/// - V3 Kriyā (क्रिया) - The verb/action being performed
/// - V4 Karaṇa (करण) - Instrumental: BY WHAT MEANS
/// - V5 Sampradāna (सम्प्रदान) - Dative: FOR WHOM / recipient
/// - V6 Apādāna (अपादान) - Ablative: FROM WHERE / source
/// - V7 Adhikaraṇa (अधिकरण) - Locative: WHERE/WHEN/UNDER WHAT AUTHORITY
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vakya {
    /// Protocol version
    pub vakya_version: SemanticVersion,
    
    /// Unique idempotency key (client-generated)
    pub vakya_id: VakyaId,
    
    /// V1: Kartā - The actor/agent performing the action
    pub v1_karta: Karta,
    
    /// V2: Karma - The object/resource being acted upon
    pub v2_karma: Karma,
    
    /// V3: Kriyā - The action/verb being performed
    pub v3_kriya: Kriya,
    
    /// V4: Karaṇa - The means/instrument (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v4_karana: Option<Karana>,
    
    /// V5: Sampradāna - The recipient/beneficiary (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v5_sampradana: Option<Sampradana>,
    
    /// V6: Apādāna - The source/origin (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v6_apadana: Option<Apadana>,
    
    /// V7: Adhikaraṇa - The authority/context
    pub v7_adhikarana: Adhikarana,
    
    /// V8: Pratyaya (प्रत्यय) - Expected effect declaration (Phase 9f)
    /// Declares postconditions and verification criteria for the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v8_pratyaya: Option<Pratyaya>,
    
    /// Body type descriptor
    pub body_type: BodyType,
    
    /// Action-specific payload
    pub body: serde_json::Value,
    
    /// Metadata (timestamps, tracing, etc.)
    pub meta: VakyaMeta,
}

impl Vakya {
    /// Create a new VĀKYA builder
    pub fn builder() -> VakyaBuilder {
        VakyaBuilder::new()
    }

    /// Validate the VĀKYA structure
    pub fn validate(&self) -> AapiResult<()> {
        // Validate required fields
        if self.v1_karta.pid.0.is_empty() {
            return Err(AapiError::MissingField("v1_karta.pid".into()));
        }
        if self.v2_karma.rid.0.is_empty() {
            return Err(AapiError::MissingField("v2_karma.rid".into()));
        }
        if self.v3_kriya.action.is_empty() {
            return Err(AapiError::MissingField("v3_kriya.action".into()));
        }

        // Validate TTL if present
        if let Some(ref ttl) = self.v7_adhikarana.ttl {
            if ttl.expires_at.is_expired() {
                return Err(AapiError::TtlExpired {
                    expired_at: ttl.expires_at.to_string(),
                });
            }
        }

        // Validate budgets
        for budget in &self.v7_adhikarana.budgets {
            if budget.is_exhausted() {
                return Err(AapiError::BudgetExceeded {
                    resource: budget.resource.clone(),
                    used: budget.used,
                    limit: budget.limit,
                });
            }
        }

        Ok(())
    }
}

/// Unique identifier for a VĀKYA request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VakyaId(pub String);

impl VakyaId {
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Default for VakyaId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VakyaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// V1: Kartā - The actor performing the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Karta {
    /// Principal identifier (user ID, service account, agent ID)
    pub pid: PrincipalId,
    
    /// Role of the actor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    
    /// Realm/tenant the actor belongs to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    
    /// Key ID used for signing (for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    
    /// Actor type classification
    #[serde(default)]
    pub actor_type: ActorType,
    
    /// Delegation chain (if this action is delegated)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<DelegationHop>,
}

/// Type of actor performing the action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// Human user
    #[default]
    Human,
    /// AI agent
    Agent,
    /// Service/system account
    Service,
    /// Automated workflow
    Workflow,
}

/// A hop in the delegation chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationHop {
    /// Principal who delegated
    pub delegator: PrincipalId,
    /// Timestamp of delegation
    pub delegated_at: Timestamp,
    /// Reason for delegation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Capability attenuation applied at this hop
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attenuation: Option<CapabilityAttenuation>,
}

/// Capability attenuation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityAttenuation {
    /// Scopes removed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_scopes: Vec<String>,
    /// Budget reductions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reduced_budgets: Vec<Budget>,
    /// TTL reduction in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduced_ttl_ms: Option<u64>,
}

/// V2: Karma - The object being acted upon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Karma {
    /// Resource identifier
    pub rid: ResourceId,
    
    /// Resource kind/type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    
    /// Namespace the resource belongs to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ns: Option<Namespace>,
    
    /// Resource version (for optimistic concurrency)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    
    /// Resource labels for filtering
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub labels: std::collections::HashMap<String, String>,
}

/// V3: Kriyā - The action being performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kriya {
    /// Canonical action name (domain.verb format)
    pub action: String,
    
    /// Domain/category of the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    
    /// Verb/operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    
    /// Expected effect bucket
    #[serde(default)]
    pub expected_effect: EffectBucket,
    
    /// Whether this action is idempotent
    #[serde(default)]
    pub idempotent: bool,
}

impl Kriya {
    /// Create a new Kriya with domain.verb format
    pub fn new(domain: impl Into<String>, verb: impl Into<String>) -> Self {
        let domain = domain.into();
        let verb = verb.into();
        Self {
            action: format!("{}.{}", domain, verb),
            domain: Some(domain),
            verb: Some(verb),
            expected_effect: EffectBucket::None,
            idempotent: false,
        }
    }

    /// Parse action string into domain and verb
    pub fn parse_action(&self) -> Option<(&str, &str)> {
        self.action.split_once('.')
    }

    // =========================================================================
    // Phase 9f: 15 new Kriya verb constructors
    // =========================================================================

    // --- Delegation verbs ---
    /// delegate.capability — delegate a capability to another agent
    pub fn delegate_capability() -> Self { Self::new("delegate", "capability") }
    /// delegate.revoke — revoke a previously delegated capability
    pub fn delegate_revoke() -> Self { Self::new("delegate", "revoke") }
    /// delegate.attenuate — narrow an existing delegation
    pub fn delegate_attenuate() -> Self { Self::new("delegate", "attenuate") }

    // --- Port communication verbs ---
    /// port.create — create a typed communication port
    pub fn port_create() -> Self { Self::new("port", "create") }
    /// port.send — send a message through a port
    pub fn port_send() -> Self { Self::new("port", "send") }
    /// port.receive — receive a message from a port
    pub fn port_receive() -> Self { Self::new("port", "receive") }
    /// port.close — close a port and drain its buffer
    pub fn port_close() -> Self { Self::new("port", "close") }

    // --- Pipeline coordination verbs ---
    /// pipeline.handoff — hand off execution to the next agent in a pipeline
    pub fn pipeline_handoff() -> Self { Self::new("pipeline", "handoff") }
    /// pipeline.fork — fork execution into parallel branches
    pub fn pipeline_fork() -> Self { Self::new("pipeline", "fork") }
    /// pipeline.join — join parallel branches back together
    pub fn pipeline_join() -> Self { Self::new("pipeline", "join") }

    // --- Memory coordination verbs ---
    /// memory.mount — mount a namespace for cross-agent memory sharing
    pub fn memory_mount() -> Self { Self::new("memory", "mount") }
    /// memory.seal — seal a memory region (make immutable)
    pub fn memory_seal() -> Self { Self::new("memory", "seal") }
    /// memory.share — share a memory packet via port
    pub fn memory_share() -> Self { Self::new("memory", "share") }

    // --- Execution control verbs ---
    /// exec.suspend — suspend an agent's execution
    pub fn exec_suspend() -> Self { Self::new("exec", "suspend") }
    /// exec.checkpoint — checkpoint execution state for recovery
    pub fn exec_checkpoint() -> Self { Self::new("exec", "checkpoint") }
}

/// V4: Karaṇa - The means/instrument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Karana {
    /// Transport/protocol used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    
    /// Adapter to use for execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    
    /// Tool/function being invoked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    
    /// Additional instrument metadata
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

/// V5: Sampradāna - The recipient/beneficiary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sampradana {
    /// Recipient principal
    pub recipient: PrincipalId,
    
    /// Recipient type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_type: Option<String>,
    
    /// Delivery preferences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryPreference>,
}

/// Delivery preferences for recipients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryPreference {
    /// Delivery channel (email, webhook, queue, etc.)
    pub channel: String,
    /// Channel-specific address
    pub address: String,
    /// Delivery options
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub options: std::collections::HashMap<String, serde_json::Value>,
}

/// V6: Apādāna - The source/origin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Apadana {
    /// Source resource
    pub source: ResourceId,
    
    /// Source type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    
    /// Source location/URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// V7: Adhikaraṇa - The authority/context (enhanced Phase 9f)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Adhikarana {
    /// Capability token reference or inline token
    pub cap: CapabilityRef,
    
    /// Policy reference for additional rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    
    /// Time-to-live constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<TtlConstraint>,
    
    /// Budget constraints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budgets: Vec<Budget>,
    
    /// Approval lane for human-in-the-loop
    #[serde(default)]
    pub approval_lane: ApprovalLane,
    
    /// Allowed scopes for this action
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    
    /// Context/environment constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<AuthorityContext>,

    // --- Phase 9f enhancements ---

    /// Delegation proof chain CID (UCAN-compatible)
    /// References a DelegationChain in the VAC kernel that authorizes this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_chain_cid: Option<String>,

    /// Execution constraints for kernel enforcement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_constraints: Option<ExecutionConstraints>,

    /// Port ID through which this action is being communicated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_id: Option<String>,

    /// Required agent phase for this action to execute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_phase: Option<String>,

    /// Required agent role for this action to execute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_role: Option<String>,
}

/// Execution constraints for kernel enforcement (Phase 9f)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConstraints {
    /// Maximum tokens this action may consume
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Maximum cost in USD this action may incur
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,
    /// Maximum number of tool calls this action may make
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tool_calls: Option<u32>,
    /// Maximum execution time in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_execution_ms: Option<u64>,
    /// Data classification required for tools used (e.g., "phi", "pii", "public")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_classification: Option<String>,
    /// Whether this action requires human approval before execution
    #[serde(default)]
    pub requires_approval: bool,
}

/// V8: Pratyaya (प्रत्यय) - Expected effect declaration (Phase 9f)
///
/// Declares what the action is expected to produce, enabling:
/// - Pre-flight validation (can this effect be achieved?)
/// - Post-flight verification (was the expected effect achieved?)
/// - Compliance auditing (was the declared effect the actual effect?)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pratyaya {
    /// Expected postconditions (assertions that should be true after action)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub postconditions: Vec<Postcondition>,

    /// Verification method for confirming the effect
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationMethod>,

    /// Rollback strategy if postconditions are not met
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<RollbackStrategy>,

    /// Maximum acceptable latency for the effect (ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_latency_ms: Option<u64>,

    /// Whether partial success is acceptable
    #[serde(default)]
    pub allow_partial: bool,
}

/// A postcondition assertion for Pratyaya
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Postcondition {
    /// Human-readable description
    pub description: String,
    /// Machine-checkable assertion (JSONPath, CEL expression, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion: Option<String>,
    /// Assertion language (jsonpath, cel, regex, custom)
    #[serde(default = "default_assertion_lang")]
    pub lang: String,
    /// Whether this postcondition is required or advisory
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_assertion_lang() -> String { "jsonpath".to_string() }
fn default_true() -> bool { true }

/// Verification method for confirming an effect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationMethod {
    /// Poll a resource until postconditions are met
    Poll { resource: String, interval_ms: u64, max_attempts: u32 },
    /// Wait for a webhook/event callback
    Callback { event_type: String, timeout_ms: u64 },
    /// Verify by reading a specific CID from the content-addressed store
    CidCheck { expected_cid: String },
    /// No verification needed (fire-and-forget)
    None,
}

/// Rollback strategy if postconditions fail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackStrategy {
    /// Automatically reverse the action
    AutoReverse,
    /// Notify a human for manual intervention
    HumanReview { escalation_channel: String },
    /// Retry the action up to N times
    Retry { max_retries: u32, backoff_ms: u64 },
    /// Accept the failure and log it
    AcceptFailure,
}

/// Reference to a capability token
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CapabilityRef {
    /// Reference to an external capability
    Reference { cap_ref: String },
    /// Inline capability token
    Inline(CapabilityToken),
}

/// Inline capability token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Token ID
    pub token_id: String,
    /// Issuer of the token
    pub issuer: PrincipalId,
    /// Subject (who the token is for)
    pub subject: PrincipalId,
    /// Allowed actions (glob patterns)
    pub actions: Vec<String>,
    /// Allowed resources (glob patterns)
    pub resources: Vec<String>,
    /// Token expiration
    pub expires_at: Timestamp,
    /// Token signature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Caveats (Macaroon-style restrictions)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
}

/// Caveat for capability attenuation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caveat {
    /// Caveat type
    pub caveat_type: String,
    /// Caveat value
    pub value: serde_json::Value,
}

/// TTL constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlConstraint {
    /// Absolute expiration time
    pub expires_at: Timestamp,
    /// Maximum duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_ms: Option<u64>,
}

/// Authority context constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityContext {
    /// Required environment (production, staging, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Geographic constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoConstraint>,
    /// Time window constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
}

/// Geographic constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConstraint {
    /// Allowed regions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_regions: Vec<String>,
    /// Denied regions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_regions: Vec<String>,
}

/// Time window constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start time (inclusive)
    pub start: Timestamp,
    /// End time (exclusive)
    pub end: Timestamp,
    /// Allowed days of week (0=Sunday, 6=Saturday)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_days: Vec<u8>,
    /// Timezone for day calculations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Body type descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyType {
    /// Schema name
    pub name: String,
    /// Schema version
    pub version: SemanticVersion,
    /// Content type
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

fn default_content_type() -> String {
    "application/json".to_string()
}

/// VĀKYA metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VakyaMeta {
    /// Creation timestamp
    pub created_at: Timestamp,
    
    /// Trace context for distributed tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceContext>,
    
    /// Reasoning/justification for the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hetu: Option<Hetu>,
    
    /// Client information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientInfo>,
    
    /// VAC memory linkage — connects this action to VAC memory packets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vac_ref: Option<VacRef>,
    
    /// Compliance context — regulatory metadata for audit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ComplianceContext>,
    
    /// Agent context — identifies the agent, namespace, session, and model
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_context: Option<crate::types::AgentContext>,
    
    /// Custom extensions
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
}

/// VAC memory reference — links an AAPI action to VAC memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VacRef {
    /// CID of the VAC event that triggered this action
    pub event_cid: Option<String>,
    /// CIDs of VAC MemPackets that serve as evidence
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packet_cids: Vec<String>,
    /// Pipeline ID grouping related packets
    pub pipeline_id: Option<String>,
    /// Block number in the VAC chain where evidence is committed
    pub block_no: Option<u64>,
    /// Prolly tree root CID at time of action
    pub prolly_root: Option<String>,
}

/// Compliance context — regulatory metadata for audit trails
///
/// Satisfies: EU AI Act Art. 12, HIPAA §164.312, FINRA Rule 3110,
/// FDA 21 CFR Part 11
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceContext {
    /// Applicable regulations (e.g., "HIPAA", "EU_AI_ACT", "FINRA")
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regulations: Vec<String>,
    /// Data classification level (e.g., "PHI", "PII", "PUBLIC")
    pub data_classification: Option<String>,
    /// Whether human review is required before execution
    #[serde(default)]
    pub requires_human_review: bool,
    /// Reason human review is required
    pub review_reason: Option<String>,
    /// Retention period in days (0 = indefinite)
    #[serde(default)]
    pub retention_days: u64,
    /// Jurisdiction (e.g., "US", "EU", "UK")
    pub jurisdiction: Option<String>,
}

/// Hetu - Reasoning/justification for the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hetu {
    /// Human-readable reason
    pub reason: String,
    /// Reasoning chain (for AI agents)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<ReasoningStep>,
    /// Confidence score (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// VAC evidence CIDs that support this reasoning (provenance linkage)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_cids: Vec<String>,
}

/// A step in the reasoning chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    /// Step description
    pub step: String,
    /// Evidence supporting this step
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// Client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client name/identifier
    pub name: String,
    /// Client version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// SDK version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
}

/// Builder for constructing VĀKYA requests
#[derive(Debug, Default)]
pub struct VakyaBuilder {
    karta: Option<Karta>,
    karma: Option<Karma>,
    kriya: Option<Kriya>,
    karana: Option<Karana>,
    sampradana: Option<Sampradana>,
    apadana: Option<Apadana>,
    adhikarana: Option<Adhikarana>,
    body_type: Option<BodyType>,
    body: Option<serde_json::Value>,
    trace: Option<TraceContext>,
    hetu: Option<Hetu>,
}

impl VakyaBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn karta(mut self, karta: Karta) -> Self {
        self.karta = Some(karta);
        self
    }

    pub fn karma(mut self, karma: Karma) -> Self {
        self.karma = Some(karma);
        self
    }

    pub fn kriya(mut self, kriya: Kriya) -> Self {
        self.kriya = Some(kriya);
        self
    }

    pub fn karana(mut self, karana: Karana) -> Self {
        self.karana = Some(karana);
        self
    }

    pub fn sampradana(mut self, sampradana: Sampradana) -> Self {
        self.sampradana = Some(sampradana);
        self
    }

    pub fn apadana(mut self, apadana: Apadana) -> Self {
        self.apadana = Some(apadana);
        self
    }

    pub fn adhikarana(mut self, adhikarana: Adhikarana) -> Self {
        self.adhikarana = Some(adhikarana);
        self
    }

    pub fn body_type(mut self, body_type: BodyType) -> Self {
        self.body_type = Some(body_type);
        self
    }

    pub fn body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }

    pub fn trace(mut self, trace: TraceContext) -> Self {
        self.trace = Some(trace);
        self
    }

    pub fn hetu(mut self, hetu: Hetu) -> Self {
        self.hetu = Some(hetu);
        self
    }

    pub fn build(self) -> AapiResult<Vakya> {
        let karta = self.karta.ok_or_else(|| AapiError::MissingField("karta".into()))?;
        let karma = self.karma.ok_or_else(|| AapiError::MissingField("karma".into()))?;
        let kriya = self.kriya.ok_or_else(|| AapiError::MissingField("kriya".into()))?;
        let adhikarana = self.adhikarana.ok_or_else(|| AapiError::MissingField("adhikarana".into()))?;

        let body_type = self.body_type.unwrap_or_else(|| BodyType {
            name: "generic".to_string(),
            version: SemanticVersion::v0_1_0(),
            content_type: "application/json".to_string(),
        });

        let body = self.body.unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let vakya = Vakya {
            vakya_version: SemanticVersion::v0_1_0(),
            vakya_id: VakyaId::new(),
            v1_karta: karta,
            v2_karma: karma,
            v3_kriya: kriya,
            v4_karana: self.karana,
            v5_sampradana: self.sampradana,
            v6_apadana: self.apadana,
            v7_adhikarana: adhikarana,
            v8_pratyaya: None,
            body_type,
            body,
            meta: VakyaMeta {
                created_at: Timestamp::now(),
                trace: self.trace,
                hetu: self.hetu,
                client: None,
                vac_ref: None,
                compliance: None,
                agent_context: None,
                extensions: std::collections::HashMap::new(),
            },
        };

        vakya.validate()?;
        Ok(vakya)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_adhikarana() -> Adhikarana {
        Adhikarana {
            cap: CapabilityRef::Reference { cap_ref: "cap:test:123".to_string() },
            policy_ref: None,
            ttl: Some(TtlConstraint {
                expires_at: Timestamp(chrono::Utc::now() + Duration::hours(1)),
                max_duration_ms: None,
            }),
            budgets: vec![],
            approval_lane: ApprovalLane::None,
            scopes: vec!["read".to_string(), "write".to_string()],
            context: None,
            delegation_chain_cid: None,
            execution_constraints: None,
            port_id: None,
            required_phase: None,
            required_role: None,
        }
    }

    #[test]
    fn test_vakya_builder() {
        let vakya = Vakya::builder()
            .karta(Karta {
                pid: PrincipalId::new("user:alice"),
                role: Some("admin".to_string()),
                realm: Some("example.com".to_string()),
                key_id: None,
                actor_type: ActorType::Human,
                delegation_chain: vec![],
            })
            .karma(Karma {
                rid: ResourceId::new("file:/data/report.pdf"),
                kind: Some("file".to_string()),
                ns: Some(Namespace::new("documents")),
                version: None,
                labels: std::collections::HashMap::new(),
            })
            .kriya(Kriya::new("file", "read"))
            .adhikarana(create_test_adhikarana())
            .build();

        assert!(vakya.is_ok());
        let vakya = vakya.unwrap();
        assert_eq!(vakya.v3_kriya.action, "file.read");
    }

    #[test]
    fn test_vakya_validation_missing_pid() {
        let result = Vakya::builder()
            .karta(Karta {
                pid: PrincipalId::new(""),
                role: None,
                realm: None,
                key_id: None,
                actor_type: ActorType::Human,
                delegation_chain: vec![],
            })
            .karma(Karma {
                rid: ResourceId::new("test"),
                kind: None,
                ns: None,
                version: None,
                labels: std::collections::HashMap::new(),
            })
            .kriya(Kriya::new("test", "action"))
            .adhikarana(create_test_adhikarana())
            .build();

        assert!(matches!(result, Err(AapiError::MissingField(_))));
    }

    #[test]
    fn test_kriya_parse_action() {
        let kriya = Kriya::new("database", "query");
        assert_eq!(kriya.parse_action(), Some(("database", "query")));
    }
}
