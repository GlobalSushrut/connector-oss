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

/// V7: Adhikaraṇa - The authority/context
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
    
    /// Custom extensions
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
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
            body_type,
            body,
            meta: VakyaMeta {
                created_at: Timestamp::now(),
                trace: self.trace,
                hetu: self.hetu,
                client: None,
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
