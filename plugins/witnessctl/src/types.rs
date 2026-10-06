use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Session ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub upstream: String,
    pub role: String,
    pub agent_pid: Option<String>,
    pub mode: SessionMode,
    pub status: SessionStatus,
    pub frameworks: Vec<ComplianceFramework>,
    pub policy: SessionPolicy,
    pub session_token: String,
    pub chain_head_hmac: Option<String>,
    pub receipt_seq: i64,
    pub total_calls: i64,
    pub total_blocked: i64,
    pub total_pii_hits: i64,
    pub cost_usd: f64,
    pub proof_id: Option<String>,
    pub bundle_path: Option<String>,
    pub sealed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Proxy,
    SdkShim,
    Webhook,
}

impl std::fmt::Display for SessionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionMode::Proxy => write!(f, "proxy"),
            SessionMode::SdkShim => write!(f, "sdk_shim"),
            SessionMode::Webhook => write!(f, "webhook"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Locked,
    Quarantined,
    Sealed,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "active"),
            SessionStatus::Locked => write!(f, "locked"),
            SessionStatus::Quarantined => write!(f, "quarantined"),
            SessionStatus::Sealed => write!(f, "sealed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Hipaa,
    Soc2,
    Gdpr,
    EuAiAct,
    Iso27001,
    PciDss,
    Nist80053,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceFramework::Hipaa => write!(f, "hipaa"),
            ComplianceFramework::Soc2 => write!(f, "soc2"),
            ComplianceFramework::Gdpr => write!(f, "gdpr"),
            ComplianceFramework::EuAiAct => write!(f, "eu_ai_act"),
            ComplianceFramework::Iso27001 => write!(f, "iso_27001"),
            ComplianceFramework::PciDss => write!(f, "pci_dss"),
            ComplianceFramework::Nist80053 => write!(f, "nist_800_53"),
        }
    }
}

impl ComplianceFramework {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "hipaa" => Some(Self::Hipaa),
            "soc2" | "soc2_type2" => Some(Self::Soc2),
            "gdpr" => Some(Self::Gdpr),
            "eu_ai_act" | "eu-ai-act" => Some(Self::EuAiAct),
            "iso_27001" | "iso27001" | "iso-27001" => Some(Self::Iso27001),
            "pci_dss" | "pcidss" | "pci-dss" => Some(Self::PciDss),
            "nist_800_53" | "nist80053" | "nist-800-53" => Some(Self::Nist80053),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionPolicy {
    pub clearance: Option<i32>,
    pub denied_hosts: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub pii_action: PiiAction,
    pub require_admission: bool,
    pub risk_level: Option<String>,
    pub erasure_flag: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    #[default]
    LogAndAllow,
    Block,
    Redact,
}

// ── Capture (one per API call) ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    pub id: Uuid,
    pub session_id: Uuid,
    pub seq: i64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub request_hash: String,
    pub response_hash: Option<String>,
    pub response_status: Option<i32>,
    pub latency_ms: Option<i32>,
    pub admission_verdict: AdmissionVerdict,
    pub admission_reason: Option<String>,
    pub firewall_blocked: bool,
    pub firewall_checked: bool,
    pub firewall_status: Option<String>,
    pub firewall_reason: Option<String>,
    pub pii_in_request: bool,
    pub pii_in_response: bool,
    pub schema_drift: bool,
    pub drift_fields: Vec<String>,
    pub receipt_id: Option<Uuid>,
    pub receipt_hmac: Option<String>,
    pub cost_usd: Option<f64>,
    /// Forensic flow id from `X-Connector-FNI` / `x-connector-flow-id` when present (P6.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fni_flow_id: Option<String>,
    /// `unverified` until CFNI verify; never decorative green (P6.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fni_verify_status: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionVerdict {
    Allow,
    Deny,
    Hold,
}

impl std::fmt::Display for AdmissionVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionVerdict::Allow => write!(f, "allow"),
            AdmissionVerdict::Deny => write!(f, "deny"),
            AdmissionVerdict::Hold => write!(f, "hold"),
        }
    }
}

// ── Receipt (HMAC-chained) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub id: Uuid,
    pub session_id: Uuid,
    pub capture_id: Option<Uuid>,
    pub event_type: String,
    pub seq: i64,
    pub payload: serde_json::Value,
    pub hmac: String,
    pub prev_hmac: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ── PII hit ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiHit {
    pub id: Uuid,
    pub session_id: Uuid,
    pub capture_id: Uuid,
    pub location: String,
    pub field_path: String,
    pub pii_type: PiiType,
    pub action: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    Email,
    Phone,
    Ssn,
    CreditCard,
    Phi,
    IpAddress,
    ApiKey,
    AwsKey,
    Password,
    Generic,
}

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiType::Email => write!(f, "email"),
            PiiType::Phone => write!(f, "phone"),
            PiiType::Ssn => write!(f, "ssn"),
            PiiType::CreditCard => write!(f, "credit_card"),
            PiiType::Phi => write!(f, "phi"),
            PiiType::IpAddress => write!(f, "ip_address"),
            PiiType::ApiKey => write!(f, "api_key"),
            PiiType::AwsKey => write!(f, "aws_key"),
            PiiType::Password => write!(f, "password"),
            PiiType::Generic => write!(f, "generic"),
        }
    }
}

// ── Schema snapshot ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaSnapshot {
    pub id: Uuid,
    pub session_id: Uuid,
    pub host: String,
    pub path: String,
    pub method: String,
    pub schema_version: i32,
    pub request_schema: serde_json::Value,
    pub response_schema: serde_json::Value,
    pub status_codes: Vec<i32>,
    pub drift_log: Vec<DriftEvent>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    pub drift_type: String,
    pub field_path: String,
    pub from_type: Option<String>,
    pub to_type: Option<String>,
    pub detected_at: DateTime<Utc>,
}

// ── Compliance verdict ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceVerdict {
    pub id: Uuid,
    pub session_id: Uuid,
    pub framework: String,
    pub passed: bool,
    pub score: i32,
    pub controls: serde_json::Value,
    pub failed_controls: Vec<String>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualAttestation {
    pub id: Uuid,
    pub session_id: Uuid,
    pub control_name: String,
    pub evidence_url: String,
    pub attestor: String,
    pub attestor_subject: Option<String>,
    pub attestor_token_jti: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ── Decision Pentest Report types ────────────────────────────────────────────

/// A single step in a dehallucination chain produced by Connector OS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehallucinationChainStep {
    /// 0-indexed step number in the chain.
    pub step: usize,
    /// Human-readable phase name (e.g. "prompt_grounding", "policy_gate", "response_validation").
    pub phase: String,
    /// Grounding / hallucination risk score for this step, 0.0 (clean) – 1.0 (high risk).
    pub risk_score: f64,
    /// Whether this step flagged a potential hallucination.
    pub flagged: bool,
    /// Human-readable reason or evidence for the flag.
    pub reason: Option<String>,
    /// Connector-side stable chain step id for cross-run comparison.
    pub step_id: Option<String>,
}

/// A single bin in a heatmap (either dehallucination or knot/diversion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapBin {
    pub label: String,
    pub value: f64,
    pub flagged: bool,
}

/// Connector-computed knot diversion report for one decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnotDiversionReport {
    /// Overall knot/diversion score, 0.0 – 1.0.
    pub score: f64,
    /// Confidence band for the score, 0.0 – 1.0.
    pub confidence: Option<f64>,
    /// Whether the decision materially diverged from intended routing.
    pub diverted: bool,
    /// Key factors that contributed to the diversion score.
    pub factors: Vec<String>,
    /// Heatmap bins aligned with chain steps.
    pub heatmap: Vec<HeatmapBin>,
}

/// One PII component that participated in a decision, as reported by Connector OS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDecisionComponent {
    /// Connector-assigned component id.
    pub component_id: String,
    /// Semantic type of the PII.
    pub pii_type: String,
    /// Which part of the decision this appeared in.
    pub location: String,
    /// Action taken on this component (tokenized, redacted, blocked, allowed).
    pub action: String,
    /// Tokenization ID if the field was vaulted/surrogate-replaced (else None).
    pub tokenization_id: Option<String>,
}

/// One step in a tokenization trace, showing how a private datum moved through the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizationTraceStep {
    /// Connector-issued stable tokenization ID (surrogate / vault reference).
    pub token_id: String,
    /// The step in execution this token appeared in.
    pub step: usize,
    /// Phase label matching chain steps where possible.
    pub phase: String,
    /// What happened at this step (e.g. "replaced_with_surrogate", "decrypted_for_policy", "forwarded_as_token").
    pub action: String,
    /// Whether the original private value was exposed at this step.
    pub private_data_exposed: bool,
}

/// A node in the mini pentest graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentestGraphNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub risk_score: f64,
    pub flagged: bool,
}

/// An edge in the mini pentest graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentestGraphEdge {
    pub from: String,
    pub to: String,
    pub label: Option<String>,
}

/// Compact pentest graph for a single decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionPentestMiniGraph {
    pub nodes: Vec<PentestGraphNode>,
    pub edges: Vec<PentestGraphEdge>,
}

/// Per-decision pentest report as assembled by WitnessCtl from Connector OS data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionPentestReport {
    pub session_id: uuid::Uuid,
    /// TraceTramp/Connector trace_id that identifies the decision.
    pub trace_id: String,
    /// Connector-side request_id.
    pub request_id: Option<String>,
    /// WitnessCtl capture_id this decision maps to.
    pub capture_id: Option<uuid::Uuid>,

    /// Dehallucination chain steps.
    pub dehallucination_chain: Vec<DehallucinationChainStep>,
    /// Heatmap aligned with dehallucination steps.
    pub dehallucination_heatmap: Vec<HeatmapBin>,

    /// Knot diversion report.
    pub knot_diversion: KnotDiversionReport,

    /// PII components involved in this decision.
    pub pii_components: Vec<PiiDecisionComponent>,
    /// Ordered tokenization ID trace.
    pub tokenization_trace: Vec<TokenizationTraceStep>,

    /// Mini pentest graph.
    pub pentest_graph: DecisionPentestMiniGraph,

    /// Combined stability verdict: "stable", "suspect", or "infected".
    pub stability_verdict: String,
    /// SHA-256 over normalized Connector OS payload for memory-infection auditing.
    pub payload_hash: String,
    /// Whether Connector OS data was available (false means partial report from WitnessCtl-only signals).
    pub connector_available: bool,

    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Summary fields shown per-decision in list views (no full chain/heatmap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionPentestSummary {
    pub trace_id: String,
    pub capture_id: Option<uuid::Uuid>,
    pub seq: Option<i64>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub dehallucination_step_count: usize,
    pub dehallucination_chain_flagged: bool,
    pub knot_score: f64,
    pub knot_diverted: bool,
    pub pii_component_count: usize,
    pub tokenization_count: usize,
    pub stability_verdict: String,
    pub connector_available: bool,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

// ── API request/response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct OpenSessionRequest {
    pub upstream: String,
    pub role: String,
    pub mode: Option<SessionMode>,
    pub frameworks: Option<Vec<String>>,
    pub policy: Option<SessionPolicy>,
}

#[derive(Debug, Serialize)]
pub struct OpenSessionResponse {
    pub session_id: Uuid,
    pub agent_pid: Option<String>,
    pub session_token: String,
    pub proxy_url: String,
    pub proxy_header: String,
    pub receipt_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    pub session_id: Uuid,
    pub request: RawRequest,
    pub response: Option<RawResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ManualAttestRequest {
    pub control_name: String,
    pub evidence_url: String,
    pub attestor: String,
    pub attestor_token: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawRequest {
    pub method: String,
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<String>,
    pub timestamp_ms: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawResponse {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<String>,
    pub latency_ms: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct CaptureResponse {
    pub capture_id: Uuid,
    pub receipt_id: Uuid,
    pub seq: i64,
    pub admission_verdict: AdmissionVerdict,
    pub firewall_blocked: bool,
    pub pii_in_request: bool,
    pub pii_in_response: bool,
    pub schema_drift: bool,
    pub forwarded: bool,
    pub response: Option<RawResponse>,
    pub latency_ms: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct SealResponse {
    pub session_id: Uuid,
    pub proof_id: String,
    pub bundle_path: String,
    pub chain_verified: bool,
    pub proof_source: String,
    pub warning: Option<String>,
    pub receipt_count: i64,
    pub total_calls: i64,
    pub pii_hits: i64,
    pub compliance_pass: bool,
    pub compliance_verdicts: std::collections::HashMap<String, bool>,
    pub cost_usd: f64,
}

#[derive(Debug, Serialize)]
pub struct SessionStats {
    pub session_id: Uuid,
    pub upstream: String,
    pub role: String,
    pub status: SessionStatus,
    pub total_calls: i64,
    pub total_blocked: i64,
    pub total_pii_hits: i64,
    pub cost_usd: f64,
    pub receipt_seq: i64,
    pub created_at: DateTime<Utc>,
}
