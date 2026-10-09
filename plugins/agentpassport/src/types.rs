//! Domain types for AgentPassport.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use validator::Validate;

// ── Agent status ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Pending,
    Active,
    Suspended,
    Quarantined,
    Revoked,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending     => write!(f, "pending"),
            Self::Active      => write!(f, "active"),
            Self::Suspended   => write!(f, "suspended"),
            Self::Quarantined => write!(f, "quarantined"),
            Self::Revoked     => write!(f, "revoked"),
        }
    }
}

// ── Credential types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CredentialType {
    CapabilityCredential,
    ComplianceCredential,
    ProvenanceCredential,
    IdentityCredential,
    CustomCredential,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityCredential  => write!(f, "CapabilityCredential"),
            Self::ComplianceCredential  => write!(f, "ComplianceCredential"),
            Self::ProvenanceCredential  => write!(f, "ProvenanceCredential"),
            Self::IdentityCredential    => write!(f, "IdentityCredential"),
            Self::CustomCredential      => write!(f, "CustomCredential"),
        }
    }
}

// ── Incident severity ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low      => write!(f, "low"),
            Self::Medium   => write!(f, "medium"),
            Self::High     => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ── DB row types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRow {
    pub id:                 Uuid,
    pub org_id:             Uuid,
    pub did:                String,
    pub name:               String,
    pub version:            String,
    pub description:        Option<String>,
    pub agent_card:         Value,
    pub connector_pid:      Option<String>,
    pub status:             String,
    pub trust_score:        f64,
    pub total_interactions: i64,
    pub violation_count:    i32,
    pub incident_count:     i32,
    pub public_key_ed25519: Option<String>,
    pub created_at:         DateTime<Utc>,
    pub activated_at:       Option<DateTime<Utc>>,
    pub last_seen_at:       Option<DateTime<Utc>>,
    pub revoked_at:         Option<DateTime<Utc>>,
    pub revocation_reason:  Option<String>,
    pub revoked_by:         Option<String>,
    pub audit_cid:          Option<String>,
    pub metadata:           Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorRow {
    pub id:                 Uuid,
    pub agent_id:           Uuid,
    pub org_id:             Uuid,
    pub user_did:           String,
    pub user_email:         String,
    pub display_name:       String,
    pub legal_entity:       String,
    pub jurisdiction:       Option<String>,
    pub tax_id_hash:        Option<String>,
    pub liability_sig:      String,
    pub status:             String,
    pub verified_at:        Option<DateTime<Utc>>,
    pub expires_at:         Option<DateTime<Utc>>,
    pub revoked_at:         Option<DateTime<Utc>>,
    pub created_at:         DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRow {
    pub id:               Uuid,
    pub agent_id:         Uuid,
    pub org_id:           Uuid,
    pub credential_type:  String,
    pub issuer_did:       String,
    pub issuer_name:      String,
    pub subject:          Value,
    pub proof_type:       String,
    pub proof_sig:        String,
    pub vc_json:          Value,
    pub issued_at:        DateTime<Utc>,
    pub expires_at:       Option<DateTime<Utc>>,
    pub revoked_at:       Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRow {
    pub id:                  Uuid,
    pub agent_id:            Uuid,
    pub org_id:              Uuid,
    pub incident_type:       String,
    pub severity:            String,
    pub title:               String,
    pub description:         String,
    pub evidence_cid:        Option<String>,
    pub auto_action:         Option<String>,
    pub reputation_delta:    Option<f64>,
    pub sponsor_notified_at: Option<DateTime<Utc>>,
    pub resolved_at:         Option<DateTime<Utc>>,
    pub created_at:          DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPeerRow {
    pub id:              Uuid,
    pub org_id:          Uuid,
    pub peer_name:       String,
    pub peer_url:        String,
    pub peer_public_key: Option<String>,
    pub trust_scope:     Value,
    pub min_trust_score: f64,
    pub auto_trust:      bool,
    pub status:          String,
    pub last_sync_at:    Option<DateTime<Utc>>,
    pub agent_count:     i32,
    pub created_at:      DateTime<Utc>,
}

// ── Request types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegisterAgentRequest {
    #[validate(length(min = 2, max = 120))]
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    #[validate(email)]
    pub sponsor_email: String,
    #[validate(length(min = 2, max = 200))]
    pub sponsor_display_name: String,
    #[validate(length(min = 2, max = 200))]
    pub sponsor_legal_entity: String,
    pub sponsor_jurisdiction: Option<String>,
    pub agent_card: Option<Value>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct IssueCredentialRequest {
    pub agent_did:       String,
    pub credential_type: String,
    #[validate(length(min = 2, max = 200))]
    pub issuer_name:     String,
    pub subject:         Value,
    pub expires_days:    Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RevokeRequest {
    #[validate(length(min = 2, max = 500))]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub did:                    String,
    pub required_credentials:   Option<Vec<String>>,
    pub min_trust_score:        Option<f64>,
    pub require_active_sponsor: Option<bool>,
    pub max_violations:         Option<i32>,
    pub issued_after:           Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub verified:               bool,
    pub agent_did:              String,
    pub agent_name:             Option<String>,
    pub trust_score:            Option<f64>,
    pub sponsor:                Option<SponsorSummary>,
    pub credentials_verified:   Vec<String>,
    pub violations:             i32,
    pub failure_reason:         Option<String>,
    pub verified_at:            DateTime<Utc>,
    pub expires_in_sec:         u64,
    pub proof:                  VerificationProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorSummary {
    pub display_name:  String,
    pub legal_entity:  String,
    pub jurisdiction:  Option<String>,
    pub verified:      bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationProof {
    pub proof_type:           String,
    pub created:              DateTime<Utc>,
    pub verification_method:  String,
    pub signature:            String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegisterFederationPeerRequest {
    #[validate(length(min = 2, max = 120))]
    pub peer_name:       String,
    #[validate(url)]
    pub peer_url:        String,
    pub peer_public_key: Option<String>,
    pub min_trust_score: Option<f64>,
    pub auto_trust:      Option<bool>,
    pub trust_scope:     Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateIncidentRequest {
    pub agent_did:     String,
    pub incident_type: String,
    pub severity:      String,
    #[validate(length(min = 2, max = 200))]
    pub title:         String,
    #[validate(length(min = 2, max = 2000))]
    pub description:   String,
    pub evidence_cid:  Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ResolveIncidentRequest {
    #[validate(length(min = 2, max = 1000))]
    pub resolution_note: String,
}

// ── Pagination ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct Pagination {
    #[validate(range(min = 1, max = 200))]
    pub limit:  Option<i64>,
    pub offset: Option<i64>,
    pub status: Option<String>,
}

impl Pagination {
    pub fn limit(&self) -> i64  { self.limit.unwrap_or(50).min(200) }
    pub fn offset(&self) -> i64 { self.offset.unwrap_or(0).max(0) }
}
