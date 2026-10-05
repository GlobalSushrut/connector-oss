//! IIA v2 contract types — intelligence identity spine.

use serde::{Deserialize, Serialize};

use super::signing::SignedPayloadV2;

pub const IIA_SCHEMA: &str = "connector.iia.v2";
pub const PRINCIPAL_PREFIX: &str = "cnktr:agent:";

/// Signing tier honesty — never market court-grade on HmacLab.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningTierV2 {
    HmacLab,
    Ed25519Court,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligencePrincipalV2 {
    pub schema: String,
    pub principal_id: String,
    pub issuer: String,
    #[serde(default)]
    pub authority_chain: Vec<String>,
    pub public_key_hex: String,
    pub contract_digest_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_id: Option<String>,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_witness_pubkey_hex: Option<String>,
    pub contract_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentContractV2 {
    pub schema: String,
    pub agent_id: String,
    pub issuer: String,
    pub purpose: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub denied_operations: Vec<String>,
    #[serde(default)]
    pub filesystem_read: Vec<String>,
    #[serde(default)]
    pub filesystem_write: Vec<String>,
    #[serde(default)]
    pub network_allow: Vec<String>,
    pub network_default: String,
    pub receipt_required: bool,
    pub contract_digest_sha256: String,
    pub contract_version: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileQuadrantV2 {
    Claimed,
    Observed,
    Attested,
    ContractAccepted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligenceProfileV2 {
    pub schema: String,
    pub intelligence_id: String,
    pub model_ref: String,
    pub provider: String,
    pub claimed: serde_json::Value,
    pub observed: serde_json::Value,
    pub attested: serde_json::Value,
    pub contract_accepted: bool,
    pub qualified: bool,
    pub handshake_at_ms: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextClassV2 {
    KernelFact,
    Policy,
    Memory,
    ToolResult,
    Untrusted,
    Instruction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextSliceV2 {
    pub class: ContextClassV2,
    pub provenance: String,
    pub content_digest_sha256: String,
}

/// Cognitive Proposal Object — non-authoritative model output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CognitiveProposalV2 {
    pub schema: String,
    pub cpo_id: String,
    pub principal_id: String,
    pub intelligence_id: String,
    pub proposed_action: String,
    pub proposed_target: String,
    #[serde(default)]
    pub context_slices: Vec<ContextSliceV2>,
    pub non_authoritative: bool,
    pub issued_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignedPayloadV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionQuantumV2 {
    pub schema: String,
    pub quantum_id: String,
    pub cpo_id: String,
    pub principal_id: String,
    pub contract_digest_sha256: String,
    pub action: String,
    pub target: String,
    pub nonce: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub single_use: bool,
    #[serde(default)]
    pub consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignedPayloadV2>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationTierV2 {
    None,
    Tpm,
    Tdx,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionRealityManifestV2 {
    pub schema: String,
    pub manifest_id: String,
    pub node_id: String,
    pub cell_id: String,
    pub runtime_hash: String,
    pub hardware_fingerprint: String,
    pub attestation_tier: AttestationTierV2,
    pub issued_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignedPayloadV2>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityStateV2 {
    Verified,
    Broken,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContinuityRecordV2 {
    pub schema: String,
    pub principal_id: String,
    pub state: ContinuityStateV2,
    pub model_ref: String,
    pub runtime_hash: String,
    pub contract_digest_sha256: String,
    pub evaluated_at_ms: i64,
    #[serde(default)]
    pub break_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligenceReceiptV2 {
    pub schema: String,
    pub receipt_id: String,
    pub principal_id: String,
    pub intelligence_id: String,
    pub cpo_id: Option<String>,
    pub quantum_id: Option<String>,
    pub docklock_profile_id: Option<String>,
    pub effect_digest_sha256: String,
    pub previous_receipt_digest: Option<String>,
    pub chain_head_digest: String,
    pub issued_at_ms: i64,
    pub signing_tier: SigningTierV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignedPayloadV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundationFusionV2 {
    /// Hash-linked tunnel circuit (Tor-style onion layering — integrity, not anonymity claim).
    pub schema: String,
    pub onion_circuit_fingerprint: String,
    /// Append-only receipt chain anchor at register (blockchain-style hash chain head).
    pub receipt_chain_anchor_digest: String,
    pub tunnel_integrity_mac: String,
}

/// Cryptographic foundation block minted at agent register — the agent IS this block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentFoundationBlockV2 {
    pub schema: String,
    pub foundation_id: String,
    /// SHA-256 anchor over principal + purpose + model + geo + memory plane.
    pub agent_intelligence_hash: String,
    pub principal_id: String,
    pub intelligence_id: String,
    pub purpose: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_agent_id: Option<String>,
    /// Model endpoint / ref the intelligence binds to (not the AgentID).
    pub model_address: String,
    pub geo_id: String,
    pub memory_state_address: String,
    /// P99 memory anchor — root packet namespace session for this agent plane.
    pub p99_memory_id: String,
    pub knowledge_base_address: String,
    pub knowledge_base_id: String,
    pub hardware_state_digest: String,
    pub isolation_cage_block_id: String,
    pub handshake_proof_receipt_id: String,
    pub foundation_fusion: FoundationFusionV2,
    pub four_id: FourIdLinkageV2,
    pub minted_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_signature: Option<SignedPayloadV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeSelfEnvelopeV2 {
    pub schema: String,
    pub principal: IntelligencePrincipalV2,
    pub contract: AgentContractV2,
    pub continuity: ContinuityRecordV2,
    pub signing_tier: SigningTierV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_signature: Option<SignedPayloadV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foundation_block: Option<AgentFoundationBlockV2>,
    /// Kernel-authoritative answer for "who am I?" — LLM must not contradict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub who_am_i_authoritative: Option<String>,
}

/// Four-ID linkage for mesh / CFNI headers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FourIdLinkageV2 {
    pub agent_id: String,
    pub intelligence_id: String,
    pub runtime_id: String,
    pub machine_id: String,
}

pub fn mint_principal_id(short: &str) -> String {
    format!("{PRINCIPAL_PREFIX}{short}")
}

// ═══════════════════════════════════════════════════════════════════════════
// Agent Identity Envelope (P10.10) — setup, activation, forensic universal record
// ═══════════════════════════════════════════════════════════════════════════

pub const AGENT_IDENTITY_SCHEMA: &str = "connector.agent_identity.v2";
pub const FORENSIC_UNIVERSAL_SCHEMA: &str = "connector.forensic.universal_envelope.v2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HitlPolicyV2 {
    None,
    Egress,
    Tool,
    Export,
    AllMaterial,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForensicProfileV2 {
    Off,
    Standard,
    Soc2,
    Hipaa,
    Court,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStateV2 {
    Registered,
    SetupReady,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryProfileV2 {
    pub default_memory_type: String,
    pub quota_tier: String,
    #[serde(default)]
    pub enabled_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceGrantV2 {
    pub grant_id: String,
    pub path: String,
    #[serde(default)]
    pub readable_by: Vec<String>,
    #[serde(default)]
    pub writable_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSetupSpecV2 {
    pub schema: String,
    pub agent_pid: String,
    pub name: String,
    pub acume: String,
    pub namespace: String,
    pub memory_profile: MemoryProfileV2,
    pub knowledge_base_id: String,
    pub knowledge_base_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_case_def: Option<serde_json::Value>,
    pub contract_ref: String,
    pub hitl_policy: HitlPolicyV2,
    pub forensic_profile: ForensicProfileV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub philosophy_digest: Option<String>,
    #[serde(default)]
    pub common_spaces: Vec<NamespaceGrantV2>,
    pub configured_at_ms: i64,
    pub setup_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentCapabilityManifestV2 {
    pub schema: String,
    #[serde(default)]
    pub memory_types: std::collections::BTreeMap<String, bool>,
    #[serde(default)]
    pub namespace_prefixes: std::collections::BTreeMap<String, bool>,
    pub thinking: bool,
    pub knowledge_rag: bool,
    pub knot_graph: bool,
    pub forensic_iia: bool,
    pub forensic_tracetramp: bool,
    pub forensic_witnessctl: bool,
    pub hitl: bool,
    pub activated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActivationProfileV2 {
    pub schema: String,
    pub agent_pid: String,
    pub state: ActivationStateV2,
    pub setup_spec_digest_sha256: String,
    pub capability_manifest: AgentCapabilityManifestV2,
    pub witnessctl_session_hint: Option<String>,
    pub activation_receipt_id: Option<String>,
    pub activated_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentMemorySummaryV2 {
    #[serde(default)]
    pub counts_by_type: std::collections::BTreeMap<String, u64>,
    pub total_packets: u64,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_packet_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentKnowledgeSummaryV2 {
    pub knowledge_base_id: String,
    pub knowledge_base_address: String,
    pub packet_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_ingest_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentKnotSummaryV2 {
    pub node_count: u64,
    pub edge_count: u64,
    pub agent_entity_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentNamespaceScopeV2 {
    pub private_memory: String,
    pub private_control: String,
    pub knowledge_base: String,
    #[serde(default)]
    pub readable_paths: Vec<String>,
    #[serde(default)]
    pub writable_paths: Vec<String>,
    #[serde(default)]
    pub common_spaces: Vec<NamespaceGrantV2>,
    pub isolation_enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HitlPostureV2 {
    pub policy: HitlPolicyV2,
    pub pending_count: u64,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicPostureV2 {
    pub profile: ForensicProfileV2,
    #[serde(default)]
    pub compliance_frameworks: Vec<String>,
    pub universal_envelope_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_envelope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnessctl_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentityEnvelopeV2 {
    pub schema: String,
    pub base: RuntimeSelfEnvelopeV2,
    pub activation: AgentActivationProfileV2,
    pub capability_manifest: AgentCapabilityManifestV2,
    pub memory_summary: AgentMemorySummaryV2,
    pub knowledge_summary: AgentKnowledgeSummaryV2,
    pub knot_summary: AgentKnotSummaryV2,
    pub namespace_scope: AgentNamespaceScopeV2,
    pub hitl_posture: HitlPostureV2,
    pub forensic_posture: ForensicPostureV2,
    pub execution_rules_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub who_am_i_authoritative: Option<String>,
}

/// Universal forensic record — SOC2/HIPAA/GDPR-ready; WitnessCtl export consumes this shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicUniversalEnvelopeV2 {
    pub schema: String,
    pub envelope_id: String,
    pub event_kind: String,
    pub agent_pid: String,
    pub principal_id: String,
    pub intelligence_id: String,
    pub four_id: FourIdLinkageV2,
    pub identity_envelope_digest_sha256: String,
    pub activation_profile_digest_sha256: String,
    pub forensic_profile: ForensicProfileV2,
    #[serde(default)]
    pub compliance_frameworks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnessctl_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_summary: Option<String>,
    pub issued_at_ms: i64,
    pub signing_tier: SigningTierV2,
}

pub const COGNITIVE_MEMORY_TYPES: &[&str] = &[
    "working",
    "episodic",
    "semantic",
    "procedural",
    "relational",
    "reflective",
    "evidentiary",
];

pub const NAMESPACE_PREFIX_TYPES: &[&str] = &[
    "memory",
    "knowledge",
    "asset",
    "app",
    "core",
    "agent",
    "tool",
    "system",
    "public",
];

pub const COMPLIANCE_CONTRACT_SCHEMA: &str = "connector.compliance_contract.v2";
pub const FORENSIC_ROLLUP_SCHEMA: &str = "connector.forensic_rollup_bucket.v2";
pub const FORENSIC_PACKAGE_SCHEMA: &str = "connector.forensic_package.v2";
pub const FORENSIC_CORRELATION_SCHEMA: &str = "connector.forensic_correlation_join.v2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceFrameworkBindingV2 {
    pub id: String,
    #[serde(default)]
    pub families: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePolicyV2 {
    pub retain_raw_receipts: bool,
    pub rollup_bucket: String,
    pub merkle_segments: bool,
    pub witnessctl_session_required: bool,
    pub offline_verify_required: bool,
    pub legal_hold_compatible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceContractV2 {
    pub schema: String,
    pub contract_id: String,
    pub version: u32,
    pub signing_tier: SigningTierV2,
    pub agent_pid: String,
    pub principal_id: String,
    pub intelligence_id: String,
    pub four_id: FourIdLinkageV2,
    pub acume: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_case_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub philosophy_digest_sha256: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub denied_operations: Vec<String>,
    pub hitl_policy: HitlPolicyV2,
    pub forensic_profile: ForensicProfileV2,
    pub private_memory: String,
    pub knowledge_base: String,
    #[serde(default)]
    pub common_spaces: Vec<NamespaceGrantV2>,
    pub isolation_enforced: bool,
    #[serde(default)]
    pub frameworks: Vec<ComplianceFrameworkBindingV2>,
    pub evidence_policy: EvidencePolicyV2,
    pub identity_envelope_digest_sha256: String,
    pub activation_profile_digest_sha256: String,
    pub agent_contract_digest_sha256: String,
    pub compliance_contract_digest_sha256: String,
    pub bound_at_ms: i64,
    pub bound_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnessctl_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignedPayloadV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ForensicRollupCountsV2 {
    #[serde(default)]
    pub n4_cognize: u64,
    #[serde(default)]
    pub qpr_intent: u64,
    #[serde(default)]
    pub memory_write: u64,
    #[serde(default)]
    pub gateway_turn: u64,
    #[serde(default)]
    pub tool_dispatch: u64,
    #[serde(default)]
    pub admission_deny: u64,
    #[serde(default)]
    pub continuity_break: u64,
    #[serde(default)]
    pub activate: u64,
    #[serde(default)]
    pub universal_envelope: u64,
    #[serde(default)]
    pub intelligence_receipt: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ForensicRollupMemoryTraceV2 {
    #[serde(default)]
    pub namespaces_touched: Vec<String>,
    #[serde(default)]
    pub packet_cid_count: u64,
    #[serde(default)]
    pub cross_agent_attempts_denied: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicRollupBucketV2 {
    pub schema: String,
    pub bucket_id: String,
    pub agent_pid: String,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub counts: ForensicRollupCountsV2,
    pub events_merkle_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_universal_envelope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_universal_envelope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iia_chain_head_at_close: Option<String>,
    pub memory_trace: ForensicRollupMemoryTraceV2,
    #[serde(default)]
    pub hitl_pending_peak: u64,
    #[serde(default)]
    pub quarantine_events: u64,
    #[serde(default)]
    pub egress_isolated: bool,
    /// Ordered leaf digests contributing to merkle root (capped for storage; root always exact for included leaves).
    #[serde(default)]
    pub leaf_digests: Vec<String>,
    pub closed: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicCorrelationJoinV2 {
    pub schema: String,
    pub join_id: String,
    pub agent_pid: String,
    pub principal_id: String,
    pub four_id: FourIdLinkageV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpo_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantum_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docklock_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub universal_envelope_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnessctl_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracetramp_trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fni_flow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollup_bucket_id: Option<String>,
    pub event_kind: String,
    pub issued_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicPackageHonestyV2 {
    pub hmac_paths_present: bool,
    pub hmac_not_court_grade: bool,
    pub fni_verify_status: String,
    #[serde(default)]
    pub stubs_in_window: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForensicPackageManifestV2 {
    pub schema: String,
    pub package_id: String,
    pub from_ms: i64,
    pub to_ms: i64,
    pub agent_pid: String,
    pub principal_id: String,
    pub acume: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnessctl_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_contract_id: Option<String>,
    pub signing_tier: SigningTierV2,
    pub package_root_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iia_chain_head: Option<String>,
    #[serde(default)]
    pub artifact_log_segment_roots: Vec<String>,
    pub honesty: ForensicPackageHonestyV2,
    pub receipt_count: u64,
    pub universal_envelope_count: u64,
    pub rollup_count: u64,
    pub join_count: u64,
    pub verify_cli: String,
    pub issued_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignedPayloadV2>,
}

impl ForensicProfileV2 {
    pub fn compliance_frameworks(&self) -> Vec<String> {
        self.framework_bindings().into_iter().map(|b| b.id).collect()
    }

    pub fn framework_bindings(&self) -> Vec<ComplianceFrameworkBindingV2> {
        match self {
            ForensicProfileV2::Off => vec![],
            ForensicProfileV2::Standard => vec![ComplianceFrameworkBindingV2 {
                id: "connector.internal".into(),
                families: vec!["ops".into()],
            }],
            ForensicProfileV2::Soc2 => vec![
                ComplianceFrameworkBindingV2 {
                    id: "soc2".into(),
                    families: vec!["CC6".into(), "CC7".into(), "CC8".into(), "CC9".into()],
                },
                ComplianceFrameworkBindingV2 {
                    id: "iso27001".into(),
                    families: vec!["A.8".into(), "A.9".into(), "A.12".into(), "A.16".into()],
                },
                ComplianceFrameworkBindingV2 {
                    id: "nist_800_53".into(),
                    families: vec!["AC".into(), "AU".into(), "SI".into(), "CM".into()],
                },
            ],
            ForensicProfileV2::Hipaa => vec![
                ComplianceFrameworkBindingV2 {
                    id: "hipaa".into(),
                    families: vec![
                        "164.312(a)".into(),
                        "164.312(b)".into(),
                        "164.312(c)".into(),
                        "164.312(d)".into(),
                    ],
                },
                ComplianceFrameworkBindingV2 {
                    id: "soc2".into(),
                    families: vec!["CC6".into(), "CC7".into()],
                },
                ComplianceFrameworkBindingV2 {
                    id: "gdpr".into(),
                    families: vec!["Art.5".into(), "Art.32".into()],
                },
            ],
            ForensicProfileV2::Court => vec![
                ComplianceFrameworkBindingV2 {
                    id: "soc2".into(),
                    families: vec!["CC6".into(), "CC7".into(), "CC8".into(), "CC9".into()],
                },
                ComplianceFrameworkBindingV2 {
                    id: "hipaa".into(),
                    families: vec![
                        "164.312(a)".into(),
                        "164.312(b)".into(),
                        "164.312(c)".into(),
                        "164.312(d)".into(),
                    ],
                },
                ComplianceFrameworkBindingV2 {
                    id: "gdpr".into(),
                    families: vec![
                        "Art.5".into(),
                        "Art.17".into(),
                        "Art.25".into(),
                        "Art.30".into(),
                        "Art.32".into(),
                    ],
                },
                ComplianceFrameworkBindingV2 {
                    id: "eu_ai_act".into(),
                    families: vec!["Art.9".into(), "Art.12".into(), "Art.14".into()],
                },
                ComplianceFrameworkBindingV2 {
                    id: "pci_dss".into(),
                    families: vec!["7".into(), "8".into(), "10".into()],
                },
                ComplianceFrameworkBindingV2 {
                    id: "nist_800_53".into(),
                    families: vec!["AC".into(), "AU".into(), "SI".into(), "CM".into()],
                },
                ComplianceFrameworkBindingV2 {
                    id: "iso27001".into(),
                    families: vec!["A.8".into(), "A.9".into(), "A.12".into(), "A.16".into()],
                },
            ],
        }
    }

    pub fn evidence_policy(&self) -> EvidencePolicyV2 {
        match self {
            ForensicProfileV2::Off => EvidencePolicyV2 {
                retain_raw_receipts: false,
                rollup_bucket: "hour".into(),
                merkle_segments: false,
                witnessctl_session_required: false,
                offline_verify_required: false,
                legal_hold_compatible: false,
            },
            ForensicProfileV2::Standard => EvidencePolicyV2 {
                retain_raw_receipts: false,
                rollup_bucket: "hour".into(),
                merkle_segments: true,
                witnessctl_session_required: false,
                offline_verify_required: true,
                legal_hold_compatible: false,
            },
            ForensicProfileV2::Soc2 | ForensicProfileV2::Hipaa => EvidencePolicyV2 {
                retain_raw_receipts: true,
                rollup_bucket: "hour".into(),
                merkle_segments: true,
                witnessctl_session_required: true,
                offline_verify_required: true,
                legal_hold_compatible: true,
            },
            ForensicProfileV2::Court => EvidencePolicyV2 {
                retain_raw_receipts: true,
                rollup_bucket: "hour".into(),
                merkle_segments: true,
                witnessctl_session_required: true,
                offline_verify_required: true,
                legal_hold_compatible: true,
            },
        }
    }
}
