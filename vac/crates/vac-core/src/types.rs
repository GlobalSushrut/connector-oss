//! Core types for VAC - Vault Attestation Chain
//!
//! All types are designed for DAG-CBOR encoding with CIDv1 addressing.

use cid::Cid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Source of an event or claim
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Source {
    /// Kind of source: "self", "user", "tool", "web", "untrusted"
    pub kind: SourceKind,
    /// DID of the principal
    pub principal_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    #[serde(rename = "self")]
    SelfSource,
    User,
    Tool,
    Web,
    Untrusted,
}

/// Verification status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verification {
    pub status: VerificationStatus,
    pub receipt_cid: Option<Cid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Pending,
    Verified,
    Failed,
}

/// Score components for deterministic heap derivation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreComponents {
    pub salience: f32,
    pub recency: f32,
    pub connectivity: u16,
}

/// Event - raw input atom (§2.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    // Identity
    pub ts: i64,
    
    // Content
    pub chapter_hint: Option<String>,
    pub actors: Vec<String>,
    pub tags: Vec<String>,
    pub entities: Vec<String>,
    pub payload_ref: Cid,
    pub feature_sketch: Vec<u8>,
    
    // Scores
    pub entropy: f32,
    pub importance: f32,
    pub score_components: ScoreComponents,
    
    // Trust model
    pub source: Source,
    pub trust_tier: u8,
    pub verification: Option<Verification>,
    
    // Links and metadata
    pub links: BTreeMap<String, Cid>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Event {
    pub fn new(ts: i64, payload_ref: Cid, source: Source) -> Self {
        Self {
            type_: "event".to_string(),
            version: 1,
            ts,
            chapter_hint: None,
            actors: Vec::new(),
            tags: Vec::new(),
            entities: Vec::new(),
            payload_ref,
            feature_sketch: Vec::new(),
            entropy: 0.5,
            importance: 0.5,
            score_components: ScoreComponents {
                salience: 0.5,
                recency: 1.0,
                connectivity: 0,
            },
            source,
            trust_tier: 1,
            verification: None,
            links: BTreeMap::new(),
            metadata: BTreeMap::new(),
        }
    }
}

/// Epistemic status for claims
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Epistemic {
    Observed,
    Inferred,
    Verified,
    Retracted,
}

/// Validity time range
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidityRange {
    pub from: i64,
    pub to: Option<i64>,
}

/// ClaimBundle - structured assertion (§2.2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimBundle {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    // Claim identity
    pub subject_id: String,
    pub predicate_key: String,
    pub value: serde_json::Value,
    pub value_type: String,
    pub units: Option<String>,
    
    // Epistemics
    pub epistemic: Epistemic,
    pub asserted_ts: i64,
    pub valid_ts_range: Option<ValidityRange>,
    pub confidence: Option<f32>,
    
    // Provenance
    pub evidence_refs: Vec<Cid>,
    pub supersedes: Option<Cid>,
    
    // Trust model
    pub source: Source,
    pub trust_tier: u8,
    
    // Links and metadata
    pub links: BTreeMap<String, Vec<Cid>>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl ClaimBundle {
    pub fn new(
        subject_id: String,
        predicate_key: String,
        value: serde_json::Value,
        source: Source,
    ) -> Self {
        let value_type = match &value {
            serde_json::Value::String(_) => "string",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::Bool(_) => "bool",
            _ => "json",
        }.to_string();
        
        Self {
            type_: "claim_bundle".to_string(),
            version: 1,
            subject_id,
            predicate_key,
            value,
            value_type,
            units: None,
            epistemic: Epistemic::Observed,
            asserted_ts: 0,
            valid_ts_range: None,
            confidence: None,
            evidence_refs: Vec::new(),
            supersedes: None,
            source,
            trust_tier: 1,
            links: BTreeMap::new(),
            metadata: BTreeMap::new(),
        }
    }
}

/// Entropy band for brackets
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EntropyBand {
    Low,
    Mid,
    High,
}

/// Bracket - time-entropy window (§2.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bracket {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub t_min: i64,
    pub t_max: i64,
    pub entropy_band: EntropyBand,
    pub detail_level: u8,
    
    pub links: BTreeMap<String, Cid>,
    pub merkle_root: [u8; 32],
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// Node kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum NodeKind {
    Leaf,
    Summary,
}

/// Time range
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeRange {
    pub min: i64,
    pub max: i64,
}

/// Node - compression tree node (§2.5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub kind: NodeKind,
    pub ts_range: TimeRange,
    pub entropy: f32,
    pub importance: f32,
    pub score_components: ScoreComponents,
    
    // LEAF only
    pub event_refs: Option<Vec<Cid>>,
    
    // SUMMARY only
    pub summary_ref: Option<Cid>,
    pub children: Option<Vec<Cid>>,
    
    pub links: BTreeMap<String, Vec<Cid>>,
    pub merkle_hash: [u8; 32],
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// Frame - snapshot page (§2.7)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub chapter_id: String,
    pub frame_ts: i64,
    
    pub links: FrameLinks,
    pub merkle_root: [u8; 32],
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameLinks {
    pub bracket: Cid,
    pub frame_summary: Option<Cid>,
    pub parents: Vec<Cid>,
    pub children: Vec<Cid>,
}

/// Signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub public_key: String,
    pub signature: Vec<u8>,
}

/// BlockHeader - attestation block (§10.3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub block_no: u64,
    pub prev_block_hash: [u8; 32],
    pub ts: i64,
    
    pub links: BlockLinks,
    pub signatures: Vec<Signature>,
    pub block_hash: [u8; 32],
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockLinks {
    pub patch: Cid,
    pub manifest: Cid,
}

/// ManifestRoot - per-block root summary (§10.3.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRoot {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub block_no: u64,
    
    // Index roots
    pub chapter_index_root: [u8; 32],
    pub snaptree_roots: BTreeMap<String, [u8; 32]>,
    
    // PCNN roots
    pub pcnn_basis_root: [u8; 32],
    pub pcnn_mpn_root: [u8; 32],
    pub pcnn_ie_root: [u8; 32],
    
    // Body root
    pub body_cas_root: [u8; 32],
    
    // Policy roots
    pub policy_root: [u8; 32],
    pub revocation_root: [u8; 32],
    
    pub manifest_hash: [u8; 32],
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// VaultPatch - change manifest (§10.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPatch {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub parent_block_hash: [u8; 32],
    pub added_cids: Vec<Cid>,
    pub removed_refs: Vec<Cid>,
    pub updated_roots: BTreeMap<String, [u8; 32]>,
    
    pub links: BTreeMap<String, Vec<Cid>>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// IE kind
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IeKind {
    Reinforce,
    Contradict,
    Refine,
    Alias,
}

/// IE - Interference Edge (§25.10)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterferenceEdge {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub kind: IeKind,
    pub strength: f32,
    pub created_ts: i64,
    
    pub links: IeLinks,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IeLinks {
    pub from: Cid,
    pub to: Cid,
}

/// ProllyNode - narrow tree node (§25.9)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProllyNode {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    pub level: u8,
    pub keys: Vec<Vec<u8>>,
    pub values: Vec<Cid>,
    
    pub node_hash: [u8; 32],
    pub metadata: BTreeMap<String, serde_json::Value>,
}

// =============================================================================
// MemPacket — Universal Memory Unit with 3D Envelope
//
// Every agent artifact (LLM output, extraction, decision, tool call, action,
// feedback, contradiction, state change) becomes a MemPacket — a content-
// addressed, provenance-tracked, authority-wrapped card stored under Prolly
// tree roots.
// =============================================================================

/// Type of memory packet — classifies every agent artifact
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    /// Raw user/sensor input
    Input,
    /// Raw LLM generation output (full response)
    LlmRaw,
    /// Structured facts extracted from LLM output
    Extraction,
    /// Agent's decision with reasoning
    Decision,
    /// Tool invocation with parameters
    ToolCall,
    /// Tool response/result
    ToolResult,
    /// Authorized VĀKYA action (AAPI envelope)
    Action,
    /// Human correction/approval/feedback
    Feedback,
    /// Detected conflict between facts
    Contradiction,
    /// Before/after state transition
    StateChange,
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketType::Input => write!(f, "input"),
            PacketType::LlmRaw => write!(f, "llm_raw"),
            PacketType::Extraction => write!(f, "extraction"),
            PacketType::Decision => write!(f, "decision"),
            PacketType::ToolCall => write!(f, "tool_call"),
            PacketType::ToolResult => write!(f, "tool_result"),
            PacketType::Action => write!(f, "action"),
            PacketType::Feedback => write!(f, "feedback"),
            PacketType::Contradiction => write!(f, "contradiction"),
            PacketType::StateChange => write!(f, "state_change"),
        }
    }
}

/// Dimension 1: Content Plane — WHAT happened
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContentPlane {
    /// Type of this packet
    pub packet_type: PacketType,
    /// The actual payload (JSON-serializable)
    pub payload: serde_json::Value,
    /// CID of the payload content
    pub payload_cid: Cid,
    /// Schema version for the payload format
    pub schema_version: String,
    /// Encoding format
    #[serde(default = "default_encoding")]
    pub encoding: String,
    /// Named entities referenced in this packet
    #[serde(default)]
    pub entities: Vec<String>,
    /// Classification tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Chapter/session hint for grouping
    pub chapter_hint: Option<String>,
}

fn default_encoding() -> String {
    "json".to_string()
}

/// Dimension 2: Provenance Plane — WHERE it came from
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvenancePlane {
    /// Source of this packet
    pub source: Source,
    /// Trust tier (3=self/verified, 2=tool, 1=user, 0=untrusted)
    pub trust_tier: u8,
    /// CIDs of packets that serve as evidence for this one
    #[serde(default)]
    pub evidence_refs: Vec<Cid>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: Option<f32>,
    /// Epistemic status
    pub epistemic: Epistemic,
    /// CID of the packet this one supersedes (for contradiction handling)
    pub supersedes: Option<Cid>,
    /// Human-readable reasoning chain
    pub reasoning: Option<String>,
    /// Domain-specific code (e.g., ICD-10 for healthcare)
    pub domain_code: Option<String>,
}

/// Dimension 3: Authority Plane — WHO authorized it
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityPlane {
    /// AAPI VĀKYA ID that authorized this packet (if applicable)
    pub vakya_id: Option<String>,
    /// Actor who authorized
    pub actor: Option<String>,
    /// Capability reference used
    pub capability_ref: Option<String>,
    /// Delegation chain (who delegated to whom)
    #[serde(default)]
    pub delegation: Vec<DelegationStep>,
    /// Ed25519 signature over the packet
    pub signature: Option<String>,
    /// Policy reference that was evaluated
    pub policy_ref: Option<String>,
    /// TTL in seconds (0 = no expiry)
    #[serde(default)]
    pub ttl_secs: u64,
}

/// A step in the delegation chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DelegationStep {
    /// Principal who delegated
    pub from: String,
    /// Principal who received delegation
    pub to: String,
    /// Reason for delegation
    pub reason: Option<String>,
    /// Timestamp of delegation
    pub ts: i64,
}

/// Index metadata — WHERE the packet is stored
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PacketIndex {
    /// Content-addressed ID of the full envelope
    pub packet_cid: Cid,
    /// Block number this packet was committed in (-1 = uncommitted)
    #[serde(default)]
    pub block_no: i64,
    /// Structured Prolly tree key: "{type}:{subject}:{predicate}:{cid}"
    pub prolly_key: Vec<u8>,
    /// Merkle inclusion proof (populated after block commit)
    pub merkle_proof: Option<String>,
    /// Timestamp (ms epoch)
    pub ts: i64,
    /// Sequential index within the pipeline
    #[serde(default)]
    pub seq_index: u64,
}

/// MemPacket — The universal memory unit with 3D Envelope
///
/// Every agent artifact becomes a MemPacket. The three planes (Content,
/// Provenance, Authority) plus the Index provide complete traceability
/// from intent to execution, satisfying EU AI Act Art. 12, HIPAA §164.312,
/// FINRA Rule 3110, and FDA 21 CFR Part 11 simultaneously.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemPacket {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,
    
    /// Dimension 1: What happened
    pub content: ContentPlane,
    /// Dimension 2: Where it came from
    pub provenance: ProvenancePlane,
    /// Dimension 3: Who authorized it
    pub authority: AuthorityPlane,
    /// Index: Where it's stored
    pub index: PacketIndex,
    
    /// Pipeline ID grouping related packets from one interaction
    pub pipeline_id: String,
    /// Subject ID (e.g., patient ID, user ID)
    pub subject_id: String,
    
    /// Memory storage tier (hot/warm/cold/archive)
    pub tier: MemoryTier,
    /// Memory scope (working/episodic/semantic/procedural)
    pub scope: MemoryScope,
    
    /// Session ID this packet belongs to
    pub session_id: Option<String>,
    /// Agent namespace for multi-agent isolation
    pub namespace: Option<String>,
    
    /// Tool interaction details (for tool_call/tool_result packets)
    pub tool_interaction: Option<ToolInteraction>,
    /// State snapshot (for state_change/action packets)
    pub state_snapshot: Option<StateSnapshot>,
    
    /// Additional metadata
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl MemPacket {
    /// Create a new MemPacket with the given content plane
    pub fn new(
        packet_type: PacketType,
        payload: serde_json::Value,
        payload_cid: Cid,
        subject_id: String,
        pipeline_id: String,
        source: Source,
        ts: i64,
    ) -> Self {
        let trust_tier = match source.kind {
            SourceKind::SelfSource => 3,
            SourceKind::Tool => 2,
            SourceKind::User => 1,
            _ => 0,
        };
        
        // Derive default scope from packet type
        let scope = match &packet_type {
            PacketType::Input | PacketType::LlmRaw | PacketType::ToolResult => MemoryScope::Working,
            PacketType::Extraction | PacketType::Contradiction => MemoryScope::Semantic,
            PacketType::Decision | PacketType::Action | PacketType::Feedback => MemoryScope::Episodic,
            PacketType::ToolCall | PacketType::StateChange => MemoryScope::Episodic,
        };
        
        Self {
            type_: "mem_packet".to_string(),
            version: 1,
            content: ContentPlane {
                packet_type,
                payload,
                payload_cid: payload_cid.clone(),
                schema_version: "1.0".to_string(),
                encoding: "json".to_string(),
                entities: Vec::new(),
                tags: Vec::new(),
                chapter_hint: None,
            },
            provenance: ProvenancePlane {
                source,
                trust_tier,
                evidence_refs: Vec::new(),
                confidence: None,
                epistemic: Epistemic::Observed,
                supersedes: None,
                reasoning: None,
                domain_code: None,
            },
            authority: AuthorityPlane {
                vakya_id: None,
                actor: None,
                capability_ref: None,
                delegation: Vec::new(),
                signature: None,
                policy_ref: None,
                ttl_secs: 0,
            },
            index: PacketIndex {
                packet_cid: payload_cid,
                block_no: -1,
                prolly_key: Vec::new(),
                merkle_proof: None,
                ts,
                seq_index: 0,
            },
            pipeline_id,
            subject_id,
            tier: MemoryTier::Hot,
            scope,
            session_id: None,
            namespace: None,
            tool_interaction: None,
            state_snapshot: None,
            metadata: BTreeMap::new(),
        }
    }
    
    /// Set evidence references (provenance chain)
    pub fn with_evidence(mut self, refs: Vec<Cid>) -> Self {
        self.provenance.evidence_refs = refs;
        self
    }
    
    /// Set confidence score
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.provenance.confidence = Some(confidence);
        self
    }
    
    /// Set supersedes (contradiction handling)
    pub fn with_supersedes(mut self, supersedes: Cid) -> Self {
        self.provenance.supersedes = Some(supersedes);
        self.provenance.epistemic = Epistemic::Retracted;
        self
    }
    
    /// Set reasoning
    pub fn with_reasoning(mut self, reasoning: String) -> Self {
        self.provenance.reasoning = Some(reasoning);
        self
    }
    
    /// Set domain code (e.g., ICD-10)
    pub fn with_domain_code(mut self, code: String) -> Self {
        self.provenance.domain_code = Some(code);
        self
    }
    
    /// Set AAPI authority (VĀKYA linkage)
    pub fn with_authority(
        mut self,
        vakya_id: String,
        actor: String,
        capability_ref: String,
    ) -> Self {
        self.authority.vakya_id = Some(vakya_id);
        self.authority.actor = Some(actor);
        self.authority.capability_ref = Some(capability_ref);
        self
    }
    
    /// Set signature
    pub fn with_signature(mut self, signature: String) -> Self {
        self.authority.signature = Some(signature);
        self
    }
    
    /// Set entities
    pub fn with_entities(mut self, entities: Vec<String>) -> Self {
        self.content.entities = entities;
        self
    }
    
    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.content.tags = tags;
        self
    }
    
    /// Set the structured Prolly key
    pub fn with_prolly_key(mut self, key: Vec<u8>) -> Self {
        self.index.prolly_key = key;
        self
    }
    
    /// Set sequential index
    pub fn with_seq_index(mut self, seq: u64) -> Self {
        self.index.seq_index = seq;
        self
    }
    
    /// Set session ID
    pub fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }
    
    /// Set namespace
    pub fn with_namespace(mut self, namespace: String) -> Self {
        self.namespace = Some(namespace);
        self
    }
    
    /// Set memory tier
    pub fn with_tier(mut self, tier: MemoryTier) -> Self {
        self.tier = tier;
        self
    }
    
    /// Set memory scope (override auto-derived default)
    pub fn with_scope(mut self, scope: MemoryScope) -> Self {
        self.scope = scope;
        self
    }
    
    /// Set tool interaction details
    pub fn with_tool_interaction(mut self, interaction: ToolInteraction) -> Self {
        self.tool_interaction = Some(interaction);
        self
    }
    
    /// Set state snapshot
    pub fn with_state_snapshot(mut self, snapshot: StateSnapshot) -> Self {
        self.state_snapshot = Some(snapshot);
        self
    }
    
    /// Demote to a lower storage tier
    pub fn demote(&mut self, tier: MemoryTier) {
        self.tier = tier;
    }
    
    /// Check if this packet has AAPI authority
    pub fn has_authority(&self) -> bool {
        self.authority.vakya_id.is_some()
    }
    
    /// Check if this packet supersedes another
    pub fn is_superseding(&self) -> bool {
        self.provenance.supersedes.is_some()
    }
    
    /// Get the packet type
    pub fn packet_type(&self) -> &PacketType {
        &self.content.packet_type
    }
}

// =============================================================================
// Universal Memory Management Layer
//
// Inspired by MemGPT/Letta OS-level memory hierarchy, LangGraph state
// management, CrewAI role-based memory, and cognitive science (episodic,
// semantic, procedural memory). This layer makes Connector the universal
// memory substrate for ALL AI agents — from casual chat to critical
// agentic pipelines — with verifiable provenance that no other framework
// provides.
// =============================================================================

/// Memory storage tier — analogous to OS virtual memory hierarchy
/// (MemGPT: main context ↔ archival storage; Letta: message buffer ↔ recall ↔ archival)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTier {
    /// Hot: In the agent's active context window (analogous to CPU cache/RAM)
    /// Used for: current conversation turn, active reasoning, tool results
    Hot,
    /// Warm: Recent history, quickly retrievable (analogous to SSD)
    /// Used for: conversation history within session, recent extractions
    Warm,
    /// Cold: Long-term storage, requires retrieval (analogous to HDD)
    /// Used for: past sessions, accumulated knowledge, archived facts
    Cold,
    /// Archive: Immutable, compressed, rarely accessed (analogous to tape)
    /// Used for: compliance records, audit trails, old contradictions
    Archive,
}

impl std::fmt::Display for MemoryTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryTier::Hot => write!(f, "hot"),
            MemoryTier::Warm => write!(f, "warm"),
            MemoryTier::Cold => write!(f, "cold"),
            MemoryTier::Archive => write!(f, "archive"),
        }
    }
}

/// Memory scope — cognitive memory classification
/// (Based on cognitive science: working, episodic, semantic, procedural)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MemoryScope {
    /// Working: Transient state for current task execution
    /// Resets per interaction. Holds intermediate reasoning, tool outputs.
    Working,
    /// Episodic: Specific experiences with temporal context
    /// "What happened when?" — conversation logs, interaction records, outcomes
    Episodic,
    /// Semantic: Factual knowledge independent of specific experiences
    /// "What is true?" — extracted facts, user preferences, domain knowledge
    Semantic,
    /// Procedural: Learned workflows and behavioral patterns
    /// "How to do X?" — cached routines, decision templates, SOP steps
    Procedural,
}

impl std::fmt::Display for MemoryScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryScope::Working => write!(f, "working"),
            MemoryScope::Episodic => write!(f, "episodic"),
            MemoryScope::Semantic => write!(f, "semantic"),
            MemoryScope::Procedural => write!(f, "procedural"),
        }
    }
}

/// Session envelope — groups MemPackets into a coherent conversation/interaction
///
/// Every agent interaction (chat turn, pipeline run, multi-step workflow)
/// produces a session. Sessions are the unit of episodic memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionEnvelope {
    #[serde(rename = "type")]
    pub type_: String,
    pub version: u32,

    /// Unique session/thread ID
    pub session_id: String,
    /// Agent ID that owns this session
    pub agent_id: String,
    /// Agent namespace for multi-agent isolation
    pub namespace: String,
    /// Human-readable session label
    pub label: Option<String>,

    /// Ordered CIDs of MemPackets in this session
    pub packet_cids: Vec<Cid>,
    /// Session start timestamp (ms epoch)
    pub started_at: i64,
    /// Session end timestamp (ms epoch, None if ongoing)
    pub ended_at: Option<i64>,

    /// Memory tier this session currently resides in
    pub tier: MemoryTier,
    /// Memory scope classification
    pub scope: MemoryScope,

    /// Compression metadata (populated when session is summarized)
    pub compression: Option<CompressionMeta>,

    /// Parent session ID (for sub-conversations, branching)
    pub parent_session_id: Option<String>,
    /// Child session IDs
    #[serde(default)]
    pub child_session_ids: Vec<String>,

    /// Summary text (populated by compression/sleep-time agents)
    pub summary: Option<String>,
    /// Summary CID (content-addressed summary for verification)
    pub summary_cid: Option<Cid>,

    /// Total token count across all packets in this session
    #[serde(default)]
    pub total_tokens: u64,

    /// Additional metadata
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl SessionEnvelope {
    pub fn new(
        session_id: String,
        agent_id: String,
        namespace: String,
        started_at: i64,
    ) -> Self {
        Self {
            type_: "session".to_string(),
            version: 1,
            session_id,
            agent_id,
            namespace,
            label: None,
            packet_cids: Vec::new(),
            started_at,
            ended_at: None,
            tier: MemoryTier::Hot,
            scope: MemoryScope::Episodic,
            compression: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            summary: None,
            summary_cid: None,
            total_tokens: 0,
            metadata: BTreeMap::new(),
        }
    }

    /// Add a packet CID to this session
    pub fn add_packet(&mut self, cid: Cid) {
        self.packet_cids.push(cid);
    }

    /// Close the session
    pub fn close(&mut self, ended_at: i64) {
        self.ended_at = Some(ended_at);
    }

    /// Demote to a lower storage tier
    pub fn demote(&mut self, tier: MemoryTier) {
        self.tier = tier;
    }

    /// Check if session is still active
    pub fn is_active(&self) -> bool {
        self.ended_at.is_none()
    }

    /// Get packet count
    pub fn packet_count(&self) -> usize {
        self.packet_cids.len()
    }
}

/// Compression metadata — tracks when/how memories were compressed
///
/// When a session exceeds context limits, older messages are evicted
/// and recursively summarized (MemGPT pattern). This metadata preserves
/// the provenance of the compression itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompressionMeta {
    /// Algorithm used for compression (e.g., "recursive_summarization", "eviction_70pct")
    pub algorithm: String,
    /// Number of original packets before compression
    pub original_count: u64,
    /// Number of packets after compression
    pub compressed_count: u64,
    /// CIDs of packets that were evicted/compressed
    pub evicted_cids: Vec<Cid>,
    /// Compression ratio (0.0 - 1.0, lower = more compressed)
    pub ratio: f32,
    /// Timestamp of compression
    pub compressed_at: i64,
    /// Agent that performed the compression (e.g., sleep-time agent)
    pub compressor_agent: Option<String>,
}

/// Tool interaction record — captures full request/response for any tool/API call
///
/// Every time an agent calls a tool, API, database, or external service,
/// the full interaction is captured as a ToolInteraction. This enables:
/// - Complete audit trail of all machine-world interactions
/// - Replay and debugging of agent behavior
/// - Cost tracking and rate limit management
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolInteraction {
    /// Tool/service name (e.g., "openai.chat", "postgres.query", "http.get")
    pub tool_name: String,
    /// Tool version or API version
    pub tool_version: Option<String>,
    /// Full request payload
    pub request: serde_json::Value,
    /// Full response payload
    pub response: Option<serde_json::Value>,
    /// HTTP status code or tool-specific status
    pub status_code: Option<i32>,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
    /// Token usage (for LLM calls)
    pub token_usage: Option<TokenUsage>,
    /// Cost in USD (for billing tracking)
    pub cost_usd: Option<f64>,
    /// Error message if the call failed
    pub error: Option<String>,
    /// Whether the call was retried
    #[serde(default)]
    pub retried: bool,
    /// Retry count
    #[serde(default)]
    pub retry_count: u32,
}

/// Token usage for LLM calls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Model name (e.g., "gpt-4o", "deepseek-chat", "claude-3.5-sonnet")
    pub model: String,
}

/// State snapshot — before/after state for reversibility
///
/// Captures the state of a resource before and after an agent action,
/// enabling rollback and audit. This is critical for:
/// - FINRA: reversing unauthorized trades
/// - HIPAA: undoing incorrect medical record updates
/// - General: any destructive action that might need reversal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateSnapshot {
    /// Resource identifier
    pub resource_id: String,
    /// Resource type (e.g., "ehr_record", "database_row", "file", "api_state")
    pub resource_type: String,
    /// State before the action
    pub before: Option<serde_json::Value>,
    /// State after the action
    pub after: Option<serde_json::Value>,
    /// Hash of the before state (for verification without storing full state)
    pub before_hash: Option<String>,
    /// Hash of the after state
    pub after_hash: Option<String>,
    /// Delta/diff representation
    pub delta: Option<serde_json::Value>,
    /// Whether this action is reversible
    #[serde(default)]
    pub reversible: bool,
    /// Instructions for reversal (if reversible)
    pub reversal_instructions: Option<serde_json::Value>,
}

/// Memory query — structured query for retrieving memories
///
/// Supports the retrieval patterns needed by all agent frameworks:
/// - By time range (LangGraph checkpoints)
/// - By entity (CrewAI role-based)
/// - By semantic similarity (MemGPT archival search)
/// - By scope (working/episodic/semantic/procedural)
/// - By packet type (LLM output, tool call, decision, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryQuery {
    /// Filter by agent namespace
    pub namespace: Option<String>,
    /// Filter by agent ID
    pub agent_id: Option<String>,
    /// Filter by session ID
    pub session_id: Option<String>,
    /// Filter by subject ID
    pub subject_id: Option<String>,
    /// Filter by packet types
    #[serde(default)]
    pub packet_types: Vec<PacketType>,
    /// Filter by memory scope
    pub scope: Option<MemoryScope>,
    /// Filter by memory tier
    pub tier: Option<MemoryTier>,
    /// Filter by time range (start, ms epoch)
    pub time_from: Option<i64>,
    /// Filter by time range (end, ms epoch)
    pub time_to: Option<i64>,
    /// Filter by entities mentioned
    #[serde(default)]
    pub entities: Vec<String>,
    /// Filter by tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Semantic search query (for vector similarity)
    pub semantic_query: Option<String>,
    /// Maximum number of results
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Offset for pagination
    #[serde(default)]
    pub offset: u32,
    /// Sort order
    #[serde(default)]
    pub sort: QuerySort,
    /// Minimum trust tier (0-3)
    pub min_trust_tier: Option<u8>,
    /// Include only packets with AAPI authority
    #[serde(default)]
    pub require_authority: bool,
}

fn default_limit() -> u32 {
    50
}

/// Sort order for memory queries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuerySort {
    /// Most recent first
    #[default]
    RecencyDesc,
    /// Oldest first
    RecencyAsc,
    /// Highest relevance first (for semantic queries)
    RelevanceDesc,
    /// Highest trust tier first
    TrustDesc,
    /// Sequential order within pipeline
    SequentialAsc,
}

/// Agent memory namespace — isolates memory between agents while allowing controlled sharing
///
/// In multi-agent systems (CrewAI teams, AutoGen groups), each agent has
/// its own memory namespace. Shared namespaces enable controlled knowledge
/// sharing between agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNamespace {
    /// Namespace identifier (e.g., "org:acme/team:support/agent:triage")
    pub namespace_id: String,
    /// Agent ID that owns this namespace
    pub agent_id: String,
    /// Parent namespace (for hierarchical isolation)
    pub parent_namespace: Option<String>,
    /// Namespaces this agent can read from (shared memory)
    #[serde(default)]
    pub readable_namespaces: Vec<String>,
    /// Namespaces this agent can write to
    #[serde(default)]
    pub writable_namespaces: Vec<String>,
    /// Memory quota (max packets, 0 = unlimited)
    #[serde(default)]
    pub quota_max_packets: u64,
    /// Current packet count
    #[serde(default)]
    pub current_packet_count: u64,
    /// Created timestamp
    pub created_at: i64,
}

// =============================================================================
// Agent OS Memory Kernel
//
// Modeled after AIOS (COLM 2025) LLM kernel architecture and traditional
// OS kernel patterns (PCB, syscalls, MMU, protection rings, audit logging).
//
// This is the kernel layer that makes Connector a true Agent Operating System:
// - AgentControlBlock: Per-agent state (like OS Process Control Block)
// - MemoryKernelOp: System calls for memory operations
// - ExecutionContext: Current execution state with snapshot/restore
// - MemoryRegion: Allocated memory per agent with quota + protection
// - EvictionPolicy: Memory management strategies
// - KernelAuditEntry: Every kernel operation logged for compliance
// =============================================================================

/// Agent status — lifecycle state of an agent process
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// Agent is registered but not yet started
    Registered,
    /// Agent is actively executing
    Running,
    /// Agent is suspended (context saved, can be resumed)
    Suspended,
    /// Agent is waiting for external input (human, tool, API)
    Waiting,
    /// Agent has completed its task
    Completed,
    /// Agent encountered a fatal error
    Failed,
    /// Agent was terminated by the system or operator
    Terminated,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Registered => write!(f, "registered"),
            AgentStatus::Running => write!(f, "running"),
            AgentStatus::Suspended => write!(f, "suspended"),
            AgentStatus::Waiting => write!(f, "waiting"),
            AgentStatus::Completed => write!(f, "completed"),
            AgentStatus::Failed => write!(f, "failed"),
            AgentStatus::Terminated => write!(f, "terminated"),
        }
    }
}

/// Agent Control Block — the Process Control Block (PCB) equivalent for agents
///
/// Every agent registered with the kernel gets an ACB that tracks its
/// complete lifecycle state. This is the central data structure the
/// kernel uses to manage agent processes.
///
/// Analogous to: Linux task_struct, Windows EPROCESS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentControlBlock {
    /// Unique agent process ID (assigned by kernel)
    pub agent_pid: String,
    /// Human-readable agent name
    pub agent_name: String,
    /// Agent role/type
    pub agent_role: Option<String>,
    /// Current status
    pub status: AgentStatus,
    /// Scheduling priority (0 = lowest, 255 = highest)
    pub priority: u8,

    // --- Memory ---
    /// Memory namespace (isolation boundary)
    pub namespace: String,
    /// Allocated memory region
    pub memory_region: MemoryRegion,
    /// Active session IDs
    #[serde(default)]
    pub active_sessions: Vec<String>,
    /// Total packets created by this agent
    #[serde(default)]
    pub total_packets: u64,
    /// Total tokens consumed by this agent
    #[serde(default)]
    pub total_tokens_consumed: u64,
    /// Total cost incurred (USD)
    #[serde(default)]
    pub total_cost_usd: f64,

    // --- Capabilities ---
    /// AAPI capability references this agent holds
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Namespaces this agent can read from
    #[serde(default)]
    pub readable_namespaces: Vec<String>,
    /// Namespaces this agent can write to
    #[serde(default)]
    pub writable_namespaces: Vec<String>,
    /// Tools this agent is allowed to use
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    // --- Execution ---
    /// Model being used
    pub model: Option<String>,
    /// Framework (langchain, crewai, autogen, custom)
    pub framework: Option<String>,
    /// Parent agent PID (for sub-agents)
    pub parent_pid: Option<String>,
    /// Child agent PIDs
    #[serde(default)]
    pub child_pids: Vec<String>,

    // --- Lifecycle ---
    /// Registration timestamp (ms epoch)
    pub registered_at: i64,
    /// Last activity timestamp (ms epoch)
    pub last_active_at: i64,
    /// Termination timestamp (ms epoch)
    pub terminated_at: Option<i64>,
    /// Termination reason
    pub termination_reason: Option<String>,

    // --- Phase 8: Kernel Hardening ---
    /// Current execution phase (FSM state)
    #[serde(default)]
    pub phase: AgentPhase,
    /// Agent role (determines execution policy)
    #[serde(default)]
    pub role: AgentRole,
    /// Namespace mount table (what this agent can see)
    #[serde(default)]
    pub namespace_mounts: Vec<NamespaceMount>,
    /// Tool bindings (what tools this agent can use)
    #[serde(default)]
    pub tool_bindings: Vec<ToolBinding>,
}

impl AgentControlBlock {
    pub fn new(
        agent_pid: String,
        agent_name: String,
        namespace: String,
        registered_at: i64,
    ) -> Self {
        Self {
            agent_pid,
            agent_name,
            agent_role: None,
            status: AgentStatus::Registered,
            priority: 128,
            namespace: namespace.clone(),
            memory_region: MemoryRegion::new(namespace),
            active_sessions: Vec::new(),
            total_packets: 0,
            total_tokens_consumed: 0,
            total_cost_usd: 0.0,
            capabilities: Vec::new(),
            readable_namespaces: Vec::new(),
            writable_namespaces: Vec::new(),
            allowed_tools: Vec::new(),
            model: None,
            framework: None,
            parent_pid: None,
            child_pids: Vec::new(),
            registered_at,
            last_active_at: registered_at,
            terminated_at: None,
            termination_reason: None,
            phase: AgentPhase::Registered,
            role: AgentRole::Writer,
            namespace_mounts: Vec::new(),
            tool_bindings: Vec::new(),
        }
    }

    pub fn is_alive(&self) -> bool {
        matches!(self.status, AgentStatus::Running | AgentStatus::Suspended | AgentStatus::Waiting)
    }

    pub fn is_terminated(&self) -> bool {
        matches!(self.status, AgentStatus::Completed | AgentStatus::Failed | AgentStatus::Terminated)
    }
}

/// Memory region — allocated memory space per agent with quota and protection
///
/// Analogous to: OS virtual address space with page protection flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Namespace this region belongs to
    pub namespace: String,
    /// Maximum packets allowed (0 = unlimited)
    #[serde(default)]
    pub quota_packets: u64,
    /// Maximum tokens allowed (0 = unlimited)
    #[serde(default)]
    pub quota_tokens: u64,
    /// Maximum storage bytes (0 = unlimited)
    #[serde(default)]
    pub quota_bytes: u64,
    /// Current usage: packets
    #[serde(default)]
    pub used_packets: u64,
    /// Current usage: tokens
    #[serde(default)]
    pub used_tokens: u64,
    /// Current usage: bytes
    #[serde(default)]
    pub used_bytes: u64,
    /// Memory protection flags
    pub protection: MemoryProtection,
    /// Eviction policy for this region
    pub eviction_policy: EvictionPolicy,
    /// Whether this region is sealed (no further writes)
    #[serde(default)]
    pub sealed: bool,
}

impl MemoryRegion {
    pub fn new(namespace: String) -> Self {
        Self {
            namespace,
            quota_packets: 0,
            quota_tokens: 0,
            quota_bytes: 0,
            used_packets: 0,
            used_tokens: 0,
            used_bytes: 0,
            protection: MemoryProtection::default(),
            eviction_policy: EvictionPolicy::default(),
            sealed: false,
        }
    }

    /// Check if the region has capacity for more packets
    pub fn has_capacity(&self) -> bool {
        !self.sealed && (self.quota_packets == 0 || self.used_packets < self.quota_packets)
    }

    /// Usage ratio (0.0 - 1.0), returns 0.0 if unlimited
    pub fn usage_ratio(&self) -> f64 {
        if self.quota_packets == 0 { return 0.0; }
        self.used_packets as f64 / self.quota_packets as f64
    }
}

/// Memory protection flags — controls what operations are allowed
///
/// Analogous to: OS page protection (read/write/execute/no-access)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtection {
    /// Can read from this region
    #[serde(default = "default_true")]
    pub read: bool,
    /// Can write new packets to this region
    #[serde(default = "default_true")]
    pub write: bool,
    /// Can execute actions based on data in this region
    #[serde(default = "default_true")]
    pub execute: bool,
    /// Can share data from this region with other agents
    #[serde(default)]
    pub share: bool,
    /// Can delete/evict data from this region
    #[serde(default = "default_true")]
    pub evict: bool,
    /// Requires human approval for writes
    #[serde(default)]
    pub requires_approval: bool,
}

fn default_true() -> bool { true }

impl Default for MemoryProtection {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            share: false,
            evict: true,
            requires_approval: false,
        }
    }
}

/// Eviction policy — determines how memory is reclaimed when quota is reached
///
/// Analogous to: OS page replacement algorithms (LRU, FIFO, Clock)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvictionPolicy {
    /// Least Recently Used — evict oldest accessed packets first
    #[default]
    Lru,
    /// First In First Out — evict in creation order
    Fifo,
    /// Time-To-Live — evict packets older than TTL
    Ttl,
    /// Priority-based — evict lowest trust-tier packets first
    Priority,
    /// Summarize-and-evict — compress old packets before evicting (MemGPT pattern)
    SummarizeEvict,
    /// Never evict — fail on quota exceeded (for compliance/audit data)
    Never,
}

// =============================================================================
// Phase 8a: Execution Logic System (ELS)
//
// Agent phase FSM + execution policies + role-based syscall allowlists +
// rate limits + budget enforcement. Inspired by Linux seccomp-bpf,
// Fuchsia component framework, AIOS scheduler.
// =============================================================================

/// Agent execution phase — finite state machine controlling valid syscall sequences.
///
/// Agents transition through phases; each phase restricts which syscalls are valid.
/// Analogous to: Linux seccomp-bpf syscall filtering + process states.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AgentPhase {
    /// Just registered, not yet started. Can only: AgentStart
    Registered,
    /// Actively executing. Can: MemWrite/Read, Session ops, Context ops
    Active,
    /// Paused (context saved). Can only: AgentResume, AgentTerminate
    Suspended,
    /// Read-only mode (sealed or auditor). Can only: MemRead, AccessCheck, IntegrityCheck
    ReadOnly,
    /// Shutting down. Can only: AgentTerminate
    Terminating,
}

impl Default for AgentPhase {
    fn default() -> Self {
        AgentPhase::Registered
    }
}

impl std::fmt::Display for AgentPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentPhase::Registered => write!(f, "registered"),
            AgentPhase::Active => write!(f, "active"),
            AgentPhase::Suspended => write!(f, "suspended"),
            AgentPhase::ReadOnly => write!(f, "read_only"),
            AgentPhase::Terminating => write!(f, "terminating"),
        }
    }
}

/// Agent role — determines the default execution policy (syscall allowlist).
///
/// Analogous to: Linux user groups + Fuchsia component manifests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    /// Read-only access to memory
    Reader,
    /// Read + write access to memory and sessions
    Writer,
    /// Full access to all syscalls
    Admin,
    /// Read + write + context ops, rate-limited
    ToolAgent,
    /// Read-only + integrity checks (for compliance)
    Auditor,
    /// Memory management: evict, promote, demote, GC
    Compactor,
    /// Custom role with explicit allowlist
    Custom(String),
}

impl Default for AgentRole {
    fn default() -> Self {
        AgentRole::Writer
    }
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRole::Reader => write!(f, "reader"),
            AgentRole::Writer => write!(f, "writer"),
            AgentRole::Admin => write!(f, "admin"),
            AgentRole::ToolAgent => write!(f, "tool_agent"),
            AgentRole::Auditor => write!(f, "auditor"),
            AgentRole::Compactor => write!(f, "compactor"),
            AgentRole::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// Rate limit configuration for a syscall or group of syscalls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum calls per second
    pub max_per_second: u32,
    /// Maximum calls per minute
    pub max_per_minute: u32,
    /// Burst allowance (calls allowed in a single instant)
    pub max_burst: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            max_per_second: 100,
            max_per_minute: 1000,
            max_burst: 10,
        }
    }
}

/// Budget policy — enforced at kernel dispatch to prevent runaway agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetPolicy {
    /// Max tokens an agent can consume per session (0 = unlimited)
    #[serde(default)]
    pub max_tokens_per_session: u64,
    /// Max cost in USD per session (0.0 = unlimited)
    #[serde(default)]
    pub max_cost_per_session_usd: f64,
    /// Max packets an agent can write per minute (0 = unlimited)
    #[serde(default)]
    pub max_packets_per_minute: u32,
    /// Max tool calls per session (0 = unlimited)
    #[serde(default)]
    pub max_tool_calls_per_session: u32,
    /// Whether to enforce (true) or just log warnings (false)
    #[serde(default = "default_true")]
    pub enforce: bool,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self {
            max_tokens_per_session: 0,
            max_cost_per_session_usd: 0.0,
            max_packets_per_minute: 0,
            max_tool_calls_per_session: 0,
            enforce: true,
        }
    }
}

/// Execution policy — defines what an agent role is allowed to do.
///
/// Combines syscall allowlist, phase transitions, rate limits, and budget.
/// Analogous to: seccomp-bpf filter program + Fuchsia component manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    /// Which role this policy applies to
    pub role: AgentRole,
    /// Allowed syscalls for this role
    pub allowed_ops: Vec<MemoryKernelOp>,
    /// Valid phase transitions: (from_phase, operation) → to_phase
    pub phase_transitions: Vec<PhaseTransition>,
    /// Per-operation rate limits (None = use default)
    #[serde(default)]
    pub rate_limits: BTreeMap<String, RateLimit>,
    /// Budget policy
    #[serde(default)]
    pub budget: BudgetPolicy,
}

/// A single valid phase transition rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTransition {
    /// Current phase
    pub from: AgentPhase,
    /// Operation being performed
    pub op: MemoryKernelOp,
    /// Phase after the operation completes
    pub to: AgentPhase,
}

// =============================================================================
// Phase 8b: Namespace & Filesystem Isolation (NFI)
// =============================================================================

/// Namespace mount — binds a source namespace path into an agent's view.
///
/// Analogous to: Linux mount namespace bind mounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceMount {
    /// Source namespace path (the real path)
    pub source: String,
    /// Mount point in the agent's view
    pub mount_point: String,
    /// Access mode
    pub mode: MountMode,
    /// Filters restricting what's visible
    #[serde(default)]
    pub filters: Vec<MountFilter>,
}

/// Access mode for a namespace mount.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    /// Can read packets, cannot write
    ReadOnly,
    /// Can read and write packets
    ReadWrite,
    /// Can invoke tools bound in this namespace
    Execute,
    /// Can read, content is integrity-verified on every access
    Sealed,
}

/// Filter restricting which packets are visible through a mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountFilter {
    /// Only show these packet types (None = all)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_types: Option<Vec<PacketType>>,
    /// Only show packets in this time range (ms epoch)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_range: Option<(i64, i64)>,
    /// Only show packets mentioning these entities
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_filter: Option<Vec<String>>,
    /// Only show packets in these tiers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_filter: Option<Vec<MemoryTier>>,
    /// Max packets visible through this mount
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packets: Option<u64>,
}

// =============================================================================
// Phase 8c: Tool Isolation
// =============================================================================

/// Tool binding — binds a tool into an agent's namespace with capability constraints.
///
/// Default-deny: agents can only use tools explicitly bound to them.
/// Analogous to: Fuchsia capability routing + WASI typed interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBinding {
    /// Tool identifier (e.g., "ehr.read_patient")
    pub tool_id: String,
    /// Namespace path where this tool is mounted
    pub namespace_path: String,
    /// Allowed action patterns (glob: "ehr.read_*")
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// Allowed resource patterns (glob: "patient:*")
    #[serde(default)]
    pub allowed_resources: Vec<String>,
    /// Rate limit specific to this tool
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// Data classification for audit ("phi", "pii", "public", "internal")
    #[serde(default)]
    pub data_classification: String,
    /// Whether human approval is required
    #[serde(default)]
    pub requires_approval: bool,
}

// =============================================================================
// Phase 8d: Port System (PAAC)
// =============================================================================

/// Port type — the kind of inter-agent communication channel.
///
/// Inspired by Erlang ports, Fuchsia channels, A2A protocol tasks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortType {
    /// Share specific packets/windows between agents
    MemoryShare,
    /// Grant another agent access to a tool binding
    ToolDelegate,
    /// Subscribe to namespace events (new packets, state changes)
    EventStream,
    /// Synchronous query between agents
    RequestResponse,
    /// One-to-many event distribution
    Broadcast,
    /// Ordered chain: agent A → agent B → agent C
    Pipeline,
}

/// Port direction — which way messages flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortDirection {
    /// Owner sends, bound agents receive
    Send,
    /// Owner receives, bound agents send
    Receive,
    /// Both directions
    Bidirectional,
}

/// Port — a typed, capability-gated message channel between agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    /// Unique port identifier
    pub port_id: String,
    /// The kind of communication
    pub port_type: PortType,
    /// Agent that created/owns this port
    pub owner_pid: String,
    /// Agents connected to this port
    #[serde(default)]
    pub bound_pids: Vec<String>,
    /// Direction of message flow
    pub direction: PortDirection,
    /// Whether messages queue or block
    #[serde(default)]
    pub buffered: bool,
    /// Max queued messages
    #[serde(default = "default_port_buffer")]
    pub max_buffer_size: u32,
    /// Allowed packet types through this port
    #[serde(default)]
    pub allowed_packet_types: Vec<PacketType>,
    /// Allowed action patterns
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// Max delegation depth
    #[serde(default = "default_max_delegation")]
    pub max_delegation_depth: u8,
    /// Created timestamp
    pub created_at: i64,
    /// Auto-close after this time (ms epoch)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Whether this port is closed
    #[serde(default)]
    pub closed: bool,
}

fn default_port_buffer() -> u32 { 256 }
fn default_max_delegation() -> u8 { 3 }

/// Port message — a message sent through a port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMessage {
    /// Unique message ID
    pub message_id: String,
    /// Sender agent PID
    pub sender_pid: String,
    /// Port this message was sent through
    pub port_id: String,
    /// Timestamp (ms epoch)
    pub timestamp: i64,
    /// Message payload
    pub payload: PortPayload,
}

/// Port message payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PortPayload {
    /// Share specific packet CIDs
    #[serde(rename = "packet_share")]
    PacketShare {
        cids: Vec<String>,
        namespace: String,
    },
    /// Grant tool access
    #[serde(rename = "tool_grant")]
    ToolGrant {
        tool_id: String,
        allowed_actions: Vec<String>,
    },
    /// Event notification
    #[serde(rename = "event")]
    Event {
        event_type: String,
        data: serde_json::Value,
    },
    /// Request
    #[serde(rename = "request")]
    Request {
        request_id: String,
        action: String,
        body: serde_json::Value,
    },
    /// Response
    #[serde(rename = "response")]
    Response {
        request_id: String,
        success: bool,
        body: serde_json::Value,
    },
    /// Pipeline handoff
    #[serde(rename = "pipeline_handoff")]
    PipelineHandoff {
        pipeline_id: String,
        step: u32,
        context_cids: Vec<String>,
        next_action: String,
    },
}

// =============================================================================
// Phase 8e: UCAN-Compatible Capability Tokens
// =============================================================================

/// Delegation proof — a single link in a UCAN-compatible delegation chain.
///
/// Each proof attenuates (narrows) the parent's capabilities.
/// Inspired by UCAN spec, Google Macaroons, Fuchsia handles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationProof {
    /// CID of this proof (content-addressed)
    pub proof_cid: String,
    /// Issuer principal ID
    pub issuer: String,
    /// Subject (who the capability is for)
    pub subject: String,
    /// Allowed action patterns (glob)
    pub allowed_actions: Vec<String>,
    /// Allowed resource patterns (glob)
    pub allowed_resources: Vec<String>,
    /// Expiration (ms epoch)
    pub expires_at: i64,
    /// CID of parent proof (None = root)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_proof_cid: Option<String>,
    /// Ed25519 signature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Issued timestamp
    pub issued_at: i64,
    /// Whether this proof has been revoked
    #[serde(default)]
    pub revoked: bool,
}

/// Delegation chain — ordered sequence of proofs from root to leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationChain {
    /// Ordered proofs (index 0 = root, last = current)
    pub proofs: Vec<DelegationProof>,
    /// CID of the full chain (content-addressed)
    pub chain_cid: String,
}

impl DelegationChain {
    /// Verify the chain: each proof attenuates its parent, none expired or revoked.
    pub fn verify(&self, now_ms: i64) -> Result<(), String> {
        if self.proofs.is_empty() {
            return Err("Empty delegation chain".to_string());
        }
        for (i, proof) in self.proofs.iter().enumerate() {
            if proof.revoked {
                return Err(format!("Proof {} is revoked", i));
            }
            if proof.expires_at > 0 && proof.expires_at < now_ms {
                return Err(format!("Proof {} expired at {}", i, proof.expires_at));
            }
            if i > 0 {
                let parent = &self.proofs[i - 1];
                // Attenuation check: child actions must be subset of parent actions
                for action in &proof.allowed_actions {
                    if !parent.allowed_actions.iter().any(|pa| {
                        pa == "*" || pa == action || (pa.ends_with('*') && action.starts_with(&pa[..pa.len()-1]))
                    }) {
                        return Err(format!(
                            "Proof {} action '{}' not covered by parent", i, action
                        ));
                    }
                }
                // Subject chain: child issuer must be parent subject
                if proof.issuer != parent.subject {
                    return Err(format!(
                        "Proof {} issuer '{}' != parent subject '{}'",
                        i, proof.issuer, parent.subject
                    ));
                }
            }
        }
        Ok(())
    }

    /// Verify Ed25519 signatures on all proofs in the chain.
    /// `public_keys` maps issuer principal IDs to their Ed25519 public key bytes (32 bytes).
    /// Each proof's signature is verified against the canonical JSON of the proof
    /// (excluding the signature field itself).
    pub fn verify_signatures(
        &self,
        public_keys: &std::collections::HashMap<String, [u8; 32]>,
    ) -> Result<(), String> {
        use ed25519_dalek::{Signature, VerifyingKey};

        for (i, proof) in self.proofs.iter().enumerate() {
            let sig_hex = match &proof.signature {
                Some(s) if !s.is_empty() => s,
                _ => return Err(format!("Proof {} has no signature", i)),
            };

            let pk_bytes = public_keys.get(&proof.issuer).ok_or_else(|| {
                format!("No public key for issuer '{}'", proof.issuer)
            })?;

            let verifying_key = VerifyingKey::from_bytes(pk_bytes)
                .map_err(|e| format!("Invalid public key for '{}': {}", proof.issuer, e))?;

            // Canonical message: JSON of proof fields excluding signature
            let canonical = serde_json::json!({
                "proof_cid": proof.proof_cid,
                "issuer": proof.issuer,
                "subject": proof.subject,
                "allowed_actions": proof.allowed_actions,
                "allowed_resources": proof.allowed_resources,
                "expires_at": proof.expires_at,
                "parent_proof_cid": proof.parent_proof_cid,
                "issued_at": proof.issued_at,
            });
            let message = serde_json::to_vec(&canonical)
                .map_err(|e| format!("Serialization error: {}", e))?;

            let sig_bytes = hex_decode(sig_hex)
                .map_err(|e| format!("Invalid signature hex for proof {}: {}", i, e))?;

            if sig_bytes.len() != 64 {
                return Err(format!("Proof {} signature must be 64 bytes, got {}", i, sig_bytes.len()));
            }

            let signature = Signature::from_bytes(sig_bytes[..64].try_into().unwrap());

            // Use verify_strict: rejects malleable signatures (S >= L) and small-order keys
            verifying_key.verify_strict(&message, &signature)
                .map_err(|_| format!("Proof {} signature verification failed", i))?;
        }
        Ok(())
    }

    /// Sign a proof with an Ed25519 signing key. Returns hex-encoded signature.
    pub fn sign_proof(
        proof: &DelegationProof,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> String {
        use ed25519_dalek::Signer;

        let canonical = serde_json::json!({
            "proof_cid": proof.proof_cid,
            "issuer": proof.issuer,
            "subject": proof.subject,
            "allowed_actions": proof.allowed_actions,
            "allowed_resources": proof.allowed_resources,
            "expires_at": proof.expires_at,
            "parent_proof_cid": proof.parent_proof_cid,
            "issued_at": proof.issued_at,
        });
        let message = serde_json::to_vec(&canonical).unwrap();
        let signature = signing_key.sign(&message);
        hex_encode(&signature.to_bytes())
    }

    /// Check if the chain grants a specific action on a specific resource.
    pub fn allows(&self, action: &str, resource: &str, now_ms: i64) -> bool {
        if self.verify(now_ms).is_err() {
            return false;
        }
        // The leaf (last) proof determines the effective capability
        if let Some(leaf) = self.proofs.last() {
            let action_ok = leaf.allowed_actions.iter().any(|a| {
                a == "*" || a == action || (a.ends_with('*') && action.starts_with(&a[..a.len()-1]))
            });
            let resource_ok = leaf.allowed_resources.iter().any(|r| {
                r == "*" || r == resource || (r.ends_with('*') && resource.starts_with(&r[..r.len()-1]))
            });
            action_ok && resource_ok
        } else {
            false
        }
    }
}

/// Memory kernel operation — system call for memory management
///
/// Every memory operation goes through the kernel as a syscall.
/// Each syscall is logged in the audit trail for full traceability.
///
/// Analogous to: AIOS LLM syscalls (mem_write, mem_read, mem_clear, mem_alloc)
/// + Linux syscalls (mmap, munmap, mprotect, brk)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKernelOp {
    // --- Agent lifecycle ---
    /// Register a new agent (creates ACB + memory region)
    AgentRegister,
    /// Start agent execution
    AgentStart,
    /// Suspend agent (save context)
    AgentSuspend,
    /// Resume agent (restore context)
    AgentResume,
    /// Terminate agent
    AgentTerminate,

    // --- Memory operations ---
    /// Allocate memory region for an agent
    MemAlloc,
    /// Write a MemPacket to memory
    MemWrite,
    /// Read a MemPacket from memory
    MemRead,
    /// Evict packets from memory (reclaim space)
    MemEvict,
    /// Promote packet to higher tier (cold → warm → hot)
    MemPromote,
    /// Demote packet to lower tier (hot → warm → cold → archive)
    MemDemote,
    /// Clear all memory for an agent
    MemClear,
    /// Seal memory region (make read-only, for compliance)
    MemSeal,

    // --- Session operations ---
    /// Create a new session
    SessionCreate,
    /// Close a session
    SessionClose,
    /// Compress/summarize a session
    SessionCompress,

    // --- Context operations ---
    /// Snapshot execution context (for suspend/resume)
    ContextSnapshot,
    /// Restore execution context
    ContextRestore,

    // --- Access control ---
    /// Grant access to a namespace
    AccessGrant,
    /// Revoke access to a namespace
    AccessRevoke,
    /// Check access permission
    AccessCheck,

    // --- Maintenance ---
    /// Garbage collect unreferenced packets
    GarbageCollect,
    /// Rebuild indexes
    IndexRebuild,
    /// Verify Merkle tree integrity
    IntegrityCheck,

    // --- Port operations (Phase 8d) ---
    /// Create a typed communication port
    PortCreate,
    /// Bind an agent to a port
    PortBind,
    /// Send a message through a port
    PortSend,
    /// Receive a message from a port
    PortReceive,
    /// Close a port
    PortClose,
    /// Delegate a port capability to another agent
    PortDelegate,

    // --- Tool operations (Phase 9b) ---
    /// Dispatch a tool call (default-deny, requires ToolBinding)
    ToolDispatch,
}

impl std::fmt::Display for MemoryKernelOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).unwrap_or_else(|_| "unknown".to_string());
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// Execution context — the current state of an agent's execution
///
/// Captured on suspend, restored on resume. This is the agent equivalent
/// of a CPU register file + stack pointer saved during a context switch.
///
/// Analogous to: OS thread context (registers, stack, program counter)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionContext {
    /// Agent PID
    pub agent_pid: String,
    /// Current session ID
    pub session_id: String,
    /// Current pipeline ID
    pub pipeline_id: String,
    /// Step counter (how many steps executed in this pipeline)
    pub step_counter: u64,
    /// Current packet type being processed
    pub current_step_type: Option<PacketType>,
    /// Pending tool calls (waiting for results)
    #[serde(default)]
    pub pending_tool_calls: Vec<String>,
    /// Context window: CIDs of packets currently in the agent's "working memory"
    #[serde(default)]
    pub context_window: Vec<Cid>,
    /// Context window token count
    pub context_tokens: u64,
    /// Context window max tokens
    pub context_max_tokens: u64,
    /// Accumulated reasoning chain (CIDs of decision/extraction packets)
    #[serde(default)]
    pub reasoning_chain: Vec<Cid>,
    /// Snapshot timestamp (ms epoch)
    pub snapshot_at: i64,
    /// Snapshot CID (content-addressed for verification)
    pub snapshot_cid: Option<Cid>,
    /// Whether this context has been restored (vs. fresh)
    #[serde(default)]
    pub restored: bool,
    /// Number of times this context has been suspended/restored
    #[serde(default)]
    pub suspend_count: u32,
    /// D5 FIX: Snapshot of the session state at snapshot time.
    /// Without this, restoring a context loses session summary, compression meta,
    /// and packet_cids — the session appears empty after restore.
    #[serde(default)]
    pub session_snapshot: Option<SessionEnvelope>,
}

/// Kernel audit entry — every kernel operation is logged
///
/// This is the foundation of the audit trail. Every syscall, every
/// memory operation, every access check is recorded with full provenance.
///
/// Satisfies: EU AI Act Art. 12 (logging), HIPAA §164.312 (audit controls),
/// FINRA Rule 3110 (supervision), FDA 21 CFR Part 11 (electronic records)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelAuditEntry {
    /// Unique audit entry ID
    pub audit_id: String,
    /// Timestamp (ms epoch)
    pub timestamp: i64,
    /// Kernel operation performed
    pub operation: MemoryKernelOp,
    /// Agent PID that initiated the operation
    pub agent_pid: String,
    /// Target of the operation (packet CID, session ID, namespace, etc.)
    pub target: Option<String>,
    /// Operation outcome
    pub outcome: OpOutcome,
    /// Reason for the operation
    pub reason: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Duration in microseconds
    pub duration_us: Option<u64>,
    /// AAPI VĀKYA ID (if this operation was authorized by AAPI)
    pub vakya_id: Option<String>,
    /// Before-state hash (for mutations)
    pub before_hash: Option<String>,
    /// After-state hash (for mutations)
    pub after_hash: Option<String>,
    /// Merkle root at time of operation
    pub merkle_root: Option<String>,
    /// SCITT receipt CID linking this audit entry to a transparency log (Phase 9h)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scitt_receipt_cid: Option<String>,
}

/// Outcome of a kernel operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpOutcome {
    /// Operation succeeded
    Success,
    /// Operation denied (access control)
    Denied,
    /// Operation failed (error)
    Failed,
    /// Operation skipped (no-op, e.g., evict on empty region)
    Skipped,
    /// Operation pending (async, waiting for approval)
    Pending,
}

impl std::fmt::Display for OpOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpOutcome::Success => write!(f, "success"),
            OpOutcome::Denied => write!(f, "denied"),
            OpOutcome::Failed => write!(f, "failed"),
            OpOutcome::Skipped => write!(f, "skipped"),
            OpOutcome::Pending => write!(f, "pending"),
        }
    }
}

/// Any VAC object (union type for storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VacObject {
    #[serde(rename = "event")]
    Event(Event),
    #[serde(rename = "claim_bundle")]
    ClaimBundle(ClaimBundle),
    #[serde(rename = "bracket")]
    Bracket(Bracket),
    #[serde(rename = "node")]
    Node(Node),
    #[serde(rename = "frame")]
    Frame(Frame),
    #[serde(rename = "block_header")]
    BlockHeader(BlockHeader),
    #[serde(rename = "manifest_root")]
    ManifestRoot(ManifestRoot),
    #[serde(rename = "vault_patch")]
    VaultPatch(VaultPatch),
    #[serde(rename = "ie")]
    InterferenceEdge(InterferenceEdge),
    #[serde(rename = "prolly_node")]
    ProllyNode(ProllyNode),
    #[serde(rename = "mem_packet")]
    MemPacket(MemPacket),
    #[serde(rename = "session")]
    Session(SessionEnvelope),
}

// =============================================================================
// Hex encoding/decoding helpers (Phase 9g)
// =============================================================================

/// Encode bytes to hex string
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Odd-length hex string".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_creation() {
        let source = Source {
            kind: SourceKind::User,
            principal_id: "did:key:z6Mk...".to_string(),
        };
        let payload_cid = Cid::default();
        let event = Event::new(1706764800000, payload_cid, source);
        
        assert_eq!(event.type_, "event");
        assert_eq!(event.version, 1);
        assert_eq!(event.trust_tier, 1);
    }
    
    #[test]
    fn test_claim_bundle_creation() {
        let source = Source {
            kind: SourceKind::User,
            principal_id: "did:key:z6Mk...".to_string(),
        };
        let claim = ClaimBundle::new(
            "user:alice".to_string(),
            "preference:food".to_string(),
            serde_json::json!("vegetarian"),
            source,
        );
        
        assert_eq!(claim.type_, "claim_bundle");
        assert_eq!(claim.value_type, "string");
    }
    
    #[test]
    fn test_mem_packet_creation() {
        let source = Source {
            kind: SourceKind::Tool,
            principal_id: "did:key:z6MkAgent".to_string(),
        };
        let payload_cid = Cid::default();
        let packet = MemPacket::new(
            PacketType::LlmRaw,
            serde_json::json!({"response": "Patient reports penicillin allergy"}),
            payload_cid,
            "patient:P-44291".to_string(),
            "pipeline:abc123".to_string(),
            source,
            1706764800000,
        );
        
        assert_eq!(packet.type_, "mem_packet");
        assert_eq!(packet.version, 1);
        assert_eq!(*packet.packet_type(), PacketType::LlmRaw);
        assert_eq!(packet.subject_id, "patient:P-44291");
        assert_eq!(packet.pipeline_id, "pipeline:abc123");
        assert_eq!(packet.provenance.trust_tier, 2); // Tool = tier 2
        assert_eq!(packet.provenance.epistemic, Epistemic::Observed);
        assert!(!packet.has_authority());
        assert!(!packet.is_superseding());
        assert_eq!(packet.index.block_no, -1); // Uncommitted
    }
    
    #[test]
    fn test_mem_packet_builder_chain() {
        let source = Source {
            kind: SourceKind::SelfSource,
            principal_id: "did:key:z6MkSelf".to_string(),
        };
        let payload_cid = Cid::default();
        let evidence_cid = Cid::default();
        
        let packet = MemPacket::new(
            PacketType::Extraction,
            serde_json::json!({"allergy": "penicillin", "severity": "severe"}),
            payload_cid,
            "patient:P-44291".to_string(),
            "pipeline:abc123".to_string(),
            source,
            1706764800000,
        )
        .with_evidence(vec![evidence_cid])
        .with_confidence(0.95)
        .with_reasoning("Extracted from LLM raw output".to_string())
        .with_domain_code("Z88.0".to_string())
        .with_entities(vec!["penicillin".to_string(), "patient:P-44291".to_string()])
        .with_tags(vec!["allergy".to_string(), "medication".to_string()])
        .with_authority(
            "vakya:v-001".to_string(),
            "agent:healthcare-bot".to_string(),
            "cap:ehr.write".to_string(),
        )
        .with_seq_index(2);
        
        assert_eq!(packet.provenance.trust_tier, 3); // Self = tier 3
        assert_eq!(packet.provenance.evidence_refs.len(), 1);
        assert_eq!(packet.provenance.confidence, Some(0.95));
        assert_eq!(packet.provenance.reasoning.as_deref(), Some("Extracted from LLM raw output"));
        assert_eq!(packet.provenance.domain_code.as_deref(), Some("Z88.0"));
        assert_eq!(packet.content.entities.len(), 2);
        assert_eq!(packet.content.tags.len(), 2);
        assert!(packet.has_authority());
        assert_eq!(packet.authority.vakya_id.as_deref(), Some("vakya:v-001"));
        assert_eq!(packet.index.seq_index, 2);
    }
    
    #[test]
    fn test_mem_packet_supersedes() {
        let source = Source {
            kind: SourceKind::User,
            principal_id: "did:key:z6MkUser".to_string(),
        };
        let old_cid = Cid::default();
        
        let packet = MemPacket::new(
            PacketType::Contradiction,
            serde_json::json!({"old": "no allergy", "new": "penicillin allergy"}),
            Cid::default(),
            "patient:P-44291".to_string(),
            "pipeline:abc456".to_string(),
            source,
            1706764900000,
        )
        .with_supersedes(old_cid);
        
        assert!(packet.is_superseding());
        assert_eq!(packet.provenance.epistemic, Epistemic::Retracted);
    }
    
    #[test]
    fn test_packet_type_display() {
        assert_eq!(PacketType::Input.to_string(), "input");
        assert_eq!(PacketType::LlmRaw.to_string(), "llm_raw");
        assert_eq!(PacketType::Extraction.to_string(), "extraction");
        assert_eq!(PacketType::Decision.to_string(), "decision");
        assert_eq!(PacketType::ToolCall.to_string(), "tool_call");
        assert_eq!(PacketType::ToolResult.to_string(), "tool_result");
        assert_eq!(PacketType::Action.to_string(), "action");
        assert_eq!(PacketType::Feedback.to_string(), "feedback");
        assert_eq!(PacketType::Contradiction.to_string(), "contradiction");
        assert_eq!(PacketType::StateChange.to_string(), "state_change");
    }
    
    #[test]
    fn test_trust_tier_assignment() {
        let self_source = Source { kind: SourceKind::SelfSource, principal_id: "s".to_string() };
        let tool_source = Source { kind: SourceKind::Tool, principal_id: "t".to_string() };
        let user_source = Source { kind: SourceKind::User, principal_id: "u".to_string() };
        let web_source = Source { kind: SourceKind::Web, principal_id: "w".to_string() };
        let untrusted = Source { kind: SourceKind::Untrusted, principal_id: "x".to_string() };
        
        let mk = |s: Source| MemPacket::new(PacketType::Input, serde_json::json!(null), Cid::default(), "s".into(), "p".into(), s, 0);
        
        assert_eq!(mk(self_source).provenance.trust_tier, 3);
        assert_eq!(mk(tool_source).provenance.trust_tier, 2);
        assert_eq!(mk(user_source).provenance.trust_tier, 1);
        assert_eq!(mk(web_source).provenance.trust_tier, 0);
        assert_eq!(mk(untrusted).provenance.trust_tier, 0);
    }
    
    #[test]
    fn test_vac_object_variants() {
        let source = Source { kind: SourceKind::User, principal_id: "u".to_string() };
        let packet = MemPacket::new(
            PacketType::Decision,
            serde_json::json!({"action": "update_allergy"}),
            Cid::default(),
            "patient:P-44291".to_string(),
            "pipeline:abc".to_string(),
            source,
            1706764800000,
        );
        
        let obj = VacObject::MemPacket(packet);
        match &obj {
            VacObject::MemPacket(p) => {
                assert_eq!(*p.packet_type(), PacketType::Decision);
            }
            _ => panic!("Expected MemPacket variant"),
        }
    }
    
    #[test]
    fn test_memory_scope_auto_derived() {
        let mk = |pt: PacketType| {
            let s = Source { kind: SourceKind::Tool, principal_id: "t".into() };
            MemPacket::new(pt, serde_json::json!(null), Cid::default(), "s".into(), "p".into(), s, 0)
        };
        
        // Working scope: transient artifacts
        assert_eq!(mk(PacketType::Input).scope, MemoryScope::Working);
        assert_eq!(mk(PacketType::LlmRaw).scope, MemoryScope::Working);
        assert_eq!(mk(PacketType::ToolResult).scope, MemoryScope::Working);
        
        // Semantic scope: extracted knowledge
        assert_eq!(mk(PacketType::Extraction).scope, MemoryScope::Semantic);
        assert_eq!(mk(PacketType::Contradiction).scope, MemoryScope::Semantic);
        
        // Episodic scope: experiences and actions
        assert_eq!(mk(PacketType::Decision).scope, MemoryScope::Episodic);
        assert_eq!(mk(PacketType::Action).scope, MemoryScope::Episodic);
        assert_eq!(mk(PacketType::Feedback).scope, MemoryScope::Episodic);
        assert_eq!(mk(PacketType::ToolCall).scope, MemoryScope::Episodic);
        assert_eq!(mk(PacketType::StateChange).scope, MemoryScope::Episodic);
    }
    
    #[test]
    fn test_memory_tier_default_hot() {
        let s = Source { kind: SourceKind::User, principal_id: "u".into() };
        let packet = MemPacket::new(PacketType::Input, serde_json::json!(null), Cid::default(), "s".into(), "p".into(), s, 0);
        assert_eq!(packet.tier, MemoryTier::Hot);
    }
    
    #[test]
    fn test_mem_packet_with_session_and_namespace() {
        let s = Source { kind: SourceKind::User, principal_id: "u".into() };
        let packet = MemPacket::new(PacketType::Input, serde_json::json!("hello"), Cid::default(), "user:alice".into(), "p1".into(), s, 100)
            .with_session("session:abc".to_string())
            .with_namespace("org:acme/agent:support".to_string());
        
        assert_eq!(packet.session_id.as_deref(), Some("session:abc"));
        assert_eq!(packet.namespace.as_deref(), Some("org:acme/agent:support"));
    }
    
    #[test]
    fn test_mem_packet_with_tool_interaction() {
        let s = Source { kind: SourceKind::Tool, principal_id: "t".into() };
        let tool = ToolInteraction {
            tool_name: "openai.chat".to_string(),
            tool_version: Some("v1".to_string()),
            request: serde_json::json!({"model": "gpt-4o", "messages": []}),
            response: Some(serde_json::json!({"choices": []})),
            status_code: Some(200),
            duration_ms: Some(1500),
            token_usage: Some(TokenUsage {
                prompt_tokens: 100,
                completion_tokens: 50,
                total_tokens: 150,
                model: "gpt-4o".to_string(),
            }),
            cost_usd: Some(0.003),
            error: None,
            retried: false,
            retry_count: 0,
        };
        
        let packet = MemPacket::new(PacketType::ToolCall, serde_json::json!(null), Cid::default(), "s".into(), "p".into(), s, 0)
            .with_tool_interaction(tool);
        
        assert!(packet.tool_interaction.is_some());
        let ti = packet.tool_interaction.unwrap();
        assert_eq!(ti.tool_name, "openai.chat");
        assert_eq!(ti.token_usage.unwrap().total_tokens, 150);
    }
    
    #[test]
    fn test_mem_packet_with_state_snapshot() {
        let s = Source { kind: SourceKind::Tool, principal_id: "t".into() };
        let snap = StateSnapshot {
            resource_id: "ehr:patient:P-44291".to_string(),
            resource_type: "ehr_record".to_string(),
            before: Some(serde_json::json!({"allergies": []})),
            after: Some(serde_json::json!({"allergies": ["penicillin"]})),
            before_hash: None,
            after_hash: None,
            delta: Some(serde_json::json!({"added": ["penicillin"]})),
            reversible: true,
            reversal_instructions: Some(serde_json::json!({"action": "remove_allergy", "value": "penicillin"})),
        };
        
        let packet = MemPacket::new(PacketType::StateChange, serde_json::json!(null), Cid::default(), "s".into(), "p".into(), s, 0)
            .with_state_snapshot(snap);
        
        assert!(packet.state_snapshot.is_some());
        assert!(packet.state_snapshot.as_ref().unwrap().reversible);
    }
    
    #[test]
    fn test_mem_packet_tier_demote() {
        let s = Source { kind: SourceKind::User, principal_id: "u".into() };
        let mut packet = MemPacket::new(PacketType::Input, serde_json::json!(null), Cid::default(), "s".into(), "p".into(), s, 0);
        
        assert_eq!(packet.tier, MemoryTier::Hot);
        packet.demote(MemoryTier::Warm);
        assert_eq!(packet.tier, MemoryTier::Warm);
        packet.demote(MemoryTier::Cold);
        assert_eq!(packet.tier, MemoryTier::Cold);
        packet.demote(MemoryTier::Archive);
        assert_eq!(packet.tier, MemoryTier::Archive);
    }
    
    #[test]
    fn test_session_envelope_lifecycle() {
        let mut session = SessionEnvelope::new(
            "session:001".to_string(),
            "agent:healthcare-bot".to_string(),
            "org:hospital/team:er".to_string(),
            1706764800000,
        );
        
        assert_eq!(session.type_, "session");
        assert!(session.is_active());
        assert_eq!(session.packet_count(), 0);
        assert_eq!(session.tier, MemoryTier::Hot);
        assert_eq!(session.scope, MemoryScope::Episodic);
        
        // Add packets
        session.add_packet(Cid::default());
        session.add_packet(Cid::default());
        assert_eq!(session.packet_count(), 2);
        
        // Close session
        session.close(1706764900000);
        assert!(!session.is_active());
        assert_eq!(session.ended_at, Some(1706764900000));
        
        // Demote to warm
        session.demote(MemoryTier::Warm);
        assert_eq!(session.tier, MemoryTier::Warm);
    }
    
    #[test]
    fn test_memory_query_defaults() {
        let query = MemoryQuery {
            namespace: None,
            agent_id: Some("agent:bot".to_string()),
            session_id: None,
            subject_id: Some("user:alice".to_string()),
            packet_types: vec![PacketType::Extraction, PacketType::Decision],
            scope: Some(MemoryScope::Semantic),
            tier: None,
            time_from: Some(1706764800000),
            time_to: None,
            entities: vec!["penicillin".to_string()],
            tags: vec![],
            semantic_query: None,
            limit: 10,
            offset: 0,
            sort: QuerySort::RecencyDesc,
            min_trust_tier: Some(2),
            require_authority: false,
        };
        
        assert_eq!(query.packet_types.len(), 2);
        assert_eq!(query.limit, 10);
        assert_eq!(query.sort, QuerySort::RecencyDesc);
    }
    
    #[test]
    fn test_agent_namespace() {
        let ns = AgentNamespace {
            namespace_id: "org:acme/team:support/agent:triage".to_string(),
            agent_id: "agent:triage".to_string(),
            parent_namespace: Some("org:acme/team:support".to_string()),
            readable_namespaces: vec!["org:acme/shared".to_string()],
            writable_namespaces: vec!["org:acme/team:support/agent:triage".to_string()],
            quota_max_packets: 100000,
            current_packet_count: 0,
            created_at: 1706764800000,
        };
        
        assert_eq!(ns.readable_namespaces.len(), 1);
        assert_eq!(ns.writable_namespaces.len(), 1);
    }
    
    #[test]
    fn test_memory_tier_display() {
        assert_eq!(MemoryTier::Hot.to_string(), "hot");
        assert_eq!(MemoryTier::Warm.to_string(), "warm");
        assert_eq!(MemoryTier::Cold.to_string(), "cold");
        assert_eq!(MemoryTier::Archive.to_string(), "archive");
    }
    
    #[test]
    fn test_memory_scope_display() {
        assert_eq!(MemoryScope::Working.to_string(), "working");
        assert_eq!(MemoryScope::Episodic.to_string(), "episodic");
        assert_eq!(MemoryScope::Semantic.to_string(), "semantic");
        assert_eq!(MemoryScope::Procedural.to_string(), "procedural");
    }

    // =========================================================================
    // Agent OS Memory Kernel Tests
    // =========================================================================

    #[test]
    fn test_agent_control_block_lifecycle() {
        let mut acb = AgentControlBlock::new(
            "pid:001".to_string(),
            "healthcare-bot".to_string(),
            "org:hospital/team:er".to_string(),
            1706764800000,
        );

        // Initial state
        assert_eq!(acb.status, AgentStatus::Registered);
        assert_eq!(acb.priority, 128);
        assert!(!acb.is_alive());
        assert!(!acb.is_terminated());

        // Start
        acb.status = AgentStatus::Running;
        assert!(acb.is_alive());

        // Suspend
        acb.status = AgentStatus::Suspended;
        assert!(acb.is_alive());

        // Resume
        acb.status = AgentStatus::Running;
        assert!(acb.is_alive());

        // Wait for human input
        acb.status = AgentStatus::Waiting;
        assert!(acb.is_alive());

        // Complete
        acb.status = AgentStatus::Completed;
        acb.terminated_at = Some(1706764900000);
        assert!(acb.is_terminated());
        assert!(!acb.is_alive());
    }

    #[test]
    fn test_agent_control_block_with_capabilities() {
        let mut acb = AgentControlBlock::new(
            "pid:002".to_string(),
            "trading-bot".to_string(),
            "org:finra/desk:equity".to_string(),
            1706764800000,
        );

        acb.capabilities = vec!["cap:trade-execute".to_string(), "cap:market-data-read".to_string()];
        acb.allowed_tools = vec!["bloomberg.api".to_string(), "fix.gateway".to_string()];
        acb.model = Some("gpt-4o".to_string());
        acb.framework = Some("langchain".to_string());

        assert_eq!(acb.capabilities.len(), 2);
        assert_eq!(acb.allowed_tools.len(), 2);
    }

    #[test]
    fn test_memory_region_quota() {
        let mut region = MemoryRegion::new("org:test".to_string());

        // Unlimited by default
        assert!(region.has_capacity());
        assert_eq!(region.usage_ratio(), 0.0);

        // Set quota
        region.quota_packets = 1000;
        region.used_packets = 500;
        assert!(region.has_capacity());
        assert!((region.usage_ratio() - 0.5).abs() < f64::EPSILON);

        // At capacity
        region.used_packets = 1000;
        assert!(!region.has_capacity());
        assert!((region.usage_ratio() - 1.0).abs() < f64::EPSILON);

        // Sealed
        region.used_packets = 0;
        region.sealed = true;
        assert!(!region.has_capacity());
    }

    #[test]
    fn test_memory_protection_defaults() {
        let prot = MemoryProtection::default();
        assert!(prot.read);
        assert!(prot.write);
        assert!(prot.execute);
        assert!(!prot.share);
        assert!(prot.evict);
        assert!(!prot.requires_approval);
    }

    #[test]
    fn test_memory_protection_compliance_mode() {
        let prot = MemoryProtection {
            read: true,
            write: false,
            execute: false,
            share: false,
            evict: false,
            requires_approval: true,
        };
        // Compliance mode: read-only, no eviction, requires approval
        assert!(prot.read);
        assert!(!prot.write);
        assert!(!prot.evict);
        assert!(prot.requires_approval);
    }

    #[test]
    fn test_eviction_policy_default() {
        let policy = EvictionPolicy::default();
        assert_eq!(policy, EvictionPolicy::Lru);
    }

    #[test]
    fn test_memory_kernel_ops() {
        // Verify all ops serialize correctly
        let ops = vec![
            MemoryKernelOp::AgentRegister,
            MemoryKernelOp::MemWrite,
            MemoryKernelOp::MemEvict,
            MemoryKernelOp::MemSeal,
            MemoryKernelOp::SessionCreate,
            MemoryKernelOp::ContextSnapshot,
            MemoryKernelOp::AccessGrant,
            MemoryKernelOp::GarbageCollect,
            MemoryKernelOp::IntegrityCheck,
        ];
        for op in &ops {
            let s = op.to_string();
            assert!(!s.is_empty());
            assert!(!s.contains("unknown"));
        }
    }

    #[test]
    fn test_execution_context() {
        let ctx = ExecutionContext {
            agent_pid: "pid:001".to_string(),
            session_id: "session:abc".to_string(),
            pipeline_id: "pipeline:intake".to_string(),
            step_counter: 5,
            current_step_type: Some(PacketType::Decision),
            pending_tool_calls: vec!["call:openai-1".to_string()],
            context_window: vec![Cid::default(), Cid::default()],
            context_tokens: 3500,
            context_max_tokens: 128000,
            reasoning_chain: vec![Cid::default()],
            snapshot_at: 1706764800000,
            snapshot_cid: None,
            restored: false,
            suspend_count: 0,
            session_snapshot: None,
        };

        assert_eq!(ctx.step_counter, 5);
        assert_eq!(ctx.context_window.len(), 2);
        assert_eq!(ctx.reasoning_chain.len(), 1);
        assert!(!ctx.restored);
    }

    #[test]
    fn test_kernel_audit_entry() {
        let entry = KernelAuditEntry {
            audit_id: "audit:001".to_string(),
            timestamp: 1706764800000,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:001".to_string(),
            target: Some("bafy2bzace...packet-cid".to_string()),
            outcome: OpOutcome::Success,
            reason: Some("Store LLM extraction result".to_string()),
            error: None,
            duration_us: Some(450),
            vakya_id: Some("vakya:v-001".to_string()),
            before_hash: None,
            after_hash: Some("sha256:abc123".to_string()),
            merkle_root: Some("bafy2bzace...root".to_string()),
            scitt_receipt_cid: None,
        };

        assert_eq!(entry.outcome, OpOutcome::Success);
        assert_eq!(entry.outcome.to_string(), "success");
        assert!(entry.error.is_none());
    }

    #[test]
    fn test_kernel_audit_denied() {
        let entry = KernelAuditEntry {
            audit_id: "audit:002".to_string(),
            timestamp: 1706764800000,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:rogue".to_string(),
            target: Some("ns:org:hospital/team:er".to_string()),
            outcome: OpOutcome::Denied,
            reason: None,
            error: Some("Agent pid:rogue lacks write access to namespace org:hospital/team:er".to_string()),
            duration_us: Some(12),
            vakya_id: None,
            before_hash: None,
            after_hash: None,
            merkle_root: None,
            scitt_receipt_cid: None,
        };

        assert_eq!(entry.outcome, OpOutcome::Denied);
        assert!(entry.error.is_some());
    }

    #[test]
    fn test_agent_status_display() {
        assert_eq!(AgentStatus::Registered.to_string(), "registered");
        assert_eq!(AgentStatus::Running.to_string(), "running");
        assert_eq!(AgentStatus::Suspended.to_string(), "suspended");
        assert_eq!(AgentStatus::Waiting.to_string(), "waiting");
        assert_eq!(AgentStatus::Completed.to_string(), "completed");
        assert_eq!(AgentStatus::Failed.to_string(), "failed");
        assert_eq!(AgentStatus::Terminated.to_string(), "terminated");
    }

    #[test]
    fn test_op_outcome_display() {
        assert_eq!(OpOutcome::Success.to_string(), "success");
        assert_eq!(OpOutcome::Denied.to_string(), "denied");
        assert_eq!(OpOutcome::Failed.to_string(), "failed");
        assert_eq!(OpOutcome::Skipped.to_string(), "skipped");
        assert_eq!(OpOutcome::Pending.to_string(), "pending");
    }

    #[test]
    fn test_acb_parent_child_agents() {
        let mut parent = AgentControlBlock::new(
            "pid:orchestrator".to_string(),
            "orchestrator".to_string(),
            "org:acme".to_string(),
            1706764800000,
        );

        let mut child = AgentControlBlock::new(
            "pid:worker-1".to_string(),
            "worker-1".to_string(),
            "org:acme".to_string(),
            1706764800000,
        );

        child.parent_pid = Some("pid:orchestrator".to_string());
        parent.child_pids.push("pid:worker-1".to_string());

        assert_eq!(parent.child_pids.len(), 1);
        assert_eq!(child.parent_pid.as_deref(), Some("pid:orchestrator"));
    }
}
