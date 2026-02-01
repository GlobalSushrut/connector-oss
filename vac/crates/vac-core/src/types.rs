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
}
