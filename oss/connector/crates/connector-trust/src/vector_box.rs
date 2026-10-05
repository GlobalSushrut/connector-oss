//! Memory Vector Box — universal inspectable memory container.
//!
//! Lifts a content-addressed memory packet into a product-facing shape with:
//! - `super_key` — stable address key (prolly-compatible)
//! - `identity_key` — owning principal / agent DID / agent_pid
//! - `cid` + `timestamp_ms` — what TraceTramp prove already surfaces
//! - `raw` — payload / content plane projection
//! - `log` — audit / provenance projection for play and analysis

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Deterministic super key for a memory vector box (UTF-8, prolly-compatible).
///
/// Format: `{packet_type}/{subject_id}/{predicate}/{cid_short}`
pub fn build_super_key(
    packet_type: &str,
    subject_id: &str,
    predicate: &str,
    cid: &str,
) -> String {
    let cid_short = if cid.len() > 36 { &cid[..36] } else { cid };
    format!(
        "{}/{}/{}/{}",
        sanitize_key_part(packet_type),
        sanitize_key_part(subject_id),
        sanitize_key_part(predicate),
        cid_short
    )
}

fn sanitize_key_part(s: &str) -> String {
    s.chars()
        .map(|c| if c == '/' { '_' } else { c })
        .collect()
}

/// Hex digest of the super key — useful as a compact index id.
pub fn super_key_digest(super_key: &str) -> String {
    let hash = Sha256::digest(super_key.as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Universal memory vector box — audit, analyse, and play surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryVectorBox {
    /// Stable content/address key for this box.
    pub super_key: String,
    /// Owning identity (agent DID, principal subject, or agent_pid).
    pub identity_key: String,
    /// Content address of the packet (CIDv1 string when available).
    pub cid: String,
    /// Packet timestamp (unix ms).
    pub timestamp_ms: i64,
    /// Namespace the packet lives in (isolation boundary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Tenant when multi-tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Session correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Raw memory projection (payload + light content metadata).
    pub raw: MemoryRawPlane,
    /// Log / provenance / authority projection for auditing.
    pub log: MemoryLogPlane,
    /// Optional embedding vector (semantic channel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
    /// Related packet CIDs / graph edges.
    #[serde(default)]
    pub graph_links: Vec<String>,
    /// Memory cognitive type string (working/episodic/relational/…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_type: Option<String>,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryRawPlane {
    pub packet_type: String,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_cid: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryLogPlane {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vakya_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_ticket_id: Option<String>,
}

impl MemoryVectorBox {
    /// Build from flattened packet fields (platform / plugin adapters).
    pub fn from_parts(
        packet_type: &str,
        subject_id: &str,
        predicate: &str,
        cid: &str,
        timestamp_ms: i64,
        identity_key: impl Into<String>,
        raw: MemoryRawPlane,
        log: MemoryLogPlane,
    ) -> Self {
        let super_key = build_super_key(packet_type, subject_id, predicate, cid);
        Self {
            super_key,
            identity_key: identity_key.into(),
            cid: cid.to_string(),
            timestamp_ms,
            namespace: None,
            tenant_id: None,
            session_id: None,
            raw,
            log,
            embedding: None,
            graph_links: vec![],
            memory_type: None,
            contract_version: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn super_key_is_stable_and_sanitized() {
        let k = build_super_key("extraction", "patient/P1", "allergy", "bafybeiabcdefghijklmnopqrstuvwxyz012345");
        assert!(k.starts_with("extraction/patient_P1/allergy/"));
        assert_eq!(super_key_digest(&k).len(), 64);
    }
}
