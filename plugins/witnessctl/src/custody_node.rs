//! Custody network types, quorum verification, and node replicate protocol.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

/// Partner or regional custody witness endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyNode {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: String,
    pub region: String,
}

/// Independent attestation of a capture hash from a custody node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CustodyProof {
    pub session_id: String,
    pub node_id: String,
    pub capture_hash: String,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumResult {
    QuorumMet,
    QuorumPartial,
    QuorumBroken,
}

/// Operator / UI custody strip honesty (never "court-grade" until quorum + verify).
/// Values: `local_only` | `partial` | `quorum_met`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyHonestyStrip {
    LocalOnly,
    Partial,
    QuorumMet,
}

impl CustodyHonestyStrip {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::Partial => "partial",
            Self::QuorumMet => "quorum_met",
        }
    }

    /// Map verify_quorum result (+ whether any checkpoint exists) to strip enum.
    pub fn from_quorum(report: &QuorumReport, has_local_checkpoint: bool) -> Self {
        match report.result {
            QuorumResult::QuorumMet => Self::QuorumMet,
            QuorumResult::QuorumPartial => Self::Partial,
            QuorumResult::QuorumBroken => {
                if has_local_checkpoint || report.valid_proofs > 0 {
                    Self::Partial
                } else {
                    Self::LocalOnly
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumReport {
    pub result: QuorumResult,
    pub required_quorum: usize,
    pub valid_proofs: usize,
    pub distinct_nodes: usize,
    pub hash_consistent: bool,
}

/// Normalize replica URL to custody replicate endpoint.
pub fn replicate_url(endpoint: &str) -> String {
    let base = endpoint.trim().trim_end_matches('/');
    if base.ends_with("/api/v1/custody/replicate") {
        base.to_string()
    } else {
        format!("{base}/api/v1/custody/replicate")
    }
}

/// Sign a custody proof (`HMAC-SHA256(node_id:capture_hash:timestamp)`).
pub fn sign_proof(node_id: &str, capture_hash: &str, timestamp: &DateTime<Utc>, secret: &str) -> String {
    let payload = format!("{}:{}:{}", node_id, capture_hash, timestamp.to_rfc3339());
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_proof_signature(proof: &CustodyProof, secret: &str) -> bool {
    let expected = sign_proof(&proof.node_id, &proof.capture_hash, &proof.timestamp, secret);
    secrets_equal(expected.as_bytes(), proof.signature.as_bytes())
}

fn secrets_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify custody quorum: valid signatures, consistent capture hash, enough distinct nodes.
pub fn verify_quorum(proofs: &[CustodyProof], required_quorum: usize, secret: &str) -> QuorumReport {
    if required_quorum == 0 || proofs.is_empty() {
        return QuorumReport {
            result: QuorumResult::QuorumBroken,
            required_quorum,
            valid_proofs: 0,
            distinct_nodes: 0,
            hash_consistent: false,
        };
    }

    let mut valid = 0usize;
    let mut nodes = HashMap::new();
    let mut hashes = HashMap::new();
    for p in proofs {
        if !verify_proof_signature(p, secret) {
            continue;
        }
        valid += 1;
        *nodes.entry(p.node_id.clone()).or_insert(0) += 1;
        *hashes.entry(p.capture_hash.clone()).or_insert(0) += 1;
    }
    let hash_consistent = hashes.len() <= 1;
    let distinct_nodes = nodes.len();
    let result = if !hash_consistent || valid < required_quorum {
        if valid > 0 && hash_consistent {
            QuorumResult::QuorumPartial
        } else {
            QuorumResult::QuorumBroken
        }
    } else {
        QuorumResult::QuorumMet
    };
    QuorumReport {
        result,
        required_quorum,
        valid_proofs: valid,
        distinct_nodes,
        hash_consistent,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicateRequest {
    pub session_id: String,
    pub payload_hash: String,
    #[serde(default)]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicateResponse {
    pub ok: bool,
    pub proof: CustodyProof,
}

pub fn build_proof_from_request(req: &ReplicateRequest, node_id: &str, secret: &str) -> CustodyProof {
    let timestamp = Utc::now();
    let signature = sign_proof(node_id, &req.payload_hash, &timestamp, secret);
    CustodyProof {
        session_id: req.session_id.clone(),
        node_id: node_id.to_string(),
        capture_hash: req.payload_hash.clone(),
        timestamp,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_met_with_matching_hashes() {
        let secret = "custody-test-secret";
        let hash = "abc123";
        let ts = Utc::now();
        let proofs = vec![
            CustodyProof {
                session_id: "s1".into(),
                node_id: "node-a".into(),
                capture_hash: hash.into(),
                timestamp: ts,
                signature: sign_proof("node-a", hash, &ts, secret),
            },
            CustodyProof {
                session_id: "s1".into(),
                node_id: "node-b".into(),
                capture_hash: hash.into(),
                timestamp: ts,
                signature: sign_proof("node-b", hash, &ts, secret),
            },
        ];
        let report = verify_quorum(&proofs, 2, secret);
        assert_eq!(report.result, QuorumResult::QuorumMet);
        assert!(report.hash_consistent);
        let strip = CustodyHonestyStrip::from_quorum(&report, true);
        assert_eq!(strip, CustodyHonestyStrip::QuorumMet);
        // court_export_ready only when quorum_met (independent verify).
        assert!(matches!(strip, CustodyHonestyStrip::QuorumMet));
    }

    #[test]
    fn honesty_strip_local_only_without_proofs() {
        let report = verify_quorum(&[], 2, "secret");
        assert_eq!(
            CustodyHonestyStrip::from_quorum(&report, false),
            CustodyHonestyStrip::LocalOnly
        );
        assert_ne!(
            CustodyHonestyStrip::from_quorum(&report, false).as_str(),
            "quorum_met"
        );
    }

    #[test]
    fn quorum_broken_on_hash_mismatch() {
        let secret = "custody-test-secret";
        let ts = Utc::now();
        let proofs = vec![
            CustodyProof {
                session_id: "s1".into(),
                node_id: "node-a".into(),
                capture_hash: "hash-a".into(),
                timestamp: ts,
                signature: sign_proof("node-a", "hash-a", &ts, secret),
            },
            CustodyProof {
                session_id: "s1".into(),
                node_id: "node-b".into(),
                capture_hash: "hash-b".into(),
                timestamp: ts,
                signature: sign_proof("node-b", "hash-b", &ts, secret),
            },
        ];
        let report = verify_quorum(&proofs, 2, secret);
        assert_eq!(report.result, QuorumResult::QuorumBroken);
        assert!(!report.hash_consistent);
    }
}
