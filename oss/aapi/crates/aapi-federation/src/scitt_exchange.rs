//! SCITT Receipt Exchange — Cross-org attestation.
//!
//! Issues and verifies SCITT transparency receipts for cross-cell actions.
//! Each organization has a keypair; receipts are signed attestations that
//! an action was executed and its evidence CIDs are authentic.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::debug;

use crate::error::{FederationError, FederationResult};

// ============================================================================
// Types
// ============================================================================

/// A SCITT transparency receipt for a cross-cell action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScittReceipt {
    /// Unique receipt ID.
    pub receipt_id: String,
    /// CID of the action record being attested.
    pub action_cid: String,
    /// CIDs of evidence artifacts.
    pub evidence_cids: Vec<String>,
    /// Issuer identifier (org or cell).
    pub issuer: String,
    /// Timestamp of issuance.
    pub issued_at: DateTime<Utc>,
    /// SHA-256 hash of the receipt payload (action_cid + evidence_cids + issuer + ts).
    pub payload_hash: String,
    /// Ed25519 signature over payload_hash (hex-encoded).
    /// In production this would be a real signature; here we use HMAC-like hash.
    pub signature: String,
}

// ============================================================================
// ScittExchange
// ============================================================================

/// Cross-org attestation via SCITT transparency receipts.
pub struct ScittExchange {
    /// Local issuer identifier.
    local_issuer: String,
    /// Local signing secret (simplified — in production use Ed25519 keypair).
    local_secret: Vec<u8>,
    /// Known issuers: issuer_id → public key / shared secret.
    known_issuers: HashMap<String, Vec<u8>>,
}

impl ScittExchange {
    pub fn new(local_issuer: impl Into<String>, local_secret: Vec<u8>) -> Self {
        Self {
            local_issuer: local_issuer.into(),
            local_secret,
            known_issuers: HashMap::new(),
        }
    }

    /// Register a known issuer's public key.
    pub fn register_issuer(&mut self, issuer_id: &str, public_key: Vec<u8>) {
        self.known_issuers
            .insert(issuer_id.to_string(), public_key);
    }

    /// Deregister an issuer.
    pub fn deregister_issuer(&mut self, issuer_id: &str) {
        self.known_issuers.remove(issuer_id);
    }

    /// Number of known issuers.
    pub fn issuer_count(&self) -> usize {
        self.known_issuers.len()
    }

    /// Issue a SCITT receipt for a cross-cell action.
    pub fn issue_receipt(
        &self,
        action_cid: &str,
        evidence_cids: Vec<String>,
    ) -> ScittReceipt {
        let issued_at = Utc::now();
        let receipt_id = uuid::Uuid::new_v4().to_string();

        let payload_hash = Self::compute_payload_hash(
            action_cid,
            &evidence_cids,
            &self.local_issuer,
            &issued_at,
        );

        let signature = Self::sign(&payload_hash, &self.local_secret);

        debug!(
            receipt_id = %receipt_id,
            action_cid = %action_cid,
            issuer = %self.local_issuer,
            "Issued SCITT receipt"
        );

        ScittReceipt {
            receipt_id,
            action_cid: action_cid.to_string(),
            evidence_cids,
            issuer: self.local_issuer.clone(),
            issued_at,
            payload_hash,
            signature,
        }
    }

    /// Verify a SCITT receipt from another org.
    pub fn verify_receipt(&self, receipt: &ScittReceipt) -> FederationResult<bool> {
        // 1. Check issuer is known
        let issuer_key = self
            .known_issuers
            .get(&receipt.issuer)
            .ok_or_else(|| FederationError::UnknownIssuer(receipt.issuer.clone()))?;

        // 2. Recompute payload hash
        let expected_hash = Self::compute_payload_hash(
            &receipt.action_cid,
            &receipt.evidence_cids,
            &receipt.issuer,
            &receipt.issued_at,
        );

        if expected_hash != receipt.payload_hash {
            return Err(FederationError::ReceiptVerificationFailed(
                "payload hash mismatch".into(),
            ));
        }

        // 3. Verify signature
        let expected_sig = Self::sign(&expected_hash, issuer_key);
        if expected_sig != receipt.signature {
            return Err(FederationError::ReceiptVerificationFailed(
                "signature mismatch".into(),
            ));
        }

        debug!(
            receipt_id = %receipt.receipt_id,
            issuer = %receipt.issuer,
            "SCITT receipt verified"
        );

        Ok(true)
    }

    /// Compute SHA-256 hash of the receipt payload.
    fn compute_payload_hash(
        action_cid: &str,
        evidence_cids: &[String],
        issuer: &str,
        issued_at: &DateTime<Utc>,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(action_cid.as_bytes());
        for cid in evidence_cids {
            hasher.update(cid.as_bytes());
        }
        hasher.update(issuer.as_bytes());
        hasher.update(issued_at.to_rfc3339().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Sign a payload hash with a secret (HMAC-like: SHA256(hash || secret)).
    fn sign(payload_hash: &str, secret: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload_hash.as_bytes());
        hasher.update(secret);
        hex::encode(hasher.finalize())
    }
}
