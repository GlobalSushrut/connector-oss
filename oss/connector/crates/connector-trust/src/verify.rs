//! Independent verification helpers for custody receipts and causal envelopes.
//!
//! These functions intentionally do not call the Connector HTTP API — callers
//! supply the material. Status never defaults to verified.

use sha2::{Digest, Sha256};

use crate::custody::{CustodyReceiptV2, CustodyVerificationStatus};
use crate::causal::CausalEnvelopeV2;

/// Recompute a simple SHA-256 digest over canonical JSON fields of an envelope.
pub fn envelope_content_digest(env: &CausalEnvelopeV2) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        env.envelope_id,
        env.principal_id,
        env.tenant_id.as_deref().unwrap_or(""),
        env.action,
        env.resource,
        env.decision,
        env.admission_ticket_id.as_deref().unwrap_or(""),
        env.occurred_at_ms
    );
    let hash = Sha256::digest(canonical.as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verify a custody receipt's structural completeness (not cryptographic trust of issuer).
pub fn verify_custody_receipt_structure(receipt: &CustodyReceiptV2) -> CustodyVerificationStatus {
    if receipt.receipt_id.is_empty() || receipt.principal_id.is_empty() {
        return CustodyVerificationStatus::Incomplete;
    }
    if receipt.chain_head.is_none() && receipt.signature_hex.is_none() {
        return CustodyVerificationStatus::Incomplete;
    }
    if receipt.artifact_digests.is_empty() && receipt.chain_head.is_none() {
        return CustodyVerificationStatus::Incomplete;
    }
    // Structure ok — cryptographic verification remains caller-supplied.
    CustodyVerificationStatus::Unverified
}

/// Compare stored integrity_mac on an envelope against recomputed digest when no HMAC key given.
pub fn verify_envelope_digest_binding(env: &CausalEnvelopeV2) -> bool {
    match env.integrity_mac.as_deref() {
        Some(mac) if !mac.is_empty() => mac == envelope_content_digest(env),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::CustodyReceiptV2;

    #[test]
    fn incomplete_receipt_without_head_or_sig() {
        let r = CustodyReceiptV2 {
            receipt_id: "r1".into(),
            proof_id: None,
            principal_id: "p1".into(),
            tenant_id: None,
            event_range_start: None,
            event_range_end: None,
            policy_revision: None,
            chain_head: None,
            signer_key_id: None,
            artifact_digests: vec![],
            signature_hex: None,
            verification_status: CustodyVerificationStatus::Unverified,
            contract_version: 2,
        };
        assert_eq!(
            verify_custody_receipt_structure(&r),
            CustodyVerificationStatus::Incomplete
        );
    }
}
