//! Offline verification for IIA artifacts — no HTTP trust required.

use super::signing::verify_signed_payload_v2;
use super::types::{
    AgentContractV2, CognitiveProposalV2, ContinuityStateV2, ContinuityRecordV2,
    ExecutionQuantumV2, IntelligencePrincipalV2, IntelligenceReceiptV2, RuntimeSelfEnvelopeV2,
    SigningTierV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IiaVerifyStatus {
    Ok,
    Incomplete,
    Expired,
    Consumed,
    ContinuityBroken,
    Tampered,
    WrongTier,
}

pub fn verify_principal_envelope(env: &RuntimeSelfEnvelopeV2) -> IiaVerifyStatus {
    if env.principal.principal_id.is_empty() || env.contract.agent_id.is_empty() {
        return IiaVerifyStatus::Incomplete;
    }
    if env.principal.principal_id != env.contract.agent_id {
        return IiaVerifyStatus::Tampered;
    }
    if env.continuity.state == ContinuityStateV2::Broken {
        return IiaVerifyStatus::ContinuityBroken;
    }
    if env.signing_tier != SigningTierV2::Ed25519Court {
        return IiaVerifyStatus::WrongTier;
    }
    IiaVerifyStatus::Ok
}

pub fn verify_cpo_structure(cpo: &CognitiveProposalV2) -> IiaVerifyStatus {
    if !cpo.non_authoritative {
        return IiaVerifyStatus::Tampered;
    }
    if cpo.cpo_id.is_empty() || cpo.principal_id.is_empty() {
        return IiaVerifyStatus::Incomplete;
    }
    IiaVerifyStatus::Ok
}

pub fn verify_quantum_active(q: &ExecutionQuantumV2, now_ms: i64) -> IiaVerifyStatus {
    if q.quantum_id.is_empty() || q.nonce.is_empty() {
        return IiaVerifyStatus::Incomplete;
    }
    if q.consumed {
        return IiaVerifyStatus::Consumed;
    }
    if now_ms > q.expires_at_ms {
        return IiaVerifyStatus::Expired;
    }
    IiaVerifyStatus::Ok
}

pub fn verify_export_chain(receipts: &[IntelligenceReceiptV2]) -> IiaVerifyStatus {
    if receipts.is_empty() {
        return IiaVerifyStatus::Incomplete;
    }
    let mut prev: Option<String> = None;
    for r in receipts {
        if r.signing_tier != SigningTierV2::Ed25519Court {
            return IiaVerifyStatus::WrongTier;
        }
        // Court-tier export: every receipt must carry a valid Ed25519 payload.
        let Some(sig) = r.signature.as_ref() else {
            return IiaVerifyStatus::Incomplete;
        };
        let mut unsigned = r.clone();
        unsigned.signature = None;
        if !verify_signed_payload_v2(&unsigned, sig) {
            return IiaVerifyStatus::Tampered;
        }
        if let Some(p) = &prev {
            if r.previous_receipt_digest.as_deref() != Some(p.as_str()) {
                return IiaVerifyStatus::Tampered;
            }
        }
        prev = Some(r.chain_head_digest.clone());
    }
    IiaVerifyStatus::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iia::signing::sign_json_ed25519;
    use crate::iia::types::{IIA_SCHEMA, PRINCIPAL_PREFIX};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn export_chain_rejects_tampered_signature() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut r = IntelligenceReceiptV2 {
            schema: IIA_SCHEMA.into(),
            receipt_id: "ir_1".into(),
            principal_id: format!("{PRINCIPAL_PREFIX}a"),
            intelligence_id: "iid_1".into(),
            cpo_id: None,
            quantum_id: None,
            docklock_profile_id: None,
            effect_digest_sha256: "ee".into(),
            previous_receipt_digest: None,
            chain_head_digest: "ch1".into(),
            issued_at_ms: 1,
            signing_tier: SigningTierV2::Ed25519Court,
            signature: None,
        };
        r.signature = Some(sign_json_ed25519(&sk, &r).unwrap());
        assert_eq!(verify_export_chain(&[r.clone()]), IiaVerifyStatus::Ok);

        let mut bad = r;
        if let Some(sig) = bad.signature.as_mut() {
            sig.signature_b64 = format!("AAAA{}", sig.signature_b64);
        }
        assert_eq!(verify_export_chain(&[bad]), IiaVerifyStatus::Tampered);
    }

    fn sample_principal() -> IntelligencePrincipalV2 {
        IntelligencePrincipalV2 {
            schema: IIA_SCHEMA.into(),
            principal_id: format!("{PRINCIPAL_PREFIX}test"),
            issuer: "cnktr:org:lab".into(),
            authority_chain: vec![],
            public_key_hex: "aa".repeat(32),
            contract_digest_sha256: "cd".into(),
            model_ref: None,
            runtime_hash: None,
            intelligence_id: None,
            created_at_ms: 1,
            node_witness_pubkey_hex: None,
            contract_version: 2,
        }
    }

    #[test]
    fn broken_continuity_fails_envelope() {
        let pid = format!("{PRINCIPAL_PREFIX}test");
        let env = RuntimeSelfEnvelopeV2 {
            schema: IIA_SCHEMA.into(),
            principal: sample_principal(),
            contract: AgentContractV2 {
                schema: IIA_SCHEMA.into(),
                agent_id: pid,
                issuer: "cnktr:org:lab".into(),
                purpose: vec![],
                capabilities: vec![],
                denied_operations: vec![],
                filesystem_read: vec![],
                filesystem_write: vec![],
                network_allow: vec![],
                network_default: "deny".into(),
                receipt_required: true,
                contract_digest_sha256: "cd".into(),
                contract_version: 2,
            },
            continuity: ContinuityRecordV2 {
                schema: IIA_SCHEMA.into(),
                principal_id: format!("{PRINCIPAL_PREFIX}test"),
                state: ContinuityStateV2::Broken,
                model_ref: "m".into(),
                runtime_hash: "r".into(),
                contract_digest_sha256: "cd".into(),
                evaluated_at_ms: 1,
                break_reason: Some("tamper".into()),
            },
            signing_tier: SigningTierV2::Ed25519Court,
            principal_signature: None,
            foundation_block: None,
            who_am_i_authoritative: None,
        };
        assert_eq!(
            verify_principal_envelope(&env),
            IiaVerifyStatus::ContinuityBroken
        );
    }
}
