//! Trust firewall — T0–T4 lattice; transform never raises authority.

use connector_trust::{MemoryEnvelope, TrustTier, MEMORY_ENVELOPE_SCHEMA};
use sha2::{Digest, Sha256};

use super::now_ms;

/// Build a non-removable envelope. Callers must not strip this on rollup/fade.
pub fn bind_envelope(
    cid: &str,
    agent_pid: &str,
    origin: &str,
    origin_authority: TrustTier,
    verification_state: &str,
    evidence_cids: Vec<String>,
    world_scope: Option<String>,
    skill_scope: Option<String>,
    valid_from_ms: Option<i64>,
    valid_until_ms: Option<i64>,
) -> MemoryEnvelope {
    let now = now_ms();
    let mut env = MemoryEnvelope {
        schema: MEMORY_ENVELOPE_SCHEMA.into(),
        cid: cid.into(),
        agent_pid: agent_pid.into(),
        origin: origin.into(),
        origin_authority,
        created_at_ms: now,
        observed_at_ms: now,
        verification_state: verification_state.into(),
        evidence_cids,
        world_scope,
        skill_scope,
        valid_from_ms,
        valid_until_ms,
        lineage_digest: String::new(),
    };
    env.lineage_digest = env.digest();
    env
}

/// Derive a child envelope from a parent — authority may only attenuate.
pub fn derive_envelope(
    parent: &MemoryEnvelope,
    child_cid: &str,
    origin: &str,
    requested_authority: TrustTier,
    verification_state: &str,
) -> Result<MemoryEnvelope, String> {
    if TrustTier::promotion_violation(parent.origin_authority, requested_authority) {
        return Err(format!(
            "trust_promotion_forbidden: parent={} requested={} (LLM/summary cannot raise authority)",
            parent.origin_authority.as_str(),
            requested_authority.as_str()
        ));
    }
    let authority = parent.origin_authority.attenuate(requested_authority);
    let mut evidence = parent.evidence_cids.clone();
    if !evidence.iter().any(|c| c == &parent.cid) {
        evidence.push(parent.cid.clone());
    }
    let lineage = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                parent.lineage_digest, child_cid, origin, authority.as_str()
            )
            .as_bytes()
        )
    );
    Ok(MemoryEnvelope {
        schema: MEMORY_ENVELOPE_SCHEMA.into(),
        cid: child_cid.into(),
        agent_pid: parent.agent_pid.clone(),
        origin: origin.into(),
        origin_authority: authority,
        created_at_ms: now_ms(),
        observed_at_ms: now_ms(),
        verification_state: verification_state.into(),
        evidence_cids: evidence,
        world_scope: parent.world_scope.clone(),
        skill_scope: parent.skill_scope.clone(),
        valid_from_ms: parent.valid_from_ms,
        valid_until_ms: parent.valid_until_ms,
        lineage_digest: lineage,
    })
}

/// Hard gate: minimum trust for cognition on this action.
pub fn meets_floor(env: &MemoryEnvelope, floor: TrustTier) -> bool {
    env.origin_authority.rank() >= floor.rank()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_cannot_promote_t0() {
        let parent = bind_envelope(
            "cid:web",
            "agent:1",
            "webpage",
            TrustTier::T0External,
            "observed",
            vec![],
            None,
            None,
            None,
            None,
        );
        let err = derive_envelope(
            &parent,
            "cid:summary",
            "llm_summary",
            TrustTier::T3EnvVerified,
            "confirmed_by_model",
        )
        .unwrap_err();
        assert!(err.contains("trust_promotion_forbidden"));
    }

    #[test]
    fn attenuate_keeps_lower() {
        let parent = bind_envelope(
            "cid:a",
            "agent:1",
            "tool",
            TrustTier::T3EnvVerified,
            "verified",
            vec![],
            None,
            None,
            None,
            None,
        );
        let child = derive_envelope(
            &parent,
            "cid:b",
            "rollup",
            TrustTier::T1Observed,
            "rolled",
        )
        .unwrap();
        assert_eq!(child.origin_authority, TrustTier::T1Observed);
        assert!(child.evidence_cids.contains(&"cid:a".to_string()));
    }
}
