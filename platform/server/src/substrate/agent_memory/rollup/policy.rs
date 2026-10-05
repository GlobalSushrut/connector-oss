//! Per-agent / tenant / evidence-class FadePolicy resolution (§15).

use connector_trust::{EvidenceClass, FadePolicy};

use crate::state::PlatformState;

pub const POLICY_FOLDER: &str = "agent_memory_fade_policies";

/// Resolve policy: agent-scoped override → class preset → STANDARD.
pub fn resolve(
    state: &PlatformState,
    agent_vid: &str,
    evidence_class: Option<&str>,
) -> FadePolicy {
    if let Some(p) = load_agent_policy(state, agent_vid) {
        return p;
    }
    if let Some(cls) = evidence_class {
        return FadePolicy::for_class(EvidenceClass::parse(cls));
    }
    FadePolicy::default()
}

pub fn load_agent_policy(state: &PlatformState, agent_vid: &str) -> Option<FadePolicy> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(POLICY_FOLDER, agent_vid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn put_agent_policy(state: &PlatformState, agent_vid: &str, mut policy: FadePolicy) -> FadePolicy {
    policy.scope_kind = Some("agent".into());
    policy.scope_id = Some(agent_vid.into());
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            POLICY_FOLDER,
            agent_vid,
            &serde_json::to_value(&policy).unwrap_or_default(),
        );
    }
    policy
}

pub fn put_class_override(
    state: &PlatformState,
    agent_vid: &str,
    class: EvidenceClass,
) -> FadePolicy {
    let mut p = FadePolicy::for_class(class);
    p.scope_kind = Some("agent_class".into());
    p.scope_id = Some(format!("{agent_vid}:{}", class.as_str()));
    let key = format!("{agent_vid}:class:{}", class.as_str());
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            POLICY_FOLDER,
            &key,
            &serde_json::to_value(&p).unwrap_or_default(),
        );
    }
    p
}

pub fn resolve_for_class(
    state: &PlatformState,
    agent_vid: &str,
    class: EvidenceClass,
) -> FadePolicy {
    let key = format!("{agent_vid}:class:{}", class.as_str());
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get(POLICY_FOLDER, &key) {
            if let Ok(p) = serde_json::from_value::<FadePolicy>(v) {
                return p;
            }
        }
    }
    if let Some(p) = load_agent_policy(state, agent_vid) {
        return p;
    }
    FadePolicy::for_class(class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn financial_is_legal_hold() {
        let p = FadePolicy::for_class(EvidenceClass::FinancialAction);
        assert!(p.legal_retention);
        assert_eq!(p.minimum_proof_level, Some(connector_trust::ProofLevel::P0Full));
    }

    #[test]
    fn telemetry_fades_fast() {
        let t = FadePolicy::for_class(EvidenceClass::Telemetry);
        let s = FadePolicy::default();
        assert!(t.f0_to_f1_ms < s.f0_to_f1_ms);
    }
}
