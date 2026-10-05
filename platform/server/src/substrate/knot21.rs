//! Knot-21 — evidence-calibrated entropic affordance (shadow / observe-only in P2).
//!
//! Does **not** authorize effects. Emits a versioned profile for dashboards and
//! RGO disorder bumps; ActionBinding/PATE remain the sole consequence boundary.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;
use crate::substrate::egcm;

pub const KNOT21_SCHEMA: &str = "connector.knot21.profile.v1";
pub const KNOT21_VERSION: &str = "21.shadow.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Present,
    Missing,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceBinding {
    pub name: String,
    pub state: SourceState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Knot21Profile {
    pub schema: String,
    pub version: String,
    pub agent_pid: String,
    pub shadow: bool,
    pub sources: Vec<SourceBinding>,
    /// Monotonic profile counter for this agent (engine_store).
    pub profile_seq: u64,
    pub disorder: f32,
    pub affordance_hint: String,
}

fn shadow_enabled() -> bool {
    match std::env::var("CONNECTOR_KNOT21_SHADOW").ok().as_deref() {
        Some("0") | Some("false") | Some("off") => false,
        _ => true,
    }
}

/// Observe-only Knot-21 profile. Never used as admit authority.
pub fn observe(state: &PlatformState, agent_pid: &str) -> Knot21Profile {
    let egcm = egcm::snapshot_for_agent(state, agent_pid);
    let mut sources = vec![
        SourceBinding {
            name: "egcm_control_graph".into(),
            state: SourceState::Present,
            detail: format!("nodes={} disorder={:.3}", egcm.nodes.len(), egcm.disorder),
        },
        SourceBinding {
            name: "conp_capability_registry".into(),
            state: SourceState::Present,
            detail: "ProtocolCapabilityRegistry::with_defaults".into(),
        },
    ];

    let mut profile_seq = 0u64;
    if let Ok(es) = state.engine_store.lock() {
        match es.folder_get("knot21_profiles", agent_pid) {
            Ok(Some(v)) => {
                profile_seq = v.get("profile_seq").and_then(|x| x.as_u64()).unwrap_or(0) + 1;
                sources.push(SourceBinding {
                    name: "prior_profile".into(),
                    state: SourceState::Present,
                    detail: format!("seq={}", profile_seq.saturating_sub(1)),
                });
            }
            Ok(None) => {
                profile_seq = 1;
                sources.push(SourceBinding {
                    name: "prior_profile".into(),
                    state: SourceState::Missing,
                    detail: "first observe".into(),
                });
            }
            Err(e) => {
                sources.push(SourceBinding {
                    name: "prior_profile".into(),
                    state: SourceState::Stale,
                    detail: format!("{e}"),
                });
            }
        }
    }

    let affordance_hint = if egcm.disorder_bump {
        "narrow_affordance_shadow".into()
    } else {
        "nominal_affordance_shadow".into()
    };

    let profile = Knot21Profile {
        schema: KNOT21_SCHEMA.into(),
        version: KNOT21_VERSION.into(),
        agent_pid: agent_pid.into(),
        shadow: shadow_enabled(),
        sources,
        profile_seq,
        disorder: egcm.disorder,
        affordance_hint,
    };

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "knot21_profiles",
            agent_pid,
            &serde_json::to_value(&profile).unwrap_or(Value::Null),
        );
    }
    profile
}

pub fn observe_json(state: &PlatformState, agent_pid: &str) -> Value {
    serde_json::to_value(observe(state, agent_pid)).unwrap_or(json!({ "error": "knot21" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_versioned() {
        assert!(KNOT21_SCHEMA.contains("knot21"));
        assert!(KNOT21_VERSION.contains("shadow"));
    }
}
