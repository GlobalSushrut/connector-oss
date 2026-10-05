//! Agentic World Dynamics V0 — a view over stores Connector already owns.
//!
//! Canonical state is DIM plus the intelligence principal, the live broker
//! generation, the WorldGrant count, and the spend ceiling. A transition sits
//! beside the ATU. The perception packet is injected only while the memory
//! epoch is live. Experience does not mint or widen a grant. A prediction
//! does not admit. PATE remains the only admission.
//!
//! V1–V5 (empirical transitions, clustering, successor features, learned
//! latents, a cross-agent model) are not implemented here.

use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};

pub const STATE_SCHEMA: &str = "connector.awd.state.v1";
pub const TRANSITION_SCHEMA: &str = "connector.awd.transition.v1";
pub const PACKET_SCHEMA: &str = "connector.awd.perception.v1";
pub const FOLDER: &str = "awd_transition_v1";

/// Experience updates write this folder only. The delta on WorldGrant is zero.
pub fn experience_authority_delta() -> i64 {
    0
}

/// Confidence is a condition. It is never an Allow, including when PATE would deny.
pub fn prediction_admits(_confidence: f32, _pate_would_deny: bool) -> bool {
    false
}

/// Inputs already loaded from DIM, the principal, grants, and the ceiling.
/// Missing rows stay `None` so the view can say `absent` instead of inventing them.
pub struct ViewInputs<'a> {
    pub agent_pid: &'a str,
    pub principal_id: Option<&'a str>,
    pub intelligence_id: Option<&'a str>,
    pub generation: u64,
    pub grant_count: u64,
    pub spend_max_usd: Option<f64>,
    pub spend_max_iterations: Option<u64>,
    pub dim_regime: Option<&'a str>,
    pub dim_prediction_error: Option<f32>,
    pub experience_ref: Option<&'a str>,
}

pub fn project_view(inputs: &ViewInputs<'_>) -> Value {
    let experience = match inputs.experience_ref {
        Some(r) if !r.is_empty() => json!(r),
        _ => json!("absent"),
    };
    let condition = match inputs.dim_regime {
        Some(r) if !r.is_empty() => json!({
            "regime": r,
            "prediction_error": inputs.dim_prediction_error,
            "honesty": "DIM condition in [0,1]. Not permission.",
        }),
        _ => json!("absent"),
    };
    let spend = match (inputs.spend_max_usd, inputs.spend_max_iterations) {
        (Some(usd), Some(iters)) => json!({ "max_usd": usd, "max_iterations": iters }),
        _ => json!("absent"),
    };
    json!({
        "schema": STATE_SCHEMA,
        "agent_pid": inputs.agent_pid,
        "principal_id": inputs.principal_id.map(|s| json!(s)).unwrap_or(json!("absent")),
        "intelligence_id": inputs.intelligence_id.map(|s| json!(s)).unwrap_or(json!("absent")),
        "generation": inputs.generation,
        "grant_count": inputs.grant_count,
        "spend_ceiling": spend,
        "condition": condition,
        "experience": experience,
        "authority": "not_minted_here",
        "predictor": "absent",
    })
}

pub fn transition_body(
    agent_pid: &str,
    task_id: &str,
    pate_verdict: &str,
    observation: &str,
    moment_id: Option<&str>,
) -> Value {
    json!({
        "schema": TRANSITION_SCHEMA,
        "agent_pid": agent_pid,
        "task_id": task_id,
        "pate_verdict": pate_verdict,
        "prediction": "absent",
        "confidence": "absent",
        "observation": if observation.is_empty() { "absent" } else { observation },
        "moment_id": moment_id.filter(|s| !s.is_empty()),
        "experience": moment_id.filter(|s| !s.is_empty()).map(|s| json!(s)).unwrap_or(json!("absent")),
        "authority_delta": experience_authority_delta(),
        "writes": [FOLDER],
        "admits": prediction_admits(1.0, true),
        "honesty": "V0 pairs an absent prediction with the ATU outcome. It does not estimate P(S'|S,A) and does not admit.",
    })
}

/// `live` is the memory-epoch gate. A sealed epoch returns no packet.
pub fn perception_packet(view: &Value, live: bool) -> Option<Value> {
    if !live {
        return None;
    }
    let regime = view
        .get("condition")
        .and_then(|c| c.get("regime"))
        .and_then(|r| r.as_str());
    Some(json!({
        "schema": PACKET_SCHEMA,
        "agent_pid": view.get("agent_pid").cloned().unwrap_or(json!("absent")),
        "generation": view.get("generation").cloned().unwrap_or(json!(0)),
        "grant_count": view.get("grant_count").cloned().unwrap_or(json!(0)),
        "condition": view.get("condition").cloned().unwrap_or(json!("absent")),
        "experience": view.get("experience").cloned().unwrap_or(json!("absent")),
        "spend_ceiling": view.get("spend_ceiling").cloned().unwrap_or(json!("absent")),
        "loop": loop_signal(regime),
        "calls_cease": false,
        "admits": false,
        "honesty": "Bounded view. Not a history dump. Loop is a field; it does not invoke Cease.",
    }))
}

fn loop_signal(regime: Option<&str>) -> &'static str {
    match regime {
        None => "absent",
        Some("stuck") | Some("discontinuous") | Some("stale") => "no_progress",
        Some(_) => "continuing",
    }
}

pub fn read_view(state: &PlatformState, agent_pid: &str) -> Value {
    let principal = crate::kernel::agent_principal::load_principal(state, agent_pid);
    let principal_id = principal.as_ref().map(|p| p.principal_id.as_str());
    let intelligence_id = principal.as_ref().and_then(|p| p.intelligence_id.as_deref());
    let generation = broker_generation(state, agent_pid);
    let grant_count = crate::kernel::world_gateway::list_grants(state, Some(agent_pid)).len() as u64;
    let gen_key = generation.to_string();
    let ceiling = crate::substrate::spend_cease::get_ceiling(state, agent_pid, &gen_key);
    let (usd, iters) = match &ceiling {
        Some(c) => (Some(c.max_usd), Some(c.max_iterations)),
        None => (None, None),
    };
    let dim = dim_row(state, agent_pid);
    let regime = dim.as_ref().map(|z| z.regime.as_str());
    let err = dim.as_ref().map(|z| z.prediction_error);
    let experience = latest_experience(state, agent_pid);
    project_view(&ViewInputs {
        agent_pid,
        principal_id,
        intelligence_id,
        generation,
        grant_count,
        spend_max_usd: usd,
        spend_max_iterations: iters,
        dim_regime: regime,
        dim_prediction_error: err,
        experience_ref: experience.as_deref(),
    })
}

fn broker_generation(state: &PlatformState, agent_pid: &str) -> u64 {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    es.folder_get(
        crate::substrate::llm_context_broker::FOLDER,
        &format!("gen:{agent_pid}"),
    )
    .ok()
    .flatten()
    .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
    .unwrap_or(0)
}

fn dim_row(
    state: &PlatformState,
    agent_pid: &str,
) -> Option<crate::substrate::dim::DynamicIntelligenceState> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(crate::substrate::dim::DIM_FOLDER, agent_pid)
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

fn latest_experience(state: &PlatformState, agent_pid: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(FOLDER, &format!("latest:{agent_pid}"))
        .ok()
        .flatten()?;
    let id = v.get("moment_id").and_then(|m| m.as_str())?;
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

/// Prompt block, or nothing when the memory epoch is sealed.
pub fn perception_block(state: &SharedState, agent_pid: &str) -> Option<String> {
    if !crate::substrate::cvr::runtime_adapter::injection_allowed(state, agent_pid) {
        return None;
    }
    let view = read_view(state.as_ref(), agent_pid);
    let packet = perception_packet(&view, true)?;
    let text = serde_json::to_string(&packet).ok()?;
    Some(format!("[connector.awd.perception]\n{text}"))
}

pub fn attach_prediction(state: &SharedState, task_id: &str, agent_pid: &str, pate_verdict: &str) {
    let body = transition_body(agent_pid, task_id, pate_verdict, "absent", None);
    store_transition(state.as_ref(), agent_pid, task_id, &body);
}

pub fn attach_observation(
    state: &SharedState,
    task_id: &str,
    agent_pid: &str,
    pate_verdict: &str,
    outcome: &str,
    moment_id: Option<&str>,
) {
    let body = transition_body(agent_pid, task_id, pate_verdict, outcome, moment_id);
    store_transition(state.as_ref(), agent_pid, task_id, &body);
}

fn store_transition(state: &PlatformState, agent_pid: &str, task_id: &str, body: &Value) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let _ = es.folder_put(FOLDER, &format!("{agent_pid}::{task_id}"), body);
    let _ = es.folder_put(FOLDER, &format!("latest:{agent_pid}"), body);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_view(experience: Option<&str>, regime: Option<&str>) -> Value {
        project_view(&ViewInputs {
            agent_pid: "agent-1",
            principal_id: Some("prin-1"),
            intelligence_id: Some("cnktr:intelligence:abc"),
            generation: 4,
            grant_count: 1,
            spend_max_usd: Some(5.0),
            spend_max_iterations: Some(32),
            dim_regime: regime,
            dim_prediction_error: regime.map(|_| 0.2),
            experience_ref: experience,
        })
    }

    #[test]
    fn experience_update_does_not_create_or_widen_a_grant() {
        let body = transition_body("agent-1", "pate_1_abc", "proceed", "ok", Some("moment-9"));
        assert_eq!(body["authority_delta"], 0);
        assert_eq!(experience_authority_delta(), 0);
        assert_eq!(body["writes"], json!([FOLDER]));
        assert!(!body["writes"].to_string().contains("iia_world_grants"));
        assert_eq!(body["experience"], "moment-9");
        assert_eq!(body["admits"], false);
    }

    #[test]
    fn high_confidence_prediction_does_not_admit_when_pate_would_deny() {
        assert!(!prediction_admits(0.99, true));
        assert!(!prediction_admits(1.0, true));
        let body = transition_body("agent-1", "t", "block", "absent", None);
        assert_eq!(body["pate_verdict"], "block");
        assert_eq!(body["confidence"], "absent");
        assert_eq!(body["admits"], false);
    }

    #[test]
    fn sealed_epoch_omits_the_packet() {
        let view = sample_view(None, Some("observing"));
        assert!(perception_packet(&view, false).is_none());
        let live = perception_packet(&view, true).expect("live epoch includes the packet");
        assert_eq!(live["schema"], PACKET_SCHEMA);
        assert_eq!(live["calls_cease"], false);
        assert_eq!(live["admits"], false);
        assert_eq!(live["loop"], "continuing");
    }

    #[test]
    fn missing_experience_is_absent() {
        let view = sample_view(None, None);
        assert_eq!(view["experience"], "absent");
        assert_eq!(view["condition"], "absent");
        assert_eq!(view["predictor"], "absent");
        assert_eq!(view["authority"], "not_minted_here");
        let packet = perception_packet(&view, true).expect("packet");
        assert_eq!(packet["experience"], "absent");
        assert_eq!(packet["loop"], "absent");
    }

    #[test]
    fn stuck_regime_is_a_loop_field_and_does_not_admit() {
        let view = sample_view(None, Some("stuck"));
        let packet = perception_packet(&view, true).expect("packet");
        assert_eq!(packet["loop"], "no_progress");
        assert_eq!(packet["calls_cease"], false);
        assert_eq!(packet["admits"], false);
    }
}
