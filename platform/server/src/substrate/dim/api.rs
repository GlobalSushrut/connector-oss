//! DIM HTTP surface — operator inspect + refresh + regulate.

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{persist, regulate, refresh_for_agent};
use super::state::RegulationAction;
use crate::state::SharedState;

/// GET /api/v1/dim/:agent_pid — inspect intelligence condition.
pub async fn get_dim(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let z = persist::load(state.as_ref(), &agent_pid);
    Json(z.operator_view())
}

/// POST /api/v1/dim/:agent_pid/refresh — re-estimate Z_t from live signals.
pub async fn post_dim_refresh(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let z = refresh_for_agent(state.as_ref(), &agent_pid);
    Json(json!({
        "ok": true,
        "condition": z.operator_view(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct RegulateBody {
    #[serde(default)]
    pub action: Option<String>,
    /// If true, run propose_regulation instead of client-supplied action.
    #[serde(default)]
    pub auto: bool,
}

/// POST /api/v1/dim/:agent_pid/regulate — apply bounded RegulationAction.
pub async fn post_dim_regulate(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Json(body): Json<RegulateBody>,
) -> Json<Value> {
    let mut z = refresh_for_agent(state.as_ref(), &agent_pid);
    let action = if body.auto || body.action.is_none() {
        regulate::propose_regulation(&z)
    } else {
        parse_action(body.action.as_deref().unwrap_or("none"))
    };
    let result = regulate::apply_regulation(state.as_ref(), &mut z, action);
    Json(json!({
        "ok": true,
        "regulation": result,
        "condition": z.operator_view(),
    }))
}

/// GET /api/v1/dim/:agent_pid/journal — recent DIM transitions.
pub async fn get_dim_journal(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let entries = persist::list_recent_journal(state.as_ref(), &agent_pid, 32);
    Json(json!({
        "ok": true,
        "agent_pid": agent_pid,
        "entries": entries,
    }))
}

/// POST /api/v1/dim/:agent_pid/wake/evaluate — idle wake without new prompt (A19/S9).
pub async fn post_dim_wake_evaluate(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    Json(super::wake::evaluate_wake(state.as_ref(), &agent_pid))
}

/// GET /api/v1/dim/:agent_pid/wake — pending wake signals.
pub async fn get_dim_wake_pending(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let pending = super::wake::pending_wakes(state.as_ref(), &agent_pid);
    Json(json!({
        "ok": true,
        "agent_pid": agent_pid,
        "pending": pending,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConsumeWakeBody {
    pub wake_id: String,
}

/// POST /api/v1/dim/:agent_pid/wake/consume
pub async fn post_dim_wake_consume(
    State(state): State<SharedState>,
    Path(_agent_pid): Path<String>,
    Json(body): Json<ConsumeWakeBody>,
) -> Json<Value> {
    Json(super::wake::consume_wake(state.as_ref(), &body.wake_id))
}

/// POST /api/v1/dim/:agent_pid/poison — S27: degrade path (Ψ↓ / verification↑), authority unchanged.
pub async fn post_dim_poison(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let mut z = refresh_for_agent(state.as_ref(), &agent_pid);
    // Raise prediction error + interference → Φ↑ → IncreaseVerification.
    z.prediction_error = (z.prediction_error + 0.35).min(1.0);
    z.interference = (z.interference + 0.25).min(1.0);
    z.recompute_phi();
    z.recompute_temperature();
    let action = RegulationAction::IncreaseVerification;
    let result = regulate::apply_regulation(state.as_ref(), &mut z, action);
    Json(json!({
        "ok": true,
        "schema": "connector.dim.poison.v1",
        "regulation": result,
        "condition": z.operator_view(),
        "authority": "unchanged",
        "honesty": "Poison degrades cognition only — NF³ / ActionBinding / grants unchanged",
    }))
}

fn parse_action(s: &str) -> RegulationAction {
    match s {
        "increase_recall_radius" => RegulationAction::IncreaseRecallRadius,
        "decrease_recall_radius" => RegulationAction::DecreaseRecallRadius,
        "increase_verification" => RegulationAction::IncreaseVerification,
        "decrease_candidate_breadth" => RegulationAction::DecreaseCandidateBreadth,
        "increase_candidate_breadth" => RegulationAction::IncreaseCandidateBreadth,
        "pause_consolidation" => RegulationAction::PauseConsolidation,
        "resume_consolidation" => RegulationAction::ResumeConsolidation,
        "refresh_world_evidence" => RegulationAction::RefreshWorldEvidence,
        "reduce_tool_parallelism" => RegulationAction::ReduceToolParallelism,
        "increase_counterfactual_depth" => RegulationAction::IncreaseCounterfactualDepth,
        "wake_cognition" => RegulationAction::WakeCognition,
        "enter_waiting" => RegulationAction::EnterWaiting,
        "increase_human_coupling" => RegulationAction::IncreaseHumanCoupling,
        _ => RegulationAction::None,
    }
}
