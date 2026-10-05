//! HTTP API — DAL start / turn / snapshot (Phase 5).

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::operator::honesty::operator_envelope;
use crate::state::SharedState;
use crate::substrate::dynamic_agent_loop::{self, AgentRunState};

/// POST /api/v1/dal/start
#[derive(Debug, Deserialize)]
pub struct StartBody {
    pub agent_vid: String,
    pub goal: String,
    #[serde(default)]
    pub mission_id: Option<String>,
}

pub async fn post_start(
    State(state): State<SharedState>,
    Json(body): Json<StartBody>,
) -> Json<Value> {
    match dynamic_agent_loop::start_run(&state, &body.agent_vid, &body.goal, body.mission_id) {
        Ok(run) => Json(operator_envelope(json!({
            "ok": true,
            "run": dynamic_agent_loop::public_snapshot(&run),
        }))),
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": e.denial_reason.slug(),
            "message": e.human_readable,
        }))),
    }
}

/// GET /api/v1/dal/:run_id
pub async fn get_run(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
) -> Json<Value> {
    match dynamic_agent_loop::load(state.as_ref(), &run_id) {
        Ok(Some(run)) => Json(operator_envelope(json!({
            "ok": true,
            "run": dynamic_agent_loop::public_snapshot(&run),
            "cip": crate::substrate::cip_executive::to_json(
                &crate::substrate::cip_executive::project_from_run(&run)
            ),
        }))),
        Ok(None) => Json(operator_envelope(json!({
            "ok": false,
            "error": "run_not_found",
            "run_id": run_id,
        }))),
        Err(e) => Json(operator_envelope(json!({
            "ok": false,
            "error": e.denial_reason.slug(),
            "message": e.human_readable,
        }))),
    }
}

#[derive(Debug, Deserialize)]
pub struct TurnBody {
    #[serde(default)]
    pub tool_calls: Vec<Value>,
    #[serde(default)]
    pub assistant_text: Option<String>,
    #[serde(default)]
    pub reasoning: Option<String>,
}

/// POST /api/v1/dal/:run_id/turn — proposals only (Ring-1); sandwich in tools.
pub async fn post_turn(
    State(state): State<SharedState>,
    Path(run_id): Path<String>,
    Json(body): Json<TurnBody>,
) -> Json<Value> {
    let mut run = match dynamic_agent_loop::load(state.as_ref(), &run_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": "run_not_found",
                "run_id": run_id,
            })));
        }
        Err(e) => {
            return Json(operator_envelope(json!({
                "ok": false,
                "error": e.denial_reason.slug(),
                "message": e.human_readable,
            })));
        }
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &run.agent_pid,
        "dal",
        "dal_turn",
        &json!({"run_id": run_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match dynamic_agent_loop::run_turn(
        &state,
        &mut run,
        &body.tool_calls,
        body.assistant_text.as_deref(),
        body.reasoning.as_deref(),
    )
    .await
    {
        Ok(turn) => {
            open_proceed.finish_observed(true);
            Json(operator_envelope(json!({
            "ok": true,
            "task_id": admitted.task_id,
            "executed": true,
            "admits": false,
            "turn": turn,
            "run": dynamic_agent_loop::public_snapshot(&run),
        })))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(operator_envelope(json!({
            "ok": false,
            "error": e.denial_reason.slug(),
            "message": e.human_readable,
            "hint": e.hint,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
            "run": dynamic_agent_loop::public_snapshot(&run),
        })))
        }
    }
}

/// GET /api/v1/dal/posture
pub async fn get_posture(State(_state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(json!({
        "schema": "connector.dal.posture.v1",
        "owns": "turn orchestration — PROJECT/propose/act/verify",
        "does_not_own": "tools sandwich (validate→Admit→expand→CDP) — stays in tools.rs",
        "ring1": "proposals only — no Talk auto-dispatch",
        "broker_epoch": "stamped from llm_context_broker::current_generation on start/turn",
        "cip": "should_inhibit_effect blocks Act",
        "ltl": "tool receipts stitched for next Talk",
        "docs": "platform/docs/arch/CONNECTOR_SVF.md",
    })))
}

#[allow(dead_code)]
fn _type_assert(run: &AgentRunState) {
    let _ = dynamic_agent_loop::svf_epoch(run);
}
