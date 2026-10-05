//! TG-3 — Mission journal HTTP API (durable execution, not chat).

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::PlatformRole;
use crate::kernel::mission_journal::{self, MissionStatus, StepKind, StepStatus};
use crate::services::agents::caller;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct CreateMissionBody {
    pub agent_pid: String,
    pub label: Option<String>,
}

/// POST /missions
pub async fn create_mission(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateMissionBody>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &body.agent_pid,
        "lifecycle",
        "create_mission",
        &json!({"agent_pid": body.agent_pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match mission_journal::create_mission(state.as_ref(), &body.agent_pid, body.label) {
        Ok(m) => {
            open_proceed.finish_observed(true);
            Json(json!({"ok": true, "mission": m, "task_id": admitted.task_id, "executed": true, "admits": false}))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "status": 500, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

/// GET /missions/:id
pub async fn get_mission(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
    }
    match mission_journal::load_mission(state.as_ref(), &id) {
        Some(m) => {
            let steps = mission_journal::list_steps(state.as_ref(), &id);
            Json(json!({"ok": true, "mission": m, "steps": steps, "step_count": steps.len()}))
        }
        None => Json(json!({"ok": false, "error": "mission_not_found", "status": 404})),
    }
}

/// POST /missions/:id/resume
pub async fn resume_mission(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let Some(existing) = mission_journal::load_mission(state.as_ref(), &id) else {
        return Json(json!({"ok": false, "error": "mission_not_found", "status": 404}));
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &existing.agent_pid,
        "lifecycle",
        "resume_mission",
        &json!({"mission_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match mission_journal::resume_snapshot(state.as_ref(), &id) {
        Ok(mut v) => {
            open_proceed.finish_observed(true);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("task_id".into(), json!(admitted.task_id));
                obj.insert("executed".into(), json!(true));
                obj.insert("admits".into(), json!(false));
            }
            Json(v)
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AppendStepBody {
    pub kind: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub input: Value,
    pub protocol: Option<Value>,
    /// When set, mark the new step completed with this receipt.
    pub complete_with: Option<Value>,
}

/// POST /missions/:id/steps — append or complete a journal step.
pub async fn append_step(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AppendStepBody>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let Some(mission) = mission_journal::load_mission(state.as_ref(), &id) else {
        return Json(json!({"ok": false, "error": "mission_not_found", "status": 404}));
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &mission.agent_pid,
        "lifecycle",
        "append_mission_step",
        &json!({"mission_id": id.as_str(), "kind": body.kind.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let kind = parse_kind(&body.kind);
    match mission_journal::begin_step(
        state.as_ref(),
        &id,
        &mission.agent_pid,
        kind,
        &body.idempotency_key,
        &body.input,
        body.protocol,
    ) {
        Ok(mut step) => {
            if step.status == StepStatus::Completed {
                open_proceed.finish_observed(true);
                return Json(json!({"ok": true, "replayed": true, "step": step, "task_id": admitted.task_id, "executed": true, "admits": false}));
            }
            if let Some(receipt) = body.complete_with {
                match mission_journal::complete_step(state.as_ref(), &id, &step.step_id, receipt) {
                    Ok(s) => step = s,
                    Err(e) => {
                        open_proceed.finish_observed(false);
                        return Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}));
                    }
                }
            }
            open_proceed.finish_observed(true);
            Json(json!({"ok": true, "replayed": false, "step": step, "task_id": admitted.task_id, "executed": true, "admits": false}))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "status": 400, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

fn parse_kind(s: &str) -> StepKind {
    match s.to_ascii_lowercase().as_str() {
        "llm" => StepKind::Llm,
        "hitl_wait" | "hitl" => StepKind::HitlWait,
        "fabric" => StepKind::Fabric,
        "conp_command" | "conp" => StepKind::ConpCommand,
        "cnp_message" | "cnp" => StepKind::CnpMessage,
        "compensate" => StepKind::Compensate,
        _ => StepKind::Tool,
    }
}

/// POST /missions/:id/complete
pub async fn complete_mission(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let Some(mut m) = mission_journal::load_mission(state.as_ref(), &id) else {
        return Json(json!({"ok": false, "error": "mission_not_found", "status": 404}));
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &m.agent_pid,
        "lifecycle",
        "complete_mission",
        &json!({"mission_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    m.status = MissionStatus::Completed;
    m.updated_at_ms = chrono::Utc::now().timestamp_millis();
    let persisted = if let Ok(mut es) = state.engine_store.lock() {
        if let Ok(v) = serde_json::to_value(&m) {
            let _ = es.folder_put(mission_journal::MISSION_FOLDER, &id, &v);
        }
        drop(es);
        true
    } else {
        false
    };
    open_proceed.finish_observed(persisted);
    Json(json!({
        "ok": persisted,
        "mission": m,
        "operation": m.to_operation_ref(),
        "task_id": admitted.task_id,
        "executed": persisted,
        "admits": false,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CancelMissionBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /missions/:id/cancel — durable cancel; skips open steps; no re-fire.
pub async fn cancel_mission(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<CancelMissionBody>>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let reason = body
        .and_then(|b| b.reason.clone())
        .unwrap_or_else(|| "operator_cancel".into());
    let Some(existing) = mission_journal::load_mission(state.as_ref(), &id) else {
        return Json(json!({"ok": false, "error": "mission_not_found", "status": 404}));
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &existing.agent_pid,
        "lifecycle",
        "cancel_mission",
        &json!({"mission_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match mission_journal::cancel_mission(state.as_ref(), &id, &reason) {
        Ok((m, skipped)) => {
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "mission": m,
                "operation": m.to_operation_ref(),
                "skipped_steps": skipped,
                "honesty": "Canceled — open Pending/Waiting steps skipped; further accept_step denied",
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}
