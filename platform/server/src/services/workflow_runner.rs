//! Durable lease-based CLS blueprint runner.
//!
//! ENABLE (or bootstrap `run: true`) enqueues a run. A background loop claims a
//! lease, executes planned CLS steps through kernel admission (`admit_tool_or_ask`
//! for tools; audit-only for other ops), retries, then DLQs. Cancel is durable.
//! This is not a live CNP bus worker — list honesty stays explicit.

use connector_engine::engine_store::EngineStore;
use serde_json::{json, Value};
use vac_core::types::{MemoryKernelOp, OpOutcome};

use crate::{
    kernel::action_binding::admit_tool_or_ask,
    services::cls::ccl_static_action_blueprint,
    services::workflow_runtime::{get_workflow, WorkflowRecord, WorkflowState},
    state::SharedState,
};

pub(crate) const RUN_QUEUE_FOLDER: &str = "workflow_run_queue";
pub(crate) const RUN_LEASE_FOLDER: &str = "workflow_run_leases";
pub(crate) const RUN_DLQ_FOLDER: &str = "workflow_run_dlq";
pub(crate) const RUN_RECORD_FOLDER: &str = "workflow_durable_runs";

const MAX_ATTEMPTS: u32 = 3;
const LEASE_TTL_SECS: i64 = 45;
const MAX_STEPS_PER_TICK: usize = 8;

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn lease_key(workflow_id: &str, run_id: &str) -> String {
    format!("{workflow_id}:{run_id}")
}

pub fn enqueue_enabled_run(state: &SharedState, rec: &WorkflowRecord) -> Value {
    let run_id = format!("run_{}", uuid::Uuid::new_v4().simple());
    let blueprint = ccl_static_action_blueprint(&rec.cls_source).unwrap_or_default();
    let record = json!({
        "run_id": run_id,
        "workflow_id": rec.workflow_id,
        "status": "queued",
        "attempt": 0,
        "max_attempts": MAX_ATTEMPTS,
        "step_index": 0,
        "created_at": now_rfc3339(),
        "updated_at": now_rfc3339(),
        "cancelled": false,
        "blueprint": blueprint,
        "step_outcomes": [],
        "execution_path": "cls_blueprint_lease_runner",
        "honesty": "Durable CLS blueprint execution through kernel admission. Not a live CNP bus consumer.",
    });
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(RUN_RECORD_FOLDER, &run_id, &record);
        let _ = es.folder_put(
            RUN_QUEUE_FOLDER,
            &lease_key(&rec.workflow_id, &run_id),
            &json!({
                "run_id": run_id,
                "workflow_id": rec.workflow_id,
                "queued_at": now_rfc3339(),
                "available_at": now_unix(),
            }),
        );
    }
    record
}

pub fn active_lease_summary(es: &mut dyn EngineStore, workflow_id: &str) -> Option<Value> {
    let prefix = format!("{workflow_id}:");
    let now = now_unix();
    let keys = es.folder_keys(RUN_LEASE_FOLDER, None).ok()?;
    for k in keys {
        if !k.starts_with(&prefix) {
            continue;
        }
        let Some(v) = es.folder_get(RUN_LEASE_FOLDER, &k).ok().flatten() else {
            continue;
        };
        let expires = v.get("expires_at").and_then(|x| x.as_i64()).unwrap_or(0);
        if expires > now && v.get("cancelled").and_then(|x| x.as_bool()) != Some(true) {
            return Some(v);
        }
    }
    None
}

pub fn is_executing(es: &mut dyn EngineStore, workflow_id: &str) -> bool {
    active_lease_summary(es, workflow_id).is_some()
}

pub fn has_open_run(state: &SharedState, workflow_id: &str) -> bool {
    list_runs(state, workflow_id).iter().any(|v| {
        matches!(
            v.get("status").and_then(|s| s.as_str()).unwrap_or(""),
            "queued" | "running" | "awaiting_hitl"
        )
    })
}

pub fn cancel_run(state: &SharedState, workflow_id: &str, run_id: &str) -> Result<Value, Value> {
    let mut es = state.engine_store.lock().unwrap();
    let Some(mut rec) = es
        .folder_get(RUN_RECORD_FOLDER, run_id)
        .ok()
        .flatten()
    else {
        return Err(json!({"ok": false, "error": "Run not found"}));
    };
    if rec.get("workflow_id").and_then(|v| v.as_str()) != Some(workflow_id) {
        return Err(json!({"ok": false, "error": "Run does not belong to this workflow"}));
    }
    if let Some(obj) = rec.as_object_mut() {
        obj.insert("cancelled".into(), json!(true));
        obj.insert("status".into(), json!("cancelled"));
        obj.insert("updated_at".into(), json!(now_rfc3339()));
    }
    let _ = es.folder_put(RUN_RECORD_FOLDER, run_id, &rec);
    let key = lease_key(workflow_id, run_id);
    let _ = es.folder_put(
        RUN_QUEUE_FOLDER,
        &key,
        &json!({
            "run_id": run_id,
            "workflow_id": workflow_id,
            "cancelled": true,
            "queued_at": now_rfc3339(),
        }),
    );
    if let Ok(Some(mut lease)) = es.folder_get(RUN_LEASE_FOLDER, &key) {
        if let Some(obj) = lease.as_object_mut() {
            obj.insert("cancelled".into(), json!(true));
            obj.insert("expires_at".into(), json!(0));
        }
        let _ = es.folder_put(RUN_LEASE_FOLDER, &key, &lease);
    }
    Ok(json!({"ok": true, "run": rec}))
}

pub fn list_runs(state: &SharedState, workflow_id: &str) -> Vec<Value> {
    let es = state.engine_store.lock().unwrap();
    let Ok(keys) = es.folder_keys(RUN_RECORD_FOLDER, None) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(RUN_RECORD_FOLDER, &k) {
            if v.get("workflow_id").and_then(|x| x.as_str()) == Some(workflow_id) {
                out.push(v);
            }
        }
    }
    out.sort_by(|a, b| {
        b.get("created_at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .cmp(a.get("created_at").and_then(|x| x.as_str()).unwrap_or(""))
    });
    out
}

fn load_run(es: &mut dyn EngineStore, run_id: &str) -> Option<Value> {
    es.folder_get(RUN_RECORD_FOLDER, run_id).ok().flatten()
}

fn save_run(es: &mut dyn EngineStore, run_id: &str, rec: &Value) {
    let _ = es.folder_put(RUN_RECORD_FOLDER, run_id, rec);
}

fn claim_one(state: &SharedState) -> Option<(String, String, Value)> {
    let mut es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(RUN_QUEUE_FOLDER, None).ok()?;
    let now = now_unix();
    for key in keys {
        let Some(q) = es.folder_get(RUN_QUEUE_FOLDER, &key).ok().flatten() else {
            continue;
        };
        if q.get("cancelled").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }
        let available = q.get("available_at").and_then(|v| v.as_i64()).unwrap_or(0);
        if available > now {
            continue;
        }
        let run_id = q.get("run_id")?.as_str()?.to_string();
        let workflow_id = q.get("workflow_id")?.as_str()?.to_string();
        if let Ok(Some(lease)) = es.folder_get(RUN_LEASE_FOLDER, &key) {
            let exp = lease.get("expires_at").and_then(|v| v.as_i64()).unwrap_or(0);
            if exp > now && lease.get("cancelled").and_then(|v| v.as_bool()) != Some(true) {
                continue;
            }
        }
        let Some(mut rec) = load_run(&mut **es, &run_id) else {
            continue;
        };
        if rec.get("cancelled").and_then(|v| v.as_bool()) == Some(true) {
            continue;
        }
        let status = rec.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if matches!(status, "succeeded" | "cancelled" | "dead_letter") {
            continue;
        }
        let attempt = rec.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let claim_gen = rec.get("claim_generation").and_then(|v| v.as_u64()).unwrap_or(0);
        let lease_id = uuid::Uuid::new_v4().to_string();
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("status".into(), json!("running"));
            obj.insert("claim_generation".into(), json!(claim_gen.saturating_add(1)));
            obj.insert("lease_id".into(), json!(lease_id.clone()));
            obj.insert("updated_at".into(), json!(now_rfc3339()));
            obj.insert("lease_expires_at".into(), json!(now + LEASE_TTL_SECS));
            obj.insert("attempt".into(), json!(attempt));
        }
        save_run(&mut **es, &run_id, &rec);
        let _ = es.folder_put(
            RUN_LEASE_FOLDER,
            &key,
            &json!({
                "run_id": run_id,
                "workflow_id": workflow_id,
                "holder": format!("workflow_runner:{lease_id}"),
                "lease_id": lease_id,
                "claimed_at": now_rfc3339(),
                "expires_at": now + LEASE_TTL_SECS,
            }),
        );
        return Some((workflow_id, run_id, rec));
    }
    None
}

fn heartbeat_lease(state: &SharedState, workflow_id: &str, run_id: &str) {
    let mut es = state.engine_store.lock().unwrap();
    let key = lease_key(workflow_id, run_id);
    let _ = es.folder_put(
        RUN_LEASE_FOLDER,
        &key,
        &json!({
            "run_id": run_id,
            "workflow_id": workflow_id,
            "holder": "workflow_runner",
            "claimed_at": now_rfc3339(),
            "expires_at": now_unix() + LEASE_TTL_SECS,
        }),
    );
}

fn complete_or_retry(
    state: &SharedState,
    workflow_id: &str,
    run_id: &str,
    rec: Value,
    terminal: &str,
    retry: bool,
) {
    let mut es = state.engine_store.lock().unwrap();
    let key = lease_key(workflow_id, run_id);
    let attempt = rec.get("attempt").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
    let mut rec = rec;
    if retry {
        let next = attempt.saturating_add(1);
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("attempt".into(), json!(next));
        }
        if next < MAX_ATTEMPTS {
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("status".into(), json!("queued"));
            obj.insert("updated_at".into(), json!(now_rfc3339()));
        }
        save_run(&mut **es, run_id, &rec);
        let backoff = 5i64.saturating_mul(next as i64);
        let _ = es.folder_put(
            RUN_QUEUE_FOLDER,
            &key,
            &json!({
                "run_id": run_id,
                "workflow_id": workflow_id,
                "queued_at": now_rfc3339(),
                "available_at": now_unix() + backoff,
            }),
        );
        let _ = es.folder_put(
            RUN_LEASE_FOLDER,
            &key,
            &json!({
                "run_id": run_id,
                "workflow_id": workflow_id,
                "expires_at": 0,
            }),
        );
        return;
        }
    }
    if terminal == "dead_letter" || (retry && rec.get("attempt").and_then(|v| v.as_u64()).unwrap_or(0) as u32 >= MAX_ATTEMPTS) {
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("status".into(), json!("dead_letter"));
            obj.insert("updated_at".into(), json!(now_rfc3339()));
        }
        save_run(&mut **es, run_id, &rec);
        let _ = es.folder_put(RUN_DLQ_FOLDER, &key, &rec);
    } else if let Some(obj) = rec.as_object_mut() {
        obj.insert("status".into(), json!(terminal));
        obj.insert("updated_at".into(), json!(now_rfc3339()));
        save_run(&mut **es, run_id, &rec);
    }
    let _ = es.folder_put(
        RUN_LEASE_FOLDER,
        &key,
        &json!({
            "run_id": run_id,
            "workflow_id": workflow_id,
            "expires_at": 0,
            "released": true,
        }),
    );
}

fn execute_step(state: &SharedState, rec: &WorkflowRecord, step: &Value) -> Value {
    let kind = step.get("kind").and_then(|v| v.as_str()).unwrap_or("unknown");
    let step_id = step.get("step_id").and_then(|v| v.as_str()).unwrap_or("");
    // Prefer step-bound agent; playground demo must not invent empty-parameter admits.
    let agent_pid = step
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("workflow:{}", rec.workflow_id));
    if crate::services::playground::is_playground_mode()
        && !agent_pid.starts_with("workflow:")
    {
        crate::services::agents::ensure_playground_tool_lane(state, &agent_pid);
    }
    match kind {
        "tool" => {
            let tool = step.get("tool").and_then(|v| v.as_str()).unwrap_or("tool");
            let params = step
                .get("params")
                .or_else(|| step.get("input"))
                .or_else(|| step.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let mut world_params = params.clone();
            if let Ok(expanded) =
                crate::substrate::llm_broker_gate::egress_deserialize(state, &agent_pid, &params)
            {
                world_params = expanded;
            }
            let dispatch = if let Some((bridge, tname)) = tool.split_once(':') {
                match crate::services::tools::dispatch_mcp_tool_core(
                    state,
                    bridge,
                    tname,
                    &agent_pid,
                    &world_params,
                    format!("cls_step:{step_id}"),
                    crate::services::tools::ToolMissionOpts {
                        mission_id: None,
                        idempotency_key: None,
                    },
                ) {
                    Ok(v) => json!({ "ok": true, "result": v, "pate_task_id": v.get("pate_task_id") }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            } else {
                match admit_tool_or_ask(state, &agent_pid, "cls", tool, &world_params) {
                    Ok(()) => json!({
                        "ok": true,
                        "admitted_only": true,
                        "honesty": "No bridge:tool in step.tool — admission ran with real params; wire MCP bridge for live dispatch"
                    }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            };
            if dispatch.get("ok").and_then(|v| v.as_bool()) == Some(false) {
                return json!({
                    "ok": false,
                    "kind": kind,
                    "step_id": step_id,
                    "tool": tool,
                    "detail": dispatch,
                });
            }
            return json!({
                "ok": true,
                "kind": kind,
                "step_id": step_id,
                "tool": tool,
                "admitted": true,
                "params": world_params,
                "agent_pid": agent_pid,
                "dispatch": dispatch,
            });
        }
        "llm_infer" => json!({
            "ok": true,
            "kind": kind,
            "step_id": step_id,
            "gated": true,
            "honesty": "LLM steps are recorded through the runner; inference stays on the control-plane gateway, not a guest VM.",
        }),
        other => {
            {
                let mut k = state.kernel.lock().unwrap();
                k.record_audit_event(
                    MemoryKernelOp::PolicyCheck,
                    "kernel/workflow-runner",
                    Some(format!(
                        "cls_step:workflow_id={},kind={},step_id={}",
                        rec.workflow_id, other, step_id
                    )),
                    OpOutcome::Success,
                    Some("cls_blueprint_lease_runner".into()),
                    None,
                    None,
                    None,
                );
                k.flush_audit_batch();
            }
            json!({
                "ok": true,
                "kind": other,
                "step_id": step_id,
                "recorded": true,
            })
        }
    }
}

fn execute_claimed(state: &SharedState, workflow_id: &str, run_id: &str, mut rec: Value) {
    let Some(wf) = get_workflow(state, workflow_id) else {
        complete_or_retry(state, workflow_id, run_id, rec, "dead_letter", false);
        return;
    };
    if wf.state != WorkflowState::Enabled {
        if let Some(obj) = rec.as_object_mut() {
            obj.insert(
                "last_error".into(),
                json!("workflow not ENABLED; runner will not execute"),
            );
        }
        complete_or_retry(state, workflow_id, run_id, rec, "dead_letter", false);
        return;
    }
    if rec.get("cancelled").and_then(|v| v.as_bool()) == Some(true) {
        complete_or_retry(state, workflow_id, run_id, rec, "cancelled", false);
        return;
    }
    let steps: Vec<Value> = rec
        .get("blueprint")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut idx = rec.get("step_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let mut outcomes: Vec<Value> = rec
        .get("step_outcomes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut pending_hitl = false;
    let mut failed = false;
    let mut last_error = Value::Null;
    let end = (idx + MAX_STEPS_PER_TICK).min(steps.len());
    while idx < end {
        heartbeat_lease(state, workflow_id, run_id);
        {
            let mut es = state.engine_store.lock().unwrap();
            if let Some(live) = load_run(&mut **es, run_id) {
                if live.get("cancelled").and_then(|v| v.as_bool()) == Some(true) {
                    drop(es);
                    complete_or_retry(state, workflow_id, run_id, rec, "cancelled", false);
                    return;
                }
            }
        }
        let step = &steps[idx];
        let outcome = execute_step(state, &wf, step);
        let ok = outcome.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        outcomes.push(outcome.clone());
        if !ok {
            let code = outcome
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("step_failed");
            last_error = outcome.clone();
            if code.contains("hitl") || code.contains("ask") || code == "pending_approval" {
                pending_hitl = true;
            } else {
                failed = true;
            }
            break;
        }
        idx += 1;
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("step_index".into(), json!(idx));
            obj.insert("step_outcomes".into(), json!(outcomes.clone()));
            obj.insert("updated_at".into(), json!(now_rfc3339()));
        }
        {
            let mut es = state.engine_store.lock().unwrap();
            save_run(&mut **es, run_id, &rec);
        }
    }
    if let Some(obj) = rec.as_object_mut() {
        obj.insert("step_index".into(), json!(idx));
        obj.insert("step_outcomes".into(), json!(outcomes));
        obj.insert("updated_at".into(), json!(now_rfc3339()));
        if last_error != Value::Null {
            obj.insert("last_error".into(), last_error);
        }
        if pending_hitl {
            obj.insert("status".into(), json!("awaiting_hitl"));
        }
    }
    {
        let mut es = state.engine_store.lock().unwrap();
        save_run(&mut **es, run_id, &rec);
    }
    if pending_hitl {
        let mut es = state.engine_store.lock().unwrap();
        let key = lease_key(workflow_id, run_id);
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("status".into(), json!("awaiting_hitl"));
            obj.insert("updated_at".into(), json!(now_rfc3339()));
        }
        save_run(&mut **es, run_id, &rec);
        let _ = es.folder_put(
            RUN_QUEUE_FOLDER,
            &key,
            &json!({
                "run_id": run_id,
                "workflow_id": workflow_id,
                "queued_at": now_rfc3339(),
                "available_at": now_unix(),
            }),
        );
        let _ = es.folder_put(
            RUN_LEASE_FOLDER,
            &key,
            &json!({
                "run_id": run_id,
                "workflow_id": workflow_id,
                "expires_at": 0,
            }),
        );
        return;
    }
    if failed {
        complete_or_retry(state, workflow_id, run_id, rec, "dead_letter", true);
        return;
    }
    if idx >= steps.len() {
        complete_or_retry(state, workflow_id, run_id, rec, "succeeded", false);
    } else {
        let mut es = state.engine_store.lock().unwrap();
        let key = lease_key(workflow_id, run_id);
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("status".into(), json!("queued"));
            obj.insert("updated_at".into(), json!(now_rfc3339()));
        }
        save_run(&mut **es, run_id, &rec);
        let _ = es.folder_put(
            RUN_QUEUE_FOLDER,
            &key,
            &json!({
                "run_id": run_id,
                "workflow_id": workflow_id,
                "queued_at": now_rfc3339(),
                "available_at": now_unix(),
            }),
        );
        let _ = es.folder_put(
            RUN_LEASE_FOLDER,
            &key,
            &json!({
                "run_id": run_id,
                "workflow_id": workflow_id,
                "expires_at": 0,
            }),
        );
    }
}

/// Process at most one claimed run. Returns 1 if work happened.
pub fn tick_once(state: &SharedState) -> usize {
    let Some((workflow_id, run_id, rec)) = claim_one(state) else {
        return 0;
    };
    execute_claimed(state, &workflow_id, &run_id, rec);
    1
}

pub async fn http_list_runs(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path(workflow_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::Json<Value> {
    if let Err(e) = crate::services::workflow_runtime::require_admin_or_dev(&headers) {
        return axum::Json(e);
    }
    if get_workflow(&state, &workflow_id).is_none() {
        return axum::Json(json!({"ok": false, "error": "Workflow not found"}));
    }
    axum::Json(json!({
        "ok": true,
        "workflow_id": workflow_id,
        "runs": list_runs(&state, &workflow_id),
        "honesty": "Lease-based CLS blueprint runner — not a live CNP bus worker.",
    }))
}

pub async fn http_cancel_run(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::extract::Path((workflow_id, run_id)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> axum::Json<Value> {
    if let Err(e) = crate::services::workflow_runtime::require_admin_or_dev(&headers) {
        return axum::Json(e);
    }
    match cancel_run(&state, &workflow_id, &run_id) {
        Ok(v) => axum::Json(v),
        Err(e) => axum::Json(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_key_format() {
        assert_eq!(lease_key("wf", "run_1"), "wf:run_1");
    }
}
