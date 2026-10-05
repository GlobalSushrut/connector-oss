//! # DAG Orchestrator Service — Airflow for AI Agents
//!
//! Surfaces `connector_engine::orchestrator::Orchestrator` and
//! `connector_engine::saga_bridge::PipelineManager` as a sellable service.
//!
//! Routes (deprecated `/orchestrator/*` aliases in `router.rs` — prefer canonical `/infra/orchestrator/*`):
//!   POST /infra/orchestrator/submit     — submit DAG (canonical)
//!   GET  /infra/orchestrator/{id}       — DAG status
//!   GET  /infra/orchestrator/sagas      — list saga pipelines (canonical)
//!   GET  /infra/orchestrator/sagas/{id} — saga status + rollback info
//!   POST /infra/orchestrator/sagas/{id}/rollback — manual rollback
//!   Legacy: POST /orchestrator/dag, GET /orchestrator/dag/{id}, …, /orchestrator/sagas*

use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::orchestrator::OrchestratorTask;
use serde::Deserialize;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Deserialize)]
pub struct CreateDagRequest {
    pub pipeline_id: String,
    pub tasks: Vec<TaskDef>,
}

#[derive(Deserialize)]
pub struct TaskDef {
    pub task_id: String,
    pub agent_pid: String,
    pub capability_key: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub max_retries: Option<u32>,
    pub backoff_base_ms: Option<u64>,
}

/// POST /orchestrator/dag — create a DAG pipeline with task dependencies.
/// FIX BUG-030: Now supports multiple concurrent DAGs stored in engine_store.
pub async fn create_dag(
    State(state): State<SharedState>,
    Json(req): Json<CreateDagRequest>,
) -> Json<serde_json::Value> {
    // FIX BUG-030: Create a new orchestrator for this pipeline instead of resetting the shared one
    let mut pipeline_orch = connector_engine::orchestrator::Orchestrator::new();

    for t in &req.tasks {
        let mut task = OrchestratorTask::new(&t.task_id, &t.agent_pid, &t.capability_key);
        for dep in &t.depends_on {
            task = task.with_dependency(dep);
        }
        if let (Some(retries), Some(backoff)) = (t.max_retries, t.backoff_base_ms) {
            task = task.with_retries(retries, backoff);
        }
        if let Err(e) = pipeline_orch.add_task(task) {
            return Json(serde_json::json!({"ok": false, "error": e}));
        }
    }

    let waves = pipeline_orch.compute_waves().unwrap_or_default();
    let plan: Vec<serde_json::Value> = waves
        .iter()
        .map(|w| {
            serde_json::json!({
                "wave_index": w.wave_index,
                "task_ids": w.task_ids,
                "parallel": w.task_ids.len() > 1,
            })
        })
        .collect();

    // FIX BUG-030: Store pipeline state in engine_store for multi-DAG support
    {
        let mut es = state.engine_store.lock().unwrap();
        let pipeline_data = serde_json::json!({
            "pipeline_id": req.pipeline_id,
            "task_count": req.tasks.len(),
            "wave_count": plan.len(),
            "execution_plan": plan,
            "status": "Created",
            "current_wave": 0,
            "created_at": now_iso(),
            "tasks": req.tasks.iter().map(|t| serde_json::json!({
                "task_id": t.task_id,
                "agent_pid": t.agent_pid,
                "capability_key": t.capability_key,
                "depends_on": t.depends_on,
                "state": "Pending",
            })).collect::<Vec<_>>(),
        });
        let _ = es.folder_put("orchestrator_dags", &req.pipeline_id, &pipeline_data);
    }

    // Also update the shared orchestrator for backward compatibility with status endpoints
    {
        let mut orch = state.orchestrator.lock().unwrap();
        *orch = pipeline_orch;
    }

    Json(serde_json::json!({
        "ok": true,
        "pipeline_id": req.pipeline_id,
        "task_count": req.tasks.len(),
        "wave_count": plan.len(),
        "execution_plan": plan,
        "created_at": now_iso(),
    }))
}

/// GET /orchestrator/dag/{id} — DAG status with per-task state.
pub async fn dag_status(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let orch = state.orchestrator.lock().unwrap();
    let summary = orch.summary();
    let ready = orch.ready_tasks();
    let tasks: Vec<serde_json::Value> = ready
        .iter()
        .map(|t| {
            serde_json::json!({
                "task_id": t.task_id,
                "agent_pid": t.agent_pid,
                "capability_key": t.capability_key,
                "state": format!("{:?}", t.state),
                "retry_count": t.retry_count,
                "max_retries": t.max_retries,
            })
        })
        .collect();
    Json(serde_json::json!({
        "pipeline_id": id,
        "status": if orch.is_complete() { "Completed" } else { "Running" },
        "task_count": summary.total,
        "completed": summary.completed,
        "failed": summary.failed,
        "running": summary.running,
        "pending": summary.pending,
        "ready_tasks": tasks,
    }))
}

/// POST /orchestrator/dag/{id}/advance — advance pipeline to next execution wave.
pub async fn dag_advance(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut orch = state.orchestrator.lock().unwrap();
    // Start all ready tasks
    let ready: Vec<String> = orch
        .ready_tasks()
        .iter()
        .map(|t| t.task_id.clone())
        .collect();
    let mut started = Vec::new();
    for task_id in &ready {
        if orch.start_task(task_id, now_ms()).is_ok() {
            started.push(task_id.clone());
        }
    }
    Json(serde_json::json!({
        "ok": true,
        "pipeline_id": id,
        "tasks_started": started,
        "advanced_at": now_iso(),
    }))
}

/// GET /orchestrator/dag/{id}/plan — view the full execution plan (waves).
pub async fn dag_plan(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let orch = state.orchestrator.lock().unwrap();
    let waves = orch.compute_waves().unwrap_or_default();
    let plan: Vec<serde_json::Value> = waves
        .iter()
        .map(|w| {
            serde_json::json!({
                "wave_index": w.wave_index,
                "task_ids": w.task_ids,
            })
        })
        .collect();
    Json(serde_json::json!({"pipeline_id": id, "wave_count": plan.len(), "plan": plan}))
}

/// POST /orchestrator/dag/{id}/retry — retry all failed tasks in a pipeline.
pub async fn dag_retry(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut orch = state.orchestrator.lock().unwrap();
    // Retry: fail_task on all failed tasks resets retry counter if can_retry
    let failed: Vec<String> = orch
        .ready_tasks()
        .iter()
        .filter(|t| matches!(t.state, connector_engine::orchestrator::TaskState::Failed))
        .map(|t| t.task_id.clone())
        .collect();
    let mut retried = Vec::new();
    for task_id in &failed {
        if orch.fail_task(task_id, "retry", now_ms()).unwrap_or(false) {
            retried.push(task_id.clone());
        }
    }
    Json(serde_json::json!({
        "ok": true,
        "pipeline_id": id,
        "tasks_retried": retried,
        "retried_at": now_iso(),
    }))
}

// ── Saga Pipelines ───────────────────────────────────────────────────────────

/// GET /orchestrator/sagas — list all saga-managed pipelines.
pub async fn list_sagas(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let pm = state.pipeline_mgr.lock().unwrap();
    let sagas: Vec<serde_json::Value> = pm
        .list()
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "pipeline_id": p.pipeline_id,
                "agent_pid": p.agent_pid,
                "status": p.status,
                "created_at_ms": p.created_at_ms,
                "completed_at_ms": p.completed_at_ms,
                "step_count": p.step_count(),
                "succeeded_count": p.succeeded_count(),
            })
        })
        .collect();
    Json(serde_json::json!({
        "count": sagas.len(),
        "active_count": pm.active_count(),
        "sagas": sagas,
        "note": "Use /orchestrator/sagas/{id} for full step detail on one saga."
    }))
}

/// GET /orchestrator/sagas/{id} — saga pipeline status with step details.
pub async fn saga_status(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let pm = state.pipeline_mgr.lock().unwrap();
    match pm.get(&id) {
        Some(p) => {
            let steps: Vec<serde_json::Value> = p
                .steps
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "step_id": s.step_id,
                        "action": s.action,
                        "status": format!("{:?}", s.status),
                        "reversible": s.reversible,
                        "error": s.error,
                        "result": s.result,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "pipeline_id": p.pipeline_id,
                "agent_pid": p.agent_pid,
                "status": format!("{:?}", p.status),
                "steps": steps,
                "created_at_ms": p.created_at_ms,
                "completed_at_ms": p.completed_at_ms,
            }))
        }
        None => Json(serde_json::json!({"error": "Saga pipeline not found", "status": 404})),
    }
}

/// POST /orchestrator/sagas/{id}/rollback — trigger saga rollback for a failed pipeline.
pub async fn saga_rollback(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut pm = state.pipeline_mgr.lock().unwrap();
    match pm.rollback(&id) {
        Ok(rolled_back_steps) => Json(serde_json::json!({
            "ok": true,
            "pipeline_id": id,
            "status": "RolledBack",
            "steps_rolled_back": rolled_back_steps,
            "rolled_back_at": now_iso(),
        })),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}
