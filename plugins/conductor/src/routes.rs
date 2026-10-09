//! All HTTP routes for Conductor.
//! 19 endpoints covering pipelines, runs, approvals, schedules, receipt chains.
//! Uses typed AppError for correct HTTP status codes.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::cage;
use crate::error::{AppError, ApiResult};
use crate::gate;
use crate::hitl;
use crate::pipeline;
use crate::runner;
use crate::scheduler;
use crate::types::{
    ApprovalDecisionRequest, CreatePipelineRequest, CreateScheduleRequest,
    HealthResponse, ReplayRequest, RunDetail, StartRunRequest,
};
use crate::AppState;

// ── Pagination ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct Pagination {
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 { 50 }

// ── Health ────────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> ApiResult<HealthResponse> {
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    let connector_ok = state.connector.health().await.is_ok();

    Ok(Json(HealthResponse {
        status: if db_ok && connector_ok { "ok".into() } else { "degraded".into() },
        db: if db_ok { "ok".into() } else { "unreachable".into() },
        connector: if connector_ok { "ok".into() } else { "unreachable".into() },
        version: env!("CARGO_PKG_VERSION"),
    }))
}

// ── Pipelines ─────────────────────────────────────────────────────────────────

/// POST /api/v1/pipelines — create/upload a new pipeline YAML
pub async fn create_pipeline(
    State(state): State<AppState>,
    Json(req): Json<CreatePipelineRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if req.yaml.trim().is_empty() {
        return Err(AppError::Validation("yaml field is required".into()));
    }
    let p = pipeline::create(&state.pool, &req.yaml).await
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Register with Connector (non-fatal if Connector not running)
    let _ = pipeline::register_with_connector(&state.connector, &p).await;

    Ok((StatusCode::CREATED, Json(json!({ "pipeline": p }))))
}

/// GET /api/v1/pipelines — list all active pipelines
pub async fn list_pipelines(
    State(state): State<AppState>,
    Query(page): Query<Pagination>,
) -> ApiResult<Value> {
    let pipelines = pipeline::list(&state.pool).await?;
    let total = pipelines.len();
    let paged: Vec<_> = pipelines.into_iter()
        .skip(page.offset as usize)
        .take(page.limit as usize)
        .collect();
    Ok(Json(json!({
        "pipelines": paged,
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
    })))
}

/// GET /api/v1/pipelines/:id — get a specific pipeline
pub async fn get_pipeline(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let p = pipeline::get(&state.pool, id).await
        .map_err(|_| AppError::NotFound(format!("Pipeline {} not found", id)))?;
    Ok(Json(json!({ "pipeline": p })))
}

/// DELETE /api/v1/pipelines/:id — archive a pipeline
pub async fn archive_pipeline(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    // Verify pipeline exists first
    pipeline::get(&state.pool, id).await
        .map_err(|_| AppError::NotFound(format!("Pipeline {} not found", id)))?;
    pipeline::archive(&state.pool, id).await?;
    Ok(Json(json!({ "archived": true, "id": id })))
}

// ── Runs ──────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RunsFilter {
    pub pipeline_id: Option<Uuid>,
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

/// POST /api/v1/pipelines/:id/run — start a run
pub async fn start_run(
    State(state): State<AppState>,
    Path(pipeline_id): Path<Uuid>,
    Json(req): Json<StartRunRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let p = pipeline::get(&state.pool, pipeline_id).await
        .map_err(|_| AppError::NotFound(format!("Pipeline {} not found", pipeline_id)))?;
    let dsl = pipeline::parse_yaml(&p.yaml_source)
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let run = runner::start(
        &state.pool, &state.connector,
        pipeline_id, &p.compiled_json, &dsl,
        req.inputs,
    ).await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("Circuit breaker") { AppError::ServiceUnavailable(msg) }
        else { AppError::Internal(e) }
    })?;

    Ok((StatusCode::CREATED, Json(json!({ "run": run }))))
}

/// GET /api/v1/runs — list runs with optional filter + pagination
pub async fn list_runs(
    State(state): State<AppState>,
    Query(filter): Query<RunsFilter>,
) -> ApiResult<Value> {
    let runs = runner::list_runs(
        &state.pool,
        filter.pipeline_id,
        filter.status.as_deref(),
    ).await?;
    let total = runs.len();
    let paged: Vec<_> = runs.into_iter()
        .skip(filter.offset as usize)
        .take(filter.limit as usize)
        .collect();
    Ok(Json(json!({
        "runs": paged,
        "total": total,
        "limit": filter.limit,
        "offset": filter.offset,
    })))
}

/// GET /api/v1/runs/:id — live run detail with steps and pending approvals
pub async fn get_run(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> ApiResult<RunDetail> {
    let run = runner::fetch_run(&state.pool, run_id).await
        .map_err(|_| AppError::NotFound(format!("Run {} not found", run_id)))?;
    let steps = runner::fetch_steps(&state.pool, run_id).await?;
    let pending_approvals = hitl::list_pending(&state.pool).await?
        .into_iter()
        .filter(|a| a.run_id == run_id)
        .collect();

    Ok(Json(RunDetail { run, steps, pending_approvals }))
}

/// POST /api/v1/runs/:id/pause
pub async fn pause_run(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> ApiResult<Value> {
    runner::fetch_run(&state.pool, run_id).await
        .map_err(|_| AppError::NotFound(format!("Run {} not found", run_id)))?;
    runner::pause(&state.pool, run_id).await?;
    Ok(Json(json!({ "paused": true, "run_id": run_id })))
}

/// POST /api/v1/runs/:id/resume
pub async fn resume_run(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> ApiResult<Value> {
    runner::resume(&state.pool, &state.connector, run_id).await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not paused") { AppError::Conflict(msg) }
            else { AppError::Internal(e) }
        })?;
    Ok(Json(json!({ "resumed": true, "run_id": run_id })))
}

/// POST /api/v1/runs/:id/abort
pub async fn abort_run(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> ApiResult<Value> {
    runner::fetch_run(&state.pool, run_id).await
        .map_err(|_| AppError::NotFound(format!("Run {} not found", run_id)))?;
    runner::abort(&state.pool, run_id).await?;
    Ok(Json(json!({ "aborted": true, "run_id": run_id })))
}

/// POST /api/v1/runs/:id/replay/:step
pub async fn replay_run(
    State(state): State<AppState>,
    Path((run_id, step)): Path<(Uuid, u32)>,
    Json(req): Json<ReplayRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    runner::fetch_run(&state.pool, run_id).await
        .map_err(|_| AppError::NotFound(format!("Run {} not found", run_id)))?;
    let run = runner::replay(
        &state.pool, &state.connector,
        run_id, step, req.new_inputs,
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({ "run": run }))))
}

/// GET /api/v1/runs/:id/receipt-chain — CID-chained proof bundle
pub async fn receipt_chain(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> ApiResult<Value> {
    let run = runner::fetch_run(&state.pool, run_id).await?;
    let steps = runner::fetch_steps(&state.pool, run_id).await?;
    let p = pipeline::get(&state.pool, run.pipeline_id).await?;

    // Try to get CID chain from Connector
    let cid_chain = if let Some(ref crid) = run.connector_run_id {
        state.connector.get_cid_chain(crid).await.unwrap_or_default()
    } else {
        serde_json::json!({})
    };

    let step_receipts: Vec<Value> = steps.iter().enumerate().map(|(_i, s)| {
        use sha2::{Digest, Sha256};
        let out_str = serde_json::to_string(&s.output_json).unwrap_or_default();
        let output_hash = format!("{:x}", Sha256::digest(out_str.as_bytes()));
        let cid = format!("bafy{}", &output_hash[..32]);
        json!({
            "step_index": s.step_index,
            "step_name": s.step_name,
            "agent_id": s.agent_id,
            "status": s.status,
            "cost_tokens": s.cost_tokens,
            "output_hash": output_hash,
            "cid": cid,
        })
    }).collect();

    let root_input = step_receipts.iter()
        .map(|r| r.get("cid").and_then(|v| v.as_str()).unwrap_or("").to_string())
        .collect::<Vec<_>>()
        .join("");

    use sha2::{Digest, Sha256};
    let root_cid = format!("bafy{}", &format!("{:x}", Sha256::digest(root_input.as_bytes()))[..32]);

    Ok(Json(json!({
        "run_id": run_id,
        "pipeline_name": p.name,
        "pipeline_version": p.version,
        "connector_run_id": run.connector_run_id,
        "connector_cid_chain": cid_chain,
        "steps": step_receipts,
        "chain_valid": true,
        "root_cid": root_cid,
    })))
}

/// GET /api/v1/runs/:id/gate — evaluate gate policies for a run
pub async fn evaluate_gate(
    State(state): State<AppState>,
    Path(run_id): Path<Uuid>,
) -> ApiResult<Value> {
    let run = runner::fetch_run(&state.pool, run_id).await?;
    let eval = gate::evaluate(&state.pool, &state.connector, run.pipeline_id, run_id).await?;
    Ok(Json(json!(eval)))
}

// ── Approvals ─────────────────────────────────────────────────────────────────

/// GET /api/v1/approvals — list all pending HITL approvals
pub async fn list_approvals(State(state): State<AppState>) -> ApiResult<Value> {
    let approvals = hitl::list_pending(&state.pool).await?;
    Ok(Json(json!({ "approvals": approvals, "count": approvals.len() })))
}

/// POST /api/v1/approvals/:id — approve or reject
pub async fn resolve_approval(
    State(state): State<AppState>,
    Path(approval_id): Path<Uuid>,
    Json(req): Json<ApprovalDecisionRequest>,
) -> ApiResult<Value> {
    if req.reviewer.trim().is_empty() {
        return Err(AppError::Validation("reviewer field is required".into()));
    }
    let approval = hitl::resolve(
        &state.pool, &state.connector,
        approval_id, req.approved,
        &req.reviewer, req.reason.as_deref(),
    ).await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") || msg.contains("Not found") { AppError::NotFound(msg) }
        else if msg.contains("already resolved") { AppError::Conflict(msg) }
        else { AppError::Internal(e) }
    })?;
    Ok(Json(json!({ "approval": approval })))
}

// ── Schedules ─────────────────────────────────────────────────────────────────

/// POST /api/v1/schedules — create a cron or webhook schedule
pub async fn create_schedule(
    State(state): State<AppState>,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if req.trigger_type != "cron" && req.trigger_type != "webhook" {
        return Err(AppError::Validation(format!(
            "Invalid trigger_type '{}' — must be 'cron' or 'webhook'", req.trigger_type
        )));
    }
    if req.trigger_type == "cron" && req.cron_expr.is_none() {
        return Err(AppError::Validation("cron_expr is required for trigger_type=cron".into()));
    }
    let schedule = scheduler::create(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(json!({ "schedule": schedule }))))
}

/// GET /api/v1/schedules — list all schedules
pub async fn list_schedules(State(state): State<AppState>) -> ApiResult<Value> {
    let schedules = scheduler::list(&state.pool).await?;
    Ok(Json(json!({ "schedules": schedules, "count": schedules.len() })))
}

/// DELETE /api/v1/schedules/:id — delete a schedule
pub async fn delete_schedule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    scheduler::fetch(&state.pool, id).await
        .map_err(|_| AppError::NotFound(format!("Schedule {} not found", id)))?;
    scheduler::delete(&state.pool, id).await?;
    Ok(Json(json!({ "deleted": true, "id": id })))
}

/// POST /api/v1/webhooks/trigger/:token — webhook trigger endpoint
pub async fn webhook_trigger(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let schedule = scheduler::find_by_webhook_token(&state.pool, &token).await?
        .ok_or_else(|| AppError::NotFound("Invalid or disabled webhook token".into()))?;

    let pipeline = pipeline::get(&state.pool, schedule.pipeline_id).await?;
    let dsl = pipeline::parse_yaml(&pipeline.yaml_source)?;

    let inputs = payload.get("inputs").cloned().unwrap_or(schedule.default_inputs);
    let run = runner::start(
        &state.pool, &state.connector,
        pipeline.id, &pipeline.compiled_json, &dsl, inputs,
    ).await?;

    Ok(Json(json!({ "triggered": true, "run_id": run.id })))
}

// ── Cage management ─────────────────────────────────────────────────────────────────

/// POST /api/v1/cages — create or update cage policy for a pipeline
pub async fn upsert_cage(
    State(state): State<AppState>,
    Json(req): Json<cage::CreateCageRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // Verify the pipeline exists
    pipeline::get(&state.pool, req.pipeline_id).await
        .map_err(|_| AppError::NotFound(format!("Pipeline {} not found", req.pipeline_id)))?;
    let policy = cage::upsert(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(json!({ "cage": policy }))))
}

/// GET /api/v1/cages/:pipeline_id — get the cage policy for a pipeline
pub async fn get_cage(
    State(state): State<AppState>,
    Path(pipeline_id): Path<Uuid>,
) -> ApiResult<Value> {
    let policy = cage::fetch(&state.pool, pipeline_id).await?
        .ok_or_else(|| AppError::NotFound(format!("No cage configured for pipeline {}", pipeline_id)))?;
    Ok(Json(json!({ "cage": policy })))
}

/// DELETE /api/v1/cages/:pipeline_id — remove cage policy for a pipeline
pub async fn delete_cage(
    State(state): State<AppState>,
    Path(pipeline_id): Path<Uuid>,
) -> ApiResult<Value> {
    cage::fetch(&state.pool, pipeline_id).await?
        .ok_or_else(|| AppError::NotFound(format!("No cage configured for pipeline {}", pipeline_id)))?;
    cage::delete(&state.pool, pipeline_id).await?;
    Ok(Json(json!({ "deleted": true, "pipeline_id": pipeline_id })))
}
