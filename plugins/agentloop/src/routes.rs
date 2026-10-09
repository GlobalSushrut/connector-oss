//! HTTP route handlers — all four modules + DNS + mesh + workers.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{agent_dns, debug, design, error::{ApiResult, AppError}, mesh, optimize, ship, types::*, worker, AppState};

// ── Readiness probe ───────────────────────────────────────────────────────────

pub async fn readyz(State(state): State<AppState>) -> ApiResult<Value> {
    sqlx::query("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .map_err(|_| AppError::ServiceUnavailable("Database not ready".into()))?;
    Ok(Json(json!({ "ready": true, "version": env!("CARGO_PKG_VERSION") })))
}

// ── Mesh: circuit breaker status ──────────────────────────────────────────────

pub async fn mesh_circuit_breakers(_state: State<AppState>) -> ApiResult<Value> {
    Ok(Json(json!({ "note": "circuit breaker registry is process-local; see Prometheus metrics agentloop_mesh_circuit_open_total" })))
}

// ── Health ────────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> ApiResult<HealthResponse> {
    let db_ok = sqlx::query("SELECT 1").fetch_one(&state.pool).await.is_ok();
    let conn_ok = state.connector.health().await.is_ok();
    Ok(Json(HealthResponse {
        status:    if db_ok && conn_ok { "ok".into() } else { "degraded".into() },
        db:        if db_ok { "ok".into() } else { "error".into() },
        connector: if conn_ok { "ok".into() } else { "error".into() },
        version:   env!("CARGO_PKG_VERSION").into(),
    }))
}

// ── Agents ────────────────────────────────────────────────────────────────────

pub async fn create_agent(
    State(state): State<AppState>,
    Json(req): Json<CreateAgentRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let tags     = req.tags.unwrap_or_default();
    let metadata = req.metadata.unwrap_or(json!({}));
    let agent = design::create_agent(
        &state.pool, &req.name, req.connector_id.as_deref(),
        req.description.as_deref(), req.team.as_deref(), &tags, &metadata,
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({ "agent": agent }))))
}

pub async fn list_agents(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let agents = design::list_agents(&state.pool, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "agents": agents, "limit": p.limit(), "offset": p.offset() })))
}

pub async fn get_agent(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let agent = design::get_agent(&state.pool, id).await?;
    Ok(Json(json!({ "agent": agent })))
}

// ── Agent DNS ─────────────────────────────────────────────────────────────────

pub async fn dns_register(
    State(state): State<AppState>,
    Json(req): Json<agent_dns::RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let (record, endpoint) = agent_dns::register(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(json!({ "dns_record": record, "endpoint": endpoint }))))
}

pub async fn dns_resolve(
    State(state): State<AppState>,
    Path(fqan): Path<String>,
) -> ApiResult<Value> {
    let card = agent_dns::resolve(&state.pool, &fqan).await
        .map_err(|e| AppError::NotFound(e.to_string()))?;
    Ok(Json(json!({ "agent_card": card })))
}

pub async fn dns_list(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let records = agent_dns::list_records(&state.pool, None, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "records": records })))
}

pub async fn dns_deregister(
    State(state): State<AppState>,
    Path(fqan): Path<String>,
) -> ApiResult<Value> {
    agent_dns::deregister(&state.pool, &fqan).await?;
    Ok(Json(json!({ "deregistered": true, "fqan": fqan })))
}

// ── Mesh ──────────────────────────────────────────────────────────────────────

pub async fn mesh_call(
    State(state): State<AppState>,
    Json(req): Json<mesh::MeshCallRequest>,
) -> ApiResult<Value> {
    let resp = state.mesh.call(req).await?;
    Ok(Json(json!({ "result": resp })))
}

pub async fn mesh_hops(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let hops = mesh::list_hops(&state.pool, None, None, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "hops": hops })))
}

pub async fn mesh_verify_chain(
    State(state): State<AppState>,
    Path(hop_id): Path<Uuid>,
) -> ApiResult<Value> {
    let result = mesh::verify_hop_chain(&state.pool, hop_id).await?;
    Ok(Json(result))
}

// ── Workers ───────────────────────────────────────────────────────────────────

pub async fn create_worker(
    State(state): State<AppState>,
    Json(req): Json<worker::CreateWorkerRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let w = worker::create(&state.pool, req).await?;
    Ok((StatusCode::CREATED, Json(json!({ "worker": w }))))
}

pub async fn list_workers(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let workers = worker::list(&state.pool, None, None, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "workers": workers })))
}

pub async fn get_worker(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let w = worker::get(&state.pool, id).await?;
    Ok(Json(json!({ "worker": w })))
}

pub async fn invoke_worker(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let inv = worker::invoke(&state.pool, id, Some("api".into()), payload).await?;
    Ok(Json(json!({ "invocation": inv })))
}

pub async fn worker_mcp_manifest(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let manifest = worker::mcp_manifest(&state.pool, id).await?;
    Ok(Json(manifest))
}

pub async fn worker_invocations(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let invocations = worker::list_invocations(&state.pool, id, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "invocations": invocations })))
}

// ── Design: Prompts ───────────────────────────────────────────────────────────

pub async fn create_prompt(
    State(state): State<AppState>,
    Json(req): Json<CreatePromptRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let tags         = req.tags.unwrap_or_default();
    let variables    = req.variables.unwrap_or(json!([]));
    let model_config = req.model_config.unwrap_or(json!({}));
    let (prompt, version) = design::create_prompt(
        &state.pool,
        req.agent_id,
        &req.name,
        req.description.as_deref(),
        &tags,
        req.system_prompt.as_deref(),
        req.user_template.as_deref(),
        &variables,
        &model_config,
        req.author.as_deref(),
        req.commit_message.as_deref(),
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({ "prompt": prompt, "version": version }))))
}

pub async fn list_prompts(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let prompts = design::list_prompts(&state.pool, None, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "prompts": prompts })))
}

pub async fn get_prompt(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let prompt   = design::get_prompt(&state.pool, id).await?;
    let versions = design::list_versions(&state.pool, id).await?;
    Ok(Json(json!({ "prompt": prompt, "versions": versions })))
}

pub async fn create_prompt_version(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreatePromptVersionRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let variables    = req.variables.unwrap_or(json!([]));
    let model_config = req.model_config.unwrap_or(json!({}));
    let version = design::create_version(
        &state.pool, id,
        req.system_prompt.as_deref(), req.user_template.as_deref(),
        &variables, &model_config,
        req.author.as_deref(), req.commit_message.as_deref(),
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({ "version": version }))))
}

pub async fn approve_prompt_version(
    State(state): State<AppState>,
    Path((prompt_id, version_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<ApprovePromptRequest>,
) -> ApiResult<Value> {
    let _ = prompt_id;
    let version = design::approve_version(
        &state.pool, version_id, req.approved, &req.reviewer, req.reason.as_deref(),
    ).await?;
    Ok(Json(json!({ "version": version })))
}

// ── Design: Datasets ──────────────────────────────────────────────────────────

pub async fn create_dataset(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let name   = body.get("name").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("name required".into()))?;
    let tags: Vec<String> = body.get("tags").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
    let agent_id: Option<Uuid> = body.get("agent_id").and_then(|v| v.as_str()).and_then(|s| s.parse().ok());
    let ds = design::create_dataset(&state.pool, agent_id, name, body.get("description").and_then(|v| v.as_str()), &tags).await?;
    Ok((StatusCode::CREATED, Json(json!({ "dataset": ds }))))
}

// ── Ship: Experiments ─────────────────────────────────────────────────────────

pub async fn create_experiment(
    State(state): State<AppState>,
    Json(req): Json<CreateExperimentRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let exp = ship::create_experiment(
        &state.pool,
        &state.connector,
        req.agent_id,
        &req.name,
        req.description.as_deref(),
        req.variant_control_id,
        req.variant_treatment_id,
        req.traffic_split_pct.unwrap_or(50),
        req.significance_threshold.unwrap_or(0.95),
        req.auto_promote.unwrap_or(false),
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({ "experiment": exp }))))
}

pub async fn list_experiments(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let exps = ship::list_experiments(&state.pool, None, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "experiments": exps })))
}

pub async fn get_experiment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let exp = ship::get_experiment(&state.pool, id).await?;
    Ok(Json(json!({ "experiment": exp })))
}

pub async fn start_experiment(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let exp = ship::start_experiment(&state.pool, id).await?;
    Ok(Json(json!({ "experiment": exp })))
}

pub async fn pause_experiment(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let exp = ship::pause_experiment(&state.pool, id).await?;
    Ok(Json(json!({ "experiment": exp })))
}

pub async fn promote_experiment(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let exp = ship::promote_experiment(&state.pool, &state.connector, id, false).await?;
    Ok(Json(json!({ "experiment": exp })))
}

pub async fn rollback_experiment(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> ApiResult<Value> {
    let reason = body.get("reason").and_then(|v| v.as_str());
    let exp = ship::rollback_experiment(&state.pool, &state.connector, id, reason).await?;
    Ok(Json(json!({ "experiment": exp })))
}

pub async fn refresh_experiment_metrics(State(state): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Value> {
    let exp = ship::refresh_metrics(&state.pool, &state.connector, id).await?;
    Ok(Json(json!({ "experiment": exp })))
}

// ── Debug: Timeline + Runs ────────────────────────────────────────────────────

pub async fn agent_timeline(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let runs = debug::timeline(&state.pool, agent_id, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "runs": runs, "agent_id": agent_id })))
}

pub async fn get_run(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let run   = debug::get_run(&state.pool, id).await?;
    let steps = debug::get_steps(&state.pool, id).await?;
    Ok(Json(json!({ "run": run, "steps": steps })))
}

pub async fn diff_runs(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> ApiResult<Value> {
    let left  = body.get("left_run_id").and_then(|v| v.as_str()).and_then(|s| s.parse::<Uuid>().ok())
        .ok_or_else(|| AppError::BadRequest("left_run_id required".into()))?;
    let right = body.get("right_run_id").and_then(|v| v.as_str()).and_then(|s| s.parse::<Uuid>().ok())
        .ok_or_else(|| AppError::BadRequest("right_run_id required".into()))?;
    let diff = debug::diff_runs(&state.pool, left, right).await?;
    Ok(Json(json!({ "diff": diff })))
}

pub async fn start_replay(
    State(state): State<AppState>,
    Json(req): Json<CreateReplayRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let replay = debug::start_replay(
        &state.pool, &state.connector,
        req.source_run_id, req.substitutions, req.created_by,
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({ "replay": replay }))))
}

pub async fn get_replay(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let replay = debug::get_replay(&state.pool, id).await?;
    Ok(Json(json!({ "replay": replay })))
}

pub async fn sync_history(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
) -> ApiResult<Value> {
    let agent = design::get_agent(&state.pool, agent_id).await?;
    let connector_id = agent.connector_id.ok_or_else(|| AppError::BadRequest("Agent has no connector_id".into()))?;
    let count = debug::sync_history(&state.pool, &state.connector, &connector_id, 100).await?;
    Ok(Json(json!({ "synced": count, "agent_id": agent_id })))
}

// ── Optimize ──────────────────────────────────────────────────────────────────

pub async fn fleet_summary(State(state): State<AppState>) -> ApiResult<Value> {
    let summary = optimize::fleet_summary(&state.pool).await?;
    Ok(Json(summary))
}

pub async fn create_slo(
    State(state): State<AppState>,
    Json(req): Json<CreateSloRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let slo = optimize::create_slo(
        &state.pool, req.agent_id, &req.name, &req.metric,
        req.threshold, req.window_hours.unwrap_or(24),
    ).await?;
    Ok((StatusCode::CREATED, Json(json!({ "slo": slo }))))
}

pub async fn list_slos(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
) -> ApiResult<Value> {
    let slos = optimize::list_slos(&state.pool, agent_id).await?;
    Ok(Json(json!({ "slos": slos })))
}

pub async fn evaluate_slos(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
) -> ApiResult<Value> {
    let slos = optimize::evaluate_slos(&state.pool, agent_id).await?;
    Ok(Json(json!({ "slos": slos })))
}

pub async fn list_recommendations(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let recs = optimize::list_recommendations(&state.pool, None, Some("open"), p.limit(), p.offset()).await?;
    Ok(Json(json!({ "recommendations": recs })))
}

pub async fn apply_recommendation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<ApplyRecommendationRequest>,
) -> ApiResult<Value> {
    let rec = optimize::apply_recommendation(&state.pool, &state.connector, id, &req.applied_by).await?;
    Ok(Json(json!({ "recommendation": rec })))
}

pub async fn dismiss_recommendation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let rec = optimize::dismiss_recommendation(&state.pool, id).await?;
    Ok(Json(json!({ "recommendation": rec })))
}

pub async fn list_drift_events(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
    Query(p): Query<Pagination>,
) -> ApiResult<Value> {
    let events = optimize::list_drift_events(&state.pool, agent_id, p.limit(), p.offset()).await?;
    Ok(Json(json!({ "drift_events": events })))
}

pub async fn detect_drift(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
) -> ApiResult<Value> {
    let events = optimize::detect_drift(&state.pool, agent_id).await?;
    let count = events.len();
    Ok(Json(json!({ "drift_events": events, "count": count })))
}
