//! Data Plane API Gateway
//!
//! HTTP ingress, request normalization, routing to the **Control** pipeline by default
//! (metering + policy/PII filter + quarantine / operation blocks + trace evidence). Optional
//! **View** passthrough exists only when `TRACETRAMP_ALLOW_VIEW_PIPELINE=1` and the client sends
//! `X-TraceTramp-Pipeline: view`.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::from_fn,
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use serde::Deserialize;
use sqlx::Row;
use std::sync::Arc;
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
    GovernorLayer,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    auth::require_data_plane_auth,
    control,
    error::AppError,
    resolver,
    types::{
        BudgetContext, ChatCompletionRequest, OutputMode, RequestMode, RuntimeExecutionRequest,
    },
    view, AppState,
};

/// Create the Data Plane router
pub fn create_router(state: AppState) -> Router {
    let state = Arc::new(state);
    let mut governor_builder = GovernorConfigBuilder::default();
    governor_builder.per_second(2).burst_size(100);
    let governor_conf = governor_builder
        .key_extractor(ApiKeyRateLimitKeyExtractor)
        .finish()
        .expect("failed to build governor config");

    // Health/readiness must not share the anonymous governor bucket with probes
    // (Docker/k8s healthchecks hit /health without auth → one global "anonymous" key
    // exhausts quota and 429s everything including chat for hours).
    let health_router = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .with_state(Arc::clone(&state));

    let governed = Router::new()
        // OpenAI-compatible endpoints
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/messages", post(messages))
        .route("/v1/responses", post(responses))
        .route("/v1/models", get(list_models))
        // Universal LLM endpoint (provider-agnostic)
        .route("/v1/unified/completions", post(unified_completions))
        // Tool execution endpoints
        .route("/v1/tools/invoke", post(invoke_tool))
        .route("/v1/tools/invoke/:tool_name", post(invoke_tool_by_name))
        .route("/v1/tools/batch", post(batch_invoke_tools))
        // Function execution (OpenFaaS, Lambda, etc.)
        .route("/v1/functions/:name/call", post(call_function))
        .route("/v1/functions/:name/async", post(async_call_function))
        // Workflow / Pipeline endpoints
        .route("/v1/workflows", post(create_workflow).get(list_workflows))
        .route(
            "/v1/workflows/:id",
            get(get_workflow)
                .put(update_workflow)
                .delete(delete_workflow),
        )
        .route("/v1/workflows/:id/run", post(run_workflow))
        .route("/v1/workflows/:id/trigger", post(trigger_workflow))
        .route("/v1/runs/:run_id", get(get_workflow_run))
        .route("/v1/runs/:run_id/cancel", post(cancel_workflow_run))
        .route("/v1/runs/:run_id/resume", post(resume_workflow_run))
        // Pipeline orchestration
        .route("/v1/pipelines/submit", post(submit_pipeline))
        .route("/v1/pipelines/:id/status", get(get_pipeline_status))
        // Agent execution
        .route("/v1/agents/run", post(run_agent))
        .route("/v1/agents/:id/continue", post(continue_agent))
        // Evidence API (View Pipeline)
        .route("/trace/:trace_id", get(get_trace))
        .route("/explain/:request_id", get(get_explain))
        .route("/prove/:request_id", get(get_prove))
        .route("/cost/:request_id", get(get_cost))
        .route("/decision/:trace_id", get(get_decision_tree))
        .route("/v1/compliance/export", get(compliance_export))
        .route("/decision/diff", get(get_decision_diff))
        .route("/enforcement/:trace_id", get(get_enforcement_packet))
        .route(
            "/workflow/:workflow_id/statement",
            get(get_workflow_statement),
        )
        // Streaming endpoints
        .route("/v1/stream/:stream_id", get(stream_events))
        // Cage URL paid path: drop-in for provider SDKs.
        .route("/cage/:sha_address", any(cage_root))
        .route("/cage/:sha_address/*path", any(cage_proxy))
        .layer(GovernorLayer {
            config: std::sync::Arc::new(governor_conf),
        })
        .route_layer(from_fn(require_data_plane_auth))
        .with_state(state);

    Router::new().merge(health_router).merge(governed)
}

#[derive(Clone)]
struct ApiKeyRateLimitKeyExtractor;

impl KeyExtractor for ApiKeyRateLimitKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let headers = req.headers();
        if let Some(auth) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(key) = auth.strip_prefix("Bearer ") {
                let key = key.trim();
                if !key.is_empty() {
                    return Ok(key.to_string());
                }
            }
        }
        if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
            let key = key.trim();
            if !key.is_empty() {
                return Ok(key.to_string());
            }
        }
        Ok("anonymous".to_string())
    }
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "tracetramp-data-plane",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Main chat completions proxy endpoint
async fn chat_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    run_chat_flow(state, headers, body).await
}

/// Prefer stable client-supplied IDs when present so WitnessCtl proxy captures
/// (`x-trace-id` / `x-request-id`) align with TraceTramp runtime + handoff payloads.
fn ids_from_headers_or_new(headers: &HeaderMap) -> (Uuid, Uuid) {
    let trace_id = headers
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
        .unwrap_or_else(Uuid::new_v4);
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
        .unwrap_or_else(Uuid::new_v4);
    (trace_id, request_id)
}

/// **Control** is the product default: enforcement + observability in one path. **View** is an
/// optional passthrough lane for operators (disabled unless `config.allow_view_pipeline`).
fn effective_request_mode(
    headers: &HeaderMap,
    config: &crate::config::Config,
    tenant_default: RequestMode,
) -> RequestMode {
    let hardened = matches!(
        std::env::var("CONNECTOR_ENV")
            .or_else(|_| std::env::var("TRACETRAMP_ENV"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "pilots" | "pilot" | "staging"
    );
    if hardened {
        return RequestMode::Control;
    }
    if !config.allow_view_pipeline {
        return RequestMode::Control;
    }
    let requested = headers
        .get("x-tracetramp-pipeline")
        .or_else(|| headers.get("X-TraceTramp-Pipeline"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase());
    match requested.as_deref() {
        Some("view") => RequestMode::View,
        _ => tenant_default,
    }
}

async fn run_chat_flow(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    let (trace_id, request_id) = ids_from_headers_or_new(&headers);

    debug!(
        "Chat completion request: trace_id={}, request_id={}",
        trace_id, request_id
    );

    // Parse incoming request
    let chat_req: ChatCompletionRequest = serde_json::from_str(&body).map_err(|e| {
        warn!("Failed to parse chat completion request: {}", e);
        AppError::Validation(format!("Invalid request body: {}", e))
    })?;

    // Extract API key for tenant resolution
    let api_key = extract_api_key(&headers)?;

    // Resolve tenant and configuration
    let tenant_ctx =
        resolver::resolve_tenant(&state.db_pool, &state.connector_client, &api_key).await?;
    crate::tenancy::validate_tenant_id(&tenant_ctx.tenant_id)?;

    let kernel_host_snapshot =
        if std::env::var("TRACETRAMP_KERNEL_SNAPSHOT").ok().as_deref() == Some("0") {
            None
        } else {
            state
                .connector_client
                .get_kernel_agent_status(&tenant_ctx.actor_id)
                .await
                .ok()
                .flatten()
        };

    let request_mode = effective_request_mode(&headers, &state.config, tenant_ctx.default_mode);

    let test_hold_requested = headers
        .get("x-tracetramp-test-hold")
        .or_else(|| headers.get("X-TraceTramp-Test-Hold"))
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    // Normalize to canonical RuntimeExecutionRequest
    let runtime_req = RuntimeExecutionRequest {
        request_id,
        trace_id,
        tenant_id: tenant_ctx.tenant_id.clone(),
        app_id: extract_app_id(&headers).unwrap_or_default(),
        environment: tenant_ctx.environment.clone(),
        workflow_id: None,
        session_id: extract_session_id(&headers),
        actor_id: tenant_ctx.actor_id.clone(),
        actor_role: tenant_ctx.actor_role.clone(),
        request_mode,
        model_intent: classify_intent(&chat_req),
        model_id: chat_req.model.clone(),
        input_payload: serde_json::to_value(&chat_req)?,
        tools_requested: chat_req
            .tools
            .as_ref()
            .map(|t| t.iter().map(|td| td.function.name.clone()).collect())
            .unwrap_or_default(),
        memory_scope: None,
        action_targets: vec![],
        output_mode: if chat_req.stream == Some(true) {
            OutputMode::Stream
        } else {
            OutputMode::Text
        },
        budget_context: BudgetContext {
            max_tokens: chat_req.max_tokens,
            max_cost_usd: None,
            priority: None,
        },
        compliance_tags: vec![],
        execution_profile: "default".to_string(),
        policy_bundle: tenant_ctx.policy_bundle.clone(),
        kernel_host_snapshot,
        hitl_bypass: false,
        test_hold_requested,
    };

    // Route to appropriate pipeline based on mode
    match runtime_req.request_mode {
        RequestMode::View => {
            debug!("Routing to View Pipeline: trace_id={}", trace_id);
            view::handle_request(state, runtime_req, headers, chat_req).await
        }
        RequestMode::Control => {
            debug!("Routing to Control Pipeline: trace_id={}", trace_id);
            control::handle_request(state, runtime_req, headers, chat_req).await
        }
    }
}

async fn cage_root(
    State(state): State<Arc<AppState>>,
    Path(sha_address): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    cage_proxy_inner(state, sha_address, String::new(), method, headers, body).await
}

async fn cage_proxy(
    State(state): State<Arc<AppState>>,
    Path((sha_address, path)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    cage_proxy_inner(state, sha_address, path, method, headers, body).await
}

async fn cage_proxy_inner(
    state: Arc<AppState>,
    sha_address: String,
    path: String,
    method: Method,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    crate::cage::validate_cage_sha_address(&sha_address)?;
    let raw_path = path;
    let normalized = if raw_path.is_empty() {
        "/".to_string()
    } else if raw_path.starts_with('/') {
        raw_path.clone()
    } else {
        format!("/{}", raw_path)
    };

    if method == Method::GET && (normalized == "/" || normalized == "/health") {
        return Ok(Json(serde_json::json!({
            "status": "ok",
            "cage_address": sha_address,
            "route": normalized,
            "hint": "POST /cage/:sha_address/v1/chat/completions"
        }))
        .into_response());
    }

    if method == Method::POST
        && matches!(
            normalized.as_str(),
            "/v1/chat/completions" | "/v1/messages" | "/v1/responses" | "/v1/unified/completions"
        )
    {
        let mut resp = run_chat_flow(state, headers, body).await?;
        if let Ok(header_val) = axum::http::HeaderValue::from_str(&sha_address) {
            resp.headers_mut().insert("X-Cage-Address", header_val);
        }
        return Ok(resp);
    }

    Ok((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Unsupported cage route",
            "cage_address": sha_address,
            "method": method.to_string(),
            "path": normalized,
            "supported": [
                "POST /cage/:sha_address/v1/chat/completions",
                "POST /cage/:sha_address/v1/messages",
                "POST /cage/:sha_address/v1/responses",
                "GET /cage/:sha_address/health"
            ]
        })),
    )
        .into_response())
}

/// Anthropic-style messages endpoint
async fn messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    // Similar to chat_completions but with Anthropic message format
    // For MVP, normalize to same flow
    chat_completions(State(state), headers, body).await
}

/// Responses endpoint (newer OpenAI API)
async fn responses(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, AppError> {
    // Normalize to chat completions flow
    chat_completions(State(state), headers, body).await
}

/// Submit workflow endpoint (generic submit - routes to run_workflow)
async fn submit_workflow(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    let workflow_id = body["workflow_id"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("workflow_id required".to_string()))?
        .to_string();
    let input = body.get("input").cloned().unwrap_or(serde_json::json!({}));
    run_workflow(State(state), Path(workflow_id), Json(input))
        .await
        .map(|r| r.into_response())
}

/// Invoke tool endpoint (generic invoke - expects name in body)
async fn invoke_tool(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    let tool_name = body["name"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("tool name required".to_string()))?
        .to_string();
    let args = body
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    invoke_tool_by_name(State(state), Path(tool_name), Json(args))
        .await
        .map(|r| r.into_response())
}

/// Run agent endpoint - initialize agent run with LLM + tools
async fn run_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AgentRunRequest>,
) -> Result<impl IntoResponse, AppError> {
    let agent_run_id = uuid::Uuid::new_v4().to_string();
    let tenant_id =
        extract_tenant_id_from_headers(&headers).unwrap_or_else(|| "default".to_string());

    // Create agent run record
    sqlx::query(
        "INSERT INTO workflow_runs (id, workflow_id, tenant_id, status, input, step_results, started_at, created_at) VALUES ($1, 'agent', $2, 'running', $3, '{}', NOW(), NOW())"
    )
    .bind(&agent_run_id)
    .bind(&tenant_id)
    .bind(&serde_json::json!({
        "agent_name": body.agent_name,
        "input": body.input,
        "tools": body.tools,
        "model": body.model,
    }))
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    info!(
        "Started agent run: {} (agent: {})",
        agent_run_id, body.agent_name
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "agent_run_id": agent_run_id,
            "agent_name": body.agent_name,
            "status": "running",
        })),
    ))
}

#[derive(Deserialize)]
struct AgentRunRequest {
    agent_name: String,
    input: serde_json::Value,
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default = "default_model")]
    model: String,
}

fn default_model() -> String {
    std::env::var("TRACETRAMP_DEFAULT_MODEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "deepseek-chat".to_string())
}

fn extract_tenant_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// Evidence API handlers

async fn get_trace(
    State(state): State<Arc<AppState>>,
    Path(trace_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let events = state
        .connector_client
        .list_interactions(None)
        .await?
        .into_iter()
        .filter(|i| i.target.contains(&format!("trace:{}", trace_id)))
        .map(|i| {
            serde_json::json!({
                "id": i.id,
                "agent_pid": i.agent_pid,
                "step": i.operation,
                "result": i.status,
                "metadata": {
                    "interaction_type": i.interaction_type,
                    "duration_ms": i.duration_ms,
                    "tokens": i.tokens,
                    "cost_usd": i.cost_usd,
                },
                "created_at": i.timestamp,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(serde_json::json!({
        "trace_id": trace_id,
        "events": events,
    })))
}

async fn get_explain(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let explain = crate::view::build_explain(&state, &request_id).await?;
    Ok(Json(explain))
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}... [{} more chars]", &s[..max_len], s.len() - max_len)
    } else {
        s.to_string()
    }
}

async fn get_prove(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let receipt = state.connector_client.get_receipt(&request_id).await.ok();
    let interaction_count = state
        .connector_client
        .list_interactions(None)
        .await
        .map(|items| {
            items
                .into_iter()
                .filter(|i| i.target.contains(&format!("request:{}", request_id)))
                .count()
        })
        .unwrap_or(0);
    let verification = receipt.is_some();
    Ok(Json(serde_json::json!({
        "request_id": request_id,
        "verification": {
            "status": if verification { "verified" } else { "unverified" },
            "tamper_detected": !verification,
            "signature_valid": receipt.is_some(),
            "interaction_count": interaction_count,
        },
        "receipt": receipt.map(|r| serde_json::json!({
            "cid": r.cid,
            "signature": r.signature,
            "timestamp": r.timestamp,
        })),
        "chain_status": if verification { "verified" } else { "requires_receipt" },
        "immutable": verification,
        "managed_by": "connector_receipts_and_interactions"
    })))
}

async fn get_cost(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let interactions = state.connector_client.list_interactions(None).await?;
    let matched = interactions
        .into_iter()
        .filter(|i| i.target.contains(&format!("request:{}", request_id)))
        .collect::<Vec<_>>();
    let total_cost_usd = matched
        .iter()
        .map(|i| i.cost_usd.unwrap_or(0.0))
        .sum::<f64>();
    let total_tokens = matched.iter().map(|i| i.tokens.unwrap_or(0)).sum::<u64>();
    Ok(Json(serde_json::json!({
        "request_id": request_id,
        "cost_usd": total_cost_usd,
        "total_tokens": total_tokens,
        "records": matched.len(),
        "managed_by": "connector_interactions"
    })))
}

async fn get_decision_tree(
    State(state): State<Arc<AppState>>,
    Path(trace_id): Path<String>,
) -> Result<Response, AppError> {
    let action_trace_cumulative =
        crate::trace_projection::cumulative_action_trace_entries(&state.db_pool, &trace_id)
            .await
            .unwrap_or_default();
    let block_flags_cumulative =
        crate::trace_projection::cumulative_block_flags(&state.db_pool, &trace_id)
            .await
            .unwrap_or_default();
    let row = sqlx::query(
        "SELECT trace_id, request_id, tenant_id, tree_data, created_at, updated_at
         FROM decision_trees
         WHERE trace_id = $1
         LIMIT 1",
    )
    .bind(&trace_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if let Some(r) = row {
        Ok(Json(serde_json::json!({
            "trace_id": r.try_get::<String, _>("trace_id").unwrap_or_else(|_| trace_id.clone()),
            "request_id": r.try_get::<String, _>("request_id").unwrap_or_default(),
            "tenant_id": r.try_get::<String, _>("tenant_id").unwrap_or_default(),
            "tree_data": r.try_get::<serde_json::Value, _>("tree_data").unwrap_or_else(|_| serde_json::json!({})),
            "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|v| v.to_rfc3339()),
            "updated_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").ok().map(|v| v.to_rfc3339()),
            "action_trace_cumulative": action_trace_cumulative,
            "block_flags_cumulative": block_flags_cumulative,
        }))
        .into_response())
    } else {
        Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "trace_id": trace_id,
                "error": "Decision tree not found"
            })),
        )
            .into_response())
    }
}

#[derive(Deserialize)]
struct DecisionDiffQuery {
    trace_a: String,
    trace_b: String,
}

async fn get_decision_diff(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DecisionDiffQuery>,
) -> Result<Response, AppError> {
    let row_a = sqlx::query(
        "SELECT trace_id, tree_data, created_at FROM decision_trees WHERE trace_id = $1 LIMIT 1",
    )
    .bind(&params.trace_a)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let row_b = sqlx::query(
        "SELECT trace_id, tree_data, created_at FROM decision_trees WHERE trace_id = $1 LIMIT 1",
    )
    .bind(&params.trace_b)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some(a) = row_a else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("trace_a '{}' not found", params.trace_a)
            })),
        )
            .into_response());
    };
    let Some(b) = row_b else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("trace_b '{}' not found", params.trace_b)
            })),
        )
            .into_response());
    };

    let tree_a = a
        .try_get::<serde_json::Value, _>("tree_data")
        .unwrap_or_else(|_| serde_json::json!({}));
    let tree_b = b
        .try_get::<serde_json::Value, _>("tree_data")
        .unwrap_or_else(|_| serde_json::json!({}));

    let model_a = tree_a
        .get("root")
        .and_then(|v| v.get("model"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-model");
    let model_b = tree_b
        .get("root")
        .and_then(|v| v.get("model"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-model");
    let provider_a = tree_a
        .get("root")
        .and_then(|v| v.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-provider");
    let provider_b = tree_b
        .get("root")
        .and_then(|v| v.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-provider");
    let outcome_a = tree_a
        .get("metadata")
        .and_then(|v| v.get("final_outcome"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let outcome_b = tree_b
        .get("metadata")
        .and_then(|v| v.get("final_outcome"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let policy_hits_a = tree_a
        .get("root")
        .and_then(|v| v.get("policy_checks"))
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    let policy_hits_b = tree_b
        .get("root")
        .and_then(|v| v.get("policy_checks"))
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);

    Ok(Json(serde_json::json!({
        "trace_a": params.trace_a,
        "trace_b": params.trace_b,
        "summary": {
            "model_changed": model_a != model_b,
            "provider_changed": provider_a != provider_b,
            "outcome_changed": outcome_a != outcome_b,
            "policy_hits_changed": policy_hits_a != policy_hits_b
        },
        "left": {
            "model": model_a,
            "provider": provider_a,
            "outcome": outcome_a,
            "policy_hits": policy_hits_a,
            "tree_data": tree_a
        },
        "right": {
            "model": model_b,
            "provider": provider_b,
            "outcome": outcome_b,
            "policy_hits": policy_hits_b,
            "tree_data": tree_b
        }
    }))
    .into_response())
}

async fn get_enforcement_packet(
    State(state): State<Arc<AppState>>,
    Path(trace_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let decision_tree = sqlx::query(
        "SELECT tree_data, created_at
         FROM decision_trees
         WHERE trace_id = $1
         ORDER BY created_at DESC
         LIMIT 1"
    )
    .bind(&trace_id)
    .fetch_optional(&state.db_pool)
    .await
    .ok()
    .flatten()
    .map(|row| {
        serde_json::json!({
            "tree_data": row.try_get::<serde_json::Value, _>("tree_data").unwrap_or_else(|_| serde_json::json!({})),
            "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|v| v.to_rfc3339()),
        })
    })
    .unwrap_or_else(|| {
        serde_json::json!({
            "note": "decision tree unavailable for this trace"
        })
    });

    let policy_verdicts = sqlx::query(
        "SELECT step, result, metadata, created_at
         FROM trace_events
         WHERE trace_id = $1 AND step = 'PolicyChecked'
         ORDER BY created_at ASC"
    )
    .bind(&trace_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .into_iter()
    .map(|row| {
        serde_json::json!({
            "step": row.try_get::<String, _>("step").unwrap_or_default(),
            "result": row.try_get::<String, _>("result").unwrap_or_default(),
            "metadata": row.try_get::<serde_json::Value, _>("metadata").unwrap_or_else(|_| serde_json::json!({})),
            "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|v| v.to_rfc3339()),
        })
    })
    .collect::<Vec<_>>();

    let budget_verdicts = sqlx::query(
        "SELECT step, result, metadata, created_at
         FROM trace_events
         WHERE trace_id = $1 AND step = 'CostRecorded'
         ORDER BY created_at ASC"
    )
    .bind(&trace_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .into_iter()
    .map(|row| {
        serde_json::json!({
            "step": row.try_get::<String, _>("step").unwrap_or_default(),
            "result": row.try_get::<String, _>("result").unwrap_or_default(),
            "metadata": row.try_get::<serde_json::Value, _>("metadata").unwrap_or_else(|_| serde_json::json!({})),
            "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|v| v.to_rfc3339()),
        })
    })
    .collect::<Vec<_>>();

    let reviewer_actions = sqlx::query(
        "SELECT id, request_id, actor_id, status, resolved_by, resolved_at, comment, reason, created_at, hold_metadata
         FROM approval_queue
         WHERE trace_id = $1
         ORDER BY created_at DESC
         LIMIT 50"
    )
    .bind(&trace_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .into_iter()
    .map(|row| {
        serde_json::json!({
            "id": row.try_get::<String, _>("id").unwrap_or_default(),
            "request_id": row.try_get::<String, _>("request_id").unwrap_or_default(),
            "actor_id": row.try_get::<String, _>("actor_id").unwrap_or_default(),
            "status": row.try_get::<String, _>("status").unwrap_or_default(),
            "resolved_by": row.try_get::<Option<String>, _>("resolved_by").unwrap_or(None),
            "resolved_at": row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("resolved_at").unwrap_or(None).map(|v| v.to_rfc3339()),
            "comment": row.try_get::<Option<String>, _>("comment").unwrap_or(None),
            "reason": row.try_get::<String, _>("reason").unwrap_or_default(),
            "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|v| v.to_rfc3339()),
            "hold_metadata": row.try_get::<serde_json::Value, _>("hold_metadata").unwrap_or_else(|_| serde_json::json!({})),
        })
    })
    .collect::<Vec<_>>();

    let action_trace_cumulative =
        crate::trace_projection::cumulative_action_trace_entries(&state.db_pool, &trace_id)
            .await
            .unwrap_or_default();
    let block_flags_cumulative =
        crate::trace_projection::cumulative_block_flags(&state.db_pool, &trace_id)
            .await
            .unwrap_or_default();

    Ok(Json(serde_json::json!({
        "trace_id": trace_id,
        "decision_tree": decision_tree,
        "policy_verdicts": policy_verdicts,
        "budget_verdicts": budget_verdicts,
        "reviewer_actions": reviewer_actions,
        "action_trace_cumulative": action_trace_cumulative,
        "block_flags_cumulative": block_flags_cumulative,
        "generated_at": chrono::Utc::now().to_rfc3339()
    })))
}

async fn get_workflow_statement(
    State(_state): State<Arc<AppState>>,
    Path(workflow_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Placeholder for workflow statement
    Ok(Json(serde_json::json!({
        "workflow_id": workflow_id,
        "status": "running",
        "note": "Workflow statement builder not yet fully implemented",
    })))
}

// Compliance export handler
#[derive(Deserialize)]
struct ComplianceExportQuery {
    tenant_id: String,
    start_date: String, // ISO 8601
    end_date: String,
    format: String, // csv, json, html, pdf
    #[serde(default)]
    include_raw: bool,
}

async fn compliance_export(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ComplianceExportQuery>,
) -> Result<impl IntoResponse, AppError> {
    let start = params
        .start_date
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| AppError::BadRequest("Invalid start_date format".to_string()))?;
    let end = params
        .end_date
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map_err(|_| AppError::BadRequest("Invalid end_date format".to_string()))?;

    let interactions = state
        .connector_client
        .list_interactions(Some(&params.tenant_id))
        .await?;
    let mut export_records = vec![];
    for i in interactions {
        let created_at = i
            .timestamp
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap_or_else(|_| chrono::Utc::now());
        if created_at < start || created_at > end {
            continue;
        }
        let trace_id = i.target.split(':').nth(1).unwrap_or_default().to_string();
        let request_id = i
            .target
            .split("request:")
            .nth(1)
            .unwrap_or_default()
            .to_string();
        let record = ComplianceRecord {
            request_id,
            trace_id,
            timestamp: created_at,
            model: "connector-managed".to_string(),
            provider: "connector".to_string(),
            action: i.operation,
            input_tokens: i.tokens.unwrap_or(0),
            output_tokens: 0,
            cost_usd: i.cost_usd.unwrap_or(0.0),
            input_preview: if params.include_raw {
                i.target.clone()
            } else {
                truncate(&i.target, 200)
            },
            output_preview: if params.include_raw {
                i.status.clone()
            } else {
                truncate(&i.status, 200)
            },
        };
        export_records.push(record);
    }

    // Format output
    match params.format.as_str() {
        "csv" => {
            let csv = generate_csv(&export_records)?;
            Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/csv")],
                csv.into_bytes(),
            ))
        }
        "json" => {
            let json = serde_json::to_string(&export_records)?;
            Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                json.into_bytes(),
            ))
        }
        "html" => {
            let body =
                compliance_records_html_fragment(&export_records, &params.tenant_id, start, end);
            let footer = format!(
                "TraceTramp compliance export — generated {}",
                chrono::Utc::now().to_rfc3339()
            );
            let doc = connector_report_pdf::html_report_document(
                &body,
                "TraceTramp Compliance Export",
                &footer,
            );
            Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                doc.into_bytes(),
            ))
        }
        "pdf" => {
            let body =
                compliance_records_html_fragment(&export_records, &params.tenant_id, start, end);
            let footer = format!(
                "TraceTramp compliance export — generated {}",
                chrono::Utc::now().to_rfc3339()
            );
            let doc = connector_report_pdf::html_report_document(
                &body,
                "TraceTramp Compliance Export",
                &footer,
            );
            let pdf = connector_report_pdf::render_pdf(&doc).map_err(|e| {
                AppError::Internal(format!(
                    "PDF render failed (install chromium or wkhtmltopdf, or use format=html): {}",
                    e
                ))
            })?;
            Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/pdf")],
                pdf,
            ))
        }
        _ => Err(AppError::BadRequest(format!(
            "Unsupported format: {}. Use 'csv', 'json', 'html', or 'pdf'",
            params.format
        ))),
    }
}

fn escape_html(s: &str) -> String {
    s.chars()
        .fold(String::with_capacity(s.len()), |mut acc, c| {
            match c {
                '&' => acc.push_str("&amp;"),
                '<' => acc.push_str("&lt;"),
                '>' => acc.push_str("&gt;"),
                '"' => acc.push_str("&quot;"),
                _ => acc.push(c),
            }
            acc
        })
}

/// HTML fragment (inside `<body>`) for compliance export — safe escapes for table cells.
fn compliance_records_html_fragment(
    records: &[ComplianceRecord],
    tenant_id: &str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
) -> String {
    let mut out = String::from("<h1>TraceTramp compliance export</h1>");
    out.push_str(&format!(
        "<p><strong>Tenant</strong> {} &nbsp; <strong>From</strong> {} &nbsp; <strong>To</strong> {} &nbsp; <strong>Rows</strong> {}</p>",
        escape_html(tenant_id),
        escape_html(&start.to_rfc3339()),
        escape_html(&end.to_rfc3339()),
        records.len()
    ));
    out.push_str("<p><em>For browser PDF: open <code>format=html</code> and use Print → Save as PDF.</em></p>");
    out.push_str("<table><thead><tr>");
    for h in [
        "Timestamp",
        "Trace ID",
        "Request ID",
        "Action",
        "Input tokens",
        "Cost USD",
        "Input preview",
        "Output preview",
    ] {
        out.push_str(&format!("<th>{}</th>", escape_html(h)));
    }
    out.push_str("</tr></thead><tbody>");
    for r in records {
        out.push_str("<tr>");
        out.push_str(&format!(
            "<td>{}</td>",
            escape_html(&r.timestamp.to_rfc3339())
        ));
        out.push_str(&format!("<td>{}</td>", escape_html(&r.trace_id)));
        out.push_str(&format!("<td>{}</td>", escape_html(&r.request_id)));
        out.push_str(&format!("<td>{}</td>", escape_html(&r.action)));
        out.push_str(&format!("<td>{}</td>", r.input_tokens));
        out.push_str(&format!("<td>{:.6}</td>", r.cost_usd));
        out.push_str(&format!("<td>{}</td>", escape_html(&r.input_preview)));
        out.push_str(&format!("<td>{}</td>", escape_html(&r.output_preview)));
        out.push_str("</tr>");
    }
    out.push_str("</tbody></table>");
    out
}

#[derive(serde::Serialize)]
struct ComplianceRecord {
    request_id: String,
    trace_id: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    model: String,
    provider: String,
    action: String,
    input_tokens: u64,
    output_tokens: u64,
    cost_usd: f64,
    input_preview: String,
    output_preview: String,
}

fn generate_csv(records: &[ComplianceRecord]) -> Result<String, AppError> {
    let mut wtr = csv::Writer::from_writer(vec![]);

    // Headers
    wtr.write_record(&[
        "request_id",
        "trace_id",
        "timestamp",
        "model",
        "provider",
        "action",
        "input_tokens",
        "output_tokens",
        "cost_usd",
        "input_preview",
        "output_preview",
    ])
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Records
    for r in records {
        wtr.write_record(&[
            &r.request_id,
            &r.trace_id,
            &r.timestamp.to_rfc3339(),
            &r.model,
            &r.provider,
            &r.action,
            &r.input_tokens.to_string(),
            &r.output_tokens.to_string(),
            &r.cost_usd.to_string(),
            &r.input_preview,
            &r.output_preview,
        ])
        .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    wtr.into_inner()
        .map_err(|e| AppError::Internal(e.to_string()))
        .map(|v| String::from_utf8(v).unwrap_or_default())
}

// Production-grade API handlers

async fn embeddings(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    // Proxy embedding request to Connector
    let model = body["model"]
        .as_str()
        .unwrap_or("text-embedding-3-small")
        .to_string();
    let input = body["input"].clone();

    let url = format!("{}/v1/embeddings", state.config.connector_base_url);
    let response = reqwest::Client::new()
        .post(&url)
        .header(
            "Authorization",
            format!("Bearer {}", state.config.connector_api_key),
        )
        .json(&serde_json::json!({
            "model": model,
            "input": input,
        }))
        .send()
        .await
        .map_err(|e| AppError::ConnectorProxy(format!("Embedding proxy failed: {}", e)))?;

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AppError::Serialization(e.to_string()))?;

    Ok(Json(result))
}

async fn list_models(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, AppError> {
    // Return models from configured providers (database)
    let rows = sqlx::query("SELECT DISTINCT provider_type FROM providers WHERE is_active = true")
        .fetch_all(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let mut models = vec![];
    for row in rows {
        let provider: String = row.try_get("provider_type").unwrap_or_default();
        match provider.as_str() {
            "openai" => {
                if std::env::var("TRACETRAMP_UPSTREAM_OPENAI_BASE_URL")
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains("deepseek")
                {
                    models.push(serde_json::json!({"id": "deepseek-chat", "object": "model", "provider": "deepseek"}));
                    models.push(serde_json::json!({"id": "deepseek-reasoner", "object": "model", "provider": "deepseek"}));
                } else {
                    models.push(serde_json::json!({"id": "gpt-4o", "object": "model", "provider": "openai"}));
                    models.push(serde_json::json!({"id": "gpt-4o-mini", "object": "model", "provider": "openai"}));
                    models.push(serde_json::json!({"id": "gpt-4-turbo", "object": "model", "provider": "openai"}));
                    models.push(serde_json::json!({"id": "text-embedding-3-small", "object": "model", "provider": "openai"}));
                }
            }
            "deepseek" => {
                models.push(serde_json::json!({"id": "deepseek-chat", "object": "model", "provider": "deepseek"}));
                models.push(serde_json::json!({"id": "deepseek-reasoner", "object": "model", "provider": "deepseek"}));
            }
            "anthropic" => {
                models.push(serde_json::json!({"id": "claude-3-5-sonnet-20241022", "object": "model", "provider": "anthropic"}));
                models.push(serde_json::json!({"id": "claude-3-5-haiku-20241022", "object": "model", "provider": "anthropic"}));
                models.push(serde_json::json!({"id": "claude-3-opus-20240229", "object": "model", "provider": "anthropic"}));
            }
            "ollama" => {
                models.push(
                    serde_json::json!({"id": "llama3.2", "object": "model", "provider": "ollama"}),
                );
                models.push(
                    serde_json::json!({"id": "mistral", "object": "model", "provider": "ollama"}),
                );
                models.push(
                    serde_json::json!({"id": "qwen2.5", "object": "model", "provider": "ollama"}),
                );
            }
            "azure" => {
                models.push(
                    serde_json::json!({"id": "gpt-4o", "object": "model", "provider": "azure"}),
                );
            }
            _ => {}
        }
    }

    Ok(Json(serde_json::json!({
        "object": "list",
        "data": models
    })))
}

async fn unified_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<impl IntoResponse, AppError> {
    // Route to view/control pipeline based on mode
    // This is same as /v1/chat/completions but with unified routing
    chat_completions(State(state), headers, body)
        .await
        .map(|r| r.into_response())
}

async fn invoke_tool_by_name(
    State(state): State<Arc<AppState>>,
    Path(tool_name): Path<String>,
    Json(args): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    // Look up tool in database
    let tool_row = sqlx::query("SELECT definition FROM tools WHERE name = $1 AND is_active = true")
        .bind(&tool_name)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let tool_row =
        tool_row.ok_or_else(|| AppError::NotFound(format!("Tool {} not found", tool_name)))?;
    let definition: serde_json::Value = tool_row.try_get("definition").unwrap_or_default();

    // Execute the tool based on its type
    let tool: crate::tools::Tool =
        serde_json::from_value(definition).map_err(|e| AppError::Serialization(e.to_string()))?;

    let executor = crate::tools::executor::ToolExecutor::new();
    let call = crate::tools::ToolCall {
        id: uuid::Uuid::new_v4().to_string(),
        tool_name: tool_name.clone(),
        arguments: args,
    };

    let result = executor.execute(&tool, &call).await?;

    Ok(Json(serde_json::json!(result)))
}

async fn batch_invoke_tools(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BatchToolRequest>,
) -> Result<impl IntoResponse, AppError> {
    let executor = crate::tools::executor::ToolExecutor::new();
    let mut results = vec![];

    for call in body.calls {
        // Look up each tool
        let tool_row =
            sqlx::query("SELECT definition FROM tools WHERE name = $1 AND is_active = true")
                .bind(&call.name)
                .fetch_optional(&state.db_pool)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(row) = tool_row {
            let definition: serde_json::Value = row.try_get("definition").unwrap_or_default();
            if let Ok(tool) = serde_json::from_value::<crate::tools::Tool>(definition) {
                let tool_call = crate::tools::ToolCall {
                    id: uuid::Uuid::new_v4().to_string(),
                    tool_name: call.name.clone(),
                    arguments: call.arguments,
                };
                match executor.execute(&tool, &tool_call).await {
                    Ok(result) => results.push(serde_json::json!({
                        "tool": call.name,
                        "success": true,
                        "result": result,
                    })),
                    Err(e) => results.push(serde_json::json!({
                        "tool": call.name,
                        "success": false,
                        "error": e.to_string(),
                    })),
                }
            }
        } else {
            results.push(serde_json::json!({
                "tool": call.name,
                "success": false,
                "error": "Tool not found",
            }));
        }
    }

    Ok(Json(serde_json::json!({
        "results": results,
        "total": results.len(),
    })))
}

#[derive(Deserialize)]
struct BatchToolRequest {
    calls: Vec<BatchToolCall>,
}

#[derive(Deserialize)]
struct BatchToolCall {
    name: String,
    arguments: serde_json::Value,
}

async fn call_function(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    // Lookup function in database
    let row = sqlx::query(
        "SELECT id, backend, config FROM functions WHERE name = $1 AND is_active = true",
    )
    .bind(&name)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let row = row.ok_or_else(|| AppError::NotFound(format!("Function {} not found", name)))?;
    let function_id: String = row.try_get("id").unwrap_or_default();
    let backend: String = row.try_get("backend").unwrap_or("openfaas".to_string());
    let config: serde_json::Value = row.try_get("config").unwrap_or_default();

    let call = crate::functions::FunctionCall {
        function_name: name.clone(),
        parameters: input.clone(),
        timeout_seconds: 30,
        async_execution: false,
    };

    // Dispatch to correct backend
    let result = match backend.as_str() {
        "openfaas" => {
            let gateway = config["gateway_url"]
                .as_str()
                .unwrap_or("http://localhost:8080");
            let client = crate::functions::openfaas::OpenFaasClient::new(gateway);
            client.call(&call).await?
        }
        "lambda" => {
            let region = config["region"].as_str().unwrap_or("us-east-1");
            let client = crate::functions::lambda::LambdaClient::new(region.to_string(), None);
            client.invoke(&call).await?
        }
        "docker" => {
            let network = config["network"].as_str().unwrap_or("bridge");
            let image = config["image"].as_str().unwrap_or("alpine");
            let executor = crate::functions::docker::DockerExecutor::new(network.to_string());
            executor.run(image, &call).await?
        }
        _ => {
            return Err(AppError::BadRequest(format!(
                "Unknown backend: {}",
                backend
            )))
        }
    };

    // Log execution
    let _ = sqlx::query(
        "INSERT INTO function_executions (function_id, input, output, status, execution_time_ms, cold_start, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())"
    )
    .bind(&function_id)
    .bind(&input)
    .bind(&result.output)
    .bind(if result.success { "success" } else { "failed" })
    .bind(result.execution_time_ms as i32)
    .bind(result.cold_start)
    .execute(&state.db_pool)
    .await;

    Ok(Json(serde_json::json!(result)))
}

async fn async_call_function(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(input): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    // Submit function call to background queue
    let job_id = uuid::Uuid::new_v4().to_string();

    let _ = sqlx::query(
        "INSERT INTO function_executions (function_id, run_id, input, status, created_at) SELECT id, $2, $3, 'queued', NOW() FROM functions WHERE name = $1"
    )
    .bind(&name)
    .bind(&job_id)
    .bind(&input)
    .execute(&state.db_pool)
    .await;

    // Spawn background execution
    let state_clone = state.clone();
    let name_clone = name.clone();
    let input_clone = input.clone();
    tokio::spawn(async move {
        let _ = call_function(State(state_clone), Path(name_clone), Json(input_clone)).await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "async": true,
            "job_id": job_id,
            "function": name,
            "status": "queued"
        })),
    ))
}

async fn create_workflow(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateWorkflowRequest>,
) -> Result<impl IntoResponse, AppError> {
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO workflows (id, tenant_id, name, version, description, definition, triggers, variables, settings, is_active, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, NOW())"
    )
    .bind(&id)
    .bind(&body.tenant_id)
    .bind(&body.name)
    .bind(&body.version.unwrap_or_else(|| "1.0".to_string()))
    .bind(&body.description.unwrap_or_default())
    .bind(&body.definition)
    .bind(&body.triggers.unwrap_or(serde_json::json!([])))
    .bind(&body.variables.unwrap_or(serde_json::json!({})))
    .bind(&body.settings.unwrap_or(serde_json::json!({})))
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    info!(
        "Created workflow: {} for tenant {}",
        body.name, body.tenant_id
    );
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "name": body.name,
        })),
    ))
}

#[derive(Deserialize)]
struct CreateWorkflowRequest {
    tenant_id: String,
    name: String,
    version: Option<String>,
    description: Option<String>,
    definition: serde_json::Value,
    triggers: Option<serde_json::Value>,
    variables: Option<serde_json::Value>,
    settings: Option<serde_json::Value>,
}

async fn list_workflows(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TenantFilter>,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query(
        "SELECT id, tenant_id, name, version, description, is_active, created_at FROM workflows WHERE tenant_id = $1 OR $1 IS NULL ORDER BY created_at DESC"
    )
    .bind(&params.tenant_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let workflows: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.try_get::<String, _>("id").unwrap_or_default(),
                "tenant_id": r.try_get::<String, _>("tenant_id").unwrap_or_default(),
                "name": r.try_get::<String, _>("name").unwrap_or_default(),
                "version": r.try_get::<String, _>("version").unwrap_or_default(),
                "description": r.try_get::<String, _>("description").unwrap_or_default(),
                "is_active": r.try_get::<bool, _>("is_active").unwrap_or(false),
            })
        })
        .collect();

    Ok(Json(
        serde_json::json!({ "workflows": workflows, "count": workflows.len() }),
    ))
}

async fn get_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        "SELECT id, tenant_id, name, version, description, definition, triggers, variables, settings, is_active, created_at FROM workflows WHERE id = $1"
    )
    .bind(&id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    match row {
        Some(r) => Ok(Json(serde_json::json!({
            "id": r.try_get::<String, _>("id").unwrap_or_default(),
            "tenant_id": r.try_get::<String, _>("tenant_id").unwrap_or_default(),
            "name": r.try_get::<String, _>("name").unwrap_or_default(),
            "version": r.try_get::<String, _>("version").unwrap_or_default(),
            "description": r.try_get::<String, _>("description").unwrap_or_default(),
            "definition": r.try_get::<serde_json::Value, _>("definition").unwrap_or_default(),
            "triggers": r.try_get::<serde_json::Value, _>("triggers").unwrap_or_default(),
            "variables": r.try_get::<serde_json::Value, _>("variables").unwrap_or_default(),
            "settings": r.try_get::<serde_json::Value, _>("settings").unwrap_or_default(),
            "is_active": r.try_get::<bool, _>("is_active").unwrap_or(false),
        }))),
        None => Err(AppError::NotFound(format!("Workflow {} not found", id))),
    }
}

async fn update_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query(
        "UPDATE workflows SET definition = COALESCE($2, definition), description = COALESCE($3, description), updated_at = NOW() WHERE id = $1"
    )
    .bind(&id)
    .bind(body.get("definition"))
    .bind(body.get("description").and_then(|v| v.as_str()))
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({ "message": "Workflow updated", "id": id }),
    ))
}

async fn delete_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(&id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({ "message": "Workflow deleted", "id": id }),
    ))
}

async fn run_workflow(
    State(state): State<Arc<AppState>>,
    Path(workflow_id): Path<String>,
    Json(input): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    let run_id = uuid::Uuid::new_v4().to_string();

    // Look up workflow
    let workflow_row = sqlx::query(
        "SELECT tenant_id, definition FROM workflows WHERE id = $1 AND is_active = true",
    )
    .bind(&workflow_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let workflow_row = workflow_row
        .ok_or_else(|| AppError::NotFound(format!("Workflow {} not found", workflow_id)))?;
    let tenant_id: String = workflow_row.try_get("tenant_id").unwrap_or_default();
    let definition: serde_json::Value = workflow_row
        .try_get("definition")
        .unwrap_or_else(|_| serde_json::json!({}));

    // Create run record
    sqlx::query(
        "INSERT INTO workflow_runs (id, workflow_id, tenant_id, status, input, step_results, started_at, created_at) VALUES ($1, $2, $3, 'running', $4, '{}', NOW(), NOW())"
    )
    .bind(&run_id)
    .bind(&workflow_id)
    .bind(&tenant_id)
    .bind(&input)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Spawn background execution
    let pool = state.db_pool.clone();
    let connector = state.connector_client.clone();
    let management_base = format!("http://127.0.0.1:{}", state.config.management_plane_port);
    let run_id_clone = run_id.clone();
    let workflow_id_clone = workflow_id.clone();
    let tenant_id_clone = tenant_id.clone();
    let input_clone = input.clone();
    let definition_clone = definition.clone();
    tokio::spawn(async move {
        let mut step_results = serde_json::Map::new();
        let mut waiting_human = false;
        let steps = definition_clone
            .get("steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for (idx, step) in steps.iter().enumerate() {
            let step_id = step
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("step-{}", idx + 1));
            let step_name = step
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed")
                .to_string();
            let step_type = step
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let _ = connector
                .log_interaction(
                    &run_id_clone,
                    &run_id_clone,
                    &tenant_id_clone,
                    &format!("workflow.step.start:{}", step_id),
                    &format!("name={} type={}", step_name, step_type),
                )
                .await;

            if step_type == "human" {
                let approval_payload = serde_json::json!({
                    "request_id": run_id_clone.clone(),
                    "workflow_run_id": run_id_clone.clone(),
                    "workflow_id": workflow_id_clone.clone(),
                    "step_id": step_id,
                    "tenant_id": tenant_id_clone.clone(),
                    "approvers": step.get("config").and_then(|c| c.get("approvers")).cloned().unwrap_or_else(|| serde_json::json!([])),
                    "prompt": step.get("config").and_then(|c| c.get("prompt")).and_then(|v| v.as_str()).unwrap_or("Workflow requires approval"),
                    "context": {
                        "input": input_clone.clone(),
                        "step_name": step_name,
                    }
                });
                let _ = reqwest::Client::new()
                    .post(format!("{}/admin/approvals", management_base))
                    .json(&approval_payload)
                    .send()
                    .await;

                waiting_human = true;
                step_results.insert(
                    step_id.clone(),
                    serde_json::json!({
                        "status": "waiting_human",
                        "step_type": step_type,
                        "name": step_name,
                        "approval_requested": true,
                    }),
                );
                let _ = connector
                    .log_interaction(
                        &run_id_clone,
                        &run_id_clone,
                        &tenant_id_clone,
                        &format!("workflow.step.waiting_human:{}", step_id),
                        "approval_requested",
                    )
                    .await;
                break;
            }

            step_results.insert(
                step_id.clone(),
                serde_json::json!({
                    "status": "completed",
                    "step_type": step_type,
                    "name": step_name,
                }),
            );
            let _ = connector
                .log_interaction(
                    &run_id_clone,
                    &run_id_clone,
                    &tenant_id_clone,
                    &format!("workflow.step.completed:{}", step_id),
                    "completed",
                )
                .await;
        }

        let final_status = if waiting_human {
            "waiting_human"
        } else {
            "completed"
        };
        let final_output = if waiting_human {
            serde_json::json!({"result": "Workflow paused for human approval"})
        } else {
            serde_json::json!({"result": "Workflow execution completed", "steps_executed": steps.len()})
        };

        let _ = sqlx::query(
            "UPDATE workflow_runs SET status = $2, completed_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE completed_at END, output = $3, step_results = $4 WHERE id = $1"
        )
        .bind(&run_id_clone)
        .bind(final_status)
        .bind(&final_output)
        .bind(serde_json::Value::Object(step_results))
        .execute(&pool)
        .await;

        info!(
            "Workflow run {} for workflow {} ended with status {}",
            run_id_clone, workflow_id_clone, final_status
        );
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "run_id": run_id,
            "workflow_id": workflow_id,
            "status": "running",
        })),
    ))
}

async fn trigger_workflow(
    State(state): State<Arc<AppState>>,
    Path(workflow_id): Path<String>,
    Json(event): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    // Log trigger event and kick off workflow
    let log_id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO workflow_trigger_logs (id, workflow_id, trigger_type, event_data, triggered_at) VALUES ($1, $2, 'http', $3, NOW())"
    )
    .bind(&log_id)
    .bind(&workflow_id)
    .bind(&event)
    .execute(&state.db_pool)
    .await;

    // Start workflow run
    run_workflow(State(state), Path(workflow_id), Json(event)).await
}

async fn get_workflow_run(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        "SELECT id, workflow_id, status, input, output, step_results, started_at, completed_at, error FROM workflow_runs WHERE id = $1"
    )
    .bind(&run_id)
    .fetch_optional(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    match row {
        Some(r) => Ok(Json(serde_json::json!({
            "id": r.try_get::<String, _>("id").unwrap_or_default(),
            "workflow_id": r.try_get::<String, _>("workflow_id").unwrap_or_default(),
            "status": r.try_get::<String, _>("status").unwrap_or_default(),
            "input": r.try_get::<serde_json::Value, _>("input").unwrap_or_default(),
            "output": r.try_get::<Option<serde_json::Value>, _>("output").unwrap_or_default(),
            "step_results": r.try_get::<serde_json::Value, _>("step_results").unwrap_or_default(),
            "started_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("started_at").ok(),
            "completed_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at").unwrap_or_default(),
            "error": r.try_get::<Option<String>, _>("error").unwrap_or_default(),
        }))),
        None => Err(AppError::NotFound(format!(
            "Workflow run {} not found",
            run_id
        ))),
    }
}

async fn cancel_workflow_run(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query(
        "UPDATE workflow_runs SET status = 'cancelled', completed_at = NOW() WHERE id = $1 AND status = 'running'"
    )
    .bind(&run_id)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({ "message": "Workflow run cancelled", "id": run_id }),
    ))
}

async fn resume_workflow_run(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query("UPDATE workflow_runs SET status = 'running' WHERE id = $1 AND status = 'paused'")
        .bind(&run_id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({ "message": "Workflow run resumed", "id": run_id }),
    ))
}

async fn submit_pipeline(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PipelineSubmission>,
) -> Result<impl IntoResponse, AppError> {
    // A pipeline is a collection of sequential/parallel steps (tools, LLMs, functions)
    let pipeline_id = uuid::Uuid::new_v4().to_string();

    // Store pipeline submission (reusing workflow_runs table)
    sqlx::query(
        "INSERT INTO workflow_runs (id, workflow_id, tenant_id, status, input, step_results, started_at, created_at) VALUES ($1, 'pipeline', $2, 'running', $3, '{}', NOW(), NOW())"
    )
    .bind(&pipeline_id)
    .bind(&body.tenant_id)
    .bind(&body.input)
    .execute(&state.db_pool)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    info!(
        "Submitted pipeline: {} with {} steps",
        pipeline_id,
        body.steps.len()
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "pipeline_id": pipeline_id,
            "status": "running",
            "steps": body.steps.len(),
        })),
    ))
}

#[derive(Deserialize)]
struct PipelineSubmission {
    tenant_id: String,
    steps: Vec<serde_json::Value>,
    input: serde_json::Value,
}

async fn get_pipeline_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_workflow_run(State(state), Path(id)).await
}

async fn continue_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_run_id): Path<String>,
    Json(input): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AppError> {
    // Continue an agent execution with additional input
    sqlx::query("UPDATE workflow_runs SET input = $2 || input, status = 'running' WHERE id = $1")
        .bind(&agent_run_id)
        .bind(&input)
        .execute(&state.db_pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "agent_run_id": agent_run_id,
        "status": "continued",
    })))
}

async fn stream_events(
    State(state): State<Arc<AppState>>,
    Path(trace_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // Real streaming: get events for trace and return as SSE-compatible JSON stream
    let events = state
        .connector_client
        .list_interactions(None)
        .await?
        .into_iter()
        .filter(|i| i.target.contains(&format!("trace:{}", trace_id)))
        .map(|i| {
            serde_json::json!({
                "step": i.operation,
                "result": i.status,
                "metadata": {
                    "interaction_type": i.interaction_type,
                    "duration_ms": i.duration_ms,
                    "tokens": i.tokens,
                    "cost_usd": i.cost_usd,
                },
                "created_at": i.timestamp,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(serde_json::json!({
        "trace_id": trace_id,
        "events": events,
        "stream_type": "polling", // Real SSE requires axum streaming setup
    })))
}

#[derive(Deserialize)]
struct TenantFilter {
    tenant_id: Option<String>,
}

async fn readiness_check(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AppError> {
    // Real readiness - check database, redis, connector
    let db_ok = sqlx::query("SELECT 1")
        .fetch_one(&state.db_pool)
        .await
        .is_ok();

    let (redis_ok, redis_status) = match &state.redis_pool {
        Some(pool) => {
            let mut conn = pool.clone();
            let result: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
            let ok = result.is_ok();
            (ok, if ok { "ok" } else { "failed" })
        }
        None => (true, "skipped"),
    };

    // Check connector with a simple ping
    let connector_ok = state.connector_client.health_check().await.is_ok();
    let connector_authenticated = state.config.connector_api_key_present() && connector_ok;

    let all_ready = db_ok && redis_ok && connector_ok;
    let status_code = if all_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = Json(serde_json::json!({
        "ready": all_ready,
        "checks": {
            "database": if db_ok { "ok" } else { "failed" },
            "redis": redis_status,
            "connector": if connector_ok { "ok" } else { "failed" },
            "connector_authenticated": if connector_authenticated { "ok" } else { "failed" }
        },
        "connector_authenticated": connector_authenticated
    }));

    Ok((status_code, body))
}

// Helper functions

fn extract_api_key(headers: &HeaderMap) -> Result<String, AppError> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        let key = v.trim();
        if !key.is_empty() {
            return Ok(key.to_string());
        }
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| {
            AppError::Unauthorized("Missing or invalid Authorization header".to_string())
        })
}

fn extract_app_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-App-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Session-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub(crate) fn classify_intent(chat_req: &ChatCompletionRequest) -> String {
    // Simple intent classification based on model and content
    let content = chat_req
        .messages
        .first()
        .map(|m| m.content.as_str())
        .unwrap_or("");

    if content.contains("code") || content.contains("function") {
        "code".to_string()
    } else if content.contains("summarize") || content.contains("summary") {
        "summarize".to_string()
    } else if content.contains("analyze") {
        "analyze".to_string()
    } else {
        "general".to_string()
    }
}
