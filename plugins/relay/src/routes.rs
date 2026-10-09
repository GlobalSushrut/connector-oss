//! All 12 Relay API route handlers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use validator::Validate;

use crate::error::AppError;
use crate::proxy;
use crate::registry;
use crate::state::AppState;
use crate::types::{
    AsyncInvokeResponse, FunctionStats, HealthResponse, FunctionSummary,
    InvokeRequest, InvokeResponse, RegisterRequest, SuspendRequest, UpdateFunctionRequest,
};

// ─── 1. Register a function ────────────────────────────────────────────────────
// POST /api/v1/functions

pub async fn register_function(
    State(s): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    req.validate()?;

    let row = registry::register(&s.pool, &s.connector, req).await?;

    Ok(Json(json!({
        "ok":       true,
        "function": row,
        "message":  format!("Function '{}' registered. Set OPENAI_BASE_URL=<relay>/llm/v1 and RELAY_MCP_URL=<relay>/mcp in your code.", row.name),
    })))
}

// ─── 2. List registered functions ─────────────────────────────────────────────
// GET /api/v1/functions

pub async fn list_functions(
    State(s): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, name, uri, description, policy_json, instructions,
               status, health_status, health_latency_ms, last_health_at,
               agent_did, api_key, invocation_count, total_cost_usd,
               created_at, updated_at
        FROM relay_functions
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(&s.pool)
    .await
    .map_err(AppError::Database)?;

    let total = rows.len() as i64;
    let healthy   = rows.iter().filter(|r| r.health_status == "healthy").count() as i64;
    let degraded  = rows.iter().filter(|r| r.health_status == "degraded").count() as i64;
    let unreachable = rows.iter().filter(|r| r.health_status == "unreachable").count() as i64;
    let suspended = rows.iter().filter(|r| r.status == "suspended" || r.status == "quarantined").count() as i64;

    crate::metrics::set_function_counts(total, healthy);

    let functions: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":               r.id,
        "name":             r.name,
        "uri":              r.uri,
        "description":      r.description,
        "status":           r.status,
        "health_status":    r.health_status,
        "health_latency_ms": r.health_latency_ms,
        "last_health_at":   r.last_health_at,
        "agent_did":        r.agent_did,
        "invocation_count": r.invocation_count,
        "total_cost_usd":   r.total_cost_usd,
        "created_at":       r.created_at,
        "updated_at":       r.updated_at,
    })).collect();

    Ok(Json(json!({
        "functions": functions,
        "summary": {
            "total":       total,
            "healthy":     healthy,
            "degraded":    degraded,
            "unreachable": unreachable,
            "suspended":   suspended,
        },
    })))
}

// ─── 3. Get function detail ────────────────────────────────────────────────────
// GET /api/v1/functions/:name

pub async fn get_function(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    let row = registry::get_by_name(&s.pool, &name).await?;
    Ok(Json(json!({ "function": row })))
}

// ─── 4. Update policy/instructions ────────────────────────────────────────────
// PUT /api/v1/functions/:name

pub async fn update_function(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<UpdateFunctionRequest>,
) -> Result<Json<Value>, AppError> {
    let row = registry::update(
        &s.pool,
        &name,
        req.uri,
        req.description,
        req.policy,
        req.instructions,
    ).await?;

    Ok(Json(json!({ "ok": true, "function": row })))
}

// ─── 5. Deregister ────────────────────────────────────────────────────────────
// DELETE /api/v1/functions/:name

pub async fn deregister_function(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    registry::deregister(&s.pool, &name).await?;
    Ok(Json(json!({ "ok": true, "message": format!("Function '{name}' deregistered") })))
}

// ─── 6. Invoke a function (sync) ──────────────────────────────────────────────
// POST /api/v1/functions/:name/invoke

pub async fn invoke_function(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<InvokeRequest>,
) -> Result<Json<InvokeResponse>, AppError> {
    // Async mode: enqueue and return job ID
    if req.r#async.unwrap_or(false) {
        let job = sqlx::query!(
            r#"
            INSERT INTO relay_async_jobs (function_name, payload, callback_url)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            name,
            req.input,
            req.callback_url,
        )
        .fetch_one(&s.pool)
        .await
        .map_err(AppError::Database)?;

        return Ok(Json(InvokeResponse {
            invocation_id: job.id,
            function:      name,
            output:        json!({ "job_id": job.id, "status": "queued" }),
            tokens_in:     0,
            tokens_out:    0,
            cost_usd:      0.0,
            latency_ms:    0,
            outcome:       "queued".into(),
            audit_cid:     None,
            trace_id:      None,
            model_used:    None,
        }));
    }

    let result = proxy::invoke(&s.pool, &s.connector, &s.http, &name, &req).await?;

    Ok(Json(InvokeResponse {
        invocation_id: result.invocation_id,
        function:      name,
        output:        result.output,
        tokens_in:     result.tokens_in,
        tokens_out:    result.tokens_out,
        cost_usd:      result.cost_usd,
        latency_ms:    result.latency_ms,
        outcome:       result.outcome,
        audit_cid:     result.audit_cid,
        trace_id:      None,
        model_used:    result.model_used,
    }))
}

// ─── 7. Raw one-shot invocation ────────────────────────────────────────────────
// POST /api/v1/invoke

#[derive(Deserialize)]
pub struct RawInvokeQuery {
    pub uri: String,
}

pub async fn invoke_raw(
    State(s): State<AppState>,
    Query(q): Query<RawInvokeQuery>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let resp = s.http
        .post(&q.uri)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Proxy(e.to_string()))?;

    let output: Value = resp.json().await.unwrap_or(json!({}));
    Ok(Json(output))
}

// ─── 8. Invocation logs ────────────────────────────────────────────────────────
// GET /api/v1/functions/:name/logs

#[derive(Deserialize)]
pub struct LogsQuery {
    pub limit: Option<i64>,
}

pub async fn get_logs(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = q.limit.unwrap_or(50).min(500);

    let rows = sqlx::query!(
        r#"
        SELECT i.id, i.function_name, i.model_used, i.tokens_in, i.tokens_out,
               i.cost_usd, i.latency_ms, i.outcome, i.deny_reason, i.audit_cid,
               i.invoked_at
        FROM relay_invocations i
        JOIN relay_functions f ON f.id = i.function_id
        WHERE f.name = $1
        ORDER BY i.invoked_at DESC
        LIMIT $2
        "#,
        name,
        limit,
    )
    .fetch_all(&s.pool)
    .await
    .map_err(AppError::Database)?;

    if rows.is_empty() {
        let _ = registry::get_by_name(&s.pool, &name).await?; // 404 if not registered
    }

    let logs: Vec<Value> = rows.into_iter().map(|r| json!({
        "id":            r.id,
        "function":      r.function_name,
        "model_used":    r.model_used,
        "tokens_in":     r.tokens_in,
        "tokens_out":    r.tokens_out,
        "cost_usd":      r.cost_usd,
        "latency_ms":    r.latency_ms,
        "outcome":       r.outcome,
        "deny_reason":   r.deny_reason,
        "audit_cid":     r.audit_cid,
        "invoked_at":    r.invoked_at,
    })).collect();

    Ok(Json(json!({ "function": name, "logs": logs, "count": logs.len() })))
}

// ─── 9. Function stats ─────────────────────────────────────────────────────────
// GET /api/v1/functions/:name/stats

pub async fn get_stats(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<FunctionStats>, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT
            f.invocation_count,
            f.total_cost_usd,
            (SELECT AVG(latency_ms)::float8 FROM relay_invocations WHERE function_id = f.id AND invoked_at > NOW() - INTERVAL '24 hours') AS avg_latency_ms,
            (SELECT COUNT(*) FROM relay_invocations WHERE function_id = f.id AND outcome != 'success' AND invoked_at > NOW() - INTERVAL '24 hours') AS error_count_24h,
            (SELECT COUNT(*) FROM relay_invocations WHERE function_id = f.id AND invoked_at > NOW() - INTERVAL '24 hours') AS total_24h,
            (SELECT COALESCE(SUM(cost_usd), 0) FROM relay_invocations WHERE function_id = f.id AND invoked_at > NOW() - INTERVAL '24 hours') AS today_cost_usd,
            (SELECT MAX(invoked_at) FROM relay_invocations WHERE function_id = f.id) AS last_invoked_at
        FROM relay_functions f
        WHERE f.name = $1
        "#,
        name,
    )
    .fetch_optional(&s.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound(format!("Function '{name}' not found")))?;

    let total_24h   = row.total_24h.unwrap_or(0);
    let error_24h   = row.error_count_24h.unwrap_or(0);
    let error_rate  = if total_24h > 0 { error_24h as f64 / total_24h as f64 } else { 0.0 };
    let today_cost  = row.today_cost_usd.unwrap_or(0.0);

    Ok(Json(FunctionStats {
        function:             name,
        invocation_count:     row.invocation_count,
        total_cost_usd:       row.total_cost_usd,
        avg_latency_ms:       row.avg_latency_ms.map(|v: f64| v),
        p99_latency_ms:       None,
        error_rate,
        budget_remaining_usd: None,
        today_cost_usd:       today_cost,
        today_invocations:    total_24h,
        last_invoked_at:      row.last_invoked_at,
    }))
}

// ─── 10. Suspend ───────────────────────────────────────────────────────────────
// POST /api/v1/functions/:name/suspend

pub async fn suspend_function(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<SuspendRequest>,
) -> Result<Json<Value>, AppError> {
    registry::set_status(&s.pool, &name, "suspended").await?;

    tracing::warn!(
        function = %name,
        reason   = ?req.reason,
        "Function suspended"
    );

    Ok(Json(json!({
        "ok":      true,
        "status":  "suspended",
        "function": name,
        "reason":  req.reason,
    })))
}

// ─── 11. Resume ────────────────────────────────────────────────────────────────
// POST /api/v1/functions/:name/resume

pub async fn resume_function(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    registry::set_status(&s.pool, &name, "healthy").await?;

    tracing::info!(function = %name, "Function resumed");

    Ok(Json(json!({
        "ok":      true,
        "status":  "healthy",
        "function": name,
    })))
}

// ─── 12. Health ────────────────────────────────────────────────────────────────
// GET /health

pub async fn health(
    State(s): State<AppState>,
) -> Json<Value> {
    let db_ok = sqlx::query_scalar!("SELECT 1 AS one")
        .fetch_one(&s.pool)
        .await
        .is_ok();

    let connector_ok = s.connector.health().await
        .map(|h| h.status == "ok" || h.status == "healthy")
        .unwrap_or(false);

    let counts = sqlx::query!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE TRUE) AS total,
            COUNT(*) FILTER (WHERE health_status = 'healthy') AS healthy,
            COUNT(*) FILTER (WHERE health_status = 'degraded') AS degraded,
            COUNT(*) FILTER (WHERE health_status = 'unreachable') AS unreachable,
            COUNT(*) FILTER (WHERE status IN ('suspended','quarantined')) AS suspended
        FROM relay_functions
        "#,
    )
    .fetch_optional(&s.pool)
    .await
    .ok()
    .flatten();

    let summary = if let Some(c) = counts {
        json!({
            "total":       c.total.unwrap_or(0),
            "healthy":     c.healthy.unwrap_or(0),
            "degraded":    c.degraded.unwrap_or(0),
            "unreachable": c.unreachable.unwrap_or(0),
            "suspended":   c.suspended.unwrap_or(0),
        })
    } else {
        json!({ "total": 0, "healthy": 0, "degraded": 0, "unreachable": 0, "suspended": 0 })
    };

    let status = if db_ok { "ok" } else { "degraded" };

    Json(json!({
        "status":    status,
        "version":   env!("CARGO_PKG_VERSION"),
        "db":        if db_ok { "ok" } else { "error" },
        "connector": if connector_ok { "ok" } else { "degraded" },
        "functions": summary,
    }))
}
