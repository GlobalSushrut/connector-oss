//! Function Registry — register, list, get, deregister, and health-check loop.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::error::AppError;
use crate::types::{FunctionRow, PolicyConfig, RegisterRequest};

/// Persist a new function registration.
pub async fn register(
    pool:      &PgPool,
    connector: &ConnectorClient,
    req:       RegisterRequest,
) -> Result<FunctionRow, AppError> {
    // Conflict check
    let exists = sqlx::query_scalar!(
        "SELECT id FROM relay_functions WHERE name = $1",
        req.name,
    )
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    if exists.is_some() {
        return Err(AppError::Conflict(format!(
            "Function '{}' is already registered — use PUT to update",
            req.name
        )));
    }

    let policy = req.policy.clone().unwrap_or_default();
    let policy_json = serde_json::to_value(&policy)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;

    // Auto-register AgentPassport DID (non-fatal)
    let agent_did = connector.ensure_passport(&req.name).await
        .map(|p| p.did)
        .ok();

    let row = sqlx::query!(
        r#"
        INSERT INTO relay_functions
            (name, uri, description, policy_json, instructions, agent_did)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, name, uri, description, policy_json, instructions,
                  status, health_status, health_latency_ms, last_health_at,
                  agent_did, api_key, invocation_count, total_cost_usd,
                  created_at, updated_at
        "#,
        req.name,
        req.uri,
        req.description,
        policy_json,
        req.instructions,
        agent_did,
    )
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)?;

    tracing::info!(name = %row.name, uri = %row.uri, did = ?row.agent_did, "Function registered");

    build_function_row(
        row.id, row.name, row.uri, row.description,
        row.policy_json, row.instructions,
        row.status, row.health_status, row.health_latency_ms, row.last_health_at,
        row.agent_did, row.invocation_count, row.total_cost_usd,
        row.created_at, row.updated_at,
    )
}

/// Fetch a single function by name.
pub async fn get_by_name(pool: &PgPool, name: &str) -> Result<FunctionRow, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT id, name, uri, description, policy_json, instructions,
               status, health_status, health_latency_ms, last_health_at,
               agent_did, api_key, invocation_count, total_cost_usd,
               created_at, updated_at
        FROM relay_functions
        WHERE name = $1
        "#,
        name,
    )
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound(format!("Function '{name}' not registered")))?;

    build_function_row(
        row.id, row.name, row.uri, row.description,
        row.policy_json, row.instructions,
        row.status, row.health_status, row.health_latency_ms, row.last_health_at,
        row.agent_did, row.invocation_count, row.total_cost_usd,
        row.created_at, row.updated_at,
    )
}

/// Update policy/instructions without restart.
pub async fn update(
    pool: &PgPool,
    name: &str,
    uri:          Option<String>,
    description:  Option<String>,
    policy:       Option<PolicyConfig>,
    instructions: Option<String>,
) -> Result<FunctionRow, AppError> {
    let policy_json = policy.as_ref()
        .map(|p| serde_json::to_value(p).map_err(|e| AppError::Internal(anyhow::anyhow!(e))))
        .transpose()?;

    let result = sqlx::query!(
        r#"
        UPDATE relay_functions
        SET uri          = COALESCE($1, uri),
            description  = COALESCE($2, description),
            policy_json  = COALESCE($3, policy_json),
            instructions = COALESCE($4, instructions),
            updated_at   = NOW()
        WHERE name = $5
        "#,
        uri,
        description,
        policy_json,
        instructions,
        name,
    )
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Function '{name}' not found")));
    }

    get_by_name(pool, name).await
}

/// Deregister a function.
pub async fn deregister(pool: &PgPool, name: &str) -> Result<(), AppError> {
    let result = sqlx::query!(
        "DELETE FROM relay_functions WHERE name = $1",
        name,
    )
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Function '{name}' not found")));
    }

    tracing::info!(name = name, "Function deregistered");
    Ok(())
}

/// Set function status (suspend / quarantine / resume).
pub async fn set_status(pool: &PgPool, name: &str, status: &str) -> Result<(), AppError> {
    let result = sqlx::query!(
        "UPDATE relay_functions SET status = $1, updated_at = NOW() WHERE name = $2",
        status,
        name,
    )
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Function '{name}' not found")));
    }

    Ok(())
}

// ── Background health-check loop ──────────────────────────────────────────────

/// Ping all registered function URIs and update health_status + last_health_at.
pub async fn health_check_loop(pool: PgPool) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to build health-check HTTP client");

    let rows = sqlx::query!(
        "SELECT id, name, uri FROM relay_functions WHERE status NOT IN ('suspended', 'quarantined')"
    )
    .fetch_all(&pool)
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Health check: failed to list functions");
            return;
        }
    };

    for f in rows {
        let health_url = format!(
            "{}/health",
            f.uri.trim_end_matches('/').trim_end_matches("/run").trim_end_matches("/invoke")
        );

        let start = std::time::Instant::now();
        let result = http.get(&health_url).send().await;
        let latency_ms = start.elapsed().as_millis() as i32;

        let (health_status, error_msg) = match result {
            Ok(resp) if resp.status().is_success() => ("healthy", None),
            Ok(resp) => ("degraded", Some(format!("HTTP {}", resp.status()))),
            Err(e)   => ("unreachable", Some(e.to_string())),
        };

        let _ = sqlx::query!(
            r#"
            UPDATE relay_functions
            SET health_status    = $1,
                health_latency_ms = $2,
                last_health_at   = NOW()
            WHERE id = $3
            "#,
            health_status,
            latency_ms,
            f.id,
        )
        .execute(&pool)
        .await;

        let _ = sqlx::query!(
            r#"
            INSERT INTO relay_health_checks (function_id, status, latency_ms, error_msg)
            VALUES ($1, $2, $3, $4)
            "#,
            f.id,
            health_status,
            latency_ms,
            error_msg,
        )
        .execute(&pool)
        .await;

        // Purge health checks older than 48h
        let _ = sqlx::query!(
            "DELETE FROM relay_health_checks WHERE function_id = $1 AND checked_at < NOW() - INTERVAL '48 hours'",
            f.id,
        )
        .execute(&pool)
        .await;

        if health_status != "healthy" {
            tracing::warn!(
                function = %f.name,
                status   = health_status,
                latency  = latency_ms,
                "Function health check failed"
            );
        } else {
            tracing::debug!(function = %f.name, latency = latency_ms, "Health check OK");
        }
    }
}

// ── Async job worker ──────────────────────────────────────────────────────────

pub async fn async_job_worker(pool: PgPool) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("Failed to build async worker HTTP client");

    let jobs = sqlx::query!(
        r#"
        SELECT j.id, j.function_name, j.payload, j.callback_url,
               j.attempt_count, j.max_attempts,
               f.uri, f.status
        FROM relay_async_jobs j
        JOIN relay_functions f ON f.name = j.function_name
        WHERE j.status = 'pending'
          AND j.scheduled_at <= NOW()
        ORDER BY j.scheduled_at ASC
        LIMIT 20
        "#,
    )
    .fetch_all(&pool)
    .await;

    let jobs = match jobs {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "Async worker: failed to fetch jobs");
            return;
        }
    };

    for job in jobs {
        if job.status == "suspended" || job.status == "quarantined" {
            let _ = sqlx::query!(
                "UPDATE relay_async_jobs SET status = 'failed', error_msg = 'function suspended' WHERE id = $1",
                job.id,
            ).execute(&pool).await;
            continue;
        }

        let _ = sqlx::query!(
            "UPDATE relay_async_jobs SET status = 'running', started_at = NOW(), attempt_count = attempt_count + 1 WHERE id = $1",
            job.id,
        ).execute(&pool).await;

        let result = http.post(&job.uri).json(&job.payload).send().await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                let output: Value = resp.json().await.unwrap_or_default();
                let _ = sqlx::query!(
                    "UPDATE relay_async_jobs SET status = 'completed', result = $1, completed_at = NOW() WHERE id = $2",
                    output,
                    job.id,
                ).execute(&pool).await;

                // Fire callback
                if let Some(cb_url) = &job.callback_url {
                    let _ = http.post(cb_url)
                        .json(&json!({ "job_id": job.id, "status": "completed", "result": output }))
                        .send().await;
                }
            }
            err => {
                let err_msg = match err {
                    Err(e) => e.to_string(),
                    Ok(resp) => format!("HTTP {}", resp.status()),
                };

                let new_status = if job.attempt_count + 1 >= job.max_attempts {
                    "failed"
                } else {
                    "pending"
                };

                let _ = sqlx::query!(
                    "UPDATE relay_async_jobs SET status = $1, error_msg = $2 WHERE id = $3",
                    new_status,
                    err_msg,
                    job.id,
                ).execute(&pool).await;
            }
        }
    }
}

// ── Internal mapping ──────────────────────────────────────────────────────────

pub fn build_function_row(
    id:               Uuid,
    name:             String,
    uri:              String,
    description:      Option<String>,
    policy_json:      Value,
    instructions:     Option<String>,
    status:           String,
    health_status:    String,
    health_latency_ms: Option<i32>,
    last_health_at:   Option<DateTime<Utc>>,
    agent_did:        Option<String>,
    invocation_count: i64,
    total_cost_usd:   f64,
    created_at:       DateTime<Utc>,
    updated_at:       DateTime<Utc>,
) -> Result<FunctionRow, AppError> {
    let policy: PolicyConfig = serde_json::from_value(policy_json).unwrap_or_default();
    Ok(FunctionRow {
        id,
        name,
        uri,
        description,
        policy,
        instructions,
        status,
        health_status,
        health_latency_ms,
        last_health_at,
        agent_did,
        invocation_count,
        total_cost_usd,
        created_at,
        updated_at,
    })
}
