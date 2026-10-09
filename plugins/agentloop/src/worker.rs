//! Agent Workers — stateless edge compute units.
//!
//! Workers are triggered by mesh events (requests, responses, cron, A2A calls)
//! and execute a handler via HTTP or inline config.
//! Workers automatically appear in Agent DNS at `worker-name.workers.team`.

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::agent_dns;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Worker {
    pub id:               Uuid,
    pub agent_id:         Option<Uuid>,
    pub name:             String,
    pub description:      Option<String>,
    pub worker_type:      WorkerType,
    pub trigger_config:   Value,
    pub handler_url:      Option<String>,
    pub handler_inline:   Option<String>,
    pub mcp_capabilities: Value,
    pub fqan:             Option<String>,
    pub enabled:          bool,
    pub invoke_count:     i64,
    pub last_invoked_at:  Option<chrono::DateTime<Utc>>,
    pub created_at:       chrono::DateTime<Utc>,
    pub updated_at:       chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WorkerType { Request, Response, Event, Schedule, A2a, Tunnel }

impl std::fmt::Display for WorkerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerType::Request  => write!(f, "request"),
            WorkerType::Response => write!(f, "response"),
            WorkerType::Event    => write!(f, "event"),
            WorkerType::Schedule => write!(f, "schedule"),
            WorkerType::A2a      => write!(f, "a2a"),
            WorkerType::Tunnel   => write!(f, "tunnel"),
        }
    }
}

impl std::str::FromStr for WorkerType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "request"  => Ok(WorkerType::Request),
            "response" => Ok(WorkerType::Response),
            "event"    => Ok(WorkerType::Event),
            "schedule" => Ok(WorkerType::Schedule),
            "a2a"      => Ok(WorkerType::A2a),
            "tunnel"   => Ok(WorkerType::Tunnel),
            _          => anyhow::bail!("Unknown worker type: {}", s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerInvocation {
    pub id:             Uuid,
    pub worker_id:      Uuid,
    pub trigger_source: Option<String>,
    pub status:         String,
    pub input_hash:     Option<String>,
    pub output_hash:    Option<String>,
    pub error_message:  Option<String>,
    pub latency_ms:     Option<i32>,
    pub invoked_at:     chrono::DateTime<Utc>,
    pub completed_at:   Option<chrono::DateTime<Utc>>,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateWorkerRequest {
    pub agent_id:         Option<Uuid>,
    pub name:             String,
    pub description:      Option<String>,
    pub worker_type:      String,
    pub trigger_config:   Option<Value>,
    pub handler_url:      Option<String>,
    pub handler_inline:   Option<String>,
    pub mcp_capabilities: Option<Value>,
    pub team:             Option<String>,
}

// ── Worker CRUD ───────────────────────────────────────────────────────────────

pub async fn create(pool: &PgPool, req: CreateWorkerRequest) -> Result<Worker> {
    let worker_type = req.worker_type.parse::<WorkerType>()
        .map_err(|e| anyhow::anyhow!("Invalid worker_type: {}", e))?;

    if req.handler_url.is_none() && req.handler_inline.is_none() {
        anyhow::bail!("Worker must have either handler_url or handler_inline");
    }

    let id = Uuid::new_v4();

    // Build FQAN for the worker: name.workers.team (or name.workers if no team)
    let fqan = req.agent_id.as_ref().map(|_| {
        let team = req.team.as_deref().unwrap_or("default");
        format!("{}.workers.{}", req.name, team)
    });

    let row = sqlx::query(
        "INSERT INTO al_workers
         (id, agent_id, name, description, worker_type, trigger_config,
          handler_url, handler_inline, mcp_capabilities, fqan)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *"
    )
    .bind(id)
    .bind(req.agent_id)
    .bind(&req.name)
    .bind(req.description.as_deref())
    .bind(worker_type.to_string())
    .bind(req.trigger_config.unwrap_or(json!({})))
    .bind(req.handler_url.as_deref())
    .bind(req.handler_inline.as_deref())
    .bind(req.mcp_capabilities.unwrap_or(json!([])))
    .bind(fqan.as_deref())
    .fetch_one(pool).await.context("create worker")?;

    let worker = row_to_worker(row)?;

    // Auto-register in DNS if we have an agent_id and a FQAN
    if let (Some(agent_id), Some(ref _f)) = (req.agent_id, &worker.fqan) {
        if let Some(ref url) = worker.handler_url {
            let reg = agent_dns::RegisterRequest {
                agent_id:      Some(agent_id),
                name:          worker.name.clone(),
                version_label: Some("latest".into()),
                team:          req.team.clone(),
                org:           None,
                endpoint_url:  url.clone(),
                region:        None,
                weight:        Some(100),
                routing_policy: Some("round_robin".into()),
                capabilities:  Some(worker.mcp_capabilities.clone()),
                auth:          Some(json!({"type": "api_key"})),
                description:   worker.description.clone(),
            };
            if let Err(e) = agent_dns::register(pool, reg).await {
                tracing::warn!(worker_id = %id, err = %e, "Could not auto-register worker in DNS");
            }
        }
    }

    tracing::info!(worker_id = %id, name = %worker.name, worker_type = %worker.worker_type, "Worker created");
    Ok(worker)
}

pub async fn get(pool: &PgPool, id: Uuid) -> Result<Worker> {
    let row = sqlx::query("SELECT * FROM al_workers WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get worker")?;
    row_to_worker(row)
}

pub async fn list(
    pool:        &PgPool,
    agent_id:    Option<Uuid>,
    worker_type: Option<&str>,
    limit:       i64,
    offset:      i64,
) -> Result<Vec<Worker>> {
    let rows = match (agent_id, worker_type) {
        (Some(aid), Some(wt)) => sqlx::query(
            "SELECT * FROM al_workers WHERE agent_id = $1 AND worker_type = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4"
        ).bind(aid).bind(wt).bind(limit).bind(offset).fetch_all(pool).await,
        (Some(aid), None) => sqlx::query(
            "SELECT * FROM al_workers WHERE agent_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        ).bind(aid).bind(limit).bind(offset).fetch_all(pool).await,
        (None, Some(wt)) => sqlx::query(
            "SELECT * FROM al_workers WHERE worker_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        ).bind(wt).bind(limit).bind(offset).fetch_all(pool).await,
        _ => sqlx::query(
            "SELECT * FROM al_workers ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        ).bind(limit).bind(offset).fetch_all(pool).await,
    }.context("list workers")?;

    rows.into_iter().map(row_to_worker).collect()
}

pub async fn toggle(pool: &PgPool, id: Uuid, enabled: bool) -> Result<Worker> {
    let row = sqlx::query(
        "UPDATE al_workers SET enabled = $1, updated_at = NOW() WHERE id = $2 RETURNING *"
    )
    .bind(enabled).bind(id)
    .fetch_one(pool).await.context("toggle worker")?;
    row_to_worker(row)
}

// ── Invocation ────────────────────────────────────────────────────────────────

/// Invoke a worker with the given payload. Dispatches to handler_url via HTTP.
pub async fn invoke(
    pool:           &PgPool,
    worker_id:      Uuid,
    trigger_source: Option<String>,
    payload:        Value,
) -> Result<WorkerInvocation> {
    let worker = get(pool, worker_id).await?;
    if !worker.enabled {
        anyhow::bail!("Worker {} is disabled", worker_id);
    }

    let invocation_id = Uuid::new_v4();
    let input_hash    = sha256_val(&payload);

    // Write pending record
    sqlx::query(
        "INSERT INTO al_worker_invocations (id, worker_id, trigger_source, status, input_hash)
         VALUES ($1,$2,$3,'pending',$4)"
    )
    .bind(invocation_id).bind(worker_id).bind(trigger_source.as_deref()).bind(&input_hash)
    .execute(pool).await.context("create invocation")?;

    // Increment invoke count
    sqlx::query("UPDATE al_workers SET invoke_count = invoke_count + 1, last_invoked_at = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(worker_id).execute(pool).await.ok();

    // Update to running
    sqlx::query("UPDATE al_worker_invocations SET status = 'running' WHERE id = $1")
        .bind(invocation_id).execute(pool).await.ok();

    let start = std::time::Instant::now();
    let result: Result<Value> = if let Some(ref url) = worker.handler_url {
        let resp = reqwest::Client::new()
            .post(url)
            .timeout(std::time::Duration::from_secs(30))
            .header("X-Worker-ID",       worker_id.to_string())
            .header("X-Invocation-ID",   invocation_id.to_string())
            .header("X-Worker-Type",     worker.worker_type.to_string())
            .json(&payload)
            .send().await.context("invoke handler")?;
        resp.json().await.context("parse handler response")
    } else {
        Ok(json!({ "status": "inline_not_executed", "worker_id": worker_id }))
    };

    let latency = start.elapsed().as_millis() as i32;

    match result {
        Ok(out) => {
            let output_hash = sha256_val(&out);
            sqlx::query(
                "UPDATE al_worker_invocations
                 SET status = 'completed', output_hash = $1, latency_ms = $2, completed_at = NOW()
                 WHERE id = $3"
            )
            .bind(&output_hash).bind(latency).bind(invocation_id)
            .execute(pool).await.ok();
        }
        Err(ref e) => {
            sqlx::query(
                "UPDATE al_worker_invocations
                 SET status = 'failed', error_message = $1, latency_ms = $2, completed_at = NOW()
                 WHERE id = $3"
            )
            .bind(e.to_string()).bind(latency).bind(invocation_id)
            .execute(pool).await.ok();
        }
    }

    let row = sqlx::query("SELECT * FROM al_worker_invocations WHERE id = $1")
        .bind(invocation_id).fetch_one(pool).await.context("fetch invocation")?;
    Ok(row_to_invocation(row))
}

pub async fn list_invocations(
    pool:      &PgPool,
    worker_id: Uuid,
    limit:     i64,
    offset:    i64,
) -> Result<Vec<WorkerInvocation>> {
    let rows = sqlx::query(
        "SELECT * FROM al_worker_invocations WHERE worker_id = $1 ORDER BY invoked_at DESC LIMIT $2 OFFSET $3"
    )
    .bind(worker_id).bind(limit).bind(offset)
    .fetch_all(pool).await.context("list invocations")?;
    Ok(rows.into_iter().map(row_to_invocation).collect())
}

// ── MCP capabilities ──────────────────────────────────────────────────────────

/// Return the MCP tool manifest for a worker — serves as the AgentCard capabilities field.
pub async fn mcp_manifest(pool: &PgPool, worker_id: Uuid) -> Result<Value> {
    let worker = get(pool, worker_id).await?;
    Ok(json!({
        "worker_id":    worker_id,
        "fqan":         worker.fqan,
        "worker_type":  worker.worker_type.to_string(),
        "tools":        worker.mcp_capabilities,
        "handler_url":  worker.handler_url,
    }))
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn row_to_worker(row: sqlx::postgres::PgRow) -> Result<Worker> {
    let type_str: String = row.try_get("worker_type").unwrap_or_else(|_| "request".into());
    let worker_type = type_str.parse::<WorkerType>()
        .unwrap_or(WorkerType::Request);
    Ok(Worker {
        id:               row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:         row.try_get("agent_id").ok(),
        name:             row.try_get("name").unwrap_or_default(),
        description:      row.try_get("description").ok(),
        worker_type,
        trigger_config:   row.try_get("trigger_config").unwrap_or(json!({})),
        handler_url:      row.try_get("handler_url").ok(),
        handler_inline:   row.try_get("handler_inline").ok(),
        mcp_capabilities: row.try_get("mcp_capabilities").unwrap_or(json!([])),
        fqan:             row.try_get("fqan").ok(),
        enabled:          row.try_get("enabled").unwrap_or(true),
        invoke_count:     row.try_get("invoke_count").unwrap_or(0),
        last_invoked_at:  row.try_get("last_invoked_at").ok(),
        created_at:       row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:       row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    })
}

fn row_to_invocation(row: sqlx::postgres::PgRow) -> WorkerInvocation {
    WorkerInvocation {
        id:             row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        worker_id:      row.try_get("worker_id").unwrap_or_else(|_| Uuid::new_v4()),
        trigger_source: row.try_get("trigger_source").ok(),
        status:         row.try_get("status").unwrap_or_else(|_| "pending".into()),
        input_hash:     row.try_get("input_hash").ok(),
        output_hash:    row.try_get("output_hash").ok(),
        error_message:  row.try_get("error_message").ok(),
        latency_ms:     row.try_get("latency_ms").ok(),
        invoked_at:     row.try_get("invoked_at").unwrap_or_else(|_| Utc::now()),
        completed_at:   row.try_get("completed_at").ok(),
    }
}

fn sha256_val(v: &Value) -> String {
    format!("{:x}", Sha256::digest(v.to_string().as_bytes()))
}
