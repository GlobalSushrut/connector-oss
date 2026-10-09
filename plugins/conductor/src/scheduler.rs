//! Scheduler — cron + webhook trigger loop for pipeline runs.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::types::{CreateScheduleRequest, Schedule};

// ── Public API ────────────────────────────────────────────────────────────────

pub async fn create(pool: &PgPool, req: CreateScheduleRequest) -> Result<Schedule> {
    let webhook_token = if req.trigger_type == "webhook" {
        Some(generate_webhook_token())
    } else {
        None
    };

    let next_run = compute_next_run(req.cron_expr.as_deref())?;
    let inputs = req.default_inputs.unwrap_or(serde_json::json!({}));

    let row = sqlx::query(
        "INSERT INTO conductor_schedules (pipeline_id, name, trigger_type, cron_expr, webhook_token, default_inputs, next_run_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
    )
    .bind(req.pipeline_id).bind(&req.name).bind(&req.trigger_type)
    .bind(&req.cron_expr).bind(&webhook_token).bind(&inputs).bind(next_run)
    .fetch_one(pool).await.context("Failed to create schedule")?;
    let id: Uuid = row.try_get("id").context("Missing id")?;
    fetch(pool, id).await
}

pub async fn list(pool: &PgPool) -> Result<Vec<Schedule>> {
    let rows = sqlx::query("SELECT id FROM conductor_schedules ORDER BY created_at DESC")
        .fetch_all(pool).await?;
    let mut out = Vec::new();
    for row in rows {
        let id: Uuid = row.try_get("id")?;
        out.push(fetch(pool, id).await?);
    }
    Ok(out)
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM conductor_schedules WHERE id = $1")
        .bind(id).execute(pool).await.context("Schedule not found")?;
    Ok(())
}

/// Find a schedule by its webhook token (for incoming webhook triggers).
pub async fn find_by_webhook_token(pool: &PgPool, token: &str) -> Result<Option<Schedule>> {
    let row = sqlx::query("SELECT id FROM conductor_schedules WHERE webhook_token = $1 AND enabled = TRUE")
        .bind(token).fetch_optional(pool).await?;
    match row {
        Some(r) => {
            let id: Uuid = r.try_get("id")?;
            Ok(Some(fetch(pool, id).await?))
        }
        None => Ok(None),
    }
}

pub async fn fetch(pool: &PgPool, id: Uuid) -> Result<Schedule> {
    let r = sqlx::query(
        "SELECT id, pipeline_id, name, trigger_type, cron_expr, webhook_token, default_inputs, enabled, last_run_at, next_run_at, created_at FROM conductor_schedules WHERE id = $1"
    )
    .bind(id).fetch_one(pool).await.context("Schedule not found")?;
    Ok(Schedule {
        id:            r.try_get("id")?,
        pipeline_id:   r.try_get("pipeline_id")?,
        name:          r.try_get("name")?,
        trigger_type:  r.try_get("trigger_type")?,
        cron_expr:     r.try_get("cron_expr").ok(),
        webhook_token: r.try_get("webhook_token").ok(),
        default_inputs: r.try_get("default_inputs").unwrap_or_default(),
        enabled:       r.try_get("enabled").unwrap_or(true),
        last_run_at:   r.try_get("last_run_at").ok(),
        next_run_at:   r.try_get("next_run_at").ok(),
        created_at:    r.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    })
}

// ── Background tick loop ──────────────────────────────────────────────────────

/// Spawns the cron tick loop and HITL expiry checker. Call from main.rs.
pub fn spawn_scheduler(pool: PgPool, connector: ConnectorClient) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let _ = tick(&pool, &connector).await;
            let _ = crate::hitl::expire_stale(&pool).await;
        }
    });
}

async fn tick(pool: &PgPool, connector: &ConnectorClient) -> Result<()> {
    let due = sqlx::query(
        "SELECT id, pipeline_id, cron_expr, default_inputs FROM conductor_schedules WHERE enabled = TRUE AND trigger_type = 'cron' AND next_run_at IS NOT NULL AND next_run_at <= NOW()"
    )
    .fetch_all(pool).await?;

    for sched in due {
        let sched_id: Uuid = sched.try_get("id").unwrap_or_else(|_| Uuid::new_v4());
        let pipeline_id: Uuid = sched.try_get("pipeline_id").unwrap_or_else(|_| Uuid::new_v4());
        let cron_expr: Option<String> = sched.try_get("cron_expr").ok();
        let default_inputs: serde_json::Value = sched.try_get("default_inputs").unwrap_or_default();

        if let Ok(pipeline) = crate::pipeline::get(pool, pipeline_id).await {
            if let Ok(dsl) = crate::pipeline::parse_yaml(&pipeline.yaml_source) {
                let _ = crate::runner::start(
                    pool, connector, pipeline.id,
                    &pipeline.compiled_json, &dsl, default_inputs,
                ).await;
            }
        }
        let next = compute_next_run(cron_expr.as_deref()).unwrap_or(None);
        sqlx::query("UPDATE conductor_schedules SET last_run_at = NOW(), next_run_at = $1 WHERE id = $2")
            .bind(next).bind(sched_id).execute(pool).await?;
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn generate_webhook_token() -> String {
    use sha2::{Digest, Sha256};
    let random = Uuid::new_v4().to_string();
    format!("wht_{}", &format!("{:x}", Sha256::digest(random.as_bytes()))[..24])
}

pub fn compute_next_run(cron_expr: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    let expr = match cron_expr {
        Some(e) => e,
        None => return Ok(None),
    };
    let schedule = cron::Schedule::try_from(expr)
        .with_context(|| format!("Invalid cron expression: {}", expr))?;
    Ok(schedule.upcoming(Utc).next())
}
