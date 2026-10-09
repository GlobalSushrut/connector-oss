//! HITL (Human-in-the-Loop) approval engine.
//! Creates approval requests, pauses runs, resumes on sign-off.

use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::types::{Approval, ApprovalStatus, HitlConfig};

// ── Create approval ───────────────────────────────────────────────────────────

pub async fn create_approval(
    pool: &PgPool,
    run_id: Uuid,
    step_id: Uuid,
    step_index: i32,
    step_name: &str,
    config: &HitlConfig,
) -> Result<Approval> {
    let approval_id = Uuid::new_v4();
    let expires_at = config.timeout_minutes.map(|m| {
        Utc::now() + chrono::Duration::minutes(m as i64)
    });

    sqlx::query(
        "INSERT INTO conductor_approvals (id, run_id, step_id, step_index, step_name, required_if, reviewers, status, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)"
    )
    .bind(approval_id).bind(run_id).bind(step_id).bind(step_index)
    .bind(step_name).bind(config.required_if.as_deref())
    .bind(&config.reviewers).bind(expires_at)
    .execute(pool).await.context("Failed to create HITL approval")?;

    sqlx::query("UPDATE conductor_steps SET status = 'waiting_approval' WHERE id = $1")
        .bind(step_id).execute(pool).await?;

    fetch_approval(pool, approval_id).await
}

// ── Resolve approval ──────────────────────────────────────────────────────────

/// Approve or reject a HITL request. On approval, resumes the run.
pub async fn resolve(
    pool: &PgPool,
    connector: &ConnectorClient,
    approval_id: Uuid,
    approved: bool,
    reviewer: &str,
    reason: Option<&str>,
) -> Result<Approval> {
    let approval = fetch_approval(pool, approval_id).await?;

    if approval.status != ApprovalStatus::Pending {
        anyhow::bail!("Approval {} is already resolved (status: {})", approval_id, approval.status);
    }

    let new_status = if approved { "approved" } else { "rejected" };

    sqlx::query("UPDATE conductor_approvals SET status = $1, reviewer = $2, reason = $3, resolved_at = NOW() WHERE id = $4")
        .bind(new_status).bind(reviewer).bind(reason).bind(approval_id)
        .execute(pool).await?;

    let step_status = if approved { "completed" } else { "failed" };
    sqlx::query("UPDATE conductor_steps SET status = $1, ended_at = NOW() WHERE id = $2")
        .bind(step_status).bind(approval.step_id)
        .execute(pool).await?;

    if approved {
        // Tell Connector to continue the pipeline from this step
        let connector_run_id: Option<String> = sqlx::query(
            "SELECT connector_run_id FROM conductor_runs WHERE id = $1"
        )
        .bind(approval.run_id)
        .fetch_one(pool).await
        .map(|r| r.try_get("connector_run_id").ok())
        .unwrap_or(None);

        if let Some(crid) = connector_run_id {
            let approve_body = serde_json::json!({ "approved": true, "reviewer": reviewer, "reason": reason });
            let _ = connector.approve_pipeline_step(&crid, approval.step_index as u32, &approve_body).await;
        }

        sqlx::query("UPDATE conductor_runs SET status = 'running', error_message = NULL WHERE id = $1")
            .bind(approval.run_id).execute(pool).await?;

    } else {
        sqlx::query("UPDATE conductor_runs SET status = 'failed', ended_at = NOW(), error_message = $1 WHERE id = $2")
            .bind(format!("HITL step '{}' rejected by {}: {}", approval.step_name, reviewer, reason.unwrap_or("no reason")))
            .bind(approval.run_id).execute(pool).await?;
    }

    fetch_approval(pool, approval_id).await
}

// ── Expire stale approvals ────────────────────────────────────────────────────

/// Mark expired approvals and fail their runs. Called by the scheduler loop.
pub async fn expire_stale(pool: &PgPool) -> Result<usize> {
    let expired = sqlx::query(
        "UPDATE conductor_approvals SET status = 'expired', resolved_at = NOW() WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at < NOW() RETURNING run_id, step_name"
    )
    .fetch_all(pool).await?;

    let count = expired.len();
    for row in &expired {
        let run_id: Uuid = row.try_get("run_id").unwrap_or_else(|_| Uuid::new_v4());
        let step_name: String = row.try_get("step_name").unwrap_or_default();
        let _ = sqlx::query(
            "UPDATE conductor_runs SET status = 'failed', ended_at = NOW(), error_message = $1 WHERE id = $2"
        )
        .bind(format!("HITL approval for step '{}' expired", step_name))
        .bind(run_id).execute(pool).await;
    }

    Ok(count)
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

pub async fn fetch_approval(pool: &PgPool, id: Uuid) -> Result<Approval> {
    let row = sqlx::query(
        "SELECT id, run_id, step_id, step_index, step_name, required_if, reviewers, status, reviewer, reason, requested_at, resolved_at, expires_at FROM conductor_approvals WHERE id = $1"
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .context("Approval not found")?;

    Ok(row_to_approval(row))
}

pub async fn list_pending(pool: &PgPool) -> Result<Vec<Approval>> {
    let rows = sqlx::query(
        "SELECT id, run_id, step_id, step_index, step_name, required_if, reviewers, status, reviewer, reason, requested_at, resolved_at, expires_at FROM conductor_approvals WHERE status = 'pending' ORDER BY requested_at DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(row_to_approval).collect())
}

fn parse_approval_status(s: &str) -> ApprovalStatus {
    match s {
        "approved" => ApprovalStatus::Approved,
        "rejected" => ApprovalStatus::Rejected,
        "expired"  => ApprovalStatus::Expired,
        _          => ApprovalStatus::Pending,
    }
}

fn row_to_approval(row: sqlx::postgres::PgRow) -> Approval {
    let status: String = row.try_get("status").unwrap_or_default();
    Approval {
        id:           row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        run_id:       row.try_get("run_id").unwrap_or_else(|_| Uuid::new_v4()),
        step_id:      row.try_get("step_id").unwrap_or_else(|_| Uuid::new_v4()),
        step_index:   row.try_get("step_index").unwrap_or(0),
        step_name:    row.try_get("step_name").unwrap_or_default(),
        required_if:  row.try_get("required_if").ok(),
        reviewers:    row.try_get("reviewers").unwrap_or_default(),
        status:       parse_approval_status(&status),
        reviewer:     row.try_get("reviewer").ok(),
        reason:       row.try_get("reason").ok(),
        requested_at: row.try_get("requested_at").unwrap_or_else(|_| Utc::now()),
        resolved_at:  row.try_get("resolved_at").ok(),
        expires_at:   row.try_get("expires_at").ok(),
    }
}
