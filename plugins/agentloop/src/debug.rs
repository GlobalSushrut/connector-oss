//! Debug module — timeline, run detail, diff, deterministic replay.
//! Phase 1 of the build plan: first paying customers, easiest demo.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::types::{Diff, Replay, ReplayStatus, Run, Step};

// ── Timeline ──────────────────────────────────────────────────────────────────

/// Fetch the event timeline for an agent: all runs ordered by time.
pub async fn timeline(
    pool:    &PgPool,
    agent_id: Uuid,
    limit:   i64,
    offset:  i64,
) -> Result<Vec<Run>> {
    let rows = sqlx::query(
        "SELECT id, connector_run_id, agent_id, prompt_id, prompt_version, experiment_id,
         status, inputs, outputs, model, provider, total_tokens, prompt_tokens,
         completion_tokens, cost_usd, latency_ms, error_message, cid, started_at, ended_at
         FROM al_runs WHERE agent_id = $1
         ORDER BY started_at DESC LIMIT $2 OFFSET $3"
    )
    .bind(agent_id).bind(limit).bind(offset)
    .fetch_all(pool).await.context("timeline query")?;

    Ok(rows.into_iter().map(row_to_run).collect())
}

/// Fetch a single run by local UUID.
pub async fn get_run(pool: &PgPool, id: Uuid) -> Result<Run> {
    let row = sqlx::query(
        "SELECT id, connector_run_id, agent_id, prompt_id, prompt_version, experiment_id,
         status, inputs, outputs, model, provider, total_tokens, prompt_tokens,
         completion_tokens, cost_usd, latency_ms, error_message, cid, started_at, ended_at
         FROM al_runs WHERE id = $1"
    )
    .bind(id)
    .fetch_one(pool).await.context("get run")?;
    Ok(row_to_run(row))
}

/// Fetch all steps for a run.
pub async fn get_steps(pool: &PgPool, run_id: Uuid) -> Result<Vec<Step>> {
    let rows = sqlx::query(
        "SELECT id, run_id, step_index, step_type, name, inputs, outputs,
         model, tokens, cost_usd, latency_ms, error_message, started_at, ended_at
         FROM al_steps WHERE run_id = $1 ORDER BY step_index ASC"
    )
    .bind(run_id)
    .fetch_all(pool).await.context("get steps")?;
    Ok(rows.into_iter().map(row_to_step).collect())
}

/// Upsert a run synced from Connector history.
pub async fn upsert_run(pool: &PgPool, connector_run_id: &str, data: &Value) -> Result<Run> {
    let agent_connector_id = data.get("agent_id").and_then(|v| v.as_str());

    // Resolve agent_id from connector_id if present
    let agent_id: Option<Uuid> = if let Some(cid) = agent_connector_id {
        sqlx::query("SELECT id FROM al_agents WHERE connector_id = $1")
            .bind(cid).fetch_optional(pool).await.ok().flatten()
            .and_then(|r| r.try_get("id").ok())
    } else { None };

    let row = sqlx::query(
        "INSERT INTO al_runs (connector_run_id, agent_id, status, inputs, outputs, model,
         provider, total_tokens, prompt_tokens, completion_tokens, cost_usd, latency_ms,
         error_message, cid, started_at, ended_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         ON CONFLICT (connector_run_id) DO UPDATE SET
            status             = EXCLUDED.status,
            outputs            = EXCLUDED.outputs,
            total_tokens       = EXCLUDED.total_tokens,
            prompt_tokens      = EXCLUDED.prompt_tokens,
            completion_tokens  = EXCLUDED.completion_tokens,
            cost_usd           = EXCLUDED.cost_usd,
            latency_ms         = EXCLUDED.latency_ms,
            error_message      = EXCLUDED.error_message,
            cid                = EXCLUDED.cid,
            ended_at           = EXCLUDED.ended_at
         RETURNING *"
    )
    .bind(connector_run_id)
    .bind(agent_id)
    .bind(data.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"))
    .bind(data.get("inputs").cloned().unwrap_or(json!({})))
    .bind(data.get("outputs").cloned())
    .bind(data.get("model").and_then(|v| v.as_str()))
    .bind(data.get("provider").and_then(|v| v.as_str()))
    .bind(data.get("total_tokens").and_then(|v| v.as_i64()).unwrap_or(0) as i32)
    .bind(data.get("prompt_tokens").and_then(|v| v.as_i64()).unwrap_or(0) as i32)
    .bind(data.get("completion_tokens").and_then(|v| v.as_i64()).unwrap_or(0) as i32)
    .bind(data.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0))
    .bind(data.get("latency_ms").and_then(|v| v.as_i64()).unwrap_or(0) as i32)
    .bind(data.get("error").and_then(|v| v.as_str()))
    .bind(data.get("cid").and_then(|v| v.as_str()))
    .bind(data.get("started_at").and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now))
    .bind(data.get("ended_at").and_then(|v| v.as_str())
        .and_then(|s| s.parse::<chrono::DateTime<Utc>>().ok()))
    .fetch_one(pool).await.context("upsert run")?;

    Ok(row_to_run(row))
}

// ── Diff ──────────────────────────────────────────────────────────────────────

/// Compute a structured diff between two runs.
pub async fn diff_runs(
    pool:       &PgPool,
    left_id:    Uuid,
    right_id:   Uuid,
) -> Result<Diff> {
    let left  = get_run(pool, left_id).await?;
    let right = get_run(pool, right_id).await?;

    let left_steps  = get_steps(pool, left_id).await?;
    let right_steps = get_steps(pool, right_id).await?;

    let step_diffs: Vec<Value> = left_steps.iter().enumerate().map(|(i, ls)| {
        let rs = right_steps.get(i);
        json!({
            "step_index": i,
            "left":  { "model": ls.model, "tokens": ls.tokens, "cost_usd": ls.cost_usd, "latency_ms": ls.latency_ms },
            "right": rs.map(|s| json!({ "model": s.model, "tokens": s.tokens, "cost_usd": s.cost_usd, "latency_ms": s.latency_ms })),
            "diverged": rs.map(|s| s.tokens != ls.tokens || s.model != ls.model).unwrap_or(true),
        })
    }).collect();

    let first_divergence = step_diffs.iter().position(|d| d["diverged"].as_bool().unwrap_or(false));

    let diff_json = json!({
        "left_run_id":  left_id,
        "right_run_id": right_id,
        "left":  { "model": left.model, "total_tokens": left.total_tokens, "cost_usd": left.cost_usd, "latency_ms": left.latency_ms, "status": left.status.to_string() },
        "right": { "model": right.model, "total_tokens": right.total_tokens, "cost_usd": right.cost_usd, "latency_ms": right.latency_ms, "status": right.status.to_string() },
        "token_delta": right.total_tokens - left.total_tokens,
        "cost_delta":  right.cost_usd - left.cost_usd,
        "latency_delta": right.latency_ms - left.latency_ms,
        "first_divergence_step": first_divergence,
        "step_diffs": step_diffs,
    });

    let summary = format!(
        "Δtokens={:+}, Δcost={:+.4}, Δlatency={:+}ms, first divergence at step {:?}",
        right.total_tokens - left.total_tokens,
        right.cost_usd - left.cost_usd,
        right.latency_ms - left.latency_ms,
        first_divergence,
    );

    let diff_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO al_diffs (id, diff_type, left_id, right_id, diff_json, summary)
         VALUES ($1, 'run_vs_run', $2, $3, $4, $5)"
    )
    .bind(diff_id)
    .bind(left_id.to_string())
    .bind(right_id.to_string())
    .bind(&diff_json)
    .bind(&summary)
    .execute(pool).await.context("insert diff")?;

    Ok(Diff {
        id:         diff_id,
        diff_type:  "run_vs_run".into(),
        left_id:    left_id.to_string(),
        right_id:   right_id.to_string(),
        diff_json,
        summary:    Some(summary),
        created_at: Utc::now(),
    })
}

// ── Replay ────────────────────────────────────────────────────────────────────

/// Start a new replay of a source run, optionally with substitutions.
pub async fn start_replay(
    pool:          &PgPool,
    connector:     &ConnectorClient,
    source_run_id: Uuid,
    substitutions: Option<Value>,
    created_by:    Option<String>,
) -> Result<Replay> {
    let source = get_run(pool, source_run_id).await?;

    let replay_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO al_replays (id, source_run_id, agent_id, status, substitutions, created_by)
         VALUES ($1, $2, $3, 'pending', $4, $5)"
    )
    .bind(replay_id)
    .bind(source_run_id)
    .bind(source.agent_id)
    .bind(substitutions.clone().unwrap_or(json!({})))
    .bind(&created_by)
    .execute(pool).await.context("insert replay")?;

    // Kick off replay via Connector
    let body = json!({
        "source_run_id": source.connector_run_id,
        "substitutions": substitutions.unwrap_or(json!({})),
        "agentloop_replay_id": replay_id.to_string(),
    });

    let pool_clone      = pool.clone();
    let connector_clone = connector.clone();
    let source_crid     = source.connector_run_id.clone();

    tokio::spawn(async move {
        let result = connector_clone.replay_run(&source_crid, &body).await;
        match result {
            Ok(resp) => {
                let new_crid = resp.get("run_id").or_else(|| resp.get("id"))
                    .and_then(|v| v.as_str()).unwrap_or("").to_string();

                // Upsert the new run if we got a connector run id back
                let new_run_id = if !new_crid.is_empty() {
                    upsert_run(&pool_clone, &new_crid, &resp).await.ok().map(|r| r.id)
                } else { None };

                let _ = sqlx::query(
                    "UPDATE al_replays SET status = 'completed', replay_run_id = $1, completed_at = NOW()
                     WHERE id = $2"
                )
                .bind(new_run_id).bind(replay_id)
                .execute(&pool_clone).await;
            }
            Err(e) => {
                tracing::warn!(replay_id = %replay_id, err = %e, "Replay failed");
                let _ = sqlx::query(
                    "UPDATE al_replays SET status = 'failed', completed_at = NOW() WHERE id = $1"
                )
                .bind(replay_id).execute(&pool_clone).await;
            }
        }
    });

    get_replay(pool, replay_id).await
}

pub async fn get_replay(pool: &PgPool, id: Uuid) -> Result<Replay> {
    let row = sqlx::query(
        "SELECT id, source_run_id, agent_id, status, substitutions, replay_run_id,
         diverged_at_step, diff_summary, created_by, created_at, completed_at
         FROM al_replays WHERE id = $1"
    )
    .bind(id)
    .fetch_one(pool).await.context("get replay")?;
    Ok(row_to_replay(row))
}

pub async fn list_replays(pool: &PgPool, source_run_id: Uuid) -> Result<Vec<Replay>> {
    let rows = sqlx::query(
        "SELECT id, source_run_id, agent_id, status, substitutions, replay_run_id,
         diverged_at_step, diff_summary, created_by, created_at, completed_at
         FROM al_replays WHERE source_run_id = $1 ORDER BY created_at DESC"
    )
    .bind(source_run_id)
    .fetch_all(pool).await.context("list replays")?;
    Ok(rows.into_iter().map(row_to_replay).collect())
}

// ── Sync from Connector ───────────────────────────────────────────────────────

/// Pull run history for an agent from Connector and sync into al_runs.
pub async fn sync_history(
    pool:      &PgPool,
    connector: &ConnectorClient,
    agent_connector_id: &str,
    limit:     u32,
) -> Result<usize> {
    let resp = connector.get_history(agent_connector_id, limit).await?;
    let runs = resp.get("runs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let count = runs.len();
    for run in &runs {
        if let Some(crid) = run.get("id").and_then(|v| v.as_str()) {
            let _ = upsert_run(pool, crid, run).await;
        }
    }
    Ok(count)
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn row_to_run(row: sqlx::postgres::PgRow) -> Run {
    use crate::types::RunStatus;
    let status_str: String = row.try_get("status").unwrap_or_default();
    let status = match status_str.as_str() {
        "running"   => RunStatus::Running,
        "completed" => RunStatus::Completed,
        "failed"    => RunStatus::Failed,
        "aborted"   => RunStatus::Aborted,
        _           => RunStatus::Unknown,
    };
    Run {
        id:                 row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        connector_run_id:   row.try_get("connector_run_id").unwrap_or_default(),
        agent_id:           row.try_get("agent_id").ok(),
        prompt_id:          row.try_get("prompt_id").ok(),
        prompt_version:     row.try_get("prompt_version").ok(),
        experiment_id:      row.try_get("experiment_id").ok(),
        status,
        inputs:             row.try_get("inputs").unwrap_or(json!({})),
        outputs:            row.try_get("outputs").ok(),
        model:              row.try_get("model").ok(),
        provider:           row.try_get("provider").ok(),
        total_tokens:       row.try_get("total_tokens").unwrap_or(0),
        prompt_tokens:      row.try_get("prompt_tokens").unwrap_or(0),
        completion_tokens:  row.try_get("completion_tokens").unwrap_or(0),
        cost_usd:           row.try_get("cost_usd").unwrap_or(0.0),
        latency_ms:         row.try_get("latency_ms").unwrap_or(0),
        error_message:      row.try_get("error_message").ok(),
        cid:                row.try_get("cid").ok(),
        started_at:         row.try_get("started_at").unwrap_or_else(|_| Utc::now()),
        ended_at:           row.try_get("ended_at").ok(),
    }
}

fn row_to_step(row: sqlx::postgres::PgRow) -> Step {
    Step {
        id:            row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        run_id:        row.try_get("run_id").unwrap_or_else(|_| Uuid::new_v4()),
        step_index:    row.try_get("step_index").unwrap_or(0),
        step_type:     row.try_get("step_type").unwrap_or_else(|_| "llm".into()),
        name:          row.try_get("name").ok(),
        inputs:        row.try_get("inputs").unwrap_or(json!({})),
        outputs:       row.try_get("outputs").ok(),
        model:         row.try_get("model").ok(),
        tokens:        row.try_get("tokens").unwrap_or(0),
        cost_usd:      row.try_get("cost_usd").unwrap_or(0.0),
        latency_ms:    row.try_get("latency_ms").unwrap_or(0),
        error_message: row.try_get("error_message").ok(),
        started_at:    row.try_get("started_at").ok(),
        ended_at:      row.try_get("ended_at").ok(),
    }
}

fn row_to_replay(row: sqlx::postgres::PgRow) -> Replay {
    let status_str: String = row.try_get("status").unwrap_or_default();
    let status = match status_str.as_str() {
        "running"   => ReplayStatus::Running,
        "completed" => ReplayStatus::Completed,
        "failed"    => ReplayStatus::Failed,
        _           => ReplayStatus::Pending,
    };
    Replay {
        id:               row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        source_run_id:    row.try_get("source_run_id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:         row.try_get("agent_id").ok(),
        status,
        substitutions:    row.try_get("substitutions").unwrap_or(json!({})),
        replay_run_id:    row.try_get("replay_run_id").ok(),
        diverged_at_step: row.try_get("diverged_at_step").ok(),
        diff_summary:     row.try_get("diff_summary").ok(),
        created_by:       row.try_get("created_by").ok(),
        created_at:       row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        completed_at:     row.try_get("completed_at").ok(),
    }
}
