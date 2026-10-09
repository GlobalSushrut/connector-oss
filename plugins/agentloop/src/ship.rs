//! Ship module — experiments, A/B testing, statistical significance, canary rollout.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::types::{Experiment, ExperimentStatus};

// ── Experiments ───────────────────────────────────────────────────────────────

pub async fn create_experiment(
    pool:                   &PgPool,
    connector:              &ConnectorClient,
    agent_id:               Option<Uuid>,
    name:                   &str,
    description:            Option<&str>,
    control_version_id:     Uuid,
    treatment_version_id:   Uuid,
    traffic_split_pct:      i32,
    significance_threshold: f64,
    auto_promote:           bool,
) -> Result<Experiment> {
    let exp_id = Uuid::new_v4();

    let row = sqlx::query(
        "INSERT INTO al_experiments
         (id, agent_id, name, description, variant_control_id, variant_treatment_id,
          traffic_split_pct, significance_threshold, auto_promote)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *"
    )
    .bind(exp_id).bind(agent_id).bind(name).bind(description)
    .bind(control_version_id).bind(treatment_version_id)
    .bind(traffic_split_pct).bind(significance_threshold).bind(auto_promote)
    .fetch_one(pool).await.context("create experiment")?;

    // Register experiment with Connector for traffic routing
    let body = json!({
        "agentloop_experiment_id": exp_id.to_string(),
        "control_version_id":   control_version_id.to_string(),
        "treatment_version_id": treatment_version_id.to_string(),
        "traffic_split_pct":    traffic_split_pct,
    });
    if let Err(e) = connector.create_experiment(&body).await {
        tracing::warn!(exp_id = %exp_id, err = %e, "Failed to register experiment with Connector — continuing");
    }

    Ok(row_to_experiment(row))
}

pub async fn get_experiment(pool: &PgPool, id: Uuid) -> Result<Experiment> {
    let row = sqlx::query("SELECT * FROM al_experiments WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get experiment")?;
    Ok(row_to_experiment(row))
}

pub async fn list_experiments(
    pool:     &PgPool,
    agent_id: Option<Uuid>,
    limit:    i64,
    offset:   i64,
) -> Result<Vec<Experiment>> {
    let rows = if let Some(aid) = agent_id {
        sqlx::query(
            "SELECT * FROM al_experiments WHERE agent_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        ).bind(aid).bind(limit).bind(offset).fetch_all(pool).await
    } else {
        sqlx::query(
            "SELECT * FROM al_experiments ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        ).bind(limit).bind(offset).fetch_all(pool).await
    }.context("list experiments")?;
    Ok(rows.into_iter().map(row_to_experiment).collect())
}

pub async fn start_experiment(pool: &PgPool, id: Uuid) -> Result<Experiment> {
    let row = sqlx::query(
        "UPDATE al_experiments SET status = 'running', updated_at = NOW() WHERE id = $1 RETURNING *"
    )
    .bind(id).fetch_one(pool).await.context("start experiment")?;
    Ok(row_to_experiment(row))
}

pub async fn pause_experiment(pool: &PgPool, id: Uuid) -> Result<Experiment> {
    let row = sqlx::query(
        "UPDATE al_experiments SET status = 'paused', updated_at = NOW() WHERE id = $1 RETURNING *"
    )
    .bind(id).fetch_one(pool).await.context("pause experiment")?;
    Ok(row_to_experiment(row))
}

/// Pull metrics from Connector, compute significance, auto-promote if threshold met.
pub async fn refresh_metrics(
    pool:      &PgPool,
    connector: &ConnectorClient,
    id:        Uuid,
) -> Result<Experiment> {
    let exp = get_experiment(pool, id).await?;

    let metrics = match connector.get_experiment_metrics(&id.to_string()).await {
        Ok(m)  => m,
        Err(e) => {
            tracing::warn!(exp_id = %id, err = %e, "Could not fetch experiment metrics from Connector");
            json!({})
        }
    };

    let p_value       = metrics.get("p_value").and_then(|v| v.as_f64()).unwrap_or(1.0);
    let quality_delta = metrics.get("quality_delta").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let winning       = if p_value < (1.0 - exp.significance_threshold) {
        if quality_delta >= 0.0 { Some("treatment") } else { Some("control") }
    } else { None };

    let merged_metrics = json!({
        "p_value":       p_value,
        "quality_delta": quality_delta,
        "cost_delta":    metrics.get("cost_delta").and_then(|v| v.as_f64()).unwrap_or(0.0),
        "latency_delta": metrics.get("latency_delta").and_then(|v| v.as_f64()).unwrap_or(0.0),
        "sample_size":   metrics.get("sample_size").and_then(|v| v.as_i64()).unwrap_or(0),
        "significant":   winning.is_some(),
    });

    let row = sqlx::query(
        "UPDATE al_experiments SET metrics = $1, winning_variant = $2, updated_at = NOW()
         WHERE id = $3 RETURNING *"
    )
    .bind(&merged_metrics)
    .bind(winning)
    .bind(id)
    .fetch_one(pool).await.context("update experiment metrics")?;

    let updated = row_to_experiment(row);

    // Auto-promote if enabled and significant
    if updated.auto_promote && updated.winning_variant.is_some() && updated.status == ExperimentStatus::Running {
        let _ = promote_experiment(pool, connector, id, false).await;
    }

    Ok(updated)
}

/// Conclude the experiment and promote the winning variant.
pub async fn promote_experiment(
    pool:      &PgPool,
    connector: &ConnectorClient,
    id:        Uuid,
    rollback:  bool,
) -> Result<Experiment> {
    let body = json!({ "rollback": rollback });
    if let Err(e) = connector.promote_experiment(&id.to_string(), &body).await {
        tracing::warn!(exp_id = %id, err = %e, "Connector promote call failed");
    }

    let (status, col) = if rollback {
        ("rolled_back", "rolled_back_at")
    } else {
        ("concluded", "promoted_at")
    };

    let row = sqlx::query(&format!(
        "UPDATE al_experiments SET status = $1, {} = NOW(), updated_at = NOW()
         WHERE id = $2 RETURNING *", col
    ))
    .bind(status).bind(id)
    .fetch_one(pool).await.context("promote/rollback experiment")?;

    Ok(row_to_experiment(row))
}

pub async fn rollback_experiment(
    pool:      &PgPool,
    connector: &ConnectorClient,
    id:        Uuid,
    reason:    Option<&str>,
) -> Result<Experiment> {
    sqlx::query("UPDATE al_experiments SET rollback_reason = $1 WHERE id = $2")
        .bind(reason).bind(id).execute(pool).await.context("set rollback reason")?;
    promote_experiment(pool, connector, id, true).await
}

// ── Canary ────────────────────────────────────────────────────────────────────

pub async fn create_canary(pool: &PgPool, experiment_id: Uuid) -> Result<Value> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO al_canaries (id, experiment_id, stage, pct_traffic, status)
         VALUES ($1, $2, 1, 5, 'active')"
    )
    .bind(id).bind(experiment_id)
    .execute(pool).await.context("create canary")?;

    Ok(json!({ "id": id, "experiment_id": experiment_id, "stage": 1, "pct_traffic": 5, "status": "active" }))
}

pub async fn advance_canary(pool: &PgPool, experiment_id: Uuid) -> Result<Value> {
    let row = sqlx::query(
        "SELECT id, stage, pct_traffic FROM al_canaries
         WHERE experiment_id = $1 AND status = 'active' ORDER BY started_at DESC LIMIT 1"
    )
    .bind(experiment_id)
    .fetch_optional(pool).await.context("get canary")?;

    let row = match row { Some(r) => r, None => return Ok(json!({ "error": "no active canary" })) };

    let stage: i32 = row.try_get("stage").unwrap_or(1);
    let (new_stage, new_pct, new_status) = match stage {
        1 => (2, 25, "active"),
        2 => (3, 50, "active"),
        3 => (4, 100, "active"),
        _ => (stage, 100, "promoted"),
    };

    let canary_id: Uuid = row.try_get("id").unwrap_or_else(|_| Uuid::new_v4());
    sqlx::query(
        "UPDATE al_canaries SET stage = $1, pct_traffic = $2, status = $3, ended_at = CASE WHEN $3 = 'promoted' THEN NOW() ELSE NULL END
         WHERE id = $4"
    )
    .bind(new_stage).bind(new_pct).bind(new_status).bind(canary_id)
    .execute(pool).await.context("advance canary")?;

    Ok(json!({ "stage": new_stage, "pct_traffic": new_pct, "status": new_status }))
}

// ── Row mapper ────────────────────────────────────────────────────────────────

fn row_to_experiment(row: sqlx::postgres::PgRow) -> Experiment {
    let s: String = row.try_get("status").unwrap_or_default();
    let status = match s.as_str() {
        "running"      => ExperimentStatus::Running,
        "paused"       => ExperimentStatus::Paused,
        "concluded"    => ExperimentStatus::Concluded,
        "rolled_back"  => ExperimentStatus::RolledBack,
        _              => ExperimentStatus::Draft,
    };
    Experiment {
        id:                     row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:               row.try_get("agent_id").ok(),
        name:                   row.try_get("name").unwrap_or_default(),
        description:            row.try_get("description").ok(),
        status,
        variant_control_id:     row.try_get("variant_control_id").ok(),
        variant_treatment_id:   row.try_get("variant_treatment_id").ok(),
        traffic_split_pct:      row.try_get("traffic_split_pct").unwrap_or(50),
        significance_threshold: row.try_get("significance_threshold").unwrap_or(0.95),
        auto_promote:           row.try_get("auto_promote").unwrap_or(false),
        winning_variant:        row.try_get("winning_variant").ok(),
        concluded_at:           row.try_get("concluded_at").ok(),
        promoted_at:            row.try_get("promoted_at").ok(),
        rolled_back_at:         row.try_get("rolled_back_at").ok(),
        rollback_reason:        row.try_get("rollback_reason").ok(),
        metrics:                row.try_get("metrics").unwrap_or(json!({})),
        created_at:             row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
        updated_at:             row.try_get("updated_at").unwrap_or_else(|_| Utc::now()),
    }
}
