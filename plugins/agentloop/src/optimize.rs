//! Optimize module — fleet view, SLOs, drift detection, recommendations.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::types::{DriftEvent, RecStatus, Recommendation, Slo, SloStatus};

// ── SLOs ──────────────────────────────────────────────────────────────────────

pub async fn create_slo(
    pool:         &PgPool,
    agent_id:     Uuid,
    name:         &str,
    metric:       &str,
    threshold:    f64,
    window_hours: i32,
) -> Result<Slo> {
    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO al_slos (id, agent_id, name, metric, threshold, window_hours)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *"
    )
    .bind(id).bind(agent_id).bind(name).bind(metric).bind(threshold).bind(window_hours)
    .fetch_one(pool).await.context("create slo")?;
    Ok(row_to_slo(row))
}

pub async fn get_slo(pool: &PgPool, id: Uuid) -> Result<Slo> {
    let row = sqlx::query("SELECT * FROM al_slos WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get slo")?;
    Ok(row_to_slo(row))
}

pub async fn list_slos(pool: &PgPool, agent_id: Uuid) -> Result<Vec<Slo>> {
    let rows = sqlx::query("SELECT * FROM al_slos WHERE agent_id = $1 ORDER BY created_at DESC")
        .bind(agent_id).fetch_all(pool).await.context("list slos")?;
    Ok(rows.into_iter().map(row_to_slo).collect())
}

/// Evaluate all SLOs for an agent against recent run data.
pub async fn evaluate_slos(pool: &PgPool, agent_id: Uuid) -> Result<Vec<Slo>> {
    let slos = list_slos(pool, agent_id).await?;
    let mut updated = Vec::new();

    for slo in slos {
        let window_start = Utc::now() - chrono::Duration::hours(slo.window_hours as i64);

        let current_value: Option<f64> = match slo.metric.as_str() {
            "error_rate" => {
                let row = sqlx::query(
                    "SELECT CASE WHEN COUNT(*) = 0 THEN 0.0
                     ELSE COUNT(*) FILTER (WHERE status = 'failed')::float / COUNT(*)
                     END as val
                     FROM al_runs WHERE agent_id = $1 AND started_at >= $2"
                )
                .bind(agent_id).bind(window_start)
                .fetch_one(pool).await.ok();
                row.and_then(|r| r.try_get::<f64, _>("val").ok())
            }
            "latency_p99" => {
                let row = sqlx::query(
                    "SELECT PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as val
                     FROM al_runs WHERE agent_id = $1 AND started_at >= $2"
                )
                .bind(agent_id).bind(window_start)
                .fetch_one(pool).await.ok();
                row.and_then(|r| r.try_get::<f64, _>("val").ok())
            }
            "cost_per_run" => {
                let row = sqlx::query(
                    "SELECT AVG(cost_usd) as val FROM al_runs WHERE agent_id = $1 AND started_at >= $2"
                )
                .bind(agent_id).bind(window_start)
                .fetch_one(pool).await.ok();
                row.and_then(|r| r.try_get::<f64, _>("val").ok())
            }
            _ => None,
        };

        let status = match current_value {
            None => SloStatus::Healthy,
            Some(v) if v > slo.threshold * 1.1 => SloStatus::Breached,
            Some(v) if v > slo.threshold * 0.9 => SloStatus::Warning,
            _ => SloStatus::Healthy,
        };

        let row = sqlx::query(
            "UPDATE al_slos SET status = $1, current_value = $2, last_checked_at = NOW()
             WHERE id = $3 RETURNING *"
        )
        .bind(status.to_string()).bind(current_value).bind(slo.id)
        .fetch_one(pool).await.context("update slo")?;
        updated.push(row_to_slo(row));
    }
    Ok(updated)
}

pub async fn delete_slo(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM al_slos WHERE id = $1").bind(id).execute(pool).await.context("delete slo")?;
    Ok(())
}

// ── Recommendations ───────────────────────────────────────────────────────────

pub async fn list_recommendations(
    pool:     &PgPool,
    agent_id: Option<Uuid>,
    status:   Option<&str>,
    limit:    i64,
    offset:   i64,
) -> Result<Vec<Recommendation>> {
    let rows = match (agent_id, status) {
        (Some(aid), Some(s)) => sqlx::query(
            "SELECT * FROM al_recommendations WHERE agent_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4"
        ).bind(aid).bind(s).bind(limit).bind(offset).fetch_all(pool).await,
        (Some(aid), None) => sqlx::query(
            "SELECT * FROM al_recommendations WHERE agent_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        ).bind(aid).bind(limit).bind(offset).fetch_all(pool).await,
        _ => sqlx::query(
            "SELECT * FROM al_recommendations WHERE status = 'open' ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        ).bind(limit).bind(offset).fetch_all(pool).await,
    }.context("list recs")?;
    Ok(rows.into_iter().map(row_to_rec).collect())
}

pub async fn apply_recommendation(
    pool:       &PgPool,
    connector:  &ConnectorClient,
    id:         Uuid,
    applied_by: &str,
) -> Result<Recommendation> {
    let rec = get_rec(pool, id).await?;

    // Delegate action to Connector
    if let Err(e) = connector.apply_recommendation(&id.to_string(), &rec.action_payload).await {
        tracing::warn!(rec_id = %id, err = %e, "Connector apply_recommendation failed — marking applied locally");
    }

    let row = sqlx::query(
        "UPDATE al_recommendations SET status = 'applied', applied_by = $1, applied_at = NOW()
         WHERE id = $2 RETURNING *"
    )
    .bind(applied_by).bind(id)
    .fetch_one(pool).await.context("apply rec")?;
    Ok(row_to_rec(row))
}

pub async fn dismiss_recommendation(pool: &PgPool, id: Uuid) -> Result<Recommendation> {
    let row = sqlx::query(
        "UPDATE al_recommendations SET status = 'dismissed', dismissed_at = NOW()
         WHERE id = $1 RETURNING *"
    )
    .bind(id).fetch_one(pool).await.context("dismiss rec")?;
    Ok(row_to_rec(row))
}

/// Generate recommendations from Connector's insights surface and store locally.
pub async fn sync_recommendations(
    pool:      &PgPool,
    connector: &ConnectorClient,
    agent_id:  Uuid,
    connector_agent_id: &str,
) -> Result<usize> {
    let recs = match connector.get_recommendations(connector_agent_id).await {
        Ok(r)  => r,
        Err(e) => {
            tracing::warn!(agent_id = %agent_id, err = %e, "Could not fetch recs from Connector");
            return Ok(0);
        }
    };

    let items = recs.get("recommendations").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let count = items.len();

    for item in &items {
        let id = Uuid::new_v4();
        let _ = sqlx::query(
            "INSERT INTO al_recommendations
             (id, agent_id, rec_type, title, description, impact_tokens, impact_cost_usd, impact_quality, action_payload)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT DO NOTHING"
        )
        .bind(id)
        .bind(agent_id)
        .bind(item.get("type").and_then(|v| v.as_str()).unwrap_or("rightsize_model"))
        .bind(item.get("title").and_then(|v| v.as_str()).unwrap_or("Optimization available"))
        .bind(item.get("description").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(item.get("impact_tokens").and_then(|v| v.as_i64()).map(|v| v as i32))
        .bind(item.get("impact_cost_usd").and_then(|v| v.as_f64()))
        .bind(item.get("impact_quality").and_then(|v| v.as_f64()))
        .bind(item.get("action").cloned().unwrap_or(json!({})))
        .execute(pool).await;
    }
    Ok(count)
}

// ── Drift detection ───────────────────────────────────────────────────────────

pub async fn list_drift_events(
    pool:     &PgPool,
    agent_id: Uuid,
    limit:    i64,
    offset:   i64,
) -> Result<Vec<DriftEvent>> {
    let rows = sqlx::query(
        "SELECT * FROM al_drift_events WHERE agent_id = $1 ORDER BY detected_at DESC LIMIT $2 OFFSET $3"
    )
    .bind(agent_id).bind(limit).bind(offset)
    .fetch_all(pool).await.context("list drift")?;
    Ok(rows.into_iter().map(row_to_drift).collect())
}

pub async fn acknowledge_drift(pool: &PgPool, id: Uuid) -> Result<DriftEvent> {
    let row = sqlx::query(
        "UPDATE al_drift_events SET acknowledged = true WHERE id = $1 RETURNING *"
    )
    .bind(id).fetch_one(pool).await.context("ack drift")?;
    Ok(row_to_drift(row))
}

/// Detect drift by comparing last 24h metrics to the prior 7-day baseline.
pub async fn detect_drift(pool: &PgPool, agent_id: Uuid) -> Result<Vec<DriftEvent>> {
    let now      = Utc::now();
    let day_ago  = now - chrono::Duration::hours(24);
    let week_ago = now - chrono::Duration::days(7);

    // Cost drift
    let baseline: Option<f64> = sqlx::query(
        "SELECT AVG(cost_usd) FROM al_runs WHERE agent_id = $1 AND started_at >= $2 AND started_at < $3"
    ).bind(agent_id).bind(week_ago).bind(day_ago)
    .fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok());

    let recent: Option<f64> = sqlx::query(
        "SELECT AVG(cost_usd) FROM al_runs WHERE agent_id = $1 AND started_at >= $2"
    ).bind(agent_id).bind(day_ago)
    .fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok());

    let mut events = Vec::new();

    if let (Some(base), Some(curr)) = (baseline, recent) {
        if base > 0.0 {
            let delta_pct = (curr - base) / base * 100.0;
            if delta_pct.abs() > 20.0 {
                let severity = if delta_pct.abs() > 50.0 { "high" } else if delta_pct.abs() > 30.0 { "medium" } else { "low" };
                let id = Uuid::new_v4();
                let _ = sqlx::query(
                    "INSERT INTO al_drift_events
                     (id, agent_id, drift_type, severity, description, baseline_value, current_value, delta_pct)
                     VALUES ($1,$2,'cost','$3',$4,$5,$6,$7)"
                )
                .bind(id).bind(agent_id).bind(severity)
                .bind(format!("Cost per run drifted {:+.1}% vs 7-day baseline", delta_pct))
                .bind(base).bind(curr).bind(delta_pct)
                .execute(pool).await;

                let row = sqlx::query("SELECT * FROM al_drift_events WHERE id = $1").bind(id).fetch_optional(pool).await.ok().flatten();
                if let Some(r) = row { events.push(row_to_drift(r)); }
            }
        }
    }

    Ok(events)
}

// ── Fleet overview ────────────────────────────────────────────────────────────

pub async fn fleet_summary(pool: &PgPool) -> Result<Value> {
    let agent_count: i64 = sqlx::query("SELECT COUNT(*) FROM al_agents WHERE status = 'active'")
        .fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok()).unwrap_or(0);

    let run_count_24h: i64 = sqlx::query(
        "SELECT COUNT(*) FROM al_runs WHERE started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok()).unwrap_or(0);

    let total_cost_24h: f64 = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd), 0) FROM al_runs WHERE started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok()).unwrap_or(0.0);

    let error_rate_24h: f64 = sqlx::query(
        "SELECT CASE WHEN COUNT(*) = 0 THEN 0.0 ELSE COUNT(*) FILTER (WHERE status = 'failed')::float / COUNT(*) END
         FROM al_runs WHERE started_at >= NOW() - INTERVAL '24 hours'"
    ).fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok()).unwrap_or(0.0);

    let breached_slos: i64 = sqlx::query("SELECT COUNT(*) FROM al_slos WHERE status = 'breached'")
        .fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok()).unwrap_or(0);

    let open_recs: i64 = sqlx::query("SELECT COUNT(*) FROM al_recommendations WHERE status = 'open'")
        .fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok()).unwrap_or(0);

    let unacked_drift: i64 = sqlx::query("SELECT COUNT(*) FROM al_drift_events WHERE acknowledged = false AND detected_at >= NOW() - INTERVAL '24 hours'")
        .fetch_one(pool).await.ok().and_then(|r| r.try_get(0).ok()).unwrap_or(0);

    Ok(json!({
        "agents_active":     agent_count,
        "runs_24h":          run_count_24h,
        "cost_usd_24h":      total_cost_24h,
        "error_rate_24h":    error_rate_24h,
        "slos_breached":     breached_slos,
        "open_recommendations": open_recs,
        "unacked_drift_events": unacked_drift,
        "as_of":             Utc::now(),
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn get_rec(pool: &PgPool, id: Uuid) -> Result<Recommendation> {
    let row = sqlx::query("SELECT * FROM al_recommendations WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get rec")?;
    Ok(row_to_rec(row))
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn row_to_slo(row: sqlx::postgres::PgRow) -> Slo {
    let s: String = row.try_get("status").unwrap_or_default();
    let status = match s.as_str() { "warning" => SloStatus::Warning, "breached" => SloStatus::Breached, _ => SloStatus::Healthy };
    Slo {
        id:              row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:        row.try_get("agent_id").unwrap_or_else(|_| Uuid::new_v4()),
        name:            row.try_get("name").unwrap_or_default(),
        metric:          row.try_get("metric").unwrap_or_default(),
        threshold:       row.try_get("threshold").unwrap_or(0.0),
        window_hours:    row.try_get("window_hours").unwrap_or(24),
        status,
        current_value:   row.try_get("current_value").ok(),
        last_checked_at: row.try_get("last_checked_at").ok(),
        created_at:      row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_rec(row: sqlx::postgres::PgRow) -> Recommendation {
    let s: String = row.try_get("status").unwrap_or_default();
    let status = match s.as_str() { "applied" => RecStatus::Applied, "dismissed" => RecStatus::Dismissed, "snoozed" => RecStatus::Snoozed, _ => RecStatus::Open };
    Recommendation {
        id:              row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:        row.try_get("agent_id").ok(),
        rec_type:        row.try_get("rec_type").unwrap_or_default(),
        title:           row.try_get("title").unwrap_or_default(),
        description:     row.try_get("description").unwrap_or_default(),
        impact_tokens:   row.try_get("impact_tokens").ok(),
        impact_cost_usd: row.try_get("impact_cost_usd").ok(),
        impact_quality:  row.try_get("impact_quality").ok(),
        status,
        action_payload:  row.try_get("action_payload").unwrap_or(json!({})),
        applied_by:      row.try_get("applied_by").ok(),
        applied_at:      row.try_get("applied_at").ok(),
        dismissed_at:    row.try_get("dismissed_at").ok(),
        created_at:      row.try_get("created_at").unwrap_or_else(|_| Utc::now()),
    }
}

fn row_to_drift(row: sqlx::postgres::PgRow) -> DriftEvent {
    DriftEvent {
        id:             row.try_get("id").unwrap_or_else(|_| Uuid::new_v4()),
        agent_id:       row.try_get("agent_id").unwrap_or_else(|_| Uuid::new_v4()),
        drift_type:     row.try_get("drift_type").unwrap_or_default(),
        severity:       row.try_get("severity").unwrap_or_else(|_| "low".into()),
        description:    row.try_get("description").unwrap_or_default(),
        baseline_value: row.try_get("baseline_value").ok(),
        current_value:  row.try_get("current_value").ok(),
        delta_pct:      row.try_get("delta_pct").ok(),
        run_id:         row.try_get("run_id").ok(),
        acknowledged:   row.try_get("acknowledged").unwrap_or(false),
        detected_at:    row.try_get("detected_at").unwrap_or_else(|_| Utc::now()),
    }
}
