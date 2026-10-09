//! Spend forecasting and anomaly detection.
//!
//! Forecast model:
//!   - Pull trailing 7d and 30d average daily spend from ll_usage_records
//!   - Estimate daily avg and week-over-week growth rate
//!   - Project forward: p50 = avg × horizon, p80 = p50 × 1.25, p95 = p50 × 1.6
//!   - Snapshots stored in ll_forecasts; ConnectorOS /monitor/forecast used for enrichment
//!
//! Anomaly model:
//!   - Baseline = avg hourly spend over the last 7 days (same hour-of-day)
//!   - Observed = spend in the current window (ANOMALY_WINDOW_HOURS)
//!   - Alert when observed >= baseline × ANOMALY_MULTIPLIER

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::db_decimal::get_decimal;
use crate::types::{Anomaly, Forecast, ForecastQueryParams};

// ── Forecasting ───────────────────────────────────────────────────────────────

pub async fn run_forecast(
    pool:      &PgPool,
    connector: &ConnectorClient,
    dim_type:  &str,
    dim_value: Option<&str>,
    horizon:   i32,
) -> Result<Forecast> {
    let scope_sql = match (dim_type, dim_value) {
        ("feature",  Some(v)) => format!("AND tag_feature = '{}'",  v.replace('\'', "''")),
        ("bu",       Some(v)) => format!("AND tag_bu = '{}'",       v.replace('\'', "''")),
        ("customer", Some(v)) => format!("AND tag_customer = '{}'", v.replace('\'', "''")),
        ("workflow", Some(v)) => format!("AND tag_workflow = '{}'", v.replace('\'', "''")),
        ("agent",    Some(v)) => format!("AND agent_id = '{}'",     v.replace('\'', "''")),
        _                     => String::new(),
    };

    let now = Utc::now();
    let thirty_ago = now - Duration::days(30);
    let seven_ago  = now - Duration::days(7);

    let sql30 = format!(
        "SELECT COALESCE(SUM(cost_usd),0) AS s FROM ll_usage_records WHERE called_at >= $1 {scope_sql}"
    );
    let sql7 = format!(
        "SELECT COALESCE(SUM(cost_usd),0) AS s FROM ll_usage_records WHERE called_at >= $1 {scope_sql}"
    );

    let row30 = sqlx::query(&sql30).bind(thirty_ago).fetch_one(pool).await.context("t30")?;
    let t30: Decimal = get_decimal(&row30, "s");
    let row7 = sqlx::query(&sql7).bind(seven_ago).fetch_one(pool).await.context("t7")?;
    let t7: Decimal  = get_decimal(&row7, "s");

    let daily_avg_30 = if t30.is_zero() { Decimal::ZERO } else { t30 / Decimal::from(30) };
    let daily_avg_7  = if t7.is_zero()  { Decimal::ZERO } else { t7  / Decimal::from(7) };

    // Weighted daily average (recent weeks weighted 2×)
    let daily_avg = if (daily_avg_30 + daily_avg_7).is_zero() {
        Decimal::ZERO
    } else {
        (daily_avg_7 * Decimal::from(2) + daily_avg_30) / Decimal::from(3)
    };

    // Growth rate: week-over-week
    let prev_7 = {
        let start = now - Duration::days(14);
        let end   = now - Duration::days(7);
        let sql = format!(
            "SELECT COALESCE(SUM(cost_usd),0) as s FROM ll_usage_records WHERE called_at BETWEEN $1 AND $2 {scope_sql}"
        );
        let row = sqlx::query(&sql).bind(start).bind(end)
            .fetch_one(pool).await.context("prev7")?;
        get_decimal(&row, "s")
    };

    let growth = if prev_7.is_zero() {
        Decimal::ZERO
    } else {
        ((t7 - prev_7) / prev_7 * Decimal::from(100)).round_dp(4)
    };

    let h   = Decimal::from(horizon);
    let p50 = daily_avg * h;
    let p80 = p50 * Decimal::try_from(1.25f64).unwrap_or(Decimal::ONE);
    let p95 = p50 * Decimal::try_from(1.60f64).unwrap_or(Decimal::ONE);

    // Enrich with ConnectorOS capacity forecast if available
    let connector_fc = connector.capacity_forecast().await.unwrap_or(Value::Null);

    let scenarios = json!({
        "flat":       { "p50": p50, "description": "Spend stays at current run rate" },
        "growth_10":  { "p50": (p50 * Decimal::try_from(1.10f64).unwrap_or(Decimal::ONE)).round_dp(4), "description": "+10% growth" },
        "growth_25":  { "p50": (p50 * Decimal::try_from(1.25f64).unwrap_or(Decimal::ONE)).round_dp(4), "description": "+25% growth" },
        "connector":  connector_fc,
    });

    use rust_decimal::prelude::ToPrimitive;
    let row = sqlx::query(
        "INSERT INTO ll_forecasts
            (dimension_type, dimension_value, horizon_days,
             p50_usd, p80_usd, p95_usd,
             trailing_30d_usd, trailing_7d_usd, daily_avg_usd,
             growth_rate_pct, scenarios)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         RETURNING *"
    )
    .bind(dim_type)
    .bind(dim_value)
    .bind(horizon)
    .bind(p50.to_f64().unwrap_or(0.0))
    .bind(p80.to_f64().unwrap_or(0.0))
    .bind(p95.to_f64().unwrap_or(0.0))
    .bind(t30.to_f64().unwrap_or(0.0))
    .bind(t7.to_f64().unwrap_or(0.0))
    .bind(daily_avg.to_f64().unwrap_or(0.0))
    .bind(growth.to_f64().unwrap_or(0.0))
    .bind(&scenarios)
    .fetch_one(pool).await.context("insert forecast")?;

    row_to_forecast(&row)
}

pub async fn list_forecasts(pool: &PgPool, params: &ForecastQueryParams) -> Result<Vec<Forecast>> {
    let dim_type  = params.dimension_type.as_deref().unwrap_or("global");
    let horizon   = params.horizon_days.unwrap_or(30);
    let rows = sqlx::query(
        "SELECT * FROM ll_forecasts WHERE dimension_type = $1 AND horizon_days = $2
         ORDER BY created_at DESC LIMIT 10"
    ).bind(dim_type).bind(horizon).fetch_all(pool).await.context("list forecasts")?;
    rows.iter().map(|r| row_to_forecast(r)).collect()
}

// ── Anomaly detection ─────────────────────────────────────────────────────────

pub async fn run_anomaly_detection(pool: &PgPool) -> Result<usize> {
    let window_hours: i64 = std::env::var("ANOMALY_WINDOW_HOURS")
        .unwrap_or_else(|_| "1".into()).parse().unwrap_or(1);
    let multiplier: f64 = std::env::var("ANOMALY_MULTIPLIER")
        .unwrap_or_else(|_| "3.0".into()).parse().unwrap_or(3.0);

    let dimensions: Vec<(&str, Option<&str>)> = vec![
        ("global", None),
        ("feature", None),
        ("bu", None),
    ];

    let now = Utc::now();
    let window_start = now - Duration::hours(window_hours);

    // Baseline: same hour-of-day over the last 7 days
    let baseline_window = Duration::days(7);
    let mut created = 0usize;

    for (dim_type, _) in &dimensions {
        let group_col = match *dim_type {
            "feature" => "COALESCE(tag_feature,'(untagged)')",
            "bu"      => "COALESCE(tag_bu,'(untagged)')",
            "agent"   => "agent_id",
            _         => "'global'",
        };

        let obs_sql = format!(
            "SELECT {group_col} as dim, SUM(cost_usd) as s FROM ll_usage_records
             WHERE called_at BETWEEN $1 AND $2 GROUP BY dim"
        );
        let base_sql = format!(
            "SELECT {group_col} as dim,
                    SUM(cost_usd) / 7.0 as s
             FROM ll_usage_records
             WHERE called_at BETWEEN $1 AND $2
               AND EXTRACT(HOUR FROM called_at) = EXTRACT(HOUR FROM $3::timestamptz)
             GROUP BY dim"
        );

        let obs_rows = sqlx::query(&obs_sql)
            .bind(window_start).bind(now)
            .fetch_all(pool).await.context("anomaly obs")?;

        let base_rows = sqlx::query(&base_sql)
            .bind(now - baseline_window).bind(now - Duration::hours(window_hours)).bind(now)
            .fetch_all(pool).await.context("anomaly base")?;

        for obs_row in &obs_rows {
            let dim: String = obs_row.try_get("dim").unwrap_or_default();
            let observed: Decimal = get_decimal(obs_row, "s");

            let baseline: Decimal = base_rows.iter()
                .find(|r| r.try_get::<String, _>("dim").unwrap_or_default() == dim)
                .map(|r| get_decimal(r, "s"))
                .unwrap_or_default();

            if baseline.is_zero() { continue; }

            let ratio = observed.to_f64().unwrap_or(0.0)
                / baseline.to_f64().unwrap_or(1.0);

            if ratio >= multiplier {
                let severity = if ratio >= multiplier * 3.0 { "critical" }
                               else if ratio >= multiplier * 1.5 { "high" }
                               else { "medium" };

                sqlx::query(
                    "INSERT INTO ll_anomalies
                        (dimension_type, dimension_value, observed_spend, baseline_spend,
                         multiplier, window_hours, severity)
                     VALUES ($1,$2,$3,$4,$5,$6,$7)
                     ON CONFLICT DO NOTHING"
                )
                .bind(dim_type)
                .bind(&dim)
                .bind(observed.to_f64().unwrap_or(0.0))
                .bind(baseline.to_f64().unwrap_or(0.0))
                .bind(ratio)
                .bind(window_hours as i32)
                .bind(severity)
                .execute(pool).await.context("insert anomaly")?;

                metrics::counter!("ledgerlens_anomalies_detected_total",
                    "dimension" => *dim_type,
                    "severity"  => severity,
                ).increment(1);

                tracing::warn!(
                    dimension    = dim_type,
                    value        = %dim,
                    observed_usd = %observed,
                    baseline_usd = %baseline,
                    ratio        = ratio,
                    severity,
                    "Anomaly detected"
                );
                created += 1;
            }
        }
    }
    Ok(created)
}

pub async fn list_anomalies(pool: &PgPool, status: Option<&str>, limit: i64) -> Result<Vec<Anomaly>> {
    let rows = if let Some(s) = status {
        sqlx::query("SELECT * FROM ll_anomalies WHERE status = $1 ORDER BY created_at DESC LIMIT $2")
            .bind(s).bind(limit).fetch_all(pool).await.context("list anomalies")?
    } else {
        sqlx::query("SELECT * FROM ll_anomalies ORDER BY created_at DESC LIMIT $1")
            .bind(limit).fetch_all(pool).await.context("list anomalies")?
    };
    rows.iter().map(|r| row_to_anomaly(r)).collect()
}

pub async fn acknowledge_anomaly(pool: &PgPool, id: Uuid, by: &str) -> Result<Anomaly> {
    let row = sqlx::query(
        "UPDATE ll_anomalies SET status='acknowledged', acknowledged_by=$1, acknowledged_at=NOW()
         WHERE id=$2 RETURNING *"
    ).bind(by).bind(id).fetch_one(pool).await.context("acknowledge anomaly")?;
    row_to_anomaly(&row)
}

pub async fn resolve_anomaly(pool: &PgPool, id: Uuid) -> Result<Anomaly> {
    let row = sqlx::query(
        "UPDATE ll_anomalies SET status='resolved', resolved_at=NOW() WHERE id=$1 RETURNING *"
    ).bind(id).fetch_one(pool).await.context("resolve anomaly")?;
    row_to_anomaly(&row)
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn row_to_forecast(r: &sqlx::postgres::PgRow) -> Result<Forecast> {
    use crate::db_decimal::{get_decimal, get_decimal_opt};
    Ok(Forecast {
        id:               r.try_get("id")?,
        dimension_type:   r.try_get("dimension_type")?,
        dimension_value:  r.try_get("dimension_value")?,
        horizon_days:     r.try_get("horizon_days")?,
        p50_usd:          get_decimal(r, "p50_usd"),
        p80_usd:          get_decimal(r, "p80_usd"),
        p95_usd:          get_decimal(r, "p95_usd"),
        trailing_30d_usd: get_decimal_opt(r, "trailing_30d_usd"),
        trailing_7d_usd:  get_decimal_opt(r, "trailing_7d_usd"),
        daily_avg_usd:    get_decimal_opt(r, "daily_avg_usd"),
        growth_rate_pct:  get_decimal_opt(r, "growth_rate_pct"),
        scenarios:        r.try_get("scenarios")?,
        created_at:       r.try_get("created_at")?,
    })
}

fn row_to_anomaly(r: &sqlx::postgres::PgRow) -> Result<Anomaly> {
    use crate::db_decimal::get_decimal;
    Ok(Anomaly {
        id:              r.try_get("id")?,
        dimension_type:  r.try_get("dimension_type")?,
        dimension_value: r.try_get("dimension_value")?,
        observed_spend:  get_decimal(r, "observed_spend"),
        baseline_spend:  get_decimal(r, "baseline_spend"),
        multiplier:      get_decimal(r, "multiplier"),
        window_hours:    r.try_get("window_hours")?,
        root_cause:      r.try_get("root_cause")?,
        top_agents:      r.try_get("top_agents")?,
        top_models:      r.try_get("top_models")?,
        status:          r.try_get("status")?,
        severity:        r.try_get("severity")?,
        acknowledged_by: r.try_get("acknowledged_by")?,
        acknowledged_at: r.try_get("acknowledged_at")?,
        resolved_at:     r.try_get("resolved_at")?,
        detail:          r.try_get("detail")?,
        created_at:      r.try_get("created_at")?,
    })
}
