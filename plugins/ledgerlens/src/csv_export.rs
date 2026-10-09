//! Real CSV generation — opens natively in Excel / Google Sheets.
//!
//! Called by exports::run_export when format = "csv".
//! Returns raw CSV bytes (not base64) as a String.

use anyhow::{Context, Result};
use chrono::NaiveDate;
use sqlx::{PgPool, Row};

use crate::db_decimal::get_decimal;
use rust_decimal::prelude::ToPrimitive;

// ── Chargeback CSV ─────────────────────────────────────────────────────────────

pub async fn chargeback_csv(pool: &PgPool, from: NaiveDate, to: NaiveDate) -> Result<String> {
    let rows = sqlx::query(
        "SELECT
            COALESCE(tag_bu,'(untagged)')       AS bu,
            COALESCE(tag_team,'')               AS team,
            COALESCE(tag_workflow,'')           AS workflow,
            model,
            provider,
            COUNT(*)                            AS calls,
            SUM(input_tokens)                   AS input_tok,
            SUM(output_tokens)                  AS output_tok,
            SUM(total_tokens)                   AS total_tok,
            SUM(cost_usd)                       AS cost
         FROM ll_usage_records
         WHERE called_at BETWEEN $1::timestamptz AND $2::timestamptz
         GROUP BY bu, team, workflow, model, provider
         ORDER BY cost DESC"
    )
    .bind(from.and_hms_opt(0, 0, 0).map(|d| d.and_utc()))
    .bind(to.and_hms_opt(23, 59, 59).map(|d| d.and_utc()))
    .fetch_all(pool).await.context("chargeback csv")?;

    let total_cost: f64 = rows.iter()
        .map(|r| get_decimal(r, "cost").to_f64().unwrap_or(0.0))
        .sum();

    let mut out = String::new();
    out.push_str("Period Start,Period End,Business Unit,Team,Workflow,Model,Provider,Calls,Input Tokens,Output Tokens,Total Tokens,Cost USD,% of Total\n");

    for r in &rows {
        let cost = get_decimal(r, "cost").to_f64().unwrap_or(0.0);
        let pct  = if total_cost == 0.0 { 0.0 } else { cost / total_cost * 100.0 };
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.2}\n",
            from,
            to,
            csv_esc(r.try_get("bu").unwrap_or_default()),
            csv_esc(r.try_get("team").unwrap_or_default()),
            csv_esc(r.try_get("workflow").unwrap_or_default()),
            csv_esc(r.try_get("model").unwrap_or_default()),
            csv_esc(r.try_get("provider").unwrap_or_default()),
            r.try_get::<i64, _>("calls").unwrap_or_default(),
            r.try_get::<i64, _>("input_tok").unwrap_or_default(),
            r.try_get::<i64, _>("output_tok").unwrap_or_default(),
            r.try_get::<i64, _>("total_tok").unwrap_or_default(),
            cost,
            pct,
        ));
    }

    // Summary footer
    out.push_str(&format!(
        "TOTAL,,,,,,,,,,, {:.6},100.00\n",
        total_cost
    ));

    Ok(out)
}

// ── Unit Economics CSV ─────────────────────────────────────────────────────────

pub async fn unit_economics_csv(pool: &PgPool, from: NaiveDate, to: NaiveDate) -> Result<String> {
    let cost_rows = sqlx::query(
        "SELECT
            COALESCE(tag_customer,'(untagged)') AS customer,
            COALESCE(tag_feature,'')            AS feature,
            SUM(cost_usd)                       AS cost,
            COUNT(*)                            AS calls,
            SUM(total_tokens)                   AS tokens
         FROM ll_usage_records
         WHERE called_at BETWEEN $1::timestamptz AND $2::timestamptz
         GROUP BY customer, feature
         ORDER BY cost DESC"
    )
    .bind(from.and_hms_opt(0, 0, 0).map(|d| d.and_utc()))
    .bind(to.and_hms_opt(23, 59, 59).map(|d| d.and_utc()))
    .fetch_all(pool).await.context("unit econ csv")?;

    let mut out = String::new();
    out.push_str("Period Start,Period End,Customer,Feature,AI Cost USD,Revenue USD,Gross Margin %,Calls,Tokens,Cost per Call USD\n");

    for r in &cost_rows {
        let customer: String = r.try_get("customer").unwrap_or_default();
        let cost = get_decimal(r, "cost").to_f64().unwrap_or(0.0);
        let calls: i64 = r.try_get("calls").unwrap_or(0);

        let revenue: Option<f64> = sqlx::query_scalar(
            "SELECT SUM(revenue_usd) FROM ll_revenue_records
             WHERE dimension_type='customer' AND dimension_value=$1
               AND period_start >= $2 AND period_end <= $3"
        )
        .bind(&customer).bind(from).bind(to)
        .fetch_optional(pool).await.unwrap_or(None).flatten();

        let margin = revenue.map(|rev| {
            if rev == 0.0 { 0.0 } else { (rev - cost) / rev * 100.0 }
        });
        let cost_per_call = if calls == 0 { 0.0 } else { cost / calls as f64 };

        out.push_str(&format!(
            "{},{},{},{},{:.6},{},{},{},{},{:.8}\n",
            from, to,
            csv_esc(customer),
            csv_esc(r.try_get("feature").unwrap_or_default()),
            cost,
            revenue.map(|v| format!("{:.2}", v)).unwrap_or_default(),
            margin.map(|v| format!("{:.2}", v)).unwrap_or_default(),
            calls,
            r.try_get::<i64, _>("tokens").unwrap_or_default(),
            cost_per_call,
        ));
    }

    Ok(out)
}

// ── Waste Report CSV ──────────────────────────────────────────────────────────

pub async fn waste_report_csv(pool: &PgPool) -> Result<String> {
    let rows = sqlx::query(
        "SELECT rec_type, title, agent_id, model_current, model_suggested,
                monthly_savings_usd, quality_impact, confidence, status
         FROM ll_recommendations
         ORDER BY monthly_savings_usd DESC"
    ).fetch_all(pool).await.context("waste csv")?;

    let mut out = String::new();
    out.push_str("Type,Title,Agent ID,Current Model,Suggested Model,Monthly Savings USD,Quality Impact,Confidence,Status\n");

    for r in &rows {
        let savings = get_decimal(r, "monthly_savings_usd").to_f64().unwrap_or(0.0);
        let confidence = get_decimal(r, "confidence").to_f64().unwrap_or(0.0);
        out.push_str(&format!(
            "{},{},{},{},{},{:.4},{},{:.2},{}\n",
            csv_esc(r.try_get("rec_type").unwrap_or_default()),
            csv_esc(r.try_get("title").unwrap_or_default()),
            csv_esc(r.try_get::<Option<String>, _>("agent_id").unwrap_or_default().unwrap_or_default()),
            csv_esc(r.try_get::<Option<String>, _>("model_current").unwrap_or_default().unwrap_or_default()),
            csv_esc(r.try_get::<Option<String>, _>("model_suggested").unwrap_or_default().unwrap_or_default()),
            savings,
            csv_esc(r.try_get("quality_impact").unwrap_or_default()),
            confidence,
            r.try_get::<String, _>("status").unwrap_or_default(),
        ));
    }

    Ok(out)
}

// ── Anomaly History CSV ────────────────────────────────────────────────────────

pub async fn anomaly_history_csv(pool: &PgPool, from: NaiveDate, to: NaiveDate) -> Result<String> {
    let rows = sqlx::query(
        "SELECT dimension_type, dimension_value, observed_spend, baseline_spend,
                multiplier, severity, status, acknowledged_by, created_at
         FROM ll_anomalies
         WHERE created_at BETWEEN $1::timestamptz AND $2::timestamptz
         ORDER BY created_at DESC"
    )
    .bind(from.and_hms_opt(0, 0, 0).map(|d| d.and_utc()))
    .bind(to.and_hms_opt(23, 59, 59).map(|d| d.and_utc()))
    .fetch_all(pool).await.context("anomaly csv")?;

    let mut out = String::new();
    out.push_str("Detected At,Dimension,Value,Observed Spend USD,Baseline Spend USD,Spike Multiplier,Severity,Status,Acknowledged By\n");

    for r in &rows {
        let obs  = get_decimal(r, "observed_spend").to_f64().unwrap_or(0.0);
        let base = get_decimal(r, "baseline_spend").to_f64().unwrap_or(0.0);
        let mult = get_decimal(r, "multiplier").to_f64().unwrap_or(0.0);
        out.push_str(&format!(
            "{},{},{},{:.6},{:.6},{:.2},{},{},{}\n",
            r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default(),
            r.try_get::<String, _>("dimension_type").unwrap_or_default(),
            csv_esc(r.try_get::<Option<String>, _>("dimension_value").unwrap_or_default().unwrap_or_else(|| "global".into())),
            obs,
            base,
            mult,
            r.try_get::<String, _>("severity").unwrap_or_default(),
            r.try_get::<String, _>("status").unwrap_or_default(),
            csv_esc(r.try_get::<Option<String>, _>("acknowledged_by").unwrap_or_default().unwrap_or_default()),
        ));
    }

    Ok(out)
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Escape a string for CSV — wrap in quotes if it contains comma/newline/quote.
fn csv_esc(s: String) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}
