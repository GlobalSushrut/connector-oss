//! CFO-grade export engine.
//!
//! Export types:
//!   chargeback        — Monthly P&L by BU / cost center, journal-entry ready
//!   unit_economics    — Cost × revenue per customer/feature, margin per unit
//!   waste_report      — Waste heatmap + cache ROI in one package
//!   forecast_report   — 30/60/90-day projections with scenarios
//!   full_cfo_package  — All four combined, signed with HMAC
//!
//! All exports are signed with LEDGERLENS_HMAC_KEY for tamper evidence.

use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};
use hmac::{Hmac, Mac};
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::db_decimal::get_decimal;

use crate::connector::ConnectorClient;
use crate::optimize;
use crate::types::{CreateExportRequest, ExportJob, UnitEconomicsRow};

// ── Sign helper ───────────────────────────────────────────────────────────────

fn hmac_sign(data: &str) -> String {
    let key = std::env::var("LEDGERLENS_HMAC_KEY")
        .unwrap_or_else(|_| "ledgerlens-hmac-default".into());
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .expect("HMAC key");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ── Export CRUD ───────────────────────────────────────────────────────────────

pub async fn create_export(pool: &PgPool, req: &CreateExportRequest) -> Result<ExportJob> {
    let row = sqlx::query(
        "INSERT INTO ll_exports (export_type, format, period_start, period_end, filters, status)
         VALUES ($1,$2,$3,$4,$5,'pending') RETURNING *"
    )
    .bind(&req.export_type)
    .bind(req.format.as_deref().unwrap_or("json"))
    .bind(req.period_start)
    .bind(req.period_end)
    .bind(req.filters.as_ref().unwrap_or(&json!({})))
    .fetch_one(pool).await.context("create export")?;
    row_to_export(&row)
}

pub async fn get_export(pool: &PgPool, id: Uuid) -> Result<ExportJob> {
    let row = sqlx::query("SELECT * FROM ll_exports WHERE id=$1")
        .bind(id).fetch_one(pool).await.context("get export")?;
    row_to_export(&row)
}

pub async fn list_exports(pool: &PgPool, limit: i64) -> Result<Vec<ExportJob>> {
    let rows = sqlx::query("SELECT * FROM ll_exports ORDER BY created_at DESC LIMIT $1")
        .bind(limit).fetch_all(pool).await.context("list exports")?;
    rows.iter().map(|r| row_to_export(r)).collect()
}

/// Run the export and store payload inline as JSON (for MVP; swap to S3 later).
pub async fn run_export(pool: &PgPool, connector: &ConnectorClient, id: Uuid) -> Result<ExportJob> {
    let job = get_export(pool, id).await?;

    sqlx::query("UPDATE ll_exports SET status='running' WHERE id=$1")
        .bind(id).execute(pool).await?;

    let export_type = job.export_type.clone();
    let result = match job.export_type.as_str() {
        "chargeback"       => generate_chargeback(pool, job.period_start, job.period_end).await,
        "unit_economics"   => generate_unit_economics(pool, connector, job.period_start, job.period_end).await,
        "waste_report"     => generate_waste_report(pool, connector).await,
        "forecast_report"  => generate_forecast_report(pool, connector).await,
        "full_cfo_package" => generate_full_package(pool, connector, job.period_start, job.period_end).await,
        other              => Err(anyhow::anyhow!("Unknown export type: {other}")),
    };
    match result {
        Ok(payload) => {
            let json_str = serde_json::to_string(&payload)?;
            let sig      = hmac_sign(&json_str);
            let size     = json_str.len() as i64;
            let expires  = Utc::now() + chrono::Duration::days(7);

            // For MVP store JSON inline in download_url field (base64)
            let encoded = base64_encode(&json_str);
            let row = sqlx::query(
                "UPDATE ll_exports SET status='done', row_count=$1, size_bytes=$2,
                  download_url=$3, hmac_sig=$4, expires_at=$5, completed_at=NOW()
                 WHERE id=$6 RETURNING *"
            )
            .bind(payload.as_array().map(|a| a.len() as i32).unwrap_or(1))
            .bind(size)
            .bind(format!("data:application/json;base64,{encoded}"))
            .bind(&sig)
            .bind(expires)
            .bind(id)
            .fetch_one(pool).await.context("complete export")?;

            metrics::counter!("ledgerlens_exports_completed_total",
                "type" => export_type.clone()
            ).increment(1);
            row_to_export(&row)
        }
        Err(e) => {
            sqlx::query("UPDATE ll_exports SET status='failed', error=$1 WHERE id=$2")
                .bind(e.to_string()).bind(id).execute(pool).await?;
            Err(e)
        }
    }
}

// ── Chargeback ────────────────────────────────────────────────────────────────

async fn generate_chargeback(pool: &PgPool, from: NaiveDate, to: NaiveDate) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT COALESCE(tag_bu,'(untagged)') as bu,
                COALESCE(tag_team,'') as team,
                SUM(cost_usd) as spend, COUNT(*) as calls,
                SUM(total_tokens) as tokens
         FROM ll_usage_records
         WHERE called_at BETWEEN $1::timestamptz AND $2::timestamptz
         GROUP BY bu, team ORDER BY spend DESC"
    )
    .bind(from.and_hms_opt(0,0,0).map(|d| d.and_utc()))
    .bind(to.and_hms_opt(23,59,59).map(|d| d.and_utc()))
    .fetch_all(pool).await.context("chargeback query")?;

    let total_spend: Decimal = rows.iter()
        .map(|r| get_decimal(r, "spend"))
        .sum();

    let lines: Vec<Value> = rows.iter().map(|r| {
        let spend: Decimal = get_decimal(r, "spend");
        let pct = if total_spend.is_zero() { 0.0 } else {
            (spend / total_spend * Decimal::from(100)).to_string().parse::<f64>().unwrap_or(0.0)
        };
        json!({
            "business_unit":  r.try_get::<String,_>("bu").unwrap_or_default(),
            "team":           r.try_get::<String,_>("team").unwrap_or_default(),
            "spend_usd":      spend,
            "pct_of_total":   (pct * 100.0).round() / 100.0,
            "call_count":     r.try_get::<i64,_>("calls").unwrap_or_default(),
            "total_tokens":   r.try_get::<i64,_>("tokens").unwrap_or_default(),
            "journal_debit":  format!("AI Cost — {}", r.try_get::<String,_>("bu").unwrap_or_default()),
            "journal_credit": "AI Infrastructure Payable",
        })
    }).collect();

    Ok(json!({
        "report_type":  "chargeback",
        "period":       { "from": from, "to": to },
        "total_usd":    total_spend,
        "generated_at": Utc::now(),
        "lines":        lines,
    }))
}

// ── Unit economics ────────────────────────────────────────────────────────────

async fn generate_unit_economics(pool: &PgPool, _connector: &ConnectorClient, from: NaiveDate, to: NaiveDate) -> Result<Value> {
    let cost_rows = sqlx::query(
        "SELECT COALESCE(tag_customer,'(untagged)') as dim,
                COALESCE(tag_feature,'') as feature,
                SUM(cost_usd) as cost, COUNT(*) as calls
         FROM ll_usage_records
         WHERE called_at BETWEEN $1::timestamptz AND $2::timestamptz
         GROUP BY dim, feature ORDER BY cost DESC"
    )
    .bind(from.and_hms_opt(0,0,0).map(|d| d.and_utc()))
    .bind(to.and_hms_opt(23,59,59).map(|d| d.and_utc()))
    .fetch_all(pool).await.context("unit econ costs")?;

    let mut rows: Vec<UnitEconomicsRow> = vec![];
    for r in &cost_rows {
        let dim: String     = r.try_get("dim").unwrap_or_default();
        let cost: Decimal   = get_decimal(r, "cost");
        let calls: i64      = r.try_get("calls").unwrap_or_default();

        // Try to find revenue for this customer
        let revenue_raw: Option<f64> = sqlx::query_scalar(
            "SELECT SUM(revenue_usd) FROM ll_revenue_records
             WHERE dimension_type='customer' AND dimension_value=$1
               AND period_start >= $2 AND period_end <= $3"
        )
        .bind(&dim)
        .bind(from)
        .bind(to)
        .fetch_optional(pool).await.context("revenue lookup")?.flatten();
        let revenue: Option<Decimal> = revenue_raw.map(|v| Decimal::try_from(v).unwrap_or_default());

        let margin = revenue.map(|rev| {
            if rev.is_zero() { 0.0 } else {
                ((rev - cost) / rev * Decimal::from(100))
                    .to_string().parse::<f64>().unwrap_or(0.0)
            }
        });

        let cost_per_call = if calls == 0 { Decimal::ZERO }
                            else { cost / Decimal::from(calls) };

        rows.push(UnitEconomicsRow {
            dimension_type:  "customer".into(),
            dimension_value: dim,
            cost_usd:        cost.round_dp(6),
            revenue_usd:     revenue,
            gross_margin_pct:margin,
            cost_per_call:   cost_per_call.round_dp(8),
            call_count:      calls,
        });
    }

    Ok(json!({
        "report_type":  "unit_economics",
        "period":       { "from": from, "to": to },
        "generated_at": Utc::now(),
        "rows":         rows,
    }))
}

// ── Waste report ──────────────────────────────────────────────────────────────

async fn generate_waste_report(pool: &PgPool, connector: &ConnectorClient) -> Result<Value> {
    let waste  = optimize::waste_heatmap(pool, 20).await?;
    let cache  = optimize::cache_roi_estimates(pool).await?;
    let recs   = optimize::list_recommendations(pool, Some("open"), 50).await?;

    let total_savings: Decimal = waste.iter()
        .map(|w| w.estimated_savings_usd)
        .sum::<Decimal>()
        + cache.iter().map(|c| c.estimated_savings_usd).sum::<Decimal>();

    Ok(json!({
        "report_type":             "waste_report",
        "generated_at":            Utc::now(),
        "estimated_total_savings": total_savings,
        "waste_heatmap":           waste,
        "cache_roi":               cache,
        "recommendations":         recs,
    }))
}

// ── Forecast report ───────────────────────────────────────────────────────────

async fn generate_forecast_report(pool: &PgPool, connector: &ConnectorClient) -> Result<Value> {
    let fc30 = crate::forecast::run_forecast(pool, connector, "global", None, 30).await?;
    let fc60 = crate::forecast::run_forecast(pool, connector, "global", None, 60).await?;
    let fc90 = crate::forecast::run_forecast(pool, connector, "global", None, 90).await?;

    Ok(json!({
        "report_type":  "forecast_report",
        "generated_at": Utc::now(),
        "horizons":     { "30d": fc30, "60d": fc60, "90d": fc90 },
    }))
}

// ── Full CFO package ──────────────────────────────────────────────────────────

async fn generate_full_package(pool: &PgPool, connector: &ConnectorClient, from: NaiveDate, to: NaiveDate) -> Result<Value> {
    let chargeback   = generate_chargeback(pool, from, to).await?;
    let unit_econ    = generate_unit_economics(pool, connector, from, to).await?;
    let waste        = generate_waste_report(pool, connector).await?;
    let forecast     = generate_forecast_report(pool, connector).await?;

    Ok(json!({
        "report_type":   "full_cfo_package",
        "generated_at":  Utc::now(),
        "period":        { "from": from, "to": to },
        "chargeback":    chargeback,
        "unit_economics":unit_econ,
        "waste":         waste,
        "forecast":      forecast,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn base64_encode(s: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.encode(s.as_bytes())
}

fn row_to_export(r: &sqlx::postgres::PgRow) -> Result<ExportJob> {
    Ok(ExportJob {
        id:           r.try_get("id")?,
        export_type:  r.try_get("export_type")?,
        format:       r.try_get("format")?,
        period_start: r.try_get("period_start")?,
        period_end:   r.try_get("period_end")?,
        filters:      r.try_get("filters")?,
        status:       r.try_get("status")?,
        row_count:    r.try_get("row_count")?,
        size_bytes:   r.try_get("size_bytes")?,
        download_url: r.try_get("download_url")?,
        error:        r.try_get("error")?,
        hmac_sig:     r.try_get("hmac_sig")?,
        expires_at:   r.try_get("expires_at")?,
        created_at:   r.try_get("created_at")?,
        completed_at: r.try_get("completed_at")?,
    })
}
