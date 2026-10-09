//! CFO Dashboard — single endpoint that answers "how much are we burning?"
//!
//! GET /api/v1/dashboard returns:
//!   - MTD total spend + daily run rate
//!   - Projected month-end spend (vs budget)
//!   - Burn rate: last 1h / 24h / 7d with trend direction
//!   - Top 5 cost centers (by BU, then by agent)
//!   - Breached budgets with $ over-limit
//!   - Open anomalies with severity
//!   - Top 3 actionable savings this month
//!   - Model breakdown: what % of spend is GPT-4 class vs mini class
//!
//! Designed so a CFO can open it on a phone and immediately see
//! "we are burning $4,320/day, 23% over plan, GPT-4 is 78% of cost."

use anyhow::{Context, Result};
use chrono::{Datelike, Duration, Utc};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::db_decimal::get_decimal;

pub async fn cfo_dashboard(pool: &PgPool) -> Result<Value> {
    let now      = Utc::now();
    let mtd_start = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
        .unwrap_or(now);
    let day_start = now - Duration::hours(24);
    let hour_start = now - Duration::hours(1);
    let week_start = now - Duration::days(7);

    // ── MTD total ─────────────────────────────────────────────────────────────
    let mtd_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c, COALESCE(SUM(total_tokens),0) AS t
         FROM ll_usage_records WHERE called_at >= $1"
    ).bind(mtd_start).fetch_one(pool).await.context("mtd")?;

    let mtd_usd: Decimal = get_decimal(&mtd_row, "s");
    let mtd_calls: i64   = mtd_row.try_get("c").unwrap_or(0);
    let mtd_tokens: i64  = mtd_row.try_get("t").unwrap_or(0);

    // days elapsed this month
    let days_elapsed = (now - mtd_start).num_days().max(1) as f64;
    let daily_rate   = mtd_usd.to_f64().unwrap_or(0.0) / days_elapsed;
    let days_in_month = days_in_current_month(now.year(), now.month());
    let projected_month_end = daily_rate * days_in_month as f64;

    // ── Burn rate windows ─────────────────────────────────────────────────────
    let h1_usd  = spend_since(pool, hour_start).await?;
    let h24_usd = spend_since(pool, day_start).await?;
    let h7d_usd = spend_since(pool, week_start).await?;

    // Trend: compare last 24h vs 24h before that
    let prev_24h_usd = spend_between(pool, now - Duration::hours(48), now - Duration::hours(24)).await?;
    let trend = if h24_usd > prev_24h_usd * Decimal::try_from(1.1f64).unwrap_or(Decimal::ONE) {
        "↑ accelerating"
    } else if h24_usd < prev_24h_usd * Decimal::try_from(0.9f64).unwrap_or(Decimal::ONE) {
        "↓ decelerating"
    } else {
        "→ stable"
    };

    // ── Top 5 cost centres (BU) ───────────────────────────────────────────────
    let top_bu_rows = sqlx::query(
        "SELECT COALESCE(tag_bu,'(untagged)') AS dim,
                SUM(cost_usd) AS s, COUNT(*) AS c
         FROM ll_usage_records WHERE called_at >= $1
         GROUP BY dim ORDER BY s DESC LIMIT 5"
    ).bind(mtd_start).fetch_all(pool).await.context("top bu")?;

    let top_cost_centers: Vec<Value> = top_bu_rows.iter().map(|r| {
        let spend = get_decimal(r, "s");
        let pct = if mtd_usd.is_zero() { 0.0 } else {
            spend.to_f64().unwrap_or(0.0) / mtd_usd.to_f64().unwrap_or(1.0) * 100.0
        };
        json!({
            "bu":         r.try_get::<String, _>("dim").unwrap_or_default(),
            "spend_usd":  format_usd(spend.to_f64().unwrap_or(0.0)),
            "pct":        format!("{:.1}%", pct),
            "calls":      r.try_get::<i64, _>("c").unwrap_or_default(),
        })
    }).collect();

    // ── Top 5 agents by cost ──────────────────────────────────────────────────
    let top_agent_rows = sqlx::query(
        "SELECT agent_id, model, SUM(cost_usd) AS s, COUNT(*) AS c
         FROM ll_usage_records WHERE called_at >= $1
         GROUP BY agent_id, model ORDER BY s DESC LIMIT 5"
    ).bind(mtd_start).fetch_all(pool).await.context("top agents")?;

    let top_agents: Vec<Value> = top_agent_rows.iter().map(|r| {
        let spend = get_decimal(r, "s");
        json!({
            "agent_id": r.try_get::<String, _>("agent_id").unwrap_or_default(),
            "model":    r.try_get::<String, _>("model").unwrap_or_default(),
            "spend_usd":format_usd(spend.to_f64().unwrap_or(0.0)),
            "calls":    r.try_get::<i64, _>("c").unwrap_or_default(),
        })
    }).collect();

    // ── Model class breakdown ─────────────────────────────────────────────────
    let model_rows = sqlx::query(
        "SELECT
            CASE
                WHEN model ILIKE '%gpt-4%' OR model ILIKE '%claude-3-opus%' OR model ILIKE '%gemini-1.5-pro%'
                     THEN 'frontier'
                WHEN model ILIKE '%mini%' OR model ILIKE '%haiku%' OR model ILIKE '%flash%' OR model ILIKE '%3.5%'
                     THEN 'mid_tier'
                ELSE 'other'
            END AS tier,
            SUM(cost_usd) AS s
         FROM ll_usage_records WHERE called_at >= $1
         GROUP BY tier ORDER BY s DESC"
    ).bind(mtd_start).fetch_all(pool).await.context("model tiers")?;

    let mut frontier_pct = 0.0f64;
    let mut mid_tier_pct = 0.0f64;
    for r in &model_rows {
        let tier: String = r.try_get("tier").unwrap_or_default();
        let spend = get_decimal(r, "s");
        let pct = if mtd_usd.is_zero() { 0.0 } else {
            spend.to_f64().unwrap_or(0.0) / mtd_usd.to_f64().unwrap_or(1.0) * 100.0
        };
        match tier.as_str() {
            "frontier" => frontier_pct = pct,
            "mid_tier" => mid_tier_pct = pct,
            _ => {}
        }
    }

    // ── Breached budgets ──────────────────────────────────────────────────────
    let breach_rows = sqlx::query(
        "SELECT id, name, scope_type, scope_value,
                current_spend, limit_usd, breach_policy, breach_at
         FROM ll_budgets WHERE breached = TRUE AND enabled = TRUE
         ORDER BY (current_spend - limit_usd) DESC LIMIT 10"
    ).fetch_all(pool).await.context("breached")?;

    let breached_budgets: Vec<Value> = breach_rows.iter().map(|r| {
        let spend = get_decimal(r, "current_spend");
        let limit = get_decimal(r, "limit_usd");
        let over  = spend - limit;
        json!({
            "id":           r.try_get::<uuid::Uuid, _>("id").unwrap_or_default(),
            "name":         r.try_get::<String, _>("name").unwrap_or_default(),
            "scope":        format!("{} / {}",
                r.try_get::<String, _>("scope_type").unwrap_or_default(),
                r.try_get::<Option<String>, _>("scope_value").unwrap_or_default().unwrap_or_default()
            ),
            "spend_usd":    format_usd(spend.to_f64().unwrap_or(0.0)),
            "limit_usd":    format_usd(limit.to_f64().unwrap_or(0.0)),
            "over_by_usd":  format_usd(over.to_f64().unwrap_or(0.0).max(0.0)),
            "policy":       r.try_get::<String, _>("breach_policy").unwrap_or_default(),
            "breached_at":  r.try_get::<Option<chrono::DateTime<Utc>>, _>("breach_at").unwrap_or_default(),
        })
    }).collect();

    // ── Open anomalies ────────────────────────────────────────────────────────
    let anom_rows = sqlx::query(
        "SELECT id, dimension_type, dimension_value,
                observed_spend, baseline_spend, multiplier, severity, created_at
         FROM ll_anomalies WHERE status = 'open'
         ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
                  created_at DESC LIMIT 5"
    ).fetch_all(pool).await.context("anomalies")?;

    let open_anomalies: Vec<Value> = anom_rows.iter().map(|r| {
        let obs = get_decimal(r, "observed_spend");
        let base = get_decimal(r, "baseline_spend");
        let mult = get_decimal(r, "multiplier");
        json!({
            "id":        r.try_get::<uuid::Uuid, _>("id").unwrap_or_default(),
            "dimension": format!("{}/{}",
                r.try_get::<String, _>("dimension_type").unwrap_or_default(),
                r.try_get::<Option<String>, _>("dimension_value").unwrap_or_default().unwrap_or_else(|| "global".into())
            ),
            "observed":  format_usd(obs.to_f64().unwrap_or(0.0)),
            "baseline":  format_usd(base.to_f64().unwrap_or(0.0)),
            "spike":     format!("{:.1}×", mult.to_f64().unwrap_or(0.0)),
            "severity":  r.try_get::<String, _>("severity").unwrap_or_default(),
            "detected":  r.try_get::<chrono::DateTime<Utc>, _>("created_at").unwrap_or_else(|_| Utc::now()),
        })
    }).collect();

    // ── Top 3 savings opportunities ───────────────────────────────────────────
    let rec_rows = sqlx::query(
        "SELECT title, monthly_savings_usd, rec_type, quality_impact
         FROM ll_recommendations WHERE status = 'open'
         ORDER BY monthly_savings_usd DESC LIMIT 3"
    ).fetch_all(pool).await.context("recs")?;

    let top_savings: Vec<Value> = rec_rows.iter().map(|r| {
        let savings = get_decimal(r, "monthly_savings_usd");
        json!({
            "title":          r.try_get::<String, _>("title").unwrap_or_default(),
            "saves_per_month":format_usd(savings.to_f64().unwrap_or(0.0)),
            "type":           r.try_get::<String, _>("rec_type").unwrap_or_default(),
            "quality_impact": r.try_get::<String, _>("quality_impact").unwrap_or_default(),
        })
    }).collect();

    let total_possible_savings: f64 = rec_rows.iter()
        .map(|r| get_decimal(r, "monthly_savings_usd").to_f64().unwrap_or(0.0))
        .sum();

    // ── Budget utilisation summary ────────────────────────────────────────────
    let budget_summary = sqlx::query(
        "SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE breached = TRUE) AS breached_count,
                COALESCE(SUM(limit_usd), 0) AS total_limit,
                COALESCE(SUM(current_spend), 0) AS total_spend
         FROM ll_budgets WHERE enabled = TRUE"
    ).fetch_one(pool).await.context("budget summary")?;

    let total_limit  = get_decimal(&budget_summary, "total_limit");
    let total_spend  = get_decimal(&budget_summary, "total_spend");
    let utilisation  = if total_limit.is_zero() { 0.0 } else {
        total_spend.to_f64().unwrap_or(0.0) / total_limit.to_f64().unwrap_or(1.0) * 100.0
    };

    // ── Status signal ─────────────────────────────────────────────────────────
    let signal = if !breached_budgets.is_empty() || open_anomalies.iter().any(|a| a["severity"] == "critical") {
        "🔴 ACTION REQUIRED"
    } else if !open_anomalies.is_empty() || utilisation > 80.0 {
        "🟡 WATCH"
    } else {
        "🟢 ON TRACK"
    };

    Ok(json!({
        "signal":   signal,
        "generated_at": now,

        "spend": {
            "mtd_usd":            format_usd(mtd_usd.to_f64().unwrap_or(0.0)),
            "mtd_calls":          mtd_calls,
            "mtd_tokens":         mtd_tokens,
            "daily_run_rate_usd": format_usd(daily_rate),
            "projected_month_end_usd": format_usd(projected_month_end),
            "burn_rate": {
                "last_1h_usd":  format_usd(h1_usd.to_f64().unwrap_or(0.0)),
                "last_24h_usd": format_usd(h24_usd.to_f64().unwrap_or(0.0)),
                "last_7d_usd":  format_usd(h7d_usd.to_f64().unwrap_or(0.0)),
                "trend":        trend,
            },
        },

        "model_mix": {
            "frontier_pct":  format!("{:.1}%", frontier_pct),
            "mid_tier_pct":  format!("{:.1}%", mid_tier_pct),
            "insight": if frontier_pct > 60.0 {
                format!("⚠ {:.0}% of spend on frontier models — rightsizing could save ~${:.0}/mo",
                    frontier_pct, projected_month_end * (frontier_pct / 100.0) * 0.78)
            } else {
                "Model mix looks healthy".into()
            },
        },

        "budgets": {
            "total_active":     budget_summary.try_get::<i64, _>("total").unwrap_or(0),
            "breached":         budget_summary.try_get::<i64, _>("breached_count").unwrap_or(0),
            "utilisation_pct":  format!("{:.1}%", utilisation),
            "total_limit_usd":  format_usd(total_limit.to_f64().unwrap_or(0.0)),
            "total_spend_usd":  format_usd(total_spend.to_f64().unwrap_or(0.0)),
            "breached_detail":  breached_budgets,
        },

        "anomalies": {
            "open_count": open_anomalies.len(),
            "detail":     open_anomalies,
        },

        "top_cost_centers": top_cost_centers,
        "top_agents":        top_agents,

        "savings": {
            "total_possible_per_month_usd": format_usd(total_possible_savings),
            "top_3": top_savings,
        },
    }))
}

// ── Realtime burn rate ────────────────────────────────────────────────────────

pub async fn realtime_burn(pool: &PgPool) -> Result<Value> {
    let now = Utc::now();

    let windows: &[(&str, i64)] = &[
        ("1h",  1),
        ("6h",  6),
        ("24h", 24),
        ("7d",  168),
    ];

    let mut rates: Vec<Value> = vec![];
    for (label, hours) in windows {
        let since  = now - Duration::hours(*hours);
        let spend  = spend_since(pool, since).await?;
        let prev   = spend_between(pool, now - Duration::hours(hours * 2), since).await?;
        let trend  = if spend > prev * Decimal::try_from(1.1f64).unwrap_or(Decimal::ONE) { "↑" }
                     else if spend < prev * Decimal::try_from(0.9f64).unwrap_or(Decimal::ONE) { "↓" }
                     else { "→" };
        let hourly_rate = spend.to_f64().unwrap_or(0.0) / (*hours as f64);

        rates.push(json!({
            "window":           label,
            "spend_usd":        format_usd(spend.to_f64().unwrap_or(0.0)),
            "hourly_rate_usd":  format_usd(hourly_rate),
            "daily_run_rate_usd": format_usd(hourly_rate * 24.0),
            "vs_prior_period":  trend,
        }));
    }

    // Per-model burn in last 24h
    let model_burn = sqlx::query(
        "SELECT model, SUM(cost_usd) AS s, COUNT(*) AS c
         FROM ll_usage_records WHERE called_at >= $1
         GROUP BY model ORDER BY s DESC LIMIT 10"
    ).bind(now - Duration::hours(24)).fetch_all(pool).await.context("model burn")?;

    let by_model: Vec<Value> = model_burn.iter().map(|r| {
        let s = get_decimal(r, "s");
        json!({
            "model":    r.try_get::<String, _>("model").unwrap_or_default(),
            "spend_usd":format_usd(s.to_f64().unwrap_or(0.0)),
            "calls":    r.try_get::<i64, _>("c").unwrap_or_default(),
            "cost_per_call_usd": format!("${:.4}",
                if r.try_get::<i64, _>("c").unwrap_or(0) == 0 { 0.0 }
                else { s.to_f64().unwrap_or(0.0) / r.try_get::<i64, _>("c").unwrap_or(1) as f64 }
            ),
        })
    }).collect();

    Ok(json!({
        "as_of": now,
        "windows": rates,
        "by_model_last_24h": by_model,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn spend_since(pool: &PgPool, since: chrono::DateTime<Utc>) -> Result<Decimal> {
    let row = sqlx::query("SELECT COALESCE(SUM(cost_usd),0) AS s FROM ll_usage_records WHERE called_at >= $1")
        .bind(since).fetch_one(pool).await?;
    Ok(get_decimal(&row, "s"))
}

async fn spend_between(pool: &PgPool, from: chrono::DateTime<Utc>, to: chrono::DateTime<Utc>) -> Result<Decimal> {
    let row = sqlx::query("SELECT COALESCE(SUM(cost_usd),0) AS s FROM ll_usage_records WHERE called_at BETWEEN $1 AND $2")
        .bind(from).bind(to).fetch_one(pool).await?;
    Ok(get_decimal(&row, "s"))
}

fn format_usd(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("${:.2}M", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("${:.2}K", v / 1_000.0)
    } else {
        format!("${:.4}", v)
    }
}

fn days_in_current_month(year: i32, month: u32) -> u32 {
    let next_month = if month == 12 {
        chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1)
    } else {
        chrono::NaiveDate::from_ymd_opt(year, month + 1, 1)
    };
    let first = chrono::NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    next_month.unwrap().signed_duration_since(first).num_days() as u32
}
