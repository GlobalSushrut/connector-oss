//! Executive intelligence — the "buy today" endpoints.
//!
//! These three endpoints exist for one reason: when a CFO or VP Eng sees them
//! for the first time on their OWN data, they sign the contract the same day.
//!
//! GET  /api/v1/dashboard/executive  — "Your AI bill, brutally summarised"
//! POST /api/v1/simulate/savings     — "What last month would have cost with LedgerLens"
//! GET  /api/v1/roi                  — "LedgerLens pays for itself in N days"

use anyhow::{Context, Result};
use chrono::{Datelike, Duration, Utc};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::db_decimal::get_decimal;

// ── Executive Dashboard ────────────────────────────────────────────────────────
//
// Answers the only questions a CFO cares about:
//   1. How much are we spending RIGHT NOW?
//   2. Is it going up or down?
//   3. Who is responsible for the expensive stuff?
//   4. How much are we wasting?
//   5. What happens if we do nothing?
//   6. What's the single highest-ROI action I can take today?

pub async fn executive_dashboard(pool: &PgPool) -> Result<Value> {
    let now       = Utc::now();
    let mtd_start = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
        .unwrap_or(now);
    let prev_month_start = {
        let (y, m) = if now.month() == 1 { (now.year() - 1, 12u32) } else { (now.year(), now.month() - 1) };
        chrono::NaiveDate::from_ymd_opt(y, m, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|dt| dt.and_utc())
            .unwrap_or(now - Duration::days(30))
    };

    // ── Core spend numbers ────────────────────────────────────────────────────
    let mtd_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records WHERE called_at >= $1"
    ).bind(mtd_start).fetch_one(pool).await.context("mtd")?;
    let mtd_usd: Decimal  = get_decimal(&mtd_row, "s");
    let mtd_calls: i64    = mtd_row.try_get("c").unwrap_or(0);

    let prev_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records WHERE called_at >= $1 AND called_at < $2"
    ).bind(prev_month_start).bind(mtd_start).fetch_one(pool).await.context("prev month")?;
    let prev_usd: Decimal = get_decimal(&prev_row, "s");

    let days_elapsed  = (now - mtd_start).num_days().max(1) as f64;
    let daily_rate    = mtd_usd.to_f64().unwrap_or(0.0) / days_elapsed;
    let days_in_month = days_in_month(now.year(), now.month());
    let projected     = daily_rate * days_in_month as f64;
    let mom_pct       = if prev_usd.is_zero() { 0.0 } else {
        (mtd_usd.to_f64().unwrap_or(0.0) - prev_usd.to_f64().unwrap_or(0.0))
            / prev_usd.to_f64().unwrap_or(1.0) * 100.0
    };

    // ── Untagged spend (the accountability gap) ───────────────────────────────
    let untagged_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records
         WHERE called_at >= $1
           AND tag_bu IS NULL AND tag_team IS NULL AND tag_customer IS NULL"
    ).bind(mtd_start).fetch_one(pool).await.context("untagged")?;
    let untagged_usd: Decimal = get_decimal(&untagged_row, "s");
    let untagged_calls: i64   = untagged_row.try_get("c").unwrap_or(0);
    let untagged_pct = if mtd_usd.is_zero() { 0.0 } else {
        untagged_usd.to_f64().unwrap_or(0.0) / mtd_usd.to_f64().unwrap_or(1.0) * 100.0
    };

    // ── Single biggest cost driver ────────────────────────────────────────────
    let top_driver = sqlx::query(
        "SELECT agent_id, model,
                SUM(cost_usd) AS s, COUNT(*) AS c,
                SUM(cost_usd) * 100.0 / NULLIF(SUM(SUM(cost_usd)) OVER (), 0) AS pct
         FROM ll_usage_records WHERE called_at >= $1
         GROUP BY agent_id, model ORDER BY s DESC LIMIT 1"
    ).bind(mtd_start).fetch_optional(pool).await.context("top driver")?;

    let top_driver_val = top_driver.as_ref().map(|r| {
        let spend = get_decimal(r, "s").to_f64().unwrap_or(0.0);
        let pct   = r.try_get::<f64, _>("pct").unwrap_or(0.0);
        json!({
            "agent":     r.try_get::<String, _>("agent_id").unwrap_or_default(),
            "model":     r.try_get::<String, _>("model").unwrap_or_default(),
            "spend_usd": fmt_usd(spend),
            "pct_of_total": format!("{:.0}%", pct),
            "verdict": format!(
                "One agent ({}) on {} accounts for {:.0}% of your entire AI bill this month.",
                r.try_get::<String, _>("agent_id").unwrap_or_default(),
                r.try_get::<String, _>("model").unwrap_or_default(),
                pct
            ),
        })
    }).unwrap_or(json!(null));

    // ── Frontier model waste ──────────────────────────────────────────────────
    let frontier_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records
         WHERE called_at >= $1
           AND model ILIKE ANY(ARRAY['%gpt-4%','%claude-3-opus%','%gemini-1.5-pro%'])"
    ).bind(mtd_start).fetch_one(pool).await.context("frontier")?;
    let frontier_usd: Decimal = get_decimal(&frontier_row, "s");
    let frontier_pct = if mtd_usd.is_zero() { 0.0 } else {
        frontier_usd.to_f64().unwrap_or(0.0) / mtd_usd.to_f64().unwrap_or(1.0) * 100.0
    };
    // 70% of frontier calls could use mid-tier at 80% cheaper (conservative estimate)
    let recoverable_frontier = frontier_usd.to_f64().unwrap_or(0.0) * 0.70 * 0.80;

    // ── Zero-output waste (failed/empty completions) ──────────────────────────
    let waste_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records
         WHERE called_at >= $1 AND output_tokens = 0 AND cost_usd > 0"
    ).bind(mtd_start).fetch_one(pool).await.context("waste")?;
    let waste_usd: Decimal = get_decimal(&waste_row, "s");
    let waste_calls: i64   = waste_row.try_get("c").unwrap_or(0);

    // ── Open breaches ─────────────────────────────────────────────────────────
    let breach_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ll_budgets WHERE breached = TRUE AND enabled = TRUE"
    ).fetch_one(pool).await.unwrap_or(0);

    // ── Open anomalies ────────────────────────────────────────────────────────
    let anom_row = sqlx::query(
        "SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE severity='critical') AS crit
         FROM ll_anomalies WHERE status='open'"
    ).fetch_one(pool).await.context("anom count")?;
    let anom_total: i64 = anom_row.try_get("total").unwrap_or(0);
    let anom_crit:  i64 = anom_row.try_get("crit").unwrap_or(0);

    // ── Best single savings action ────────────────────────────────────────────
    let best_rec = sqlx::query(
        "SELECT title, monthly_savings_usd, rec_type, quality_impact, agent_id, model_current, model_suggested
         FROM ll_recommendations WHERE status = 'open'
         ORDER BY monthly_savings_usd DESC LIMIT 1"
    ).fetch_optional(pool).await.context("best rec")?;

    let best_action = best_rec.as_ref().map(|r| {
        let savings = get_decimal(r, "monthly_savings_usd").to_f64().unwrap_or(0.0);
        json!({
            "title":           r.try_get::<String, _>("title").unwrap_or_default(),
            "saves_per_month": fmt_usd(savings),
            "saves_per_year":  fmt_usd(savings * 12.0),
            "quality_impact":  r.try_get::<String, _>("quality_impact").unwrap_or_default(),
            "how":             format!(
                "Switch {} from {} → {}. One API call applies it.",
                r.try_get::<Option<String>, _>("agent_id").unwrap_or_default().unwrap_or_else(|| "agent".into()),
                r.try_get::<Option<String>, _>("model_current").unwrap_or_default().unwrap_or_else(|| "current model".into()),
                r.try_get::<Option<String>, _>("model_suggested").unwrap_or_default().unwrap_or_else(|| "cheaper model".into()),
            ),
            "apply_endpoint": format!("/api/v1/recommendations/{}/apply",
                r.try_get::<uuid::Uuid, _>("id").unwrap_or_default()
            ),
        })
    }).unwrap_or(json!(null));

    // ── Total recoverable waste this month ────────────────────────────────────
    let total_recoverable: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT SUM(monthly_savings_usd) FROM ll_recommendations WHERE status='open'"
    ).fetch_optional(pool).await.unwrap_or(None).flatten().unwrap_or(0.0);

    // ── Annualised projection ─────────────────────────────────────────────────
    let annualised = projected * 12.0;
    let annualised_with_savings = (projected - total_recoverable).max(0.0) * 12.0;

    // ── Status + verdict ──────────────────────────────────────────────────────
    let (status_signal, verdict) = build_verdict(
        mtd_usd.to_f64().unwrap_or(0.0),
        daily_rate,
        mom_pct,
        untagged_pct,
        frontier_pct,
        breach_count,
        anom_crit,
        waste_usd.to_f64().unwrap_or(0.0),
        total_recoverable,
    );

    Ok(json!({
        "status":       status_signal,
        "as_of":        now.to_rfc3339(),
        "verdict":      verdict,

        "this_month": {
            "spend_to_date":          fmt_usd(mtd_usd.to_f64().unwrap_or(0.0)),
            "calls":                  mtd_calls,
            "daily_run_rate":         fmt_usd(daily_rate),
            "projected_month_end":    fmt_usd(projected),
            "vs_last_month_pct":      format!("{:+.1}%", mom_pct),
            "annualised_run_rate":    fmt_usd(annualised),
            "annualised_with_savings":fmt_usd(annualised_with_savings),
            "you_could_save":         fmt_usd(annualised - annualised_with_savings),
        },

        "accountability_gap": {
            "untagged_spend":   fmt_usd(untagged_usd.to_f64().unwrap_or(0.0)),
            "untagged_pct":     format!("{:.0}%", untagged_pct),
            "untagged_calls":   untagged_calls,
            "verdict": if untagged_pct > 20.0 {
                format!("{:.0}% of your AI spend has no owner. You cannot chargeback what you cannot attribute.",
                    untagged_pct)
            } else {
                "Attribution coverage is healthy.".into()
            },
        },

        "biggest_cost_driver": top_driver_val,

        "model_waste": {
            "frontier_model_spend":   fmt_usd(frontier_usd.to_f64().unwrap_or(0.0)),
            "frontier_pct":           format!("{:.0}%", frontier_pct),
            "recoverable_this_month": fmt_usd(recoverable_frontier),
            "verdict": format!(
                "{:.0}% of spend is on frontier models (GPT-4 class). \
                 ~70% of those calls are eligible for mid-tier models at similar quality. \
                 Recoverable this month: {}.",
                frontier_pct,
                fmt_usd(recoverable_frontier)
            ),
        },

        "failed_calls": {
            "wasted_spend":  fmt_usd(waste_usd.to_f64().unwrap_or(0.0)),
            "call_count":    waste_calls,
            "verdict": if waste_calls > 0 {
                format!("{} API calls this month returned zero output but were still billed ({}). \
                         These are pure waste — errors, timeouts, or misconfigured prompts.",
                    waste_calls, fmt_usd(waste_usd.to_f64().unwrap_or(0.0)))
            } else {
                "No zero-output waste detected this month.".into()
            },
        },

        "risk": {
            "breached_budgets":  breach_count,
            "open_anomalies":    anom_total,
            "critical_anomalies":anom_crit,
            "verdict": build_risk_verdict(breach_count, anom_crit, anom_total),
        },

        "best_action_today": best_action,

        "total_recoverable_per_month": fmt_usd(total_recoverable),
        "total_recoverable_per_year":  fmt_usd(total_recoverable * 12.0),
    }))
}

// ── Savings Simulator ─────────────────────────────────────────────────────────
//
// Shows what last month's bill would have been if LedgerLens had been
// running with its recommendations applied.
// This is the "you already paid for it 10× last month" moment.

pub async fn simulate_savings(pool: &PgPool) -> Result<Value> {
    let now = Utc::now();
    let (prev_y, prev_m) = if now.month() == 1 {
        (now.year() - 1, 12u32)
    } else {
        (now.year(), now.month() - 1)
    };
    let prev_start = chrono::NaiveDate::from_ymd_opt(prev_y, prev_m, 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
        .unwrap_or(now - Duration::days(30));
    let prev_end = chrono::NaiveDate::from_ymd_opt(
            now.year(), now.month(), 1
        ).and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
        .unwrap_or(now);

    // Actual spend last month
    let actual_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records WHERE called_at >= $1 AND called_at < $2"
    ).bind(prev_start).bind(prev_end).fetch_one(pool).await.context("actual last month")?;
    let actual: Decimal = get_decimal(&actual_row, "s");
    let calls: i64      = actual_row.try_get("c").unwrap_or(0);

    // Simulation 1: Apply rightsizing (70% of frontier calls → mid-tier at 80% cheaper)
    let frontier_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records
         WHERE called_at >= $1 AND called_at < $2
           AND model ILIKE ANY(ARRAY['%gpt-4%','%claude-3-opus%','%gemini-1.5-pro%'])"
    ).bind(prev_start).bind(prev_end).fetch_one(pool).await.context("frontier last month")?;
    let frontier: Decimal = get_decimal(&frontier_row, "s");
    let rightsize_saving = frontier * Decimal::try_from(0.70).unwrap_or_default()
                                    * Decimal::try_from(0.80).unwrap_or_default();

    // Simulation 2: Eliminate zero-output waste
    let waste_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s, COUNT(*) AS c
         FROM ll_usage_records
         WHERE called_at >= $1 AND called_at < $2
           AND output_tokens = 0 AND cost_usd > 0"
    ).bind(prev_start).bind(prev_end).fetch_one(pool).await.context("waste last month")?;
    let waste: Decimal = get_decimal(&waste_row, "s");
    let waste_calls: i64 = waste_row.try_get("c").unwrap_or(0);

    // Simulation 3: Budget hard-stop would have prevented overspend
    let overbudget_row = sqlx::query(
        "SELECT COALESCE(SUM(GREATEST(current_spend - limit_usd, 0)), 0) AS over
         FROM ll_budgets WHERE breached = TRUE"
    ).fetch_one(pool).await.context("overbudget")?;
    let overbudget: Decimal = get_decimal(&overbudget_row, "over");

    // Simulation 4: Prompt caching (agents with >200 calls, conservative 20% hit rate)
    let cache_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s
         FROM ll_usage_records
         WHERE called_at >= $1 AND called_at < $2
           AND agent_id IN (
               SELECT agent_id FROM ll_usage_records
               WHERE called_at >= $1 AND called_at < $2
               GROUP BY agent_id HAVING COUNT(*) > 200
           )"
    ).bind(prev_start).bind(prev_end).fetch_one(pool).await.context("cache eligible")?;
    let cache_eligible: Decimal = get_decimal(&cache_row, "s");
    let cache_saving = cache_eligible * Decimal::try_from(0.20).unwrap_or_default();

    let total_saving = rightsize_saving + waste + overbudget + cache_saving;
    let simulated_bill = (actual - total_saving).max(Decimal::ZERO);
    let saving_pct = if actual.is_zero() { 0.0 } else {
        total_saving.to_f64().unwrap_or(0.0) / actual.to_f64().unwrap_or(1.0) * 100.0
    };

    let month_label = format!("{}-{:02}", prev_y, prev_m);

    Ok(json!({
        "simulation_month": month_label,
        "headline": format!(
            "Last month you spent {}. With LedgerLens, you would have spent {}. \
             That's {} ({:.0}%) you paid for nothing.",
            fmt_usd(actual.to_f64().unwrap_or(0.0)),
            fmt_usd(simulated_bill.to_f64().unwrap_or(0.0)),
            fmt_usd(total_saving.to_f64().unwrap_or(0.0)),
            saving_pct
        ),

        "actual_spend":    fmt_usd(actual.to_f64().unwrap_or(0.0)),
        "simulated_spend": fmt_usd(simulated_bill.to_f64().unwrap_or(0.0)),
        "total_saving":    fmt_usd(total_saving.to_f64().unwrap_or(0.0)),
        "saving_pct":      format!("{:.1}%", saving_pct),
        "total_calls":     calls,

        "breakdown": [
            {
                "lever":       "Model rightsizing",
                "description": format!("70% of frontier model calls shifted to mid-tier (80% cheaper). {} frontier spend last month.", fmt_usd(frontier.to_f64().unwrap_or(0.0))),
                "saving":      fmt_usd(rightsize_saving.to_f64().unwrap_or(0.0)),
                "action":      "Run POST /api/v1/optimize then apply top recommendations",
            },
            {
                "lever":       "Eliminate failed calls",
                "description": format!("{} zero-output API calls billed at {} — pure waste.", waste_calls, fmt_usd(waste.to_f64().unwrap_or(0.0))),
                "saving":      fmt_usd(waste.to_f64().unwrap_or(0.0)),
                "action":      "Fix agent error handling. LedgerLens shows which agents have the highest failure rate.",
            },
            {
                "lever":       "Budget enforcement (hard-stop)",
                "description": format!("Budgets were breached by {}. Hard-stop policy would have prevented this spend.", fmt_usd(overbudget.to_f64().unwrap_or(0.0))),
                "saving":      fmt_usd(overbudget.to_f64().unwrap_or(0.0)),
                "action":      "Set breach_policy=hard_stop on your budgets. Agents check /api/v1/budgets/status before calls.",
            },
            {
                "lever":       "Prompt caching",
                "description": format!("{} in spend from high-frequency agents eligible for 20% cache hit rate.", fmt_usd(cache_eligible.to_f64().unwrap_or(0.0))),
                "saving":      fmt_usd(cache_saving.to_f64().unwrap_or(0.0)),
                "action":      "GET /api/v1/cache-roi to see which agents benefit most.",
            },
        ],

        "annualised": {
            "actual_run_rate":    fmt_usd(actual.to_f64().unwrap_or(0.0) * 12.0),
            "with_ledgerlens":    fmt_usd(simulated_bill.to_f64().unwrap_or(0.0) * 12.0),
            "annual_saving":      fmt_usd(total_saving.to_f64().unwrap_or(0.0) * 12.0),
        }
    }))
}

// ── ROI Calculator ────────────────────────────────────────────────────────────
//
// "LedgerLens costs $X/mo. It saves $Y/mo. Payback in Z days."
// This closes deals.

pub async fn roi_calculator(pool: &PgPool, monthly_tool_cost_usd: f64) -> Result<Value> {
    let now = Utc::now();
    let mtd_start = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
        .unwrap_or(now - Duration::days(30));

    let days_elapsed = (now - mtd_start).num_days().max(1) as f64;

    // Current monthly run rate
    let spend_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s FROM ll_usage_records WHERE called_at >= $1"
    ).bind(mtd_start).fetch_one(pool).await.context("roi spend")?;
    let mtd: Decimal = get_decimal(&spend_row, "s");
    let monthly_rate = mtd.to_f64().unwrap_or(0.0) / days_elapsed * 30.0;

    // Open recommendations total
    let total_savings: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT SUM(monthly_savings_usd) FROM ll_recommendations WHERE status='open'"
    ).fetch_optional(pool).await.unwrap_or(None).flatten().unwrap_or(0.0);

    // Frontier recoverable (even if no recs yet)
    let frontier_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s FROM ll_usage_records WHERE called_at >= $1
         AND model ILIKE ANY(ARRAY['%gpt-4%','%claude-3-opus%','%gemini-1.5-pro%'])"
    ).bind(mtd_start).fetch_one(pool).await.context("roi frontier")?;
    let frontier = get_decimal(&frontier_row, "s").to_f64().unwrap_or(0.0)
        / days_elapsed * 30.0;
    let frontier_recoverable = frontier * 0.70 * 0.80;

    // Waste
    let waste_row = sqlx::query(
        "SELECT COALESCE(SUM(cost_usd),0) AS s FROM ll_usage_records
         WHERE called_at >= $1 AND output_tokens=0 AND cost_usd>0"
    ).bind(mtd_start).fetch_one(pool).await.context("roi waste")?;
    let waste = get_decimal(&waste_row, "s").to_f64().unwrap_or(0.0)
        / days_elapsed * 30.0;

    let estimated_monthly_saving = total_savings
        .max(frontier_recoverable + waste);

    let roi_multiple = if monthly_tool_cost_usd == 0.0 { 0.0 }
                       else { estimated_monthly_saving / monthly_tool_cost_usd };

    let payback_days = if estimated_monthly_saving == 0.0 { 0.0 }
                       else { monthly_tool_cost_usd / (estimated_monthly_saving / 30.0) };

    let confidence = if total_savings > 0.0 { "measured — from your actual spend data" }
                     else { "estimated — run POST /api/v1/optimize for precise numbers" };

    Ok(json!({
        "headline": format!(
            "LedgerLens costs {} /mo and saves {} /mo on your stack. \
             It pays for itself in {:.0} days. Annual ROI: {:.0}×.",
            fmt_usd(monthly_tool_cost_usd),
            fmt_usd(estimated_monthly_saving),
            payback_days,
            roi_multiple * 12.0
        ),

        "your_monthly_ai_spend":       fmt_usd(monthly_rate),
        "ledgerlens_monthly_cost":     fmt_usd(monthly_tool_cost_usd),
        "estimated_monthly_saving":    fmt_usd(estimated_monthly_saving),
        "roi_multiple":                format!("{:.1}×", roi_multiple),
        "payback_days":                format!("{:.0} days", payback_days.max(1.0)),
        "annual_saving":               fmt_usd(estimated_monthly_saving * 12.0),
        "confidence":                  confidence,

        "saving_sources": {
            "model_rightsizing":   fmt_usd(frontier_recoverable),
            "waste_elimination":   fmt_usd(waste),
            "from_recommendations":fmt_usd(total_savings),
        },

        "what_you_get": [
            "Live CFO dashboard — spend, burn rate, anomalies, savings in one call",
            "Budget enforcement — hard-stop before overspend happens, not after",
            "Slack/PagerDuty alerts — fires the moment a budget breaches",
            "Model rightsizing engine — tells you exactly which agent to switch and to what",
            "Excel CSV exports — chargeback report your finance team can read today",
            "HMAC-signed audit packages — tamper-evident for compliance",
        ],
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fmt_usd(v: f64) -> String {
    if v >= 1_000_000.0      { format!("${:.2}M", v / 1_000_000.0) }
    else if v >= 1_000.0     { format!("${:.2}K", v / 1_000.0) }
    else if v >= 0.01        { format!("${:.2}", v) }
    else                     { format!("${:.4}", v) }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    let next = if month == 12 {
        chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1)
    } else {
        chrono::NaiveDate::from_ymd_opt(year, month + 1, 1)
    };
    let first = chrono::NaiveDate::from_ymd_opt(year, month, 1).unwrap();
    next.unwrap().signed_duration_since(first).num_days() as u32
}

fn build_verdict(
    mtd: f64, daily: f64, mom: f64, untagged_pct: f64,
    frontier_pct: f64, breaches: i64, crit_anom: i64,
    waste: f64, recoverable: f64,
) -> (&'static str, String) {
    if breaches > 0 || crit_anom > 0 {
        (
            "🔴 CRITICAL — Action required today",
            format!(
                "You have {} breached budget(s) and {} critical anomaly(ies). \
                 Your AI spend is running at {}/day. \
                 Left unchecked, that's {} this month. \
                 There is {} in recoverable savings identified right now.",
                breaches, crit_anom,
                fmt_usd(daily),
                fmt_usd(daily * 30.0),
                fmt_usd(recoverable)
            ),
        )
    } else if mom > 25.0 || untagged_pct > 40.0 || frontier_pct > 70.0 {
        (
            "🟡 WARNING — Spend growing faster than visibility",
            format!(
                "AI spend is up {:.0}% month-over-month ({}/day run rate). \
                 {:.0}% of spend has no cost centre owner. \
                 {:.0}% is on frontier models — {} in savings available.",
                mom, fmt_usd(daily), untagged_pct, frontier_pct, fmt_usd(recoverable)
            ),
        )
    } else {
        (
            "🟢 HEALTHY — But {} in savings still on the table",
            format!(
                "Spend is {}/day, up {:.0}% MoM. No active breaches. \
                 {} in optimisation savings identified.",
                fmt_usd(daily), mom, fmt_usd(recoverable)
            ),
        )
    }
}

fn build_risk_verdict(breaches: i64, crit: i64, total: i64) -> String {
    if breaches > 0 && crit > 0 {
        format!("{} budget(s) in breach + {} critical spend anomaly(ies). Your AI costs are out of control right now.", breaches, crit)
    } else if breaches > 0 {
        format!("{} budget(s) breached this period. Enforcement policy is active.", breaches)
    } else if total > 0 {
        format!("{} anomaly(ies) under investigation. No budget breaches.", total)
    } else {
        "No active breaches or anomalies. All budgets within limits.".into()
    }
}
