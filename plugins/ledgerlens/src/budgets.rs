//! Budget envelope management and enforcement engine.
//!
//! ConnectorOS provides billing/metering. LedgerLens adds *business-scoped*
//! budget envelopes with 4 enforcement policies:
//!   - alert_only    → notify channels, continue
//!   - downgrade     → write recommended model into Connector insights
//!   - hard_stop     → mark breached=true; routes check this before forwarding
//!   - cap_and_queue → same as hard_stop until period resets
//!
//! The enforcement sweeper (spawned in main.rs) runs every BUDGET_SWEEP_SECS.
//! It recalculates current_spend for each active budget, fires breach events,
//! and dispatches notifications.

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::alerts::{AlertDispatcher, AlertPayload};
use crate::db_decimal::{from_f64, get_decimal};
use crate::types::{Budget, BudgetEvent, CreateBudgetRequest};

// ── CRUD ──────────────────────────────────────────────────────────────────────

pub async fn create(pool: &PgPool, req: &CreateBudgetRequest) -> Result<Budget> {
    let (period_start, period_end) = period_bounds(req.period.as_deref().unwrap_or("monthly"));
    let row = sqlx::query(
        "INSERT INTO ll_budgets
            (name, scope_type, scope_value, period, limit_usd,
             breach_policy, downgrade_model,
             alert_emails, alert_webhooks, alert_pct,
             period_start, period_end)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         RETURNING *"
    )
    .bind(&req.name)
    .bind(&req.scope_type)
    .bind(&req.scope_value)
    .bind(req.period.as_deref().unwrap_or("monthly"))
    .bind(req.limit_usd)
    .bind(req.breach_policy.as_deref().unwrap_or("alert_only"))
    .bind(&req.downgrade_model)
    .bind(json!(req.alert_emails.clone().unwrap_or_default()))
    .bind(json!(req.alert_webhooks.clone().unwrap_or_default()))
    .bind(req.alert_pct.unwrap_or(80))
    .bind(period_start)
    .bind(period_end)
    .fetch_one(pool).await.context("create budget")?;

    row_to_budget(&row)
}

pub async fn get(pool: &PgPool, id: Uuid) -> Result<Budget> {
    let row = sqlx::query("SELECT * FROM ll_budgets WHERE id = $1")
        .bind(id).fetch_one(pool).await.context("get budget")?;
    row_to_budget(&row)
}

pub async fn list(pool: &PgPool, enabled_only: bool) -> Result<Vec<Budget>> {
    let sql = if enabled_only {
        "SELECT * FROM ll_budgets WHERE enabled = TRUE ORDER BY created_at DESC"
    } else {
        "SELECT * FROM ll_budgets ORDER BY created_at DESC"
    };
    let rows = sqlx::query(sql).fetch_all(pool).await.context("list budgets")?;
    rows.iter().map(|r| row_to_budget(r)).collect()
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE ll_budgets SET enabled = FALSE, updated_at = NOW() WHERE id = $1")
        .bind(id).execute(pool).await.context("disable budget")?;
    Ok(())
}

pub async fn events(pool: &PgPool, budget_id: Uuid, limit: i64) -> Result<Vec<BudgetEvent>> {
    let rows = sqlx::query(
        "SELECT * FROM ll_budget_events WHERE budget_id = $1 ORDER BY occurred_at DESC LIMIT $2"
    ).bind(budget_id).bind(limit).fetch_all(pool).await.context("budget events")?;
    rows.iter().map(|r| row_to_event(r)).collect()
}

// ── Enforcement sweeper ───────────────────────────────────────────────────────

/// Called by background sweeper task. Recalculates spend for all active budgets.
pub async fn enforcement_sweep(pool: &PgPool) -> Result<()> {
    let dispatcher = AlertDispatcher::new();
    let budgets = list(pool, true).await?;
    let now = Utc::now();

    for b in budgets {
        // Roll period if expired
        if now > b.period_end {
            let (ps, pe) = period_bounds(&b.period);
            sqlx::query(
                "UPDATE ll_budgets SET current_spend=0, breached=FALSE, breach_at=NULL,
                  period_start=$1, period_end=$2, updated_at=NOW() WHERE id=$3"
            ).bind(ps).bind(pe).bind(b.id).execute(pool).await.context("reset period")?;
            log_event(pool, b.id, "reset", Decimal::ZERO, b.limit_usd, 0.0, Some("period_reset"), json!({})).await?;
            continue;
        }

        // Recalculate spend from usage records within this period
        let spend_row = sqlx::query(
            &format!(
                "SELECT COALESCE(SUM(cost_usd),0) as s FROM ll_usage_records
                 WHERE called_at BETWEEN $1 AND $2 AND {}",
                scope_filter(&b.scope_type, &b.scope_value)
            )
        )
        .bind(b.period_start)
        .bind(b.period_end)
        .fetch_one(pool).await.context("spend calc")?;

        let spend: Decimal = get_decimal(&spend_row, "s");
        let limit           = b.limit_usd;
        let pct             = if limit.is_zero() { 0.0 } else {
            (spend / limit * Decimal::from(100)).to_string().parse::<f64>().unwrap_or(0.0)
        };

        sqlx::query("UPDATE ll_budgets SET current_spend=$1, updated_at=NOW() WHERE id=$2")
            .bind(rust_decimal::prelude::ToPrimitive::to_f64(&spend).unwrap_or(0.0))
            .bind(b.id).execute(pool).await.context("update spend")?;

        // Warn threshold
        let alert_pct = b.alert_pct as f64;
        if !b.breached && pct >= alert_pct && pct < 100.0 {
            log_event(pool, b.id, "warn", spend, limit, pct, None, json!({"pct": pct})).await?;
            let scope_w = b.scope_type.clone();
            metrics::counter!("ledgerlens_budget_warnings_total",
                "scope" => scope_w,
            ).increment(1);
            dispatcher.dispatch(pool, &AlertPayload {
                event_type: "budget_warn".into(),
                severity:   "medium".into(),
                title:      format!("Budget '{}' at {:.0}% — ${:.2} of ${:.2}",
                    b.name, pct,
                    rust_decimal::prelude::ToPrimitive::to_f64(&spend).unwrap_or(0.0),
                    rust_decimal::prelude::ToPrimitive::to_f64(&limit).unwrap_or(0.0)),
                body:       format!("Budget '{}' has reached {:.0}% utilisation this {}. Breach policy: {}.",
                    b.name, pct, b.period, b.breach_policy),
                detail:     json!({ "budget_id": b.id, "spend": spend, "limit": limit, "pct": pct }),
            }).await;
        }

        // Breach
        if !b.breached && spend >= limit {
            sqlx::query("UPDATE ll_budgets SET breached=TRUE, breach_at=NOW(), updated_at=NOW() WHERE id=$1")
                .bind(b.id).execute(pool).await.context("set breached")?;
            log_event(pool, b.id, "breach", spend, limit, pct, Some(&b.breach_policy), json!({"policy": &b.breach_policy})).await?;
            let scope_b  = b.scope_type.clone();
            let policy_b = b.breach_policy.clone();
            metrics::counter!("ledgerlens_budget_breaches_total",
                "scope"  => scope_b,
                "policy" => policy_b,
            ).increment(1);
            use rust_decimal::prelude::ToPrimitive;
            tracing::warn!(
                budget_id  = %b.id,
                name       = %b.name,
                spend_usd  = %spend,
                limit_usd  = %limit,
                policy     = %b.breach_policy,
                "Budget breached"
            );
            let severity = if b.breach_policy == "hard_stop" || b.breach_policy == "cap_and_queue" {
                "critical"
            } else { "high" };
            dispatcher.dispatch(pool, &AlertPayload {
                event_type: "budget_breach".into(),
                severity:   severity.into(),
                title:      format!("🚨 Budget BREACHED: '{}' — ${:.2} over limit",
                    b.name,
                    (spend - limit).to_f64().unwrap_or(0.0).max(0.0)),
                body:       format!(
                    "Budget '{}' has been BREACHED.\nSpent: ${:.4}  Limit: ${:.4}  Over by: ${:.4}\nPolicy: {}\nPeriod: {} → {}",
                    b.name,
                    spend.to_f64().unwrap_or(0.0),
                    limit.to_f64().unwrap_or(0.0),
                    (spend - limit).to_f64().unwrap_or(0.0).max(0.0),
                    b.breach_policy,
                    b.period_start.format("%Y-%m-%d"),
                    b.period_end.format("%Y-%m-%d"),
                ),
                detail: json!({
                    "budget_id": b.id, "name": b.name,
                    "spend": spend, "limit": limit,
                    "policy": b.breach_policy,
                }),
            }).await;
        }
    }
    Ok(())
}

/// Check if a specific scope + value is currently hard-stopped.
pub async fn is_hard_stopped(pool: &PgPool, scope_type: &str, scope_value: &str) -> bool {
    let row = sqlx::query(
        "SELECT 1 FROM ll_budgets
         WHERE scope_type = $1 AND scope_value = $2
           AND enabled = TRUE AND breached = TRUE
           AND breach_policy IN ('hard_stop','cap_and_queue')
         LIMIT 1"
    )
    .bind(scope_type).bind(scope_value)
    .fetch_optional(pool).await;
    row.ok().flatten().is_some()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn scope_filter(scope_type: &str, scope_value: &Option<String>) -> String {
    match (scope_type, scope_value) {
        ("feature",  Some(v)) => format!("tag_feature = '{}'",  v.replace('\'', "''")),
        ("bu",       Some(v)) => format!("tag_bu = '{}'",       v.replace('\'', "''")),
        ("customer", Some(v)) => format!("tag_customer = '{}'", v.replace('\'', "''")),
        ("workflow", Some(v)) => format!("tag_workflow = '{}'", v.replace('\'', "''")),
        ("agent",    Some(v)) => format!("agent_id = '{}'",     v.replace('\'', "''")),
        ("team",     Some(v)) => format!("tag_team = '{}'",     v.replace('\'', "''")),
        _                     => "1=1".into(),
    }
}

fn period_bounds(period: &str) -> (DateTime<Utc>, DateTime<Utc>) {
    let now = Utc::now();
    match period {
        "hourly"  => {
            let s = now.date_naive().and_hms_opt(now.hour(), 0, 0)
                .map(|dt| dt.and_utc()).unwrap_or(now);
            (s, s + Duration::hours(1))
        }
        "daily"   => {
            let s = now.date_naive().and_hms_opt(0,0,0)
                .map(|dt| dt.and_utc()).unwrap_or(now);
            (s, s + Duration::days(1))
        }
        "weekly"  => {
            let days = now.weekday().num_days_from_monday() as i64;
            let s = (now - Duration::days(days)).date_naive().and_hms_opt(0,0,0)
                .map(|dt| dt.and_utc()).unwrap_or(now);
            (s, s + Duration::weeks(1))
        }
        _         => {
            // monthly
            let s = chrono::NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
                .and_then(|d| d.and_hms_opt(0,0,0))
                .map(|dt| dt.and_utc())
                .unwrap_or(now);
            let e = if now.month() == 12 {
                chrono::NaiveDate::from_ymd_opt(now.year()+1, 1, 1)
            } else {
                chrono::NaiveDate::from_ymd_opt(now.year(), now.month()+1, 1)
            }
            .and_then(|d| d.and_hms_opt(0,0,0))
            .map(|dt| dt.and_utc())
            .unwrap_or(now);
            (s, e)
        }
    }
}

async fn log_event(
    pool: &PgPool, budget_id: Uuid,
    event_type: &str, spend: Decimal, limit: Decimal,
    pct: f64, policy: Option<&str>, detail: Value,
) -> Result<()> {
    use rust_decimal::prelude::ToPrimitive;
    sqlx::query(
        "INSERT INTO ll_budget_events (budget_id, event_type, spend_usd, limit_usd, pct_used, policy, detail)
         VALUES ($1,$2,$3,$4,$5,$6,$7)"
    )
    .bind(budget_id)
    .bind(event_type)
    .bind(spend.to_f64().unwrap_or(0.0))
    .bind(limit.to_f64().unwrap_or(0.0))
    .bind(pct)
    .bind(policy)
    .bind(&detail)
    .execute(pool).await.context("log budget event")?;
    Ok(())
}

// ── Row mappers ───────────────────────────────────────────────────────────────

fn row_to_budget(r: &sqlx::postgres::PgRow) -> Result<Budget> {
    Ok(Budget {
        id:              r.try_get("id")?,
        name:            r.try_get("name")?,
        scope_type:      r.try_get("scope_type")?,
        scope_value:     r.try_get("scope_value")?,
        period:          r.try_get("period")?,
        limit_usd:       get_decimal(r, "limit_usd"),
        breach_policy:   r.try_get("breach_policy")?,
        downgrade_model: r.try_get("downgrade_model")?,
        current_spend:   get_decimal(r, "current_spend"),
        period_start:    r.try_get("period_start")?,
        period_end:      r.try_get("period_end")?,
        breached:        r.try_get("breached")?,
        breach_at:       r.try_get("breach_at")?,
        alert_emails:    r.try_get("alert_emails")?,
        alert_webhooks:  r.try_get("alert_webhooks")?,
        alert_pct:       r.try_get("alert_pct")?,
        enabled:         r.try_get("enabled")?,
        created_at:      r.try_get("created_at")?,
        updated_at:      r.try_get("updated_at")?,
    })
}

fn row_to_event(r: &sqlx::postgres::PgRow) -> Result<BudgetEvent> {
    Ok(BudgetEvent {
        id:          r.try_get("id")?,
        budget_id:   r.try_get("budget_id")?,
        event_type:  r.try_get("event_type")?,
        spend_usd:   get_decimal(r, "spend_usd"),
        limit_usd:   get_decimal(r, "limit_usd"),
        pct_used:    get_decimal(r, "pct_used"),
        policy:      r.try_get("policy")?,
        detail:      r.try_get("detail")?,
        occurred_at: r.try_get("occurred_at")?,
    })
}

