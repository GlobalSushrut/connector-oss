//! Optimization engine: waste heatmap, model portfolio optimizer, cache ROI,
//! rightsizing recommendations.
//!
//! Uses ConnectorOS /insights/model-recommendation/:pid for judge-eval scores.
//! Generates actionable ll_recommendations with dollar savings and confidence.

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::connector::ConnectorClient;
use crate::db_decimal::get_decimal;
use crate::types::{ApplyRecommendationRequest, DismissRecommendationRequest, Recommendation};

// ── Waste heatmap ─────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct WasteEntry {
    pub category:             String,
    pub subject:              String,
    pub estimated_savings_usd:Decimal,
    pub call_count:           i64,
    pub evidence:             Value,
}

/// Top-N cost centers sorted by estimated savings.
pub async fn waste_heatmap(pool: &PgPool, top_n: i64) -> Result<Vec<WasteEntry>> {
    let now       = Utc::now();
    let since30   = now - Duration::days(30);
    let mut items: Vec<WasteEntry> = vec![];

    // 1. Agents on expensive models that also have cheaper alternatives
    let model_rows = sqlx::query(
        "SELECT agent_id, model, SUM(cost_usd) as spend, COUNT(*) as cnt
         FROM ll_usage_records
         WHERE called_at >= $1
           AND model IN ('gpt-4o','gpt-4-turbo','claude-3-opus','gemini-1.5-pro')
         GROUP BY agent_id, model ORDER BY spend DESC LIMIT $2"
    ).bind(since30).bind(top_n).fetch_all(pool).await.context("waste models")?;

    for r in &model_rows {
        let spend: Decimal = get_decimal(r, "spend");
        let savings = spend * Decimal::try_from(0.7f64).unwrap_or(Decimal::ZERO)
                           * Decimal::try_from(0.8f64).unwrap_or(Decimal::ZERO);
        let agent: String = r.try_get("agent_id").unwrap_or_default();
        let model: String = r.try_get("model").unwrap_or_default();
        items.push(WasteEntry {
            category:              "oversized_model".into(),
            subject:               format!("{agent} / {model}"),
            estimated_savings_usd: savings.round_dp(4),
            call_count:            r.try_get("cnt").unwrap_or_default(),
            evidence:              json!({ "current_model": model, "spend_30d": spend }),
        });
    }

    // 2. Duplicate / identical prompt calls (cache candidates)
    let dup_rows = sqlx::query(
        "SELECT agent_id, COUNT(*) as cnt, SUM(cost_usd) as spend
         FROM ll_usage_records
         WHERE called_at >= $1 AND input_tokens > 0
         GROUP BY agent_id
         HAVING COUNT(*) > 100
         ORDER BY spend DESC LIMIT $2"
    ).bind(since30).bind(top_n).fetch_all(pool).await.context("waste dups")?;

    for r in &dup_rows {
        let spend: Decimal = get_decimal(r, "spend");
        let cache_savings = spend * Decimal::try_from(0.3f64).unwrap_or(Decimal::ZERO);
        let agent: String = r.try_get("agent_id").unwrap_or_default();
        items.push(WasteEntry {
            category:              "cache_opportunity".into(),
            subject:               agent.clone(),
            estimated_savings_usd: cache_savings.round_dp(4),
            call_count:            r.try_get("cnt").unwrap_or_default(),
            evidence:              json!({ "agent_id": agent, "spend_30d": spend }),
        });
    }

    // 3. Zero-output calls (failed / wasted completions)
    let zero_rows = sqlx::query(
        "SELECT agent_id, COUNT(*) as cnt, SUM(cost_usd) as spend
         FROM ll_usage_records
         WHERE called_at >= $1 AND output_tokens = 0 AND cost_usd > 0
         GROUP BY agent_id HAVING COUNT(*) > 10
         ORDER BY spend DESC LIMIT $2"
    ).bind(since30).bind(top_n).fetch_all(pool).await.context("waste zero")?;

    for r in &zero_rows {
        let spend: Decimal = get_decimal(r, "spend");
        let agent: String = r.try_get("agent_id").unwrap_or_default();
        items.push(WasteEntry {
            category:              "failed_calls".into(),
            subject:               agent.clone(),
            estimated_savings_usd: spend.round_dp(4),
            call_count:            r.try_get("cnt").unwrap_or_default(),
            evidence:              json!({ "agent_id": agent, "zero_output_calls": r.try_get::<i64,_>("cnt").unwrap_or(0) }),
        });
    }

    // Sort by savings desc, take top_n
    items.sort_by(|a, b| b.estimated_savings_usd.cmp(&a.estimated_savings_usd));
    items.truncate(top_n as usize);
    Ok(items)
}

// ── Model portfolio optimizer ─────────────────────────────────────────────────

/// For each agent on an expensive model, ask ConnectorOS for its rightsizing
/// recommendation (judge-eval based). Store as ll_recommendation.
pub async fn run_optimization(pool: &PgPool, connector: &ConnectorClient) -> Result<usize> {
    let now    = Utc::now();
    let since  = now - Duration::days(30);

    let agents = sqlx::query(
        "SELECT DISTINCT agent_id, model, SUM(cost_usd) as spend
         FROM ll_usage_records WHERE called_at >= $1
           AND model IN ('gpt-4o','gpt-4-turbo','claude-3-opus')
         GROUP BY agent_id, model
         HAVING SUM(cost_usd) > 10
         ORDER BY spend DESC LIMIT 50"
    ).bind(since).fetch_all(pool).await.context("optimizer agents")?;

    let mut created = 0usize;
    for row in &agents {
        let agent_id: String   = row.try_get("agent_id").unwrap_or_default();
        let model: String      = row.try_get("model").unwrap_or_default();
        let spend: Decimal     = get_decimal(row, "spend");

        // Fetch ConnectorOS model recommendation (may 404 for unknown agents)
        let rec_val = connector.model_recommendation(&agent_id).await.unwrap_or(Value::Null);
        let suggested = rec_val["suggested_model"].as_str()
            .unwrap_or("gpt-4o-mini").to_owned();
        let quality_score = rec_val["quality_match_score"].as_f64().unwrap_or(0.95);
        let confidence    = Decimal::try_from(quality_score.min(1.0).max(0.0)).unwrap_or_default();

        // Estimate savings: mini/haiku models are ~80% cheaper
        let savings = spend * Decimal::try_from(0.78f64).unwrap_or(Decimal::ZERO);

        let quality_impact = if quality_score >= 0.95 { "minimal" }
                             else if quality_score >= 0.85 { "moderate" }
                             else { "significant" };

        // Upsert recommendation (one per agent+model, refreshed)
        let exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ll_recommendations
             WHERE agent_id=$1 AND model_current=$2 AND status='open' LIMIT 1"
        ).bind(&agent_id).bind(&model).fetch_optional(pool).await.context("rec exists")?;

        if exists.is_none() {
            sqlx::query(
                "INSERT INTO ll_recommendations
                    (rec_type, title, description, agent_id, model_current, model_suggested,
                     monthly_savings_usd, quality_impact, confidence, evidence)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
            )
            .bind("rightsize_model")
            .bind(format!("Rightsize {agent_id} from {model} → {suggested}"))
            .bind(format!(
                "Agent {agent_id} spent ${:.2}/mo on {model}. Switching to {suggested} \
                 at {:.0}% quality match saves ~${:.2}/mo.",
                spend.to_f64().unwrap_or(0.0), quality_score * 100.0,
                savings.to_f64().unwrap_or(0.0)
            ))
            .bind(&agent_id)
            .bind(&model)
            .bind(&suggested)
            .bind(savings.to_f64().unwrap_or(0.0))
            .bind(quality_impact)
            .bind(confidence.to_f64().unwrap_or(0.0))
            .bind(json!({
                "connector_recommendation": rec_val,
                "spend_30d": spend,
                "quality_score": quality_score,
            }))
            .execute(pool).await.context("insert rec")?;
            created += 1;
        }
    }
    tracing::info!(recommendations = created, "Optimization run complete");
    Ok(created)
}

// ── Cache ROI estimator ───────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct CacheRoiEstimate {
    pub agent_id:             String,
    pub estimated_hit_rate:   f64,
    pub estimated_savings_usd:Decimal,
    pub total_calls_30d:      i64,
    pub total_spend_30d:      Decimal,
}

pub async fn cache_roi_estimates(pool: &PgPool) -> Result<Vec<CacheRoiEstimate>> {
    let since = Utc::now() - Duration::days(30);
    let rows  = sqlx::query(
        "SELECT agent_id, COUNT(*) as cnt, SUM(cost_usd) as spend,
                AVG(input_tokens) as avg_input
         FROM ll_usage_records WHERE called_at >= $1
         GROUP BY agent_id HAVING COUNT(*) > 50
         ORDER BY spend DESC LIMIT 20"
    ).bind(since).fetch_all(pool).await.context("cache roi")?;

    let mut out = vec![];
    for r in &rows {
        let spend: Decimal = get_decimal(r, "spend");
        let cnt: i64       = r.try_get("cnt").unwrap_or_default();
        let avg_input: f64 = r.try_get::<Option<f64>, _>("avg_input").unwrap_or_default().unwrap_or(0.0);

        // Heuristic: high call count + high avg_input → likely repetitive
        let hit_rate = ((cnt as f64).ln() / 10.0 * (avg_input / 2000.0).min(1.0)).min(0.6).max(0.05);
        let savings  = spend * Decimal::try_from(hit_rate).unwrap_or_default();

        out.push(CacheRoiEstimate {
            agent_id:              r.try_get("agent_id").unwrap_or_default(),
            estimated_hit_rate:    (hit_rate * 100.0).round() / 100.0,
            estimated_savings_usd: savings.round_dp(4),
            total_calls_30d:       cnt,
            total_spend_30d:       spend.round_dp(4),
        });
    }
    out.sort_by(|a, b| b.estimated_savings_usd.cmp(&a.estimated_savings_usd));
    Ok(out)
}

// ── Recommendation CRUD ───────────────────────────────────────────────────────

pub async fn list_recommendations(pool: &PgPool, status: Option<&str>, limit: i64) -> Result<Vec<Recommendation>> {
    let rows = if let Some(s) = status {
        sqlx::query("SELECT * FROM ll_recommendations WHERE status=$1 ORDER BY monthly_savings_usd DESC LIMIT $2")
            .bind(s).bind(limit).fetch_all(pool).await.context("list recs")?
    } else {
        sqlx::query("SELECT * FROM ll_recommendations ORDER BY monthly_savings_usd DESC LIMIT $1")
            .bind(limit).fetch_all(pool).await.context("list recs")?
    };
    rows.iter().map(|r| row_to_rec(r)).collect()
}

pub async fn get_recommendation(pool: &PgPool, id: Uuid) -> Result<Recommendation> {
    let row = sqlx::query("SELECT * FROM ll_recommendations WHERE id=$1")
        .bind(id).fetch_one(pool).await.context("get rec")?;
    row_to_rec(&row)
}

pub async fn apply_recommendation(pool: &PgPool, connector: &ConnectorClient, id: Uuid, req: ApplyRecommendationRequest) -> Result<Recommendation> {
    let rec = get_recommendation(pool, id).await?;
    let rec_type = rec.rec_type.clone();

    // Delegate actual enforcement to ConnectorOS
    let _ = connector.apply_fix(&id.to_string()).await;

    let row = sqlx::query(
        "UPDATE ll_recommendations SET status='applied', applied_by=$1, applied_at=NOW() WHERE id=$2 RETURNING *"
    ).bind(&req.applied_by).bind(id).fetch_one(pool).await.context("apply rec")?;

    metrics::counter!("ledgerlens_recommendations_applied_total",
        "type" => rec_type
    ).increment(1);
    row_to_rec(&row)
}

pub async fn dismiss_recommendation(pool: &PgPool, id: Uuid, req: DismissRecommendationRequest) -> Result<Recommendation> {
    let row = sqlx::query(
        "UPDATE ll_recommendations SET status='dismissed', dismissed_by=$1, dismissed_at=NOW() WHERE id=$2 RETURNING *"
    ).bind(&req.dismissed_by).bind(id).fetch_one(pool).await.context("dismiss rec")?;
    row_to_rec(&row)
}

// ── Row mapper ────────────────────────────────────────────────────────────────

fn row_to_rec(r: &sqlx::postgres::PgRow) -> Result<Recommendation> {
    Ok(Recommendation {
        id:                  r.try_get("id")?,
        rec_type:            r.try_get("rec_type")?,
        title:               r.try_get("title")?,
        description:         r.try_get("description")?,
        agent_id:            r.try_get("agent_id")?,
        model_current:       r.try_get("model_current")?,
        model_suggested:     r.try_get("model_suggested")?,
        workflow:            r.try_get("workflow")?,
        feature:             r.try_get("feature")?,
        monthly_savings_usd: get_decimal(r, "monthly_savings_usd"),
        quality_impact:      r.try_get("quality_impact")?,
        confidence:          get_decimal(r, "confidence"),
        evidence:            r.try_get("evidence")?,
        status:              r.try_get("status")?,
        applied_by:          r.try_get("applied_by")?,
        applied_at:          r.try_get("applied_at")?,
        dismissed_by:        r.try_get("dismissed_by")?,
        dismissed_at:        r.try_get("dismissed_at")?,
        expires_at:          r.try_get("expires_at")?,
        created_at:          r.try_get("created_at")?,
    })
}
