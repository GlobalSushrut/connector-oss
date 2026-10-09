//! Cost attribution — the heart of LedgerLens.
//!
//! Provides:
//!   - Tag ingest: attach business context to ConnectorOS usage records
//!   - Cost query: multi-dimensional pivot over ll_usage_records
//!   - Sync: pull raw usage from ConnectorOS and persist with tags
//!   - Tag key management

use anyhow::{Context, Result};
use chrono::Utc;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use validator::Validate;

use crate::connector::ConnectorClient;
use crate::db_decimal::{from_f64, get_decimal};
use crate::types::{CostPivotRow, CostQueryParams, CostSummary, IngestUsageRequest, UsageRecord};

// ── Tag key management ────────────────────────────────────────────────────────

pub async fn list_tag_keys(pool: &PgPool) -> Result<Vec<Value>> {
    let rows = sqlx::query("SELECT id, key, description, required, created_at FROM ll_tag_keys ORDER BY key")
        .fetch_all(pool).await.context("list tag keys")?;
    Ok(rows.iter().map(|r| json!({
        "id":          r.try_get::<Uuid, _>("id").unwrap_or_default(),
        "key":         r.try_get::<String, _>("key").unwrap_or_default(),
        "description": r.try_get::<Option<String>, _>("description").unwrap_or_default(),
        "required":    r.try_get::<bool, _>("required").unwrap_or_default(),
    })).collect())
}

pub async fn create_tag_key(pool: &PgPool, key: &str, description: Option<&str>, required: bool) -> Result<Value> {
    let row = sqlx::query(
        "INSERT INTO ll_tag_keys (key, description, required)
         VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description, required = EXCLUDED.required
         RETURNING id, key, description, required, created_at"
    )
    .bind(key).bind(description).bind(required)
    .fetch_one(pool).await.context("create tag key")?;

    Ok(json!({
        "id":          row.try_get::<Uuid, _>("id").unwrap_or_default(),
        "key":         row.try_get::<String, _>("key").unwrap_or_default(),
        "description": row.try_get::<Option<String>, _>("description").unwrap_or_default(),
        "required":    row.try_get::<bool, _>("required").unwrap_or_default(),
    }))
}

// ── Tag ingest ────────────────────────────────────────────────────────────────

/// Ingest a single usage record with business tags.
/// Called by the tag-ingest middleware or directly from the API.
pub async fn ingest(pool: &PgPool, req: IngestUsageRequest) -> Result<UsageRecord> {
    req.validate().map_err(|e| anyhow::anyhow!("Validation: {}", e))?;

    let tags = req.tags.clone().unwrap_or(json!({}));
    let total_tokens = req.input_tokens.unwrap_or(0) + req.output_tokens.unwrap_or(0);
    let cost: f64 = req.cost_usd;

    let row = sqlx::query(
        "INSERT INTO ll_usage_records
            (agent_id, model, provider, call_type,
             input_tokens, output_tokens, total_tokens, cost_usd,
             connector_record_id, called_at,
             tag_feature, tag_bu, tag_customer, tag_workflow, tag_team, tags)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         ON CONFLICT (connector_record_id) DO UPDATE
           SET tag_feature  = EXCLUDED.tag_feature,
               tag_bu       = EXCLUDED.tag_bu,
               tag_customer = EXCLUDED.tag_customer,
               tag_workflow = EXCLUDED.tag_workflow,
               tag_team     = EXCLUDED.tag_team,
               tags         = EXCLUDED.tags
         RETURNING *"
    )
    .bind(&req.agent_id)
    .bind(&req.model)
    .bind(req.provider.as_deref().unwrap_or("openai"))
    .bind(req.call_type.as_deref().unwrap_or("llm"))
    .bind(req.input_tokens.unwrap_or(0))
    .bind(req.output_tokens.unwrap_or(0))
    .bind(total_tokens)
    .bind(cost)
    .bind(req.connector_record_id.as_deref())
    .bind(req.called_at.unwrap_or_else(Utc::now))
    .bind(req.tag_feature.as_deref())
    .bind(req.tag_bu.as_deref())
    .bind(req.tag_customer.as_deref())
    .bind(req.tag_workflow.as_deref())
    .bind(req.tag_team.as_deref())
    .bind(&tags)
    .fetch_one(pool).await.context("ingest usage record")?;

    let m_provider = req.provider.clone().unwrap_or_else(|| "openai".into());
    let m_model    = req.model.clone();
    metrics::counter!("ledgerlens_records_ingested_total",
        "provider" => m_provider,
        "model"    => m_model,
    ).increment(1);
    metrics::counter!("ledgerlens_cost_ingested_usd_total").increment((req.cost_usd * 1_000_000.0) as u64);

    row_to_usage(&row)
}

/// Pull raw usage from ConnectorOS and store locally (preserving existing tags).
pub async fn sync_from_connector(pool: &PgPool, connector: &ConnectorClient) -> Result<usize> {
    let records = connector.usage_export(None, None).await?;
    let mut count = 0usize;
    for r in &records {
        let cost = r.cost_usd.unwrap_or(0.0);
        let total = r.input_tokens.unwrap_or(0) + r.output_tokens.unwrap_or(0);
        sqlx::query(
            "INSERT INTO ll_usage_records
                (agent_id, model, provider, input_tokens, output_tokens, total_tokens, cost_usd, connector_record_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (connector_record_id) DO NOTHING"
        )
        .bind(&r.agent_id)
        .bind(r.model.as_deref().unwrap_or("unknown"))
        .bind(r.provider.as_deref().unwrap_or("openai"))
        .bind(r.input_tokens.unwrap_or(0))
        .bind(r.output_tokens.unwrap_or(0))
        .bind(total)
        .bind(cost)
        .bind(r.id.as_deref())
        .execute(pool).await.context("sync record")?;
        count += 1;
    }
    tracing::info!(synced = count, "Synced usage records from ConnectorOS");
    Ok(count)
}

// ── Cost query / pivot ────────────────────────────────────────────────────────

pub async fn query_costs(pool: &PgPool, params: &CostQueryParams) -> Result<CostSummary> {
    // Build WHERE clause
    let mut conditions: Vec<String> = vec!["1=1".into()];
    let mut i = 1usize;
    let mut bind_vals: Vec<String> = vec![];

    if let Some(f) = &params.from {
        conditions.push(format!("called_at >= ${i}"));
        bind_vals.push(f.to_rfc3339()); i += 1;
    }
    if let Some(t) = &params.to {
        conditions.push(format!("called_at <= ${i}"));
        bind_vals.push(t.to_rfc3339()); i += 1;
    }
    if let Some(v) = &params.tag_feature  { conditions.push(format!("tag_feature = ${i}"));  bind_vals.push(v.clone()); i += 1; }
    if let Some(v) = &params.tag_bu       { conditions.push(format!("tag_bu = ${i}"));        bind_vals.push(v.clone()); i += 1; }
    if let Some(v) = &params.tag_customer { conditions.push(format!("tag_customer = ${i}")); bind_vals.push(v.clone()); i += 1; }
    if let Some(v) = &params.tag_workflow { conditions.push(format!("tag_workflow = ${i}")); bind_vals.push(v.clone()); i += 1; }
    if let Some(v) = &params.tag_team     { conditions.push(format!("tag_team = ${i}"));      bind_vals.push(v.clone()); i += 1; }
    if let Some(v) = &params.model        { conditions.push(format!("model = ${i}"));         bind_vals.push(v.clone()); i += 1; }
    if let Some(v) = &params.agent_id     { conditions.push(format!("agent_id = ${i}"));      bind_vals.push(v.clone()); i += 1; }

    let where_sql = conditions.join(" AND ");

    // Total
    let total_sql = format!("SELECT COALESCE(SUM(cost_usd),0) as t, COALESCE(SUM(total_tokens),0) as tok, COUNT(*) as cnt FROM ll_usage_records WHERE {where_sql}");
    let mut q = sqlx::query(&total_sql);
    for v in &bind_vals { q = q.bind(v); }
    let total_row = q.fetch_one(pool).await.context("total cost")?;
    let total_usd: Decimal   = get_decimal(&total_row, "t");
    let total_tokens: i64    = total_row.try_get("tok").unwrap_or_default();
    let call_count: i64      = total_row.try_get("cnt").unwrap_or_default();

    // Pivot
    let pivot_col = match params.pivot.as_deref() {
        Some("feature")   => "tag_feature",
        Some("bu")        => "tag_bu",
        Some("customer")  => "tag_customer",
        Some("workflow")  => "tag_workflow",
        Some("team")      => "tag_team",
        Some("model")     => "model",
        Some("agent")     => "agent_id",
        Some("provider")  => "provider",
        Some("call_type") => "call_type",
        _                 => "",
    };

    let mut rows: Vec<CostPivotRow> = vec![];
    if !pivot_col.is_empty() {
        let limit = params.limit.unwrap_or(50).min(500);
        let pivot_sql = format!(
            "SELECT COALESCE({pivot_col}::text,'(untagged)') as dim,
                    SUM(cost_usd) as s, SUM(total_tokens) as tok, COUNT(*) as cnt
             FROM ll_usage_records WHERE {where_sql}
             GROUP BY dim ORDER BY s DESC LIMIT {limit}"
        );
        let mut pq = sqlx::query(&pivot_sql);
        for v in &bind_vals { pq = pq.bind(v); }
        let pivot_rows = pq.fetch_all(pool).await.context("pivot query")?;

        for r in &pivot_rows {
            let row_usd: Decimal = get_decimal(r, "s");
            let pct = if total_usd.is_zero() { 0.0 } else {
                row_usd.to_string().parse::<f64>().unwrap_or(0.0)
                    / total_usd.to_string().parse::<f64>().unwrap_or(1.0) * 100.0
            };
            rows.push(CostPivotRow {
                dimension:    r.try_get("dim").unwrap_or_default(),
                total_usd:    row_usd,
                total_tokens: r.try_get("tok").unwrap_or_default(),
                call_count:   r.try_get("cnt").unwrap_or_default(),
                pct_of_total: pct,
            });
        }
    }

    Ok(CostSummary {
        total_usd,
        total_tokens,
        call_count,
        from:  params.from,
        to:    params.to,
        pivot: params.pivot.clone(),
        rows,
    })
}

// ── Row mapper ────────────────────────────────────────────────────────────────

fn row_to_usage(row: &sqlx::postgres::PgRow) -> Result<UsageRecord> {
    use crate::db_decimal::get_decimal;
    Ok(UsageRecord {
        id:                  row.try_get("id")?,
        connector_record_id: row.try_get("connector_record_id")?,
        agent_id:            row.try_get("agent_id")?,
        model:               row.try_get("model")?,
        provider:            row.try_get("provider")?,
        call_type:           row.try_get("call_type")?,
        input_tokens:        row.try_get("input_tokens")?,
        output_tokens:       row.try_get("output_tokens")?,
        total_tokens:        row.try_get("total_tokens")?,
        cost_usd:            get_decimal(row, "cost_usd"),
        tag_feature:         row.try_get("tag_feature")?,
        tag_bu:              row.try_get("tag_bu")?,
        tag_customer:        row.try_get("tag_customer")?,
        tag_workflow:        row.try_get("tag_workflow")?,
        tag_team:            row.try_get("tag_team")?,
        tags:                row.try_get("tags")?,
        called_at:           row.try_get("called_at")?,
        created_at:          row.try_get("created_at")?,
    })
}
