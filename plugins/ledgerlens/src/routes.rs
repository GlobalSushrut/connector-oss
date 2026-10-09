//! LedgerLens HTTP route handlers.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::NaiveDate;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use validator::Validate;

use crate::alerts::{AlertDispatcher, AlertPayload};
use crate::attribution;
use crate::budgets;
use crate::csv_export;
use crate::dashboard;
use crate::error::AppError;
use crate::executive;
use crate::exports;
use crate::forecast;
use crate::optimize;
use crate::state::AppState;
use crate::types::*;

// ── Health & readiness ────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let db_ok        = state.pool.acquire().await.is_ok();
    let connector_ok = state.connector.health().await.is_ok();
    Json(json!({
        "status":    if db_ok && connector_ok { "ok" } else { "degraded" },
        "db":        if db_ok { "ok" } else { "error" },
        "connector": if connector_ok { "ok" } else { "unreachable" },
        "version":   env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn readyz(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    state.pool.acquire().await
        .map_err(|e| AppError::ServiceUnavailable(format!("DB not ready: {e}")))?;
    Ok(Json(json!({ "status": "ready" })))
}

// ── Tag keys ──────────────────────────────────────────────────────────────────

pub async fn list_tag_keys(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let keys = attribution::list_tag_keys(&state.pool).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "tag_keys": keys })))
}

pub async fn create_tag_key(
    State(state): State<AppState>,
    Json(body):   Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let key         = body["key"].as_str().ok_or_else(|| AppError::BadRequest("key required".into()))?;
    let description = body["description"].as_str();
    let required    = body["required"].as_bool().unwrap_or(false);
    let k = attribution::create_tag_key(&state.pool, key, description, required).await
        .map_err(|e| AppError::Internal(e))?;
    Ok((StatusCode::CREATED, Json(json!({ "tag_key": k }))))
}

// ── Usage ingest ──────────────────────────────────────────────────────────────

pub async fn ingest_usage(
    State(state): State<AppState>,
    Json(req):    Json<IngestUsageRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let record = attribution::ingest(&state.pool, req).await
        .map_err(|e| AppError::Internal(e))?;
    Ok((StatusCode::CREATED, Json(json!({ "record": record }))))
}

pub async fn sync_from_connector(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let count = attribution::sync_from_connector(&state.pool, &state.connector).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "synced": count })))
}

// ── Cost query ────────────────────────────────────────────────────────────────

pub async fn query_costs(
    State(state): State<AppState>,
    Query(params): Query<CostQueryParams>,
) -> Result<Json<Value>, AppError> {
    params.validate().map_err(AppError::from)?;
    let summary = attribution::query_costs(&state.pool, &params).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "costs": summary })))
}

pub async fn fleet_cost_summary(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let dash = state.connector.cost_dashboard().await
        .map_err(|e| AppError::ServiceUnavailable(format!("ConnectorOS: {e}")))?;
    let center = state.connector.cost_center().await.unwrap_or(Value::Null);
    Ok(Json(json!({ "dashboard": dash, "center": center })))
}

pub async fn agent_cost(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let cost     = state.connector.agent_cost(&agent_id).await
        .map_err(|e| AppError::Internal(e))?;
    let timeline = state.connector.agent_cost_timeline(&agent_id).await.unwrap_or(Value::Null);
    Ok(Json(json!({ "cost": cost, "timeline": timeline })))
}

// ── Budget envelopes ──────────────────────────────────────────────────────────

pub async fn create_budget(
    State(state): State<AppState>,
    Json(req):    Json<CreateBudgetRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let b = budgets::create(&state.pool, &req).await
        .map_err(|e| AppError::Internal(e))?;
    Ok((StatusCode::CREATED, Json(json!({ "budget": b }))))
}

pub async fn list_budgets(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let bs = budgets::list(&state.pool, false).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "budgets": bs })))
}

pub async fn get_budget(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let b = budgets::get(&state.pool, id).await.map_err(AppError::from)?;
    Ok(Json(json!({ "budget": b })))
}

pub async fn delete_budget(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    budgets::delete(&state.pool, id).await.map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "deleted": id })))
}

pub async fn get_budget_events(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let events = budgets::events(&state.pool, id, pg.limit()).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "events": events })))
}

pub async fn budget_status(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let alerts = state.connector.budget_alerts().await.unwrap_or(Value::Null);
    let bs = budgets::list(&state.pool, true).await.map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "budgets": bs, "connector_alerts": alerts })))
}

// ── Anomalies ─────────────────────────────────────────────────────────────────

pub async fn list_anomalies(
    State(state): State<AppState>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let anoms = forecast::list_anomalies(&state.pool, Some("open"), pg.limit()).await
        .map_err(|e| AppError::Internal(e))?;
    let connector_anoms = state.connector.anomalies().await.unwrap_or(Value::Null);
    Ok(Json(json!({ "anomalies": anoms, "connector_anomalies": connector_anoms })))
}

pub async fn acknowledge_anomaly(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
    Json(req):    Json<AcknowledgeAnomalyRequest>,
) -> Result<Json<Value>, AppError> {
    let a = forecast::acknowledge_anomaly(&state.pool, id, &req.acknowledged_by).await
        .map_err(AppError::from)?;
    Ok(Json(json!({ "anomaly": a })))
}

pub async fn resolve_anomaly(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let a = forecast::resolve_anomaly(&state.pool, id).await.map_err(AppError::from)?;
    Ok(Json(json!({ "anomaly": a })))
}

// ── Revenue / unit economics ──────────────────────────────────────────────────

pub async fn create_revenue(
    State(state): State<AppState>,
    Json(req):    Json<CreateRevenueRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let row = sqlx::query(
        "INSERT INTO ll_revenue_records
            (period_start, period_end, dimension_type, dimension_value, revenue_usd, source, source_ref)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (period_start, dimension_type, dimension_value)
         DO UPDATE SET revenue_usd=EXCLUDED.revenue_usd, source=EXCLUDED.source
         RETURNING *"
    )
    .bind(req.period_start)
    .bind(req.period_end)
    .bind(&req.dimension_type)
    .bind(&req.dimension_value)
    .bind(req.revenue_usd)
    .bind(req.source.as_deref().unwrap_or("manual"))
    .bind(&req.source_ref)
    .fetch_one(&state.pool).await.map_err(AppError::from)?;

    use sqlx::Row;
    let rev = RevenueRecord {
        id:              row.try_get("id").unwrap_or_default(),
        period_start:    row.try_get("period_start").unwrap_or_default(),
        period_end:      row.try_get("period_end").unwrap_or_default(),
        dimension_type:  row.try_get("dimension_type").unwrap_or_default(),
        dimension_value: row.try_get("dimension_value").unwrap_or_default(),
        revenue_usd:     rust_decimal::Decimal::try_from(row.try_get::<f64,_>("revenue_usd").unwrap_or(0.0)).unwrap_or_default(),
        source:          row.try_get("source").unwrap_or_default(),
        source_ref:      row.try_get("source_ref").unwrap_or_default(),
        created_at:      row.try_get("created_at").unwrap_or_default(),
    };
    Ok((StatusCode::CREATED, Json(json!({ "revenue": rev }))))
}

// ── Forecasts ─────────────────────────────────────────────────────────────────

pub async fn get_forecast(
    State(state): State<AppState>,
    Query(params): Query<ForecastQueryParams>,
) -> Result<Json<Value>, AppError> {
    params.validate().map_err(AppError::from)?;
    let dim_type  = params.dimension_type.as_deref().unwrap_or("global");
    let dim_value = params.dimension_value.as_deref();
    let horizon   = params.horizon_days.unwrap_or(30);
    let fc = forecast::run_forecast(&state.pool, &state.connector, dim_type, dim_value, horizon).await
        .map_err(|e| AppError::Internal(e))?;
    let connector_fc = state.connector.capacity_forecast().await.unwrap_or(Value::Null);
    Ok(Json(json!({ "forecast": fc, "connector_forecast": connector_fc })))
}

// ── Waste & optimization ──────────────────────────────────────────────────────

pub async fn waste_heatmap(
    State(state): State<AppState>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let waste = optimize::waste_heatmap(&state.pool, pg.limit()).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "waste": waste })))
}

pub async fn cache_roi(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let roi = optimize::cache_roi_estimates(&state.pool).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "cache_roi": roi })))
}

pub async fn list_recommendations(
    State(state): State<AppState>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let recs = optimize::list_recommendations(&state.pool, Some("open"), pg.limit()).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "recommendations": recs })))
}

pub async fn apply_recommendation(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
    Json(req):    Json<ApplyRecommendationRequest>,
) -> Result<Json<Value>, AppError> {
    let r = optimize::apply_recommendation(&state.pool, &state.connector, id, req).await
        .map_err(AppError::from)?;
    Ok(Json(json!({ "recommendation": r })))
}

pub async fn dismiss_recommendation(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
    Json(req):    Json<DismissRecommendationRequest>,
) -> Result<Json<Value>, AppError> {
    let r = optimize::dismiss_recommendation(&state.pool, id, req).await
        .map_err(AppError::from)?;
    Ok(Json(json!({ "recommendation": r })))
}

pub async fn run_optimization(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let count = optimize::run_optimization(&state.pool, &state.connector).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "recommendations_generated": count })))
}

// ── Exports ───────────────────────────────────────────────────────────────────

pub async fn create_export(
    State(state): State<AppState>,
    Json(req):    Json<CreateExportRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let job = exports::create_export(&state.pool, &req).await
        .map_err(|e| AppError::Internal(e))?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "export": job }))))
}

pub async fn get_export(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let job = exports::get_export(&state.pool, id).await.map_err(AppError::from)?;
    Ok(Json(json!({ "export": job })))
}

pub async fn run_export(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let job = exports::run_export(&state.pool, &state.connector, id).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "export": job })))
}

pub async fn list_exports(
    State(state): State<AppState>,
    Query(pg):    Query<Pagination>,
) -> Result<Json<Value>, AppError> {
    pg.validate().map_err(AppError::from)?;
    let jobs = exports::list_exports(&state.pool, pg.limit()).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(json!({ "exports": jobs })))
}

// ── CFO Dashboard ─────────────────────────────────────────────────────────────

pub async fn cfo_dashboard(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let data = dashboard::cfo_dashboard(&state.pool).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(data))
}

pub async fn realtime_burn(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let data = dashboard::realtime_burn(&state.pool).await
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(data))
}

// ── CSV Downloads ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CsvParams {
    pub from: NaiveDate,
    pub to:   NaiveDate,
}

pub async fn download_chargeback_csv(
    State(state): State<AppState>,
    Query(p):     Query<CsvParams>,
) -> impl IntoResponse {
    match csv_export::chargeback_csv(&state.pool, p.from, p.to).await {
        Ok(csv) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE,        "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"chargeback.csv\""),
            ],
            csv,
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"error\":\"{}\"}}", e),
        ).into_response(),
    }
}

pub async fn download_unit_economics_csv(
    State(state): State<AppState>,
    Query(p):     Query<CsvParams>,
) -> impl IntoResponse {
    match csv_export::unit_economics_csv(&state.pool, p.from, p.to).await {
        Ok(csv) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE,        "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"unit-economics.csv\""),
            ],
            csv,
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"error\":\"{}\"}}", e),
        ).into_response(),
    }
}

pub async fn download_waste_csv(State(state): State<AppState>) -> impl IntoResponse {
    match csv_export::waste_report_csv(&state.pool).await {
        Ok(csv) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE,        "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"waste-report.csv\""),
            ],
            csv,
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"error\":\"{}\"}}", e),
        ).into_response(),
    }
}

pub async fn download_anomaly_csv(
    State(state): State<AppState>,
    Query(p):     Query<CsvParams>,
) -> impl IntoResponse {
    match csv_export::anomaly_history_csv(&state.pool, p.from, p.to).await {
        Ok(csv) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE,        "text/csv; charset=utf-8"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"anomaly-history.csv\""),
            ],
            csv,
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"error\":\"{}\"}}", e),
        ).into_response(),
    }
}

// ── Executive intelligence ────────────────────────────────────────────────

pub async fn executive_dashboard(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    executive::executive_dashboard(&state.pool).await
        .map(Json).map_err(AppError::Internal)
}

pub async fn simulate_savings(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    executive::simulate_savings(&state.pool).await
        .map(Json).map_err(AppError::Internal)
}

#[derive(Debug, Deserialize)]
pub struct RoiParams {
    /// Your monthly cost for LedgerLens (default: $299)
    pub monthly_cost_usd: Option<f64>,
}

pub async fn roi_calculator(
    State(state): State<AppState>,
    Query(p):     Query<RoiParams>,
) -> Result<Json<Value>, AppError> {
    let tool_cost = p.monthly_cost_usd.unwrap_or(299.0);
    executive::roi_calculator(&state.pool, tool_cost).await
        .map(Json).map_err(AppError::Internal)
}

// ── Notifications ─────────────────────────────────────────────────────────────

pub async fn create_channel(
    State(state): State<AppState>,
    Json(req):    Json<CreateChannelRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    req.validate().map_err(AppError::from)?;
    let row = sqlx::query(
        "INSERT INTO ll_notification_channels (name, channel_type, config)
         VALUES ($1,$2,$3) RETURNING *"
    )
    .bind(&req.name)
    .bind(&req.channel_type)
    .bind(&req.config)
    .fetch_one(&state.pool).await.map_err(AppError::from)?;
    use sqlx::Row;
    Ok((StatusCode::CREATED, Json(json!({
        "channel": {
            "id":           row.try_get::<uuid::Uuid,  _>("id").unwrap_or_default(),
            "name":         row.try_get::<String, _>("name").unwrap_or_default(),
            "channel_type": row.try_get::<String, _>("channel_type").unwrap_or_default(),
            "enabled":      row.try_get::<bool, _>("enabled").unwrap_or_default(),
            "created_at":   row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").unwrap_or_else(|_| chrono::Utc::now()),
        }
    }))))
}

pub async fn list_channels(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, name, channel_type, enabled, created_at FROM ll_notification_channels ORDER BY created_at DESC"
    ).fetch_all(&state.pool).await.map_err(AppError::from)?;
    let channels: Vec<Value> = rows.iter().map(|r| json!({
        "id":           r.try_get::<uuid::Uuid, _>("id").unwrap_or_default(),
        "name":         r.try_get::<String, _>("name").unwrap_or_default(),
        "channel_type": r.try_get::<String, _>("channel_type").unwrap_or_default(),
        "enabled":      r.try_get::<bool, _>("enabled").unwrap_or_default(),
        "created_at":   r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").unwrap_or_else(|_| chrono::Utc::now()),
    })).collect();
    Ok(Json(json!({ "channels": channels })))
}

#[derive(Debug, Deserialize)]
pub struct TestAlertBody {
    pub message: Option<String>,
}

pub async fn test_alert(
    State(state): State<AppState>,
    Path(id):     Path<Uuid>,
    Json(body):   Json<TestAlertBody>,
) -> Result<Json<Value>, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT name, channel_type FROM ll_notification_channels WHERE id=$1"
    ).bind(id).fetch_one(&state.pool).await.map_err(AppError::from)?;
    let name: String = row.try_get("name").unwrap_or_default();

    let dispatcher = AlertDispatcher::new();
    dispatcher.dispatch(&state.pool, &AlertPayload {
        event_type: "test".into(),
        severity:   "info".into(),
        title:      format!("✅ LedgerLens test alert from channel '{name}'"),
        body:       body.message.unwrap_or_else(|| "This is a test alert from LedgerLens AI FinOps.".into()),
        detail:     json!({ "channel_id": id, "channel_name": name }),
    }).await;

    Ok(Json(json!({ "fired": true, "channel": name })))
}
