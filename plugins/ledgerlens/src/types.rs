//! Domain types for LedgerLens.
//!
//! All request structs carry `#[derive(Validate)]` for input validation
//! before they reach the database layer.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use validator::Validate;

// ── Health ────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    pub status:    String,
    pub db:        String,
    pub connector: String,
    pub version:   String,
}

// ── Usage Records ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub id:                  Uuid,
    pub connector_record_id: Option<String>,
    pub agent_id:            String,
    pub model:               String,
    pub provider:            String,
    pub call_type:           String,
    pub input_tokens:        i64,
    pub output_tokens:       i64,
    pub total_tokens:        i64,
    pub cost_usd:            rust_decimal::Decimal,
    pub tag_feature:         Option<String>,
    pub tag_bu:              Option<String>,
    pub tag_customer:        Option<String>,
    pub tag_workflow:        Option<String>,
    pub tag_team:            Option<String>,
    pub tags:                Value,
    pub called_at:           DateTime<Utc>,
    pub created_at:          DateTime<Utc>,
}

/// Ingest a batch of usage records from ConnectorOS (or tag an inline call).
#[derive(Debug, Deserialize, Validate)]
pub struct IngestUsageRequest {
    #[validate(length(min = 1, max = 256))]
    pub agent_id:            String,
    #[validate(length(min = 1, max = 128))]
    pub model:               String,
    #[validate(length(max = 64))]
    pub provider:            Option<String>,
    pub call_type:           Option<String>,
    #[validate(range(min = 0))]
    pub input_tokens:        Option<i64>,
    #[validate(range(min = 0))]
    pub output_tokens:       Option<i64>,
    #[validate(range(min = 0.0))]
    pub cost_usd:            f64,
    pub connector_record_id: Option<String>,
    pub called_at:           Option<DateTime<Utc>>,
    // Business tags
    #[validate(length(max = 128))]
    pub tag_feature:         Option<String>,
    #[validate(length(max = 128))]
    pub tag_bu:              Option<String>,
    #[validate(length(max = 256))]
    pub tag_customer:        Option<String>,
    #[validate(length(max = 128))]
    pub tag_workflow:        Option<String>,
    #[validate(length(max = 128))]
    pub tag_team:            Option<String>,
    pub tags:                Option<Value>,
}

// ── Cost Query / Pivot ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct CostQueryParams {
    /// One of: feature, bu, customer, workflow, team, model, agent, provider, call_type
    #[validate(length(min = 1, max = 64))]
    pub pivot:          Option<String>,
    pub from:           Option<DateTime<Utc>>,
    pub to:             Option<DateTime<Utc>>,
    #[validate(length(max = 128))]
    pub tag_feature:    Option<String>,
    #[validate(length(max = 128))]
    pub tag_bu:         Option<String>,
    #[validate(length(max = 256))]
    pub tag_customer:   Option<String>,
    #[validate(length(max = 128))]
    pub tag_workflow:   Option<String>,
    #[validate(length(max = 128))]
    pub tag_team:       Option<String>,
    #[validate(length(max = 128))]
    pub model:          Option<String>,
    #[validate(length(max = 256))]
    pub agent_id:       Option<String>,
    pub limit:          Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CostPivotRow {
    pub dimension:    String,
    pub total_usd:    rust_decimal::Decimal,
    pub total_tokens: i64,
    pub call_count:   i64,
    pub pct_of_total: f64,
}

#[derive(Debug, Serialize)]
pub struct CostSummary {
    pub total_usd:    rust_decimal::Decimal,
    pub total_tokens: i64,
    pub call_count:   i64,
    pub from:         Option<DateTime<Utc>>,
    pub to:           Option<DateTime<Utc>>,
    pub pivot:        Option<String>,
    pub rows:         Vec<CostPivotRow>,
}

// ── Budget Envelopes ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub id:             Uuid,
    pub name:           String,
    pub scope_type:     String,
    pub scope_value:    Option<String>,
    pub period:         String,
    pub limit_usd:      rust_decimal::Decimal,
    pub breach_policy:  String,
    pub downgrade_model:Option<String>,
    pub current_spend:  rust_decimal::Decimal,
    pub period_start:   DateTime<Utc>,
    pub period_end:     DateTime<Utc>,
    pub breached:       bool,
    pub breach_at:      Option<DateTime<Utc>>,
    pub alert_emails:   Value,
    pub alert_webhooks: Value,
    pub alert_pct:      i32,
    pub enabled:        bool,
    pub created_at:     DateTime<Utc>,
    pub updated_at:     DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateBudgetRequest {
    #[validate(length(min = 1, max = 128))]
    pub name:           String,
    /// bu | feature | customer | workflow | agent | global
    #[validate(length(min = 2, max = 32))]
    pub scope_type:     String,
    #[validate(length(max = 256))]
    pub scope_value:    Option<String>,
    /// hourly | daily | weekly | monthly
    pub period:         Option<String>,
    #[validate(range(min = 0.01))]
    pub limit_usd:      f64,
    /// alert_only | downgrade | hard_stop | cap_and_queue
    pub breach_policy:  Option<String>,
    pub downgrade_model:Option<String>,
    pub alert_emails:   Option<Vec<String>>,
    pub alert_webhooks: Option<Vec<String>>,
    #[validate(range(min = 1, max = 100))]
    pub alert_pct:      Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetEvent {
    pub id:         Uuid,
    pub budget_id:  Uuid,
    pub event_type: String,
    pub spend_usd:  rust_decimal::Decimal,
    pub limit_usd:  rust_decimal::Decimal,
    pub pct_used:   rust_decimal::Decimal,
    pub policy:     Option<String>,
    pub detail:     Value,
    pub occurred_at:DateTime<Utc>,
}

// ── Anomalies ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub id:              Uuid,
    pub dimension_type:  String,
    pub dimension_value: Option<String>,
    pub observed_spend:  rust_decimal::Decimal,
    pub baseline_spend:  rust_decimal::Decimal,
    pub multiplier:      rust_decimal::Decimal,
    pub window_hours:    i32,
    pub root_cause:      Option<String>,
    pub top_agents:      Value,
    pub top_models:      Value,
    pub status:          String,
    pub severity:        String,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at:     Option<DateTime<Utc>>,
    pub detail:          Value,
    pub created_at:      DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeAnomalyRequest {
    pub acknowledged_by: String,
    pub note:            Option<String>,
}

// ── Unit Economics ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueRecord {
    pub id:              Uuid,
    pub period_start:    NaiveDate,
    pub period_end:      NaiveDate,
    pub dimension_type:  String,
    pub dimension_value: String,
    pub revenue_usd:     rust_decimal::Decimal,
    pub source:          String,
    pub source_ref:      Option<String>,
    pub created_at:      DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateRevenueRequest {
    pub period_start:    NaiveDate,
    pub period_end:      NaiveDate,
    /// customer | feature | bu | workflow
    #[validate(length(min = 2, max = 32))]
    pub dimension_type:  String,
    #[validate(length(min = 1, max = 256))]
    pub dimension_value: String,
    #[validate(range(min = 0.0))]
    pub revenue_usd:     f64,
    pub source:          Option<String>,
    pub source_ref:      Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UnitEconomicsRow {
    pub dimension_type:     String,
    pub dimension_value:    String,
    pub cost_usd:           rust_decimal::Decimal,
    pub revenue_usd:        Option<rust_decimal::Decimal>,
    pub gross_margin_pct:   Option<f64>,
    pub cost_per_call:      rust_decimal::Decimal,
    pub call_count:         i64,
}

// ── Forecast ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forecast {
    pub id:               Uuid,
    pub dimension_type:   String,
    pub dimension_value:  Option<String>,
    pub horizon_days:     i32,
    pub p50_usd:          rust_decimal::Decimal,
    pub p80_usd:          rust_decimal::Decimal,
    pub p95_usd:          rust_decimal::Decimal,
    pub trailing_30d_usd: Option<rust_decimal::Decimal>,
    pub trailing_7d_usd:  Option<rust_decimal::Decimal>,
    pub daily_avg_usd:    Option<rust_decimal::Decimal>,
    pub growth_rate_pct:  Option<rust_decimal::Decimal>,
    pub scenarios:        Value,
    pub created_at:       DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ForecastQueryParams {
    pub dimension_type:  Option<String>,
    pub dimension_value: Option<String>,
    /// 30 | 60 | 90
    #[validate(range(min = 1, max = 365))]
    pub horizon_days:    Option<i32>,
}

// ── Recommendations ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id:                  Uuid,
    pub rec_type:            String,
    pub title:               String,
    pub description:         String,
    pub agent_id:            Option<String>,
    pub model_current:       Option<String>,
    pub model_suggested:     Option<String>,
    pub workflow:            Option<String>,
    pub feature:             Option<String>,
    pub monthly_savings_usd: rust_decimal::Decimal,
    pub quality_impact:      String,
    pub confidence:          rust_decimal::Decimal,
    pub evidence:            Value,
    pub status:              String,
    pub applied_by:          Option<String>,
    pub applied_at:          Option<DateTime<Utc>>,
    pub dismissed_by:        Option<String>,
    pub dismissed_at:        Option<DateTime<Utc>>,
    pub expires_at:          Option<DateTime<Utc>>,
    pub created_at:          DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ApplyRecommendationRequest {
    pub applied_by: String,
    pub note:       Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DismissRecommendationRequest {
    pub dismissed_by: String,
    pub reason:       Option<String>,
}

// ── Exports ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportJob {
    pub id:           Uuid,
    pub export_type:  String,
    pub format:       String,
    pub period_start: NaiveDate,
    pub period_end:   NaiveDate,
    pub filters:      Value,
    pub status:       String,
    pub row_count:    Option<i32>,
    pub size_bytes:   Option<i64>,
    pub download_url: Option<String>,
    pub error:        Option<String>,
    pub hmac_sig:     Option<String>,
    pub expires_at:   Option<DateTime<Utc>>,
    pub created_at:   DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateExportRequest {
    /// chargeback | unit_economics | waste_report | forecast_report | full_cfo_package
    #[validate(length(min = 4, max = 32))]
    pub export_type:  String,
    /// json | csv
    pub format:       Option<String>,
    pub period_start: NaiveDate,
    pub period_end:   NaiveDate,
    pub filters:      Option<Value>,
}

// ── Notification channels ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub id:           Uuid,
    pub name:         String,
    pub channel_type: String,
    pub config:       Value,
    pub enabled:      bool,
    pub created_at:   DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateChannelRequest {
    #[validate(length(min = 1, max = 128))]
    pub name:         String,
    /// slack | pagerduty | opsgenie | webhook | email
    #[validate(length(min = 3, max = 32))]
    pub channel_type: String,
    pub config:       Value,
}

// ── Pagination ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct Pagination {
    #[validate(range(min = 1, max = 500))]
    pub limit:  Option<i64>,
    #[validate(range(min = 0))]
    pub offset: Option<i64>,
}

impl Pagination {
    pub fn limit(&self)  -> i64 { self.limit.unwrap_or(50).min(500) }
    pub fn offset(&self) -> i64 { self.offset.unwrap_or(0) }
}
