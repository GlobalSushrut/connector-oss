use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use validator::Validate;

// ── Policy config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    pub allowed_models:          Option<Vec<String>>,
    pub budget:                  Option<BudgetPolicy>,
    pub tools:                   Option<Vec<String>>,
    pub deny_tools:              Option<Vec<String>>,
    pub require_role:            Option<Vec<String>>,
    pub hipaa:                   Option<bool>,
    pub pii_redact:              Option<bool>,
    pub timeout_secs:            Option<u64>,
    pub require_approval_above_risk: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetPolicy {
    pub per_call_tokens: Option<i32>,
    pub per_day_usd:     Option<f64>,
    pub per_month_usd:   Option<f64>,
    pub on_exceed:       Option<String>,  // "deny" | "alert"
}

// ── Registration ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 1, max = 128))]
    pub name:         String,

    #[validate(url)]
    pub uri:          String,

    pub description:  Option<String>,
    pub policy:       Option<PolicyConfig>,
    pub instructions: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FunctionRow {
    pub id:               Uuid,
    pub name:             String,
    pub uri:              String,
    pub description:      Option<String>,
    pub policy:           PolicyConfig,
    pub instructions:     Option<String>,
    pub status:           String,
    pub health_status:    String,
    pub health_latency_ms: Option<i32>,
    pub last_health_at:   Option<DateTime<Utc>>,
    pub agent_did:        Option<String>,
    pub invocation_count: i64,
    pub total_cost_usd:   f64,
    pub created_at:       DateTime<Utc>,
    pub updated_at:       DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFunctionRequest {
    pub uri:          Option<String>,
    pub description:  Option<String>,
    pub policy:       Option<PolicyConfig>,
    pub instructions: Option<String>,
}

// ── Invocation ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct InvokeRequest {
    pub input:       Value,
    pub caller_id:   Option<String>,
    pub r#async:     Option<bool>,
    pub callback_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvokeResponse {
    pub invocation_id: Uuid,
    pub function:      String,
    pub output:        Value,
    pub tokens_in:     i32,
    pub tokens_out:    i32,
    pub cost_usd:      f64,
    pub latency_ms:    i64,
    pub outcome:       String,
    pub audit_cid:     Option<String>,
    pub trace_id:      Option<String>,
    pub model_used:    Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AsyncInvokeResponse {
    pub job_id:    Uuid,
    pub function:  String,
    pub status:    String,
    pub message:   String,
}

// ── Invocation log row ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct InvocationRow {
    pub id:           Uuid,
    pub function_name: String,
    pub model_used:   Option<String>,
    pub tokens_in:    i32,
    pub tokens_out:   i32,
    pub cost_usd:     f64,
    pub latency_ms:   Option<i32>,
    pub outcome:      String,
    pub deny_reason:  Option<String>,
    pub audit_cid:    Option<String>,
    pub invoked_at:   DateTime<Utc>,
}

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FunctionStats {
    pub function:              String,
    pub invocation_count:      i64,
    pub total_cost_usd:        f64,
    pub avg_latency_ms:        Option<f64>,
    pub p99_latency_ms:        Option<f64>,
    pub error_rate:            f64,
    pub budget_remaining_usd:  Option<f64>,
    pub today_cost_usd:        f64,
    pub today_invocations:     i64,
    pub last_invoked_at:       Option<DateTime<Utc>>,
}

// ── Suspend/resume ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SuspendRequest {
    pub reason: Option<String>,
}

// ── Health ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status:    String,
    pub version:   String,
    pub db:        String,
    pub connector: String,
    pub functions: FunctionSummary,
}

#[derive(Debug, Serialize)]
pub struct FunctionSummary {
    pub total:       i64,
    pub healthy:     i64,
    pub degraded:    i64,
    pub unreachable: i64,
    pub suspended:   i64,
}
