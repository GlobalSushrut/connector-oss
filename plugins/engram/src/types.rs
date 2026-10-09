//! Request / response types for all Engram API surfaces.
//! All types derive Serialize + Deserialize; validators guard public input.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// ── Namespace ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct CreateNamespaceRequest {
    #[validate(length(min = 2, max = 255))]
    pub path: String,

    pub team: Option<String>,

    #[serde(default = "default_retention")]
    pub retention_days: i32,

    #[serde(default = "default_entropy_alert")]
    pub entropy_alert: f64,

    #[serde(default = "default_entropy_halt")]
    pub entropy_halt: f64,

    #[serde(default)]
    pub hipaa: bool,

    #[serde(default = "default_auto_consolidate")]
    pub auto_consolidate: bool,

    #[serde(default = "default_stale_days")]
    pub stale_days: i32,
}

fn default_retention() -> i32 { 90 }
fn default_entropy_alert() -> f64 { 0.7 }
fn default_entropy_halt() -> f64 { 0.95 }
fn default_auto_consolidate() -> bool { true }
fn default_stale_days() -> i32 { 30 }

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateNamespaceRequest {
    pub team: Option<String>,
    pub retention_days: Option<i32>,
    pub entropy_alert: Option<f64>,
    pub entropy_halt: Option<f64>,
    pub auto_consolidate: Option<bool>,
    pub stale_days: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct NamespaceRow {
    pub id: Uuid,
    pub path: String,
    pub team: Option<String>,
    pub retention_days: i32,
    pub entropy_alert: f64,
    pub entropy_halt: f64,
    pub hipaa: bool,
    pub auto_consolidate: bool,
    pub stale_days: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub latest_entropy: Option<f64>,
    pub latest_knot: Option<f64>,
    pub entropy_health: String,
}

// ── Memory write / recall ────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct MemWriteRequest {
    #[validate(length(min = 1, max = 32_768))]
    pub content: String,

    #[serde(rename = "type", default = "default_mem_type")]
    pub memory_type: String,   // "working" | "evidence" | "episodic" | "semantic"

    pub tags: Option<Vec<String>>,
    pub entity_kind: Option<String>,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
}

fn default_mem_type() -> String { "semantic".into() }

#[derive(Debug, Serialize)]
pub struct MemWriteResponse {
    pub cid: String,
    pub namespace: String,
    pub entropy_score: f64,
    pub entropy_health: String,
    pub ok: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct MemRecallRequest {
    #[validate(length(min = 1, max = 2048))]
    pub query: String,

    #[serde(default = "default_top_k")]
    pub top_k: i32,

    pub memory_type: Option<String>,
    pub tags: Option<Vec<String>>,
    pub session_id: Option<String>,
}

fn default_top_k() -> i32 { 5 }

#[derive(Debug, Serialize)]
pub struct MemFact {
    pub cid: String,
    pub content: String,
    pub memory_type: String,
    pub tags: Vec<String>,
    pub score: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct MemRecallResponse {
    pub facts: Vec<MemFact>,
    pub entropy_health: String,
    pub namespace: String,
    pub sources: Vec<String>,
}

// ── EQL search ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct EqlSearchRequest {
    #[validate(length(min = 1, max = 4096))]
    pub query: String,

    #[serde(default = "default_eql_limit")]
    pub limit: i32,

    pub offset: Option<i32>,
}

fn default_eql_limit() -> i32 { 50 }

#[derive(Debug, Serialize)]
pub struct EqlSearchResponse {
    pub results: Vec<serde_json::Value>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

// ── Dehallucination / grounding ──────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct GroundRequest {
    pub claims: Vec<String>,
    pub namespace: String,
    #[serde(default = "default_ground_threshold")]
    pub threshold: f64,
    #[serde(default = "default_on_fail")]
    pub on_fail: String,   // "block" | "flag" | "hitl"
}

fn default_ground_threshold() -> f64 { 0.75 }
fn default_on_fail() -> String { "flag".into() }

#[derive(Debug, Serialize)]
pub struct ClaimResult {
    pub claim: String,
    pub grounding_score: f64,
    pub grounded: bool,
    pub source_cids: Vec<String>,
    pub outcome: String,   // "passed" | "blocked" | "flagged" | "hitl"
}

#[derive(Debug, Serialize)]
pub struct GroundResponse {
    pub results: Vec<ClaimResult>,
    pub all_grounded: bool,
    pub proof_cid: Option<String>,
}

// ── Entropy health ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct EntropyHealthResponse {
    pub namespace: String,
    pub entropy_score: f64,
    pub knot_score: f64,
    pub contradiction_count: i32,
    pub redundancy_count: i32,
    pub stale_count: i32,
    pub threads_detected: i32,
    pub health: String,    // "good" | "warning" | "critical" | "halted"
    pub recommended_action: String,
    pub snapped_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ConsolidateRequest {
    pub namespace: String,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConsolidateResponse {
    pub namespace: String,
    pub merged_count: i32,
    pub expired_count: i32,
    pub flagged_count: i32,
    pub before_entropy: f64,
    pub after_entropy: Option<f64>,
    pub dry_run: bool,
}

// ── CoT Anchor ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct CreateCotSessionRequest {
    pub session_name: Option<String>,
    #[validate(length(min = 2, max = 255))]
    pub namespace: String,
    #[validate(length(min = 1, max = 255))]
    pub agent_id: String,
    #[serde(default = "default_ground_threshold")]
    pub threshold: f64,
    #[serde(default = "default_on_fail")]
    pub on_fail: String,
}

#[derive(Debug, Serialize)]
pub struct CotSessionResponse {
    pub id: Uuid,
    pub session_name: Option<String>,
    pub namespace: String,
    pub agent_id: String,
    pub threshold: f64,
    pub on_fail: String,
    pub status: String,
    pub step_count: i32,
    pub passed_count: i32,
    pub failed_count: i32,
    pub started_at: DateTime<Utc>,
    pub concluded_at: Option<DateTime<Utc>>,
    pub proof_cid: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CotStepRequest {
    #[validate(length(min = 1, max = 16_384))]
    pub claim_text: String,
}

#[derive(Debug, Serialize)]
pub struct CotStepResponse {
    pub step_number: i32,
    pub claim_text: String,
    pub grounding_score: f64,
    pub grounded: bool,
    pub source_cids: Vec<String>,
    pub outcome: String,
    pub retry_count: i32,
    pub session_status: String,
}

#[derive(Debug, Serialize)]
pub struct CotConcludeResponse {
    pub session_id: Uuid,
    pub step_count: i32,
    pub passed_count: i32,
    pub failed_count: i32,
    pub proof_cid: Option<String>,
    pub concluded_at: DateTime<Utc>,
}

// ── Knowledge sharing ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct CreateShareRequest {
    #[validate(length(min = 2, max = 255))]
    pub source_ns: String,
    #[validate(length(min = 1, max = 255))]
    pub target_pattern: String,
    #[validate(length(min = 1, max = 512))]
    pub shared_path: String,
    pub permission: String,   // "read_only" | "read_write"
}

#[derive(Debug, Serialize)]
pub struct ShareRow {
    pub id: Uuid,
    pub source_ns: String,
    pub target_pattern: String,
    pub shared_path: String,
    pub permission: String,
    pub ucan_cid: Option<String>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

// ── Health ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub db: String,
    pub connector: String,
}
