//! # ConnectorMap Books API — Accounting-Inspired Operational Ledger
//!
//! REST endpoints for the journal-ledger-statement model.
//! Every agent action is a transaction with debit/credit posting lines.
//!
//! ## Routes
//!   GET    /books                     — System Position report
//!   GET    /books/journal             — General journal (paginated)
//!   GET    /books/journal/:seq_no     — Single journal entry
//!   GET    /books/ledger/:account_id  — Account ledger
//!   GET    /books/statement/:account_id — Full account statement
//!   GET    /books/receipt/:seq_no     — Transaction receipt (drill-down)
//!   GET    /books/costs               — Cost statement (scoped by `account_id`; untagged legacy rows only when `CONNECTOR_DEV_MODE`)
//!   GET    /books/balance             — Reconciliation balance
//!   GET    /books/live                — SSE event stream
//!   POST   /books/reconcile           — Run reconciliation check
//!   POST   /books/close/:session_id   — Close session books

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Json,
};
use chrono::{Datelike, TimeZone, Utc};
use connector_engine::books::{
    AccountId, AccountLedger, AccountStatement, CostPosition, IntegrityPosition, JournalEntry,
    LedgerAction, Outcome, PendingObligations, ReconciliationReport, ResourcesHeld, SystemPosition,
    VerificationTier,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use tokio_stream::StreamExt;
use vac_core::kernel::{SyscallPayload, SyscallRequest};
use vac_core::ocsf_adapter::{to_ocsf, to_ocsf_batch, OcsfAdapterConfig};
use vac_core::types::{MemoryKernelOp, OpOutcome};

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;

const BILLING_EVENTS_NS: &str = "billing_usage_events";

fn parse_billing_ts(v: &serde_json::Value) -> Option<chrono::DateTime<Utc>> {
    v.get("timestamp")
        .and_then(|t| t.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn billing_event_tokens(v: &serde_json::Value) -> u64 {
    v.get("total_tokens")
        .and_then(|x| x.as_u64())
        .or_else(|| {
            let a = v.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
            let b = v.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
            if a + b > 0 {
                Some(a + b)
            } else {
                None
            }
        })
        .or_else(|| v.get("tokens").and_then(|x| x.as_u64()))
        .unwrap_or(0)
}

fn billing_event_cost_usd(v: &serde_json::Value) -> f64 {
    v.get("cost_usd_estimated")
        .and_then(|x| x.as_f64())
        .unwrap_or(0.0)
}

fn billing_event_in_period(ts: &chrono::DateTime<Utc>, period: &str) -> bool {
    match period {
        "today" => ts.date_naive() == Utc::now().date_naive(),
        "month" => {
            let n = Utc::now();
            ts.year() == n.year() && ts.month() == n.month()
        }
        _ => true,
    }
}

fn connector_dev_mode() -> bool {
    std::env::var("CONNECTOR_DEV_MODE").is_ok()
}

/// When `allow_untagged_legacy` is false (typical production), events without `account_id` are excluded.
fn billing_event_matches_account(
    v: &serde_json::Value,
    account_id: &str,
    allow_untagged_legacy: bool,
) -> bool {
    match v.get("account_id").and_then(|x| x.as_str()) {
        Some(aid) => aid == account_id,
        None => allow_untagged_legacy,
    }
}

/// Today / month token + **estimated** USD totals from `billing_usage_events` (UTC).
/// When `account_id` is set, events are filtered to that account; untagged rows are included only in dev (`CONNECTOR_DEV_MODE`).
fn cost_position_from_ledger(state: &SharedState, account_id: Option<&str>) -> CostPosition {
    let now = Utc::now();
    let today = now.date_naive();
    let month = now.month();
    let year = now.year();

    let keys = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(BILLING_EVENTS_NS, None).unwrap_or_default()
    };

    let mut today_tokens = 0u64;
    let mut today_cost_usd = 0.0f64;
    let mut month_tokens = 0u64;
    let mut month_cost_usd = 0.0f64;

    let es = state.engine_store.lock().unwrap();
    for k in keys {
        let Some(v) = es.folder_get(BILLING_EVENTS_NS, &k).ok().flatten() else {
            continue;
        };
        if let Some(want) = account_id {
            if !billing_event_matches_account(&v, want, connector_dev_mode()) {
                continue;
            }
        }
        let Some(ts) = parse_billing_ts(&v) else {
            continue;
        };
        let d = ts.date_naive();
        let tok = billing_event_tokens(&v);
        let usd = billing_event_cost_usd(&v);
        if d == today {
            today_tokens = today_tokens.saturating_add(tok);
            today_cost_usd += usd;
        }
        if d.year() == year && d.month() == month {
            month_tokens = month_tokens.saturating_add(tok);
            month_cost_usd += usd;
        }
    }

    CostPosition {
        today_tokens,
        today_cost_usd,
        month_tokens,
        month_cost_usd,
    }
}

/// Aggregated billing ledger for dashboards / Monitor surface (same scope as [`cost_position_from_ledger`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BillingLedgerTotals {
    pub today_tokens: u64,
    pub today_cost_usd: f64,
    pub month_tokens: u64,
    pub month_cost_usd: f64,
    pub all_time_tokens: u64,
    pub all_time_cost_usd: f64,
}

/// Sum tokens for a billing event (public for surface overlay).
pub fn billing_token_count(v: &serde_json::Value) -> u64 {
    billing_event_tokens(v)
}

/// UTC ledger rollups from `billing_usage_events` for the authenticated account.
pub fn billing_ledger_totals(state: &SharedState, account_id: Option<&str>) -> BillingLedgerTotals {
    let cp = cost_position_from_ledger(state, account_id);
    let allow = connector_dev_mode();
    let mut all_time_tokens = 0u64;
    let mut all_time_cost_usd = 0.0f64;

    let keys = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(BILLING_EVENTS_NS, None).unwrap_or_default()
    };

    let es = state.engine_store.lock().unwrap();
    for k in keys {
        let Some(v) = es.folder_get(BILLING_EVENTS_NS, &k).ok().flatten() else {
            continue;
        };
        if let Some(want) = account_id {
            if !billing_event_matches_account(&v, want, allow) {
                continue;
            }
        }
        if parse_billing_ts(&v).is_none() {
            continue;
        }
        all_time_tokens = all_time_tokens.saturating_add(billing_event_tokens(&v));
        all_time_cost_usd += billing_event_cost_usd(&v);
    }

    BillingLedgerTotals {
        today_tokens: cp.today_tokens,
        today_cost_usd: cp.today_cost_usd,
        month_tokens: cp.month_tokens,
        month_cost_usd: cp.month_cost_usd,
        all_time_tokens,
        all_time_cost_usd,
    }
}

/// Recent billing rows (newest first) for timeline sections on Monitor surface.
pub fn recent_billing_events(
    state: &SharedState,
    account_id: Option<&str>,
    limit: usize,
) -> Vec<serde_json::Value> {
    let allow = connector_dev_mode();
    let mut recent: Vec<serde_json::Value> = Vec::new();
    let keys = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(BILLING_EVENTS_NS, None).unwrap_or_default()
    };
    let es = state.engine_store.lock().unwrap();
    for k in keys {
        let Some(v) = es.folder_get(BILLING_EVENTS_NS, &k).ok().flatten() else {
            continue;
        };
        if let Some(want) = account_id {
            if !billing_event_matches_account(&v, want, allow) {
                continue;
            }
        }
        if parse_billing_ts(&v).is_none() {
            continue;
        }
        recent.push(v);
    }
    recent.sort_by(|a, b| match (parse_billing_ts(a), parse_billing_ts(b)) {
        (Some(ta), Some(tb)) => tb.cmp(&ta),
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    });
    recent.truncate(limit);
    recent
}

// ── Auth helper ───────────────────────────────────────────────────────────────

fn caller(headers: &HeaderMap) -> Option<(String, PlatformRole)> {
    if std::env::var("CONNECTOR_DEV_MODE").is_ok() {
        return Some(("dev".to_string(), PlatformRole::SuperAdmin));
    }
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))?;
    let claims = verify_token(token).ok()?;
    Some((claims.sub, PlatformRole::from_str(&claims.role)))
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct JournalQueryParams {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    /// Output format: json (default), ocsf, jsonl
    pub format: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct CostsQueryParams {
    pub period: Option<String>,
    pub group_by: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ReceiptQueryParams {
    pub tier: Option<String>,
}

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
    pub meta: ApiMeta,
}

#[derive(Serialize)]
pub struct ApiMeta {
    pub tier: String,
    pub computed_at: String,
    pub t0_chain_verified: bool,
    pub reconciliation_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction_applied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_tier: Option<String>,
}

impl ApiMeta {
    /// Default envelope for Books JSON — does **not** claim cross-store reconciliation
    /// (REG-005 / control-beta honesty).
    fn t0() -> Self {
        Self {
            tier: "T0".to_string(),
            computed_at: chrono::Utc::now().to_rfc3339(),
            t0_chain_verified: false,
            reconciliation_status: "UNVERIFIED".to_string(),
            redaction_applied: None,
            access_tier: None,
        }
    }

    fn t2() -> Self {
        Self {
            tier: "T2".to_string(),
            computed_at: chrono::Utc::now().to_rfc3339(),
            t0_chain_verified: false,
            reconciliation_status: "UNVERIFIED".to_string(),
            redaction_applied: None,
            access_tier: None,
        }
    }

    fn with_access_tier(mut self, tier: &str) -> Self {
        self.access_tier = Some(tier.to_string());
        self
    }
}

// ── GET /books — System Position ─────────────────────────────────────────────

pub async fn get_system_position(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Gather stats from kernel (drop kernel lock before engine_store / ledger).
    let pending_approvals_count = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("pending_approvals", None)
            .map(|k| k.len())
            .unwrap_or(0)
    };

    let knot_entities = state.knot.lock().map(|k| k.node_count()).unwrap_or(0);

    let (resources, pending, chain_len, recent, chain_ok, trust_score, trust_grade) = {
        let kernel = state.kernel.lock().unwrap();
        // Real hash-chain check. Counts matching is a separate, weaker signal.
        let chain_ok = kernel.verify_audit_chain().is_ok();
        let trust = connector_engine::TrustComputer::compute(&kernel);
        let audit_log = kernel.audit_log();
        let packet_count = kernel.packet_count();

        let active_memory_bytes: u64 = kernel
            .all_packets()
            .iter()
            .map(|p| p.content.payload.to_string().len() as u64)
            .sum();

        let (mut running, mut suspended) = (0usize, 0usize);
        for (_, a) in kernel.agents().iter() {
            match a.status {
                vac_core::types::AgentStatus::Running => running += 1,
                vac_core::types::AgentStatus::Suspended => suspended += 1,
                _ => {}
            }
        }

        // A session with an end timestamp is closed, not active.
        let active_sessions = kernel
            .sessions()
            .values()
            .filter(|s| s.ended_at.is_none())
            .count();

        let resources = ResourcesHeld {
            active_memory_count: packet_count,
            active_memory_bytes,
            sealed_memory_count: None,
            sealed_memory_bytes: None,
            shared_memory_count: None,
            shared_memory_bytes: None,
            running_agents: running,
            paused_agents: None,
            suspended_agents: suspended,
            active_sessions,
            capabilities: None,
            knowledge_entities: knot_entities,
        };

        let pending = PendingObligations {
            pending_approvals: pending_approvals_count,
            pending_tool_results: 0,
            escrow_holds: 0,
        };

        let chain_len = audit_log.len() as u64;

        // Get recent entries (last 5)
        let recent: Vec<JournalEntry> = audit_log
            .iter()
            .rev()
            .take(5)
            .map(|e| JournalEntry::from(e))
            .collect();

        (
            resources,
            pending,
            chain_len,
            recent,
            chain_ok,
            trust.score,
            trust.grade,
        )
    };

    let t1_engine_audit = {
        let es = state.engine_store.lock().unwrap();
        es.audit_count().unwrap_or(0) as u64
    };
    let recon_ok = chain_len as u64 == t1_engine_audit;
    let integrity = IntegrityPosition {
        trust_score: trust_score.min(100) as u8,
        trust_grade,
        chain_length: chain_len,
        // The chain's own integrity, not the T0/T1 count match below: equal
        // counts survive an in-place edit, a broken hash link does not.
        chain_verified: chain_ok,
        last_reconciliation_ms: Some(now_ms),
        reconciliation_status: if recon_ok {
            "AUDIT_COUNTS_ALIGNED".to_string()
        } else {
            "AUDIT_COUNTS_MISMATCH".to_string()
        },
    };
    let recon_for_meta = integrity.reconciliation_status.clone();
    let chain_verified_for_meta = integrity.chain_verified;

    let cost = cost_position_from_ledger(&state, Some(&_caller.0));

    let position = SystemPosition {
        generated_at_ms: now_ms,
        resources,
        pending,
        integrity,
        cost,
        recent_entries: recent,
    };

    let mut meta = ApiMeta::t2();
    meta.t0_chain_verified = chain_verified_for_meta;
    meta.reconciliation_status = recon_for_meta;

    // P6.5 — unmetered peer honesty (never fake $0 for A2A/MCP hops without UsageReceipt).
    let unmetered_peer = crate::substrate::usage_receipt::unmetered_peer_honesty(state.as_ref());

    Json(serde_json::json!({
        "data": position,
        "meta": meta,
        "unmetered_peer": unmetered_peer,
        "usage_receipts": {
            "count": crate::substrate::usage_receipt::usage_receipt_count(state.as_ref()),
            "folder": crate::substrate::usage_receipt::USAGE_RECEIPTS_FOLDER,
            "honesty": "metered peer tokens require UsageReceipt; unavailable ≠ $0",
        },
    }))
    .into_response()
}

// ── GET /books/journal — General Journal ─────────────────────────────────────

pub async fn get_journal(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<JournalQueryParams>,
) -> Response {
    let _caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let limit = params.limit.unwrap_or(100).min(1000);
    let offset = params.offset.unwrap_or(0);

    let entries: Vec<JournalEntry> = {
        let kernel = state.kernel.lock().unwrap();
        let audit_entries = kernel.audit_log();

        audit_entries
            .iter()
            .rev() // Most recent first
            .skip(offset)
            .take(limit)
            .map(|e| JournalEntry::from(e))
            .filter(|e| {
                // Apply filters
                if let Some(ref actor) = params.actor {
                    if e.actor.id != *actor {
                        return false;
                    }
                }
                if let Some(ref outcome) = params.outcome {
                    let outcome_match = match outcome.to_lowercase().as_str() {
                        "cleared" => e.outcome == Outcome::Cleared,
                        "rejected" => e.outcome == Outcome::Rejected,
                        "failed" => e.outcome == Outcome::Failed,
                        "pending" => e.outcome == Outcome::Pending,
                        _ => true,
                    };
                    if !outcome_match {
                        return false;
                    }
                }
                true
            })
            .collect()
    };

    // Handle different output formats
    let format = params.format.as_deref().unwrap_or("json");

    match format {
        "ocsf" => {
            // Convert to OCSF 1.3.0 format for SIEM integration
            let kernel = state.kernel.lock().unwrap();
            let audit_entries = kernel.audit_log();
            let config = OcsfAdapterConfig::default();

            let ocsf_events: Vec<_> = audit_entries
                .iter()
                .rev()
                .skip(offset)
                .take(limit)
                .map(|e| to_ocsf(e, &config))
                .collect();

            let response = serde_json::json!({
                "schema": "ocsf",
                "version": "1.3.0",
                "class_uid": 1001,
                "class_name": "System Activity",
                "events": ocsf_events,
                "meta": {
                    "total": ocsf_events.len(),
                    "offset": offset,
                    "limit": limit,
                    "export_format": "ocsf_1.3.0",
                    "computed_at": chrono::Utc::now().to_rfc3339(),
                }
            });

            let mut resp = Json(response).into_response();
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json; schema=ocsf-1.3.0"),
            );
            resp
        }
        "jsonl" => {
            // JSONL format for streaming ingestion (Splunk, Datadog, etc.)
            let kernel = state.kernel.lock().unwrap();
            let audit_entries = kernel.audit_log();
            let config = OcsfAdapterConfig::default();

            let jsonl: String = audit_entries
                .iter()
                .rev()
                .skip(offset)
                .take(limit)
                .map(|e| {
                    let ocsf = to_ocsf(e, &config);
                    serde_json::to_string(&ocsf).unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join("\n");

            let mut resp = axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(axum::http::header::CONTENT_TYPE, "application/x-ndjson")
                .body(axum::body::Body::from(jsonl))
                .unwrap();
            resp
        }
        _ => {
            // Default JSON format
            #[derive(Serialize)]
            struct JournalResponse {
                entries: Vec<JournalEntry>,
                total: usize,
                offset: usize,
                limit: usize,
            }

            let response = ApiResponse {
                data: JournalResponse {
                    total: entries.len(),
                    entries,
                    offset,
                    limit,
                },
                meta: ApiMeta::t0(),
            };

            Json(response).into_response()
        }
    }
}

// ── GET /books/journal/:seq_no — Single Entry ────────────────────────────────

pub async fn get_journal_entry(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(seq_no): Path<u64>,
) -> Response {
    let _caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let entry: Option<JournalEntry> = {
        let kernel = state.kernel.lock().unwrap();
        kernel
            .audit_log()
            .iter()
            .find(|e| {
                e.audit_id
                    .strip_prefix("audit:")
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|id| id == seq_no)
                    .unwrap_or(false)
            })
            .map(|e| JournalEntry::from(e))
    };

    match entry {
        Some(e) => {
            let response = ApiResponse {
                data: e,
                meta: ApiMeta::t0(),
            };
            Json(response).into_response()
        }
        None => (StatusCode::NOT_FOUND, "Entry not found").into_response(),
    }
}

// ── GET /books/ledger/:account_id — Account Ledger ───────────────────────────

pub async fn get_ledger(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Query(params): Query<JournalQueryParams>,
) -> Response {
    let _caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let limit = params.limit.unwrap_or(1000);

    let entries: Vec<JournalEntry> = {
        let kernel = state.kernel.lock().unwrap();
        kernel
            .audit_log()
            .iter()
            .filter(|e| e.agent_pid == account_id || format!("agent:{}", e.agent_pid) == account_id)
            .take(limit)
            .map(|e| JournalEntry::from(e))
            .collect()
    };

    let account =
        AccountId::parse(&account_id).unwrap_or_else(|| AccountId::agent(&account_id, &account_id));

    let ledger = AccountLedger::from_entries(account, entries);

    let response = ApiResponse {
        data: ledger,
        meta: ApiMeta::t0(),
    };

    Json(response).into_response()
}

// ── GET /books/statement/:account_id — Full Statement ────────────────────────

pub async fn get_statement(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let _caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let entries: Vec<JournalEntry> = {
        let kernel = state.kernel.lock().unwrap();
        kernel
            .audit_log()
            .iter()
            .filter(|e| e.agent_pid == account_id || format!("agent:{}", e.agent_pid) == account_id)
            .map(|e| JournalEntry::from(e))
            .collect()
    };

    let account =
        AccountId::parse(&account_id).unwrap_or_else(|| AccountId::agent(&account_id, &account_id));

    let ledger = AccountLedger::from_entries(account, entries);
    let statement = AccountStatement::from_ledger(ledger);

    let response = ApiResponse {
        data: statement,
        meta: ApiMeta::t2(),
    };

    Json(response).into_response()
}

// ── GET /books/receipt/:seq_no — Transaction Receipt ─────────────────────────

#[derive(Serialize)]
pub struct Receipt {
    pub entry: JournalEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_context: Option<DecisionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<CostInfo>,
    pub causal_chain: Vec<CausalRef>,
    pub downstream: Vec<DownstreamRef>,
}

#[derive(Serialize)]
pub struct DecisionContext {
    pub system_prompt: Option<String>,
    pub retrieved_memories: Vec<MemoryRef>,
    pub tool_parameters: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct MemoryRef {
    pub cid: String,
    pub label: Option<String>,
    pub size_bytes: Option<u64>,
}

#[derive(Serialize)]
pub struct ResultInfo {
    pub status: String,
    pub returned_size_bytes: Option<u64>,
    pub deposited_as: Option<DepositRef>,
    pub content_preview: Option<String>,
}

#[derive(Serialize)]
pub struct DepositRef {
    pub cid: String,
    pub entry_seq: Option<u64>,
}

#[derive(Serialize)]
pub struct CostInfo {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub model: Option<String>,
    pub cost_usd: Option<f64>,
    pub computed_at: String,
}

#[derive(Serialize)]
pub struct CausalRef {
    pub seq_no: u64,
    pub action: String,
    pub actor: Option<String>,
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct DownstreamRef {
    pub seq_no: u64,
    pub actor: String,
    pub action: String,
}

pub async fn get_receipt(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(seq_no): Path<u64>,
    Query(params): Query<ReceiptQueryParams>,
) -> Response {
    let (caller_id, role) = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let access_tier = params.tier.as_deref().unwrap_or("standard");

    // Check access tier permissions
    let allowed = match access_tier {
        "summary" => true,
        "standard" => true,
        "detailed" => matches!(role, PlatformRole::Admin | PlatformRole::SuperAdmin),
        "privileged" => matches!(role, PlatformRole::SuperAdmin),
        _ => false,
    };

    if !allowed {
        return (StatusCode::FORBIDDEN, "Insufficient access tier").into_response();
    }

    let entry: Option<JournalEntry> = {
        let kernel = state.kernel.lock().unwrap();
        kernel
            .audit_log()
            .iter()
            .find(|e| {
                e.audit_id
                    .strip_prefix("audit:")
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|id| id == seq_no)
                    .unwrap_or(false)
            })
            .map(|e| JournalEntry::from(e))
    };

    let entry = match entry {
        Some(e) => e,
        None => return (StatusCode::NOT_FOUND, "Entry not found").into_response(),
    };

    // Build causal chain from causal_refs
    let causal_chain: Vec<CausalRef> = entry
        .causal_refs
        .iter()
        .filter_map(|r| {
            r.strip_prefix("je:")
                .and_then(|s| s.parse::<u64>().ok())
                .map(|seq| CausalRef {
                    seq_no: seq,
                    action: "Unknown".to_string(),
                    actor: None,
                    note: None,
                })
        })
        .collect();

    let receipt = Receipt {
        entry,
        decision_context: if access_tier == "detailed" || access_tier == "privileged" {
            Some(DecisionContext {
                system_prompt: Some("[TRUNCATED]".to_string()),
                retrieved_memories: vec![],
                tool_parameters: None,
            })
        } else {
            None
        },
        result: None,
        cost: Some(CostInfo {
            input_tokens: None,
            output_tokens: None,
            model: None,
            cost_usd: None,
            computed_at: chrono::Utc::now().to_rfc3339(),
        }),
        causal_chain,
        downstream: vec![],
    };

    let response = ApiResponse {
        data: receipt,
        meta: ApiMeta::t0().with_access_tier(access_tier),
    };

    Json(response).into_response()
}

// ── GET /books/costs — Cost Statement ────────────────────────────────────────

#[derive(Serialize)]
pub struct CostStatement {
    /// Authenticated account (`sub`) this roll-up is scoped to.
    pub account_id: String,
    /// When `true`, dev mode is on and legacy billing rows without `account_id` may be included in totals.
    pub includes_untagged_legacy_events: bool,
    pub period: String,
    pub by_agent: Vec<AgentCost>,
    pub by_model: Vec<ModelCost>,
    pub by_tool: Vec<ToolCost>,
    pub total_tokens: u64,
    pub total_duration_ms: u64,
    pub total_cost_usd: f64,
    /// Provenance for `total_cost_usd` (estimated from engine price table + API token counts—not a tax invoice).
    pub cost_basis: String,
    pub recent_events: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct AgentCost {
    pub agent_id: String,
    pub display_name: String,
    pub tokens: u64,
    pub duration_ms: u64,
    pub cost_usd: f64,
}

#[derive(Serialize)]
pub struct ModelCost {
    pub model_id: String,
    pub tokens: u64,
    pub duration_ms: u64,
    pub cost_usd: f64,
}

#[derive(Serialize)]
pub struct ToolCost {
    pub tool_id: String,
    pub calls: u64,
    pub duration_ms: u64,
    pub cost_usd: f64,
}

pub async fn get_costs(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<CostsQueryParams>,
) -> Response {
    let caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };
    let account_id = caller.0.as_str();
    let allow_untagged = connector_dev_mode();

    let period = params.period.as_deref().unwrap_or("month");

    let keys = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(BILLING_EVENTS_NS, None).unwrap_or_default()
    };

    let mut by_agent: HashMap<String, (u64, f64)> = HashMap::new();
    let mut by_model: HashMap<String, (u64, f64)> = HashMap::new();
    let mut by_tool: HashMap<String, (u64, u64, f64)> = HashMap::new();
    let mut total_tokens = 0u64;
    let mut total_cost_usd = 0.0f64;
    let mut recent: Vec<serde_json::Value> = Vec::new();

    {
        let es = state.engine_store.lock().unwrap();
        for k in keys {
            let Some(v) = es.folder_get(BILLING_EVENTS_NS, &k).ok().flatten() else {
                continue;
            };
            if !billing_event_matches_account(&v, account_id, allow_untagged) {
                continue;
            }
            let Some(ts) = parse_billing_ts(&v) else {
                continue;
            };
            if !billing_event_in_period(&ts, period) {
                continue;
            }

            let ev_type = v.get("event_type").and_then(|x| x.as_str()).unwrap_or("");
            let tok = billing_event_tokens(&v);
            let usd = billing_event_cost_usd(&v);
            total_tokens = total_tokens.saturating_add(tok);
            total_cost_usd += usd;

            let agent = v
                .get("agent_pid")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            let ae = by_agent.entry(agent).or_insert((0, 0.0));
            ae.0 = ae.0.saturating_add(tok);
            ae.1 += usd;

            match ev_type {
                "llm_completion" => {
                    let mid = v
                        .get("model_routed")
                        .and_then(|x| x.as_str())
                        .or_else(|| v.get("model_requested").and_then(|x| x.as_str()))
                        .unwrap_or("unknown")
                        .to_string();
                    let me = by_model.entry(mid).or_insert((0, 0.0));
                    me.0 = me.0.saturating_add(tok);
                    me.1 += usd;
                }
                "tool_call" => {
                    let tid = v
                        .get("tool_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let te = by_tool.entry(tid).or_insert((0, 0, 0.0));
                    te.0 += 1;
                    te.1 = te.1.saturating_add(tok);
                    te.2 += usd;
                }
                _ => {
                    let mid = "manual_or_legacy".to_string();
                    let me = by_model.entry(mid).or_insert((0, 0.0));
                    me.0 = me.0.saturating_add(tok);
                    me.1 += usd;
                }
            }

            recent.push(v);
        }
    }

    recent.sort_by(|a, b| match (parse_billing_ts(a), parse_billing_ts(b)) {
        (Some(ta), Some(tb)) => tb.cmp(&ta),
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    });
    recent.truncate(100);

    let mut by_agent_v: Vec<AgentCost> = by_agent
        .into_iter()
        .map(|(agent_id, (tokens, cost_usd))| AgentCost {
            agent_id: agent_id.clone(),
            display_name: agent_id,
            tokens,
            duration_ms: 0,
            cost_usd,
        })
        .collect();
    by_agent_v.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let mut by_model_v: Vec<ModelCost> = by_model
        .into_iter()
        .map(|(model_id, (tokens, cost_usd))| ModelCost {
            model_id,
            tokens,
            duration_ms: 0,
            cost_usd,
        })
        .collect();
    by_model_v.sort_by(|a, b| b.tokens.cmp(&a.tokens));

    let mut by_tool_v: Vec<ToolCost> = by_tool
        .into_iter()
        .map(|(tool_id, (calls, _tokens_charged, cost_usd))| ToolCost {
            tool_id,
            calls,
            duration_ms: 0,
            cost_usd,
        })
        .collect();
    by_tool_v.sort_by(|a, b| b.calls.cmp(&a.calls));

    let has_usage_data = !recent.is_empty() || total_tokens > 0;

    let cost_statement = CostStatement {
        account_id: caller.0.clone(),
        includes_untagged_legacy_events: allow_untagged,
        period: period.to_string(),
        by_agent: by_agent_v,
        by_model: by_model_v,
        by_tool: by_tool_v,
        total_tokens,
        total_duration_ms: 0,
        total_cost_usd,
        cost_basis: "USD for llm_completion rows are estimated from connector-engine llm_router per-million list × (input_tokens+output_tokens) reported by the provider SDK. Stub/no-router paths use heuristics ($0). Not a supplier invoice.".to_string(),
        recent_events: recent,
    };

    let mut meta = ApiMeta::t2();
    if !has_usage_data {
        meta.reconciliation_status = "NO_USAGE_DATA".to_string();
    }

    let mut response = serde_json::to_value(ApiResponse {
        data: cost_statement,
        meta,
    })
    .unwrap_or(serde_json::json!({}));

    if !has_usage_data {
        if let Some(data) = response.get_mut("data") {
            data["total_cost_usd"] = serde_json::Value::Null;
            data["total_tokens"] = serde_json::Value::Null;
            data["total_duration_ms"] = serde_json::Value::Null;
        }
        if let Some(meta) = response.get_mut("meta") {
            meta["has_usage_data"] = serde_json::json!(false);
            meta["honesty_note"] = serde_json::json!(
                "No billing events in period — totals are unavailable, not zero."
            );
        }
    } else if let Some(meta) = response.get_mut("meta") {
        meta["has_usage_data"] = serde_json::json!(true);
    }

    Json(response).into_response()
}

// ── GET /books/balance — Reconciliation Balance ──────────────────────────────

#[derive(Serialize)]
pub struct ReconciliationBalance {
    pub checks: Vec<BalanceCheck>,
    pub verdict: String,
    pub last_run_ms: i64,
    pub next_scheduled_ms: Option<i64>,
}

#[derive(Serialize)]
pub struct BalanceCheck {
    pub metric: String,
    pub t0_value: String,
    pub t1_value: String,
    pub status: String,
}

pub async fn get_balance(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let (t0_count, t1_count) = {
        let kernel = state.kernel.lock().unwrap();
        let es = state.engine_store.lock().unwrap();
        let t0 = kernel.audit_log().len() as u64;
        let t1 = es.audit_count().unwrap_or(0) as u64;
        (t0, t1)
    };

    let balance = ReconciliationBalance {
        checks: vec![BalanceCheck {
            metric: "Journal entry count".to_string(),
            t0_value: t0_count.to_string(),
            t1_value: t1_count.to_string(),
            status: if t0_count == t1_count {
                "MATCH"
            } else {
                "DIVERGED"
            }
            .to_string(),
        }],
        verdict: if t0_count == t1_count {
            "BOOKS RECONCILE"
        } else {
            "DIVERGED"
        }
        .to_string(),
        last_run_ms: now_ms,
        next_scheduled_ms: Some(now_ms + 600_000), // 10 minutes
    };

    let response = ApiResponse {
        data: balance,
        meta: ApiMeta::t2(),
    };

    Json(response).into_response()
}

// ── GET /books/live — SSE Event Stream ───────────────────────────────────────

pub async fn get_live_stream(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let _caller = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    // Create a stream that polls the kernel audit log
    let stream = async_stream::stream! {
        let mut last_seq = 0u64;
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            let entries: Vec<JournalEntry> = {
                let kernel = state.kernel.lock().unwrap();
                kernel
                    .audit_log()
                    .iter()
                    .rev()
                    .take(10)
                    .map(|e| JournalEntry::from(e))
                    .filter(|e| e.seq_no > last_seq)
                    .collect()
            };

            for entry in entries {
                last_seq = last_seq.max(entry.seq_no);
                let json = serde_json::to_string(&entry).unwrap_or_default();
                yield Ok::<_, Infallible>(Event::default().data(json));
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── POST /books/reconcile — Run Reconciliation ───────────────────────────────

pub async fn run_reconciliation(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    // Require Admin role
    if !matches!(role, PlatformRole::Admin | PlatformRole::SuperAdmin) {
        return (StatusCode::FORBIDDEN, "Admin role required").into_response();
    }

    let (t0_entries, t1_entries): (Vec<JournalEntry>, Vec<JournalEntry>) = {
        let kernel = state.kernel.lock().unwrap();
        let es = state.engine_store.lock().unwrap();

        let t0: Vec<JournalEntry> = kernel
            .audit_log()
            .iter()
            .map(|e| JournalEntry::from(e))
            .collect();

        // Query engine store with empty filter to get all entries
        let filter = connector_engine::engine_store::AuditFilter::default();
        let t1: Vec<JournalEntry> = es
            .query_audit(&filter)
            .unwrap_or_default()
            .iter()
            .map(|e| JournalEntry::from(e))
            .collect();

        (t0, t1)
    };

    let report = ReconciliationReport::new(&t0_entries, &t1_entries);

    let response = ApiResponse {
        data: report,
        meta: ApiMeta::t2(),
    };

    Json(response).into_response()
}

// ── POST /books/close/:session_id — Close Session Books ──────────────────────

#[derive(Serialize)]
pub struct CloseSessionResult {
    pub session_id: String,
    /// `None` when the kernel has no envelope for this id — the close still
    /// succeeded, but there is no start time to report.
    pub session_found: bool,
    pub opened_at_ms: Option<i64>,
    pub closed_at_ms: i64,
    pub duration_ms: Option<u64>,
    pub entry_count: usize,
    pub cleared_count: usize,
    pub rejected_count: usize,
    pub failed_count: usize,
    /// Not metered per session yet — reported as null rather than 0.
    pub memory_net_bytes: Option<f64>,
    pub tokens_total: u64,
    pub cost_usd: f64,
    pub cost_usd_real: f64,
    /// `provider_pricing` only when every contributing event carried real
    /// provider pricing; otherwise the total contains estimates.
    pub cost_source: String,
    /// How many metered events backed the totals. Zero means "nothing was
    /// recorded for this session", not "this session was free".
    pub usage_events: usize,
    pub trust_at_close: Option<u32>,
    pub trust_grade_at_close: Option<String>,
    pub reconciliation_status: String,
    pub final_merkle_root: Option<String>,
    pub scitt_receipt_cid: Option<String>,
}

pub async fn close_session(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Response {
    let (_, role) = match caller(&headers) {
        Some(c) => c,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    // Require Admin role
    if !matches!(role, PlatformRole::Admin | PlatformRole::SuperAdmin) {
        return (StatusCode::FORBIDDEN, "Admin role required").into_response();
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    // Read the envelope before closing — the close may drop it.
    let session_meta: Option<(i64, String, usize)> = {
        let kernel = state.kernel.lock().unwrap();
        kernel.sessions().get(&session_id).map(|s| {
            (
                s.started_at,
                s.agent_id.clone(),
                s.packet_cids.len(),
            )
        })
    };

    let close_outcome = {
        let mut kernel = state.kernel.lock().unwrap();
        kernel
            .dispatch(SyscallRequest {
                agent_pid: "system".to_string(),
                operation: MemoryKernelOp::SessionClose,
                payload: SyscallPayload::SessionClose {
                    session_id: session_id.clone(),
                },
                reason: Some("books close_session".to_string()),
                vakya_id: None,
                trace_parent: None,
                trace_state: None,
                api_version: None,
            })
            .outcome
    };

    if !matches!(close_outcome, OpOutcome::Success | OpOutcome::Skipped) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "session_close_failed",
                "outcome": format!("{:?}", close_outcome),
                "session_id": session_id,
            })),
        )
            .into_response();
    }

    let opened_at_ms = session_meta.as_ref().map(|(started, _, _)| *started);
    let duration_ms = opened_at_ms.map(|o| now_ms.saturating_sub(o).max(0) as u64);

    // Kernel operations attributable to this session: the owning agent, within
    // the session's own lifetime.
    let (entry_count, cleared_count, rejected_count, failed_count, trust, chain_len) = {
        let kernel = state.kernel.lock().unwrap();
        let trust = connector_engine::TrustComputer::compute(&kernel);
        let chain_len = kernel.audit_log().len() as u64;
        let (mut total, mut cleared, mut rejected, mut failed) = (0usize, 0usize, 0usize, 0usize);
        if let Some((started, agent_id, _)) = session_meta.as_ref() {
            for e in kernel.audit_log().iter() {
                if e.agent_pid != *agent_id || e.timestamp < *started || e.timestamp > now_ms {
                    continue;
                }
                total += 1;
                match e.outcome {
                    OpOutcome::Success | OpOutcome::Skipped => cleared += 1,
                    OpOutcome::Denied => rejected += 1,
                    OpOutcome::Failed => failed += 1,
                    OpOutcome::Pending => {}
                }
            }
        }
        (total, cleared, rejected, failed, trust, chain_len)
    };

    // Metered spend for this session, from the same events the ledger reads.
    let (tokens_total, cost_usd, cost_usd_real, usage_events, all_real) = {
        let es = state.engine_store.lock().unwrap();
        let keys = es.folder_keys(BILLING_EVENTS_NS, None).unwrap_or_default();
        let (mut tokens, mut est, mut real, mut n, mut all_real) = (0u64, 0.0f64, 0.0f64, 0usize, true);
        for k in keys {
            let Ok(Some(v)) = es.folder_get(BILLING_EVENTS_NS, &k) else {
                continue;
            };
            if v.get("session_id").and_then(|x| x.as_str()) != Some(session_id.as_str()) {
                continue;
            }
            n += 1;
            tokens += billing_event_tokens(&v);
            est += billing_event_cost_usd(&v);
            real += v
                .get("cost_usd_real")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0);
            if v.get("is_real_cost").and_then(|x| x.as_bool()) != Some(true) {
                all_real = false;
            }
        }
        (tokens, est, real, n, all_real)
    };

    let t1_engine_audit = {
        let es = state.engine_store.lock().unwrap();
        es.audit_count().unwrap_or(0) as u64
    };

    let result = CloseSessionResult {
        session_id: session_id.clone(),
        session_found: session_meta.is_some(),
        opened_at_ms,
        closed_at_ms: now_ms,
        duration_ms,
        entry_count,
        cleared_count,
        rejected_count,
        failed_count,
        memory_net_bytes: None,
        tokens_total,
        cost_usd,
        cost_usd_real,
        cost_source: if usage_events == 0 {
            "no_metered_events".to_string()
        } else if all_real {
            "provider_pricing".to_string()
        } else {
            "estimated_or_stub".to_string()
        },
        usage_events,
        trust_at_close: Some(trust.score),
        trust_grade_at_close: Some(trust.grade.clone()),
        reconciliation_status: if chain_len == t1_engine_audit {
            "AUDIT_COUNTS_ALIGNED".to_string()
        } else {
            "AUDIT_COUNTS_MISMATCH".to_string()
        },
        final_merkle_root: None,
        scitt_receipt_cid: None,
    };

    let response = ApiResponse {
        data: result,
        meta: ApiMeta::t2(),
    };

    Json(response).into_response()
}
