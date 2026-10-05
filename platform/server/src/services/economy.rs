//! # Agent Economy Service — Escrow, Pricing, Reputation, Negotiation
//!
//! Surfaces four OSS primitives as a unified agent economy:
//!   - `connector_engine::escrow::EscrowManager` — trustless payment
//!   - `connector_engine::pricing::DynamicPricer` — surge/volume/budget
//!   - `connector_engine::reputation::ReputationEngine` — EigenTrust
//!   - `connector_engine::negotiation::NegotiationManager` — contract negotiation
//!
//! Routes:
//!   POST /economy/deposit              — deposit funds
//!   GET  /economy/balance/{pid}        — agent balance
//!   POST /economy/escrow/lock          — lock funds for invocation
//!   POST /economy/escrow/{id}/release  — release on success
//!   POST /economy/escrow/{id}/slash    — slash on SLA violation
//!   POST /economy/escrow/{id}/dispute  — open dispute
//!   GET  /economy/escrow/{id}          — escrow status
//!   GET  /economy/settlements          — settlement history
//!   POST /economy/quote                — get dynamic price quote
//!   POST /economy/budget-gate          — set agent budget gate
//!   GET  /economy/budget-gate/{pid}    — check budget status
//!   POST /economy/reputation/stake     — register agent stake
//!   POST /economy/reputation/feedback  — submit feedback
//!   POST /economy/reputation/slash/{pid} — slash reputation
//!   GET  /economy/reputation/scores    — all reputation scores
//!   GET  /economy/reputation/scores/{pid} — single agent score
//!   POST /economy/negotiate/propose    — propose terms
//!   POST /economy/negotiate/{id}/counter — counter-propose
//!   POST /economy/negotiate/{id}/accept  — accept terms
//!   POST /economy/negotiate/{id}/reject  — reject terms
//!   GET  /economy/negotiate/{id}       — negotiation status
//!   GET  /economy/negotiate            — list negotiations

use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::negotiation::NegotiationTerms;
use connector_engine::reputation::Feedback;
use serde::Deserialize;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// FIX BUG-017: Add authentication helper for economy endpoints
fn require_auth(headers: &axum::http::HeaderMap) -> Result<String, Json<serde_json::Value>> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok("dev".to_string());
    }
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    match token {
        Some(t) => match crate::auth::verify_token(t) {
            Ok(claims) => Ok(claims.sub),
            Err(_) => Err(Json(
                serde_json::json!({"error": "Invalid token", "status": 401}),
            )),
        },
        None => Err(Json(
            serde_json::json!({"error": "Authentication required", "status": 401}),
        )),
    }
}

// ── Escrow ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DepositRequest {
    pub agent_pid: String,
    pub amount: u64,
}

pub async fn deposit(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DepositRequest>,
) -> Json<serde_json::Value> {
    // FIX BUG-017: Require authentication
    if let Err(e) = require_auth(&headers) {
        return e;
    }

    let mut em = state.escrow.lock().unwrap();
    em.deposit(&req.agent_pid, req.amount);
    let bal = em.balance(&req.agent_pid);
    Json(
        serde_json::json!({"ok": true, "agent_pid": req.agent_pid, "deposited": req.amount, "balance": bal}),
    )
}

pub async fn balance(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    // FIX BUG-017: Require authentication
    if let Err(e) = require_auth(&headers) {
        return e;
    }

    let em = state.escrow.lock().unwrap();
    Json(serde_json::json!({"agent_pid": pid, "balance": em.balance(&pid)}))
}

#[derive(Deserialize)]
pub struct LockRequest {
    pub requester_pid: String,
    pub provider_pid: String,
    pub amount: u64,
    pub contract_id: String,
    pub ttl_ms: Option<i64>,
}

pub async fn escrow_lock(
    State(state): State<SharedState>,
    Json(req): Json<LockRequest>,
) -> Json<serde_json::Value> {
    let mut em = state.escrow.lock().unwrap();
    let ttl = req.ttl_ms.unwrap_or(3_600_000);
    match em.lock(
        &req.requester_pid,
        &req.provider_pid,
        req.amount,
        &req.contract_id,
        now_ms(),
        ttl,
    ) {
        Ok(id) => Json(
            serde_json::json!({"ok": true, "escrow_id": id, "amount": req.amount, "locked_at": now_iso()}),
        ),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn escrow_release(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut em = state.escrow.lock().unwrap();
    match em.release(&id, now_ms()) {
        Ok(settlement) => Json(serde_json::json!({
            "ok": true, "escrow_id": id, "to_provider": settlement.to_provider,
            "settled_at": now_iso(),
        })),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn escrow_slash(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut em = state.escrow.lock().unwrap();
    match em.slash(&id, 1.0, "sla-violation", now_ms()) {
        Ok(settlement) => Json(serde_json::json!({
            "ok": true, "escrow_id": id, "slashed": settlement.slashed,
            "to_requester": settlement.to_requester, "settled_at": now_iso(),
        })),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn escrow_dispute(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut em = state.escrow.lock().unwrap();
    match em.dispute(&id, "user-initiated") {
        Ok(_) => Json(
            serde_json::json!({"ok": true, "escrow_id": id, "state": "Disputed", "disputed_at": now_iso()}),
        ),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn escrow_status(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let em = state.escrow.lock().unwrap();
    match em.get_escrow(&id) {
        Some(e) => Json(serde_json::json!({
            "escrow_id": e.escrow_id, "requester_pid": e.requester_pid,
            "provider_pid": e.provider_pid, "amount": e.amount,
            "state": format!("{:?}", e.state), "contract_id": e.contract_id,
            "created_at": e.created_at, "expires_at": e.expires_at,
        })),
        None => Json(serde_json::json!({"error": "Escrow not found", "status": 404})),
    }
}

pub async fn settlements(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let em = state.escrow.lock().unwrap();
    Json(serde_json::json!({
        "settlement_count": em.settlement_count(),
        "active_escrow_count": em.active_escrow_count(),
        "total_locked": em.total_locked(),
        "settlements": em.all_settlements(),
    }))
}

// ── Dynamic Pricing ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct QuoteRequest {
    pub requester_pid: String,
    pub provider_pid: String,
    pub base_cost: u64,
}

pub async fn price_quote(
    State(state): State<SharedState>,
    Json(req): Json<QuoteRequest>,
) -> Json<serde_json::Value> {
    let mut pr = state.pricer.lock().unwrap();
    let quote = pr.quote(
        &req.requester_pid,
        &req.provider_pid,
        req.base_cost,
        now_ms(),
    );
    Json(serde_json::json!({
        "base_cost": quote.base_cost, "surge_multiplier": quote.surge_multiplier,
        "volume_discount_pct": quote.volume_discount_pct, "final_cost": quote.final_cost,
        "budget_remaining": quote.budget_remaining, "budget_exceeded": quote.budget_exceeded,
    }))
}

#[derive(Deserialize)]
pub struct BudgetGateRequest {
    pub agent_pid: String,
    pub max_spend: u64,
    pub window_duration_ms: Option<i64>,
}

pub async fn set_budget_gate(
    State(state): State<SharedState>,
    Json(req): Json<BudgetGateRequest>,
) -> Json<serde_json::Value> {
    let mut pr = state.pricer.lock().unwrap();
    let window = req.window_duration_ms.unwrap_or(86_400_000);
    pr.set_budget(&req.agent_pid, req.max_spend, window, now_ms());
    Json(
        serde_json::json!({"ok": true, "agent_pid": req.agent_pid, "max_spend": req.max_spend, "window_ms": window}),
    )
}

/// DI-5 — economy pricer gate for gateway completions (None = no gate / not exceeded).
pub fn economy_budget_gate_violation(
    state: &crate::state::PlatformState,
    agent_pid: &str,
) -> Option<(u64, u64, u64)> {
    let pr = state.pricer.lock().ok()?;
    let bg = pr.get_budget(agent_pid)?;
    if bg.is_exceeded() {
        Some((bg.spent, bg.max_spend, bg.remaining()))
    } else {
        None
    }
}

pub async fn budget_gate_status(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let pr = state.pricer.lock().unwrap();
    match pr.get_budget(&pid) {
        Some(bg) => Json(serde_json::json!({
            "agent_pid": bg.agent_pid, "max_spend": bg.max_spend, "spent": bg.spent,
            "remaining": bg.remaining(), "exceeded": bg.is_exceeded(),
        })),
        None => Json(serde_json::json!({"agent_pid": pid, "budget_gate": null})),
    }
}

// ── Reputation ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StakeRequest {
    pub agent_pid: String,
    pub stake: u64,
}

pub async fn register_stake(
    State(state): State<SharedState>,
    Json(req): Json<StakeRequest>,
) -> Json<serde_json::Value> {
    let mut rep = state.reputation.lock().unwrap();
    rep.register_stake(&req.agent_pid, req.stake);
    Json(serde_json::json!({"ok": true, "agent_pid": req.agent_pid, "stake": req.stake}))
}

#[derive(Deserialize)]
pub struct FeedbackRequest {
    pub from: String,
    pub to: String,
    pub score: f64,
    pub invocation_id: Option<String>,
}

pub async fn submit_feedback(
    State(state): State<SharedState>,
    Json(req): Json<FeedbackRequest>,
) -> Json<serde_json::Value> {
    let mut rep = state.reputation.lock().unwrap();
    let fb = Feedback {
        from: req.from.clone(),
        to: req.to.clone(),
        score: req.score,
        weight: 1.0,
        timestamp_ms: now_ms(),
        invocation_id: req.invocation_id,
    };
    match rep.submit_feedback(fb) {
        Ok(_) => Json(
            serde_json::json!({"ok": true, "from": req.from, "to": req.to, "score": req.score}),
        ),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn reputation_slash(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let mut rep = state.reputation.lock().unwrap();
    rep.slash(&pid, 100);
    Json(serde_json::json!({"ok": true, "agent_pid": pid, "slashed_at": now_iso()}))
}

pub async fn reputation_scores(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let rep = state.reputation.lock().unwrap();
    let scores = rep.compute(now_ms());
    let items: Vec<serde_json::Value> = scores
        .iter()
        .map(|s| {
            serde_json::json!({
                "agent_pid": s.agent_pid, "global_score": s.global_score,
                "feedback_count": s.feedback_count, "stake": s.stake,
                "slashed_count": s.slashed_count,
            })
        })
        .collect();
    Json(serde_json::json!({"agent_count": items.len(), "scores": items}))
}

pub async fn reputation_score(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let rep = state.reputation.lock().unwrap();
    let scores = rep.compute(now_ms());
    match scores.iter().find(|s| s.agent_pid == pid) {
        Some(s) => Json(serde_json::json!({
            "agent_pid": s.agent_pid, "global_score": s.global_score,
            "feedback_count": s.feedback_count, "stake": s.stake,
            "slashed_count": s.slashed_count,
        })),
        None => Json(
            serde_json::json!({"agent_pid": pid, "global_score": 0.0, "note": "No reputation data"}),
        ),
    }
}

// ── Negotiation ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ProposeRequest {
    pub requester_pid: String,
    pub provider_pid: String,
    pub capability_key: String,
    pub max_latency_ms: u64,
    pub availability_pct: f64,
    pub cost_per_call: u64,
    pub stake_amount: u64,
    pub ttl_ms: Option<i64>,
}

pub async fn negotiate_propose(
    State(state): State<SharedState>,
    Json(req): Json<ProposeRequest>,
) -> Json<serde_json::Value> {
    let mut nm = state.negotiation.lock().unwrap();
    let terms = NegotiationTerms {
        max_latency_ms: req.max_latency_ms,
        availability_pct: req.availability_pct,
        cost_per_call: req.cost_per_call,
        stake_amount: req.stake_amount,
        ttl_ms: req.ttl_ms.unwrap_or(3_600_000),
    };
    let id = nm.propose(
        &req.requester_pid,
        &req.provider_pid,
        &req.capability_key,
        terms,
        now_ms(),
    );
    Json(
        serde_json::json!({"ok": true, "negotiation_id": id, "state": "Open", "proposed_at": now_iso()}),
    )
}

pub async fn negotiate_counter(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(req): Json<ProposeRequest>,
) -> Json<serde_json::Value> {
    let mut nm = state.negotiation.lock().unwrap();
    let terms = NegotiationTerms {
        max_latency_ms: req.max_latency_ms,
        availability_pct: req.availability_pct,
        cost_per_call: req.cost_per_call,
        stake_amount: req.stake_amount,
        ttl_ms: req.ttl_ms.unwrap_or(3_600_000),
    };
    match nm.counter_propose(&id, &req.provider_pid, terms, None, now_ms()) {
        Ok(_) => {
            Json(serde_json::json!({"ok": true, "negotiation_id": id, "state": "CounterProposed"}))
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn negotiate_accept(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut nm = state.negotiation.lock().unwrap();
    match nm.accept(&id, &String::new(), now_ms()) {
        Ok(terms) => Json(serde_json::json!({
            "ok": true, "negotiation_id": id, "state": "Accepted",
            "final_terms": {"max_latency_ms": terms.max_latency_ms, "availability_pct": terms.availability_pct,
                "cost_per_call": terms.cost_per_call, "stake_amount": terms.stake_amount},
        })),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn negotiate_reject(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let mut nm = state.negotiation.lock().unwrap();
    match nm.reject(&id, &String::new(), None, now_ms()) {
        Ok(_) => Json(serde_json::json!({"ok": true, "negotiation_id": id, "state": "Rejected"})),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

pub async fn negotiate_status(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let nm = state.negotiation.lock().unwrap();
    match nm.get(&id) {
        Some(n) => {
            let rounds: Vec<serde_json::Value> = n.rounds.iter().map(|r| serde_json::json!({
                "round": r.round, "from": r.from, "timestamp_ms": r.timestamp_ms,
                "terms": {"max_latency_ms": r.terms.max_latency_ms, "cost_per_call": r.terms.cost_per_call},
            })).collect();
            Json(serde_json::json!({
                "negotiation_id": n.negotiation_id, "requester_pid": n.requester_pid,
                "provider_pid": n.provider_pid, "state": format!("{:?}", n.state),
                "round_count": n.rounds.len(), "rounds": rounds,
            }))
        }
        None => Json(serde_json::json!({"error": "Negotiation not found", "status": 404})),
    }
}

pub async fn negotiate_list(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let nm = state.negotiation.lock().unwrap();
    let negotiations: Vec<serde_json::Value> = nm
        .list()
        .into_iter()
        .map(|n| {
            serde_json::json!({
                "negotiation_id": n.negotiation_id,
                "requester_pid": n.requester_pid,
                "provider_pid": n.provider_pid,
                "capability_key": n.capability_key,
                "state": format!("{:?}", n.state),
                "round_count": n.rounds.len(),
                "created_at": n.created_at,
                "expires_at": n.expires_at,
                "resolved_at": n.resolved_at,
            })
        })
        .collect();
    Json(serde_json::json!({
        "count": negotiations.len(),
        "active_count": nm.active_count(),
        "negotiations": negotiations,
    }))
}
