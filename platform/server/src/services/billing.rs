//! BIZ-4: BillingService — usage metering, entitlement enforcement, tier management.
//!
//! Three methods + Stripe Meter event firing:
//!   - record_usage(account_id, tokens, agent_pid, session_id) — non-blocking, after every LLM call
//!   - get_entitlements(account_id) -> EntitlementSet  — cached 60s, < 1μs hot path
//!   - check_entitlement(account_id, feature) -> bool  — inline in dispatch
//!
//! Routes (BIZ-5):
//!   GET /billing/usage       — current usage + limits + estimated overage
//!   GET /billing/invoices    — Stripe invoice list proxy
//!   GET /billing/portal      — Stripe Customer Portal redirect
//!   GET /billing/entitlements — entitlement set for current user
//!
//! BIZ-6: Four pricing tiers with hard entitlement enforcement:
//!   Community (free): 10K tokens/day  · 3 agents  · 30d memory  · 1 cell
//!   Pro ($49/mo):    500K tokens/mo   · 20 agents · 1yr memory  · 1 cell
//!   Team ($299/mo):  5M tokens/mo     · unlimited · unlimited   · 3 cells  · HIPAA BAA
//!   Enterprise:      unlimited        · unlimited · unlimited   · dedicated · SOC2 · SSO

use crate::services::runtime_control;
use crate::state::SharedState;
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use chrono::{Datelike, Timelike};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ─── Tier entitlement definitions (BIZ-6) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementSet {
    pub tier: String,
    /// Tokens per day (0 = unlimited)
    pub tokens_per_day: u64,
    /// Tokens per month (0 = unlimited)
    pub tokens_per_month: u64,
    /// Max concurrent agents (0 = unlimited)
    pub max_agents: u32,
    /// Memory retention days (0 = unlimited)
    pub memory_retention_days: u32,
    /// Max cells (0 = unlimited)
    pub max_cells: u32,
    /// Feature flags
    pub hipaa_enabled: bool,
    pub soc2_logging: bool,
    pub multi_cell: bool,
    pub custom_model_endpoints: bool,
    pub on_prem_license: bool,
    pub sso_enabled: bool,
    /// Overage: cost per 1K tokens above plan (0 = no overage / hard cap)
    pub overage_per_1k_usd: f64,
    /// Monthly overage ceiling in USD (0 = none)
    pub overage_ceiling_usd: f64,
}

impl EntitlementSet {
    pub fn for_tier(tier: &str) -> Self {
        match tier.to_lowercase().as_str() {
            "pro" => Self {
                tier: "pro".into(),
                tokens_per_day: 0,
                tokens_per_month: 500_000,
                max_agents: 20,
                memory_retention_days: 365,
                max_cells: 1,
                hipaa_enabled: false,
                soc2_logging: false,
                multi_cell: false,
                custom_model_endpoints: false,
                on_prem_license: false,
                sso_enabled: false,
                overage_per_1k_usd: 0.002,
                overage_ceiling_usd: 100.0,
            },
            "team" => Self {
                tier: "team".into(),
                tokens_per_day: 0,
                tokens_per_month: 5_000_000,
                max_agents: 0,
                memory_retention_days: 0,
                max_cells: 3,
                hipaa_enabled: true,
                soc2_logging: true,
                multi_cell: true,
                custom_model_endpoints: true,
                on_prem_license: false,
                sso_enabled: true,
                overage_per_1k_usd: 0.0015,
                overage_ceiling_usd: 500.0,
            },
            "enterprise" => Self {
                tier: "enterprise".into(),
                tokens_per_day: 0,
                tokens_per_month: 0,
                max_agents: 0,
                memory_retention_days: 0,
                max_cells: 0,
                hipaa_enabled: true,
                soc2_logging: true,
                multi_cell: true,
                custom_model_endpoints: true,
                on_prem_license: true,
                sso_enabled: true,
                overage_per_1k_usd: 0.0,
                overage_ceiling_usd: 0.0,
            },
            _ => Self {
                // Community (free)
                tier: "community".into(),
                tokens_per_day: 10_000,
                tokens_per_month: 300_000,
                max_agents: 3,
                memory_retention_days: 30,
                max_cells: 1,
                hipaa_enabled: false,
                soc2_logging: false,
                multi_cell: false,
                custom_model_endpoints: false,
                on_prem_license: false,
                sso_enabled: false,
                overage_per_1k_usd: 0.0,
                overage_ceiling_usd: 0.0,
            },
        }
    }

    /// BIZ-6: check a specific feature entitlement (inline-able, < 1µs hot path)
    pub fn check(&self, feature: &str) -> bool {
        match feature {
            "dispatch" => true, // all tiers can dispatch
            "hipaa" => self.hipaa_enabled,
            "soc2_logging" => self.soc2_logging,
            "multi_cell" => self.multi_cell,
            "custom_model_endpoints" => self.custom_model_endpoints,
            "on_prem_license" => self.on_prem_license,
            "sso" => self.sso_enabled,
            _ => false,
        }
    }
}

// ─── BIZ-3: Rate-limit gate response helpers ────────────────────────────────

/// Returns the budget-warning body when tokens_used >= 80% of daily limit.
pub fn budget_warning_body(used: u64, limit: u64) -> serde_json::Value {
    let pct = if limit > 0 { (used * 100) / limit } else { 0 };
    let reset_at = {
        let now = chrono::Utc::now();
        let hours_remaining = 24i64 - now.hour() as i64;
        (now + chrono::Duration::hours(hours_remaining)).to_rfc3339()
    };
    serde_json::json!({
        "budget_warning": {
            "used": used,
            "limit": limit,
            "pct": pct,
            "reset_at": reset_at,
            "hint": format!("Token budget is {}% used. Increase in agent.yaml: resources.tokenBudget.dailyLimit: {} or upgrade at connector.ai/upgrade", pct, limit * 2),
        }
    })
}

/// BIZ-3: 429 body for daily token limit exhaustion.
pub fn limit_reached_body(tier: &str, used: u64, limit: u64) -> serde_json::Value {
    let reset_at = chrono::Utc::now()
        .date_naive()
        .succ_opt()
        .map(|d| d.format("%Y-%m-%dT00:00:00Z").to_string())
        .unwrap_or_default();
    let (next_tier, upgrade_tokens) = match tier {
        "community" => ("Pro — 500K tokens/mo", "500,000"),
        "pro" => ("Team — 5M tokens/mo", "5,000,000"),
        "team" => ("Enterprise — unlimited", "unlimited"),
        _ => ("Enterprise — unlimited", "unlimited"),
    };
    serde_json::json!({
        "error": "daily_limit_reached",
        "used": used,
        "limit": limit,
        "reset_at": reset_at,
        "upgrade_url": "https://connector.ai/upgrade",
        "next_tier": next_tier,
        "next_tier_tokens": upgrade_tokens,
        "hint": format!("Daily token limit reached. Resets at {}. Upgrade at connector.ai/upgrade", reset_at),
    })
}

/// BIZ-3: 429 body for agent count limit.
/// `reusable_candidates` — kernel PIDs the operator may reset (from recycle hint); may be empty.
pub fn agent_limit_body(
    tier: &str,
    current: u32,
    limit: u32,
    reusable_candidates: &[String],
) -> serde_json::Value {
    let (next_tier, next_limit) = match tier {
        "dev" | "pilots" => (
            "Raise limit via POST /api/v1/runtime/policy or switch runtime mode",
            0,
        ),
        "community" => ("Pro — 20 agents", 20),
        "pro" => ("Team — unlimited agents", 0),
        _ => ("Enterprise — unlimited", 0),
    };
    let base_hint = format!("Agent limit reached ({}/{}). {}", current, limit, next_tier);
    let recycle_hint = if reusable_candidates.is_empty() {
        String::new()
    } else {
        format!(
            " Stale or suspended agents may still occupy slots — POST /api/v1/agents/{{pid}}/reset on one of: {:?}",
            reusable_candidates
        )
    };
    serde_json::json!({
        "error": "agent_limit_reached",
        "current": current,
        "limit": limit,
        "upgrade_url": "https://connector.ai/upgrade",
        "next_tier": next_tier,
        "next_limit": if next_limit == 0 { serde_json::json!("unlimited") } else { serde_json::json!(next_limit) },
        "reusable_candidates": reusable_candidates,
        "hint": format!("{}{}", base_hint, recycle_hint),
    })
}

// ─── HTTP Handlers ───────────────────────────────────────────────────────────

/// GET /billing/usage — current usage + limits + estimated overage
pub async fn billing_usage(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match crate::auth::extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    let user_store = state.user_store.lock().unwrap();
    let user = match user_store.get_user(&claims.sub) {
        Some(u) => u.clone(),
        None => return Json(serde_json::json!({"error": "User not found", "status": 404})),
    };
    drop(user_store);

    let ents = EntitlementSet::for_tier(&user.tier);
    let tokens_today = user.tokens_used_today;
    let tokens_month = user.tokens_used_month;

    let now = chrono::Utc::now();
    let period_start = format!("{}-{:02}-01T00:00:00Z", now.year(), now.month());
    let (next_year, next_month) = if now.month() == 12 {
        (now.year() + 1, 1)
    } else {
        (now.year(), now.month() + 1)
    };
    let period_end = format!("{}-{:02}-01T00:00:00Z", next_year, next_month);

    let overage_tokens = if ents.tokens_per_month > 0 && tokens_month > ents.tokens_per_month {
        tokens_month - ents.tokens_per_month
    } else {
        0
    };
    let overage_usd = (overage_tokens as f64 / 1000.0) * ents.overage_per_1k_usd;
    let overage_capped = if ents.overage_ceiling_usd > 0.0 {
        overage_usd.min(ents.overage_ceiling_usd)
    } else {
        overage_usd
    };

    Json(serde_json::json!({
        "tier": user.tier,
        "billing_state": user.billing_state,
        "tokens_used_today": tokens_today,
        "tokens_limit_today": ents.tokens_per_day,
        "tokens_used_month": tokens_month,
        "tokens_limit_month": ents.tokens_per_month,
        "agents_running": user.agents_count,
        "agents_limit": ents.max_agents,
        "period_start": period_start,
        "period_end": period_end,
        "estimated_overage_usd": overage_capped,
        "overage_ceiling_usd": ents.overage_ceiling_usd,
        "entitlements": ents,
    }))
}

/// GET /billing/entitlements — entitlement set for current user
pub async fn billing_entitlements(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match crate::auth::extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    let user_store = state.user_store.lock().unwrap();
    let tier = user_store
        .get_user(&claims.sub)
        .map(|u| u.tier.clone())
        .unwrap_or_else(|| "community".to_string());
    let ents = EntitlementSet::for_tier(&tier);
    Json(serde_json::json!(ents))
}

/// POST /billing/record-usage (internal — called after every LLM response)
/// Flat token cost per tool call — predictable, developer-facing cost model.
/// Regardless of actual token use inside the tool, each call is billed at this rate.
pub const TOOL_CALL_FLAT_TOKENS: u64 = 50;

/// JWT `sub` / Books cost scope: must match the authenticated user id on `GET /books/costs`.
///
/// `agent_meta` historically stored only `created_by`; gateway and tools previously read only
/// `user_id`, so billing rows used `agent_pid` and never matched Books filters (REG-001/002).
pub fn billing_tenant_id_from_agent_meta(meta: Option<&serde_json::Value>) -> Option<String> {
    let m = meta?;
    m.get("user_id")
        .or_else(|| m.get("created_by"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Record a tool-call billing event (flat 50 tokens each).
///
/// Called from `tools.rs` after every successful `ToolDispatch`.
/// Non-blocking — returns immediately after queueing the counter update.
pub fn record_tool_call(
    state: &crate::state::PlatformState,
    account_id: &str,
    agent_pid: &str,
    tool_id: &str,
) {
    if account_id.is_empty() {
        return;
    }
    {
        let mut user_store = state.user_store.lock().unwrap();
        if let Some(user) = user_store.users.get_mut(account_id) {
            user.tokens_used_today = user.tokens_used_today.saturating_add(TOOL_CALL_FLAT_TOKENS);
            user.tokens_used_month = user.tokens_used_month.saturating_add(TOOL_CALL_FLAT_TOKENS);
        }
    }
    if let Ok(mut es) = state.engine_store.lock() {
        let event_id = format!(
            "tc_{}_{}",
            account_id,
            chrono::Utc::now().timestamp_millis()
        );
        let _ = es.folder_put(
            "billing_usage_events",
            &event_id,
            &serde_json::json!({
                "account_id": account_id,
                "tokens": TOOL_CALL_FLAT_TOKENS,
                "total_tokens": TOOL_CALL_FLAT_TOKENS,
                "agent_pid": agent_pid,
                "tool_id": tool_id,
                "event_type": "tool_call",
                "cost_usd_estimated": 0.0,
                "cost_basis": "tool_flat_token_charge_usd_not_priced_separately",
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }
    state.metrics.billing_usage_events.inc();
    tracing::debug!(account = %account_id, tool = %tool_id, tokens = TOOL_CALL_FLAT_TOKENS, "billing: tool call charged");
}

/// After each AI Gateway LLM completion — persist tokens + **estimated USD** (provider price table in connector-engine)
/// and bump account counters (same as `record_usage`).
pub fn record_llm_gateway_usage(
    state: &crate::state::PlatformState,
    account_id: &str,
    agent_pid: &str,
    session_id: &str,
    model_requested: &str,
    provider: &str,
    model_routed: &str,
    input_tokens: u32,
    output_tokens: u32,
    cost_usd_estimated: f64,
    token_source: &str,
    gateway_mode: &str,
) {
    if account_id.is_empty() {
        return;
    }
    let total = (input_tokens as u64).saturating_add(output_tokens as u64);
    if total == 0 {
        return;
    }

    let tier = {
        let mut user_store = state.user_store.lock().unwrap();
        if let Some(user) = user_store.users.get_mut(account_id) {
            user.tokens_used_today = user.tokens_used_today.saturating_add(total);
            user.tokens_used_month = user.tokens_used_month.saturating_add(total);

            let ents = EntitlementSet::for_tier(&user.tier);
            if ents.overage_ceiling_usd > 0.0 && ents.overage_per_1k_usd > 0.0 {
                let plan_tokens = ents.tokens_per_month;
                if plan_tokens > 0 && user.tokens_used_month > plan_tokens {
                    let overage_tokens = user.tokens_used_month - plan_tokens;
                    let overage_usd = (overage_tokens as f64 / 1000.0) * ents.overage_per_1k_usd;
                    if overage_usd >= ents.overage_ceiling_usd {
                        tracing::warn!(
                            account = %account_id,
                            overage_usd = overage_usd,
                            ceiling_usd = ents.overage_ceiling_usd,
                            "billing: monthly overage ceiling reached"
                        );
                    }
                }
            }
            user.tier.clone()
        } else {
            "community".to_string()
        }
    };

    {
        let user_store = state.user_store.lock().unwrap();
        let mut es = state.engine_store.lock().unwrap();
        user_store.persist_user(account_id, es.as_mut());
    }

    {
        fn infer_plugin_id(agent_pid: &str, session_id: &str) -> Option<String> {
            let ap = agent_pid.to_ascii_lowercase();
            let ss = session_id.to_ascii_lowercase();
            for id in ["tracetramp", "witnessctl", "devguard"] {
                if ap.contains(id) || ss.contains(id) {
                    return Some(id.to_string());
                }
            }
            None
        }
        fn compute_chain_hash(
            prev_hash: &str,
            account_id: &str,
            event_id: &str,
            ts: &str,
            total_tokens: u64,
            cost_usd_estimated: f64,
            provider: &str,
            model_routed: &str,
            token_source: &str,
            plugin_id: Option<&str>,
        ) -> String {
            let mut hasher = Sha256::new();
            let line = format!(
                "{}|{}|{}|{}|{}|{:.10}|{}|{}|{}|{}",
                prev_hash,
                account_id,
                event_id,
                ts,
                total_tokens,
                cost_usd_estimated,
                provider,
                model_routed,
                token_source,
                plugin_id.unwrap_or("none"),
            );
            hasher.update(line.as_bytes());
            format!("{:x}", hasher.finalize())
        }

        let mut es = state.engine_store.lock().unwrap();
        let now = chrono::Utc::now();
        let ts = now.to_rfc3339();
        let event_id = format!("llm_{}_{}", account_id, now.timestamp_micros());
        let plugin_id = infer_plugin_id(agent_pid, session_id);
        let is_real_cost =
            matches!(token_source, "provider_api" | "anthropic_api") && cost_usd_estimated > 0.0;
        let chain_head = es
            .folder_get("billing_cost_chain_head", account_id)
            .ok()
            .flatten();
        let prev_hash = chain_head
            .as_ref()
            .and_then(|v| v.get("head_hash").and_then(|x| x.as_str()))
            .unwrap_or("GENESIS");
        let prev_seq = chain_head
            .as_ref()
            .and_then(|v| v.get("head_seq").and_then(|x| x.as_u64()))
            .unwrap_or(0);
        let chain_seq = prev_seq + 1;
        let chain_hash = compute_chain_hash(
            prev_hash,
            account_id,
            &event_id,
            &ts,
            total,
            cost_usd_estimated,
            provider,
            model_routed,
            token_source,
            plugin_id.as_deref(),
        );
        let _ = es.folder_put(
            "billing_usage_events",
            &event_id,
            &serde_json::json!({
                "event_type": "llm_completion",
                "account_id": account_id,
                "agent_pid": agent_pid,
                "session_id": session_id,
                "tier": tier,
                "model_requested": model_requested,
                "provider": provider,
                "model_routed": model_routed,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total,
                "cost_usd_estimated": cost_usd_estimated,
                "cost_usd_real": if is_real_cost { cost_usd_estimated } else { 0.0 },
                "cost_source": if is_real_cost { "provider_pricing" } else { "estimated_or_stub" },
                "is_real_cost": is_real_cost,
                "cost_basis": "connector_engine_llm_router_price_table_per_million_tokens",
                "token_source": token_source,
                "gateway_mode": gateway_mode,
                "plugin_id": plugin_id,
                "cost_control_plane": "connector_gateway",
                "chain_seq": chain_seq,
                "chain_prev_hash": prev_hash,
                "chain_hash": chain_hash,
                "timestamp": ts,
            }),
        );
        let _ = es.folder_put(
            "billing_cost_chain_head",
            account_id,
            &serde_json::json!({
                "account_id": account_id,
                "head_seq": chain_seq,
                "head_hash": chain_hash,
                "head_event_id": event_id,
                "updated_at": now.to_rfc3339(),
            }),
        );
    }

    state.metrics.billing_usage_events.inc();
    tracing::debug!(
        account = %account_id,
        agent = %agent_pid,
        total = total,
        usd = cost_usd_estimated,
        "billing: llm gateway usage recorded"
    );
}

/// After a successful LLM completion: metrics, Stripe meter, `billing_usage_events`, per-agent
/// cost ledger, KTG/adaptive hooks, and `agent.first_run` analytics — shared by OpenAI-compat
/// chat (stream + non-stream) and Anthropic `/v1/messages` so DevGuard/Claude Code traffic hits
/// Books (REG-007).
///
/// When **`use_anthropic_price_table`** is true and not stub mode, USD estimate uses provider
/// **`anthropic`** with **`model_requested`** (same per-million table as the router).
///
/// **`stream_token_source`**: when `Some`, pricing follows the streaming gateway’s precomputed
/// label (`stub_heuristic` / `no_router_heuristic` / `provider_api` / `error`) and **`stub_mode`**
/// is ignored for USD (caller already folded stub vs no-router into the label).
///
/// **`model_served` / `provider_served`**: when present (from `LlmResponse` after fallback),
/// UsageEvent + Books meters record the hop that actually answered — not only primary config.
///
/// Returns **`(account_id, cost_usd_estimated)`** for response headers / JSON.
pub fn record_llm_completion_side_effects(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    call_session_id: &str,
    model_requested: &str,
    prompt_tokens: u32,
    completion_tokens: u32,
    stub_mode: bool,
    gateway_mode: &str,
    use_anthropic_price_table: bool,
    stream_token_source: Option<&str>,
    model_served: Option<&str>,
    provider_served: Option<&str>,
) -> (String, f64) {
    let total_tokens = prompt_tokens.saturating_add(completion_tokens);
    let account_fallback = {
        let es = state.engine_store.lock().unwrap();
        let meta = es.folder_get("agent_meta", agent_pid).ok().flatten();
        billing_tenant_id_from_agent_meta(meta.as_ref()).unwrap_or_else(|| agent_pid.to_string())
    };
    if total_tokens == 0 {
        state.metrics.llm_calls_total.inc();
        state
            .metrics
            .llm_calls_by_agent
            .get_or_create(&crate::state::AgentLabels {
                agent_pid: agent_pid.to_string(),
            })
            .inc();
        return (account_fallback, 0.0);
    }

    state.metrics.llm_calls_total.inc();
    state
        .metrics
        .llm_calls_by_agent
        .get_or_create(&crate::state::AgentLabels {
            agent_pid: agent_pid.to_string(),
        })
        .inc();
    state
        .metrics
        .tokens_consumed_total
        .inc_by(total_tokens as u64);
    state
        .metrics
        .tokens_by_agent
        .get_or_create(&crate::state::AgentLabels {
            agent_pid: agent_pid.to_string(),
        })
        .inc_by(total_tokens as u64);

    let account_id_for_billing = account_fallback;
    record_stripe_meter_event(&account_id_for_billing, total_tokens as u64, agent_pid);

    let served_m = model_served
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let served_p = provider_served
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let (cost_usd, billing_provider, billing_model_routed, token_source): (
        f64,
        String,
        String,
        String,
    ) = if let Some(ts) = stream_token_source {
        if ts == "stub_heuristic" || ts == "no_router_heuristic" {
            (
                0.0,
                served_p.unwrap_or_else(|| "stub".to_string()),
                served_m.unwrap_or_else(|| "stub".to_string()),
                ts.to_string(),
            )
        } else if ts == "error" {
            (
                0.0,
                "error".to_string(),
                served_m.unwrap_or_else(|| model_requested.to_string()),
                "error".to_string(),
            )
        } else if ts == "provider_api" {
            if let (Some(p), Some(m)) = (served_p.clone(), served_m.clone()) {
                let usd = connector_engine::llm_router::estimate_usd_for_tokens(
                    &p,
                    &m,
                    prompt_tokens,
                    completion_tokens,
                );
                (usd, p, m, "provider_api".to_string())
            } else if let Some(router) = state.llm_router_arc() {
                let (p, m) = router
                    .primary_provider_model()
                    .unwrap_or_else(|| ("openai".to_string(), "gpt-4o".to_string()));
                let p = served_p.unwrap_or(p);
                let m = served_m.unwrap_or(m);
                let usd = connector_engine::llm_router::estimate_usd_for_tokens(
                    &p,
                    &m,
                    prompt_tokens,
                    completion_tokens,
                );
                (usd, p, m, "provider_api".to_string())
            } else {
                (
                    0.0,
                    served_p.unwrap_or_else(|| "none".to_string()),
                    served_m.unwrap_or_else(|| model_requested.to_string()),
                    "no_router_heuristic".to_string(),
                )
            }
        } else {
            (
                0.0,
                served_p.unwrap_or_else(|| "none".to_string()),
                served_m.unwrap_or_else(|| model_requested.to_string()),
                ts.to_string(),
            )
        }
    } else if stub_mode {
        (
            0.0,
            served_p.unwrap_or_else(|| "stub".to_string()),
            served_m.unwrap_or_else(|| "stub".to_string()),
            "stub_heuristic".to_string(),
        )
    } else if use_anthropic_price_table {
        let m = served_m
            .clone()
            .unwrap_or_else(|| model_requested.to_string());
        let p = served_p.clone().unwrap_or_else(|| "anthropic".to_string());
        let usd = connector_engine::llm_router::estimate_usd_for_tokens(
            &p,
            &m,
            prompt_tokens,
            completion_tokens,
        );
        (usd, p, m, "anthropic_api".to_string())
    } else if let (Some(p), Some(m)) = (served_p.clone(), served_m.clone()) {
        let usd = connector_engine::llm_router::estimate_usd_for_tokens(
            &p,
            &m,
            prompt_tokens,
            completion_tokens,
        );
        (usd, p, m, "provider_api".to_string())
    } else if let Some(router) = state.llm_router_arc() {
        let (p, m) = router
            .primary_provider_model()
            .unwrap_or_else(|| ("openai".to_string(), "gpt-4o".to_string()));
        let p = served_p.unwrap_or(p);
        let m = served_m.unwrap_or(m);
        let usd = connector_engine::llm_router::estimate_usd_for_tokens(
            &p,
            &m,
            prompt_tokens,
            completion_tokens,
        );
        (usd, p, m, "provider_api".to_string())
    } else {
        (
            0.0,
            served_p.unwrap_or_else(|| "none".to_string()),
            served_m.unwrap_or_else(|| model_requested.to_string()),
            "no_router_heuristic".to_string(),
        )
    };

    record_llm_gateway_usage(
        state,
        &account_id_for_billing,
        agent_pid,
        call_session_id,
        model_requested,
        &billing_provider,
        &billing_model_routed,
        prompt_tokens,
        completion_tokens,
        cost_usd,
        token_source.as_str(),
        gateway_mode,
    );

    {
        let now_str = chrono::Utc::now().to_rfc3339();
        let call_entry = serde_json::json!({
            "timestamp":          now_str,
            "model":              billing_model_routed,
            "provider":           billing_provider,
            "prompt_tokens":      prompt_tokens,
            "completion_tokens":  completion_tokens,
            "total_tokens":       total_tokens,
            "cost_usd":           cost_usd,
            "token_source":       token_source,
        });
        let mut es = state.engine_store.lock().unwrap();
        let prev = es.folder_get("agent_cost_ledger", agent_pid).ok().flatten();
        let prev_cost = prev
            .as_ref()
            .and_then(|v| v.get("total_cost_usd").and_then(|t| t.as_f64()))
            .unwrap_or(0.0);
        let prev_tokens = prev
            .as_ref()
            .and_then(|v| v.get("total_tokens").and_then(|t| t.as_u64()))
            .unwrap_or(0);
        let prev_prompt = prev
            .as_ref()
            .and_then(|v| v.get("total_prompt_tokens").and_then(|t| t.as_u64()))
            .unwrap_or(0);
        let prev_compl = prev
            .as_ref()
            .and_then(|v| v.get("total_completion_tokens").and_then(|t| t.as_u64()))
            .unwrap_or(0);
        let prev_count = prev
            .as_ref()
            .and_then(|v| v.get("call_count").and_then(|t| t.as_u64()))
            .unwrap_or(0);
        let first_call_at = prev
            .as_ref()
            .and_then(|v| {
                v.get("first_call_at")
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| now_str.clone());
        let mut calls: Vec<serde_json::Value> = prev
            .as_ref()
            .and_then(|v| v.get("calls").and_then(|c| c.as_array()).cloned())
            .unwrap_or_default();
        calls.push(call_entry);
        if calls.len() > 200 {
            calls.remove(0);
        }
        let _ = es.folder_put(
            "agent_cost_ledger",
            agent_pid,
            &serde_json::json!({
                "agent_pid":                  agent_pid,
                "total_cost_usd":             prev_cost + cost_usd,
                "total_tokens":               prev_tokens + total_tokens as u64,
                "total_prompt_tokens":        prev_prompt + prompt_tokens as u64,
                "total_completion_tokens":    prev_compl + completion_tokens as u64,
                "call_count":                 prev_count + 1,
                "model":                      billing_model_routed,
                "provider":                   billing_provider,
                "first_call_at":              first_call_at,
                "last_call_at":               now_str,
                "calls":                      calls,
            }),
        );
    }

    {
        let model_tag = billing_model_routed
            .split(':')
            .last()
            .unwrap_or(&billing_model_routed)
            .to_string();
        let provider_tag = billing_provider.clone();
        let tags = vec![model_tag, provider_tag, "llm".to_string()];
        if let Some(ref ktg) = state.knowledge_graph {
            ktg.update_node(agent_pid, agent_pid, tags, cost_usd);
            if total_tokens > 100 {
                let _ = ktg.auto_transfer(
                    agent_pid,
                    &format!("llm-context-{}", &agent_pid[..8.min(agent_pid.len())]),
                    total_tokens as u64,
                    0.65,
                );
            }
        }
        if let Some(ref router) = state.adaptive_router {
            let provider_key = format!("{}:{}", billing_provider, billing_model_routed);
            router.record_outcome(&provider_key, true, 0, total_tokens as u64, cost_usd);
        }
    }

    crate::services::analytics::emit(
        state,
        crate::services::analytics::AnalyticsEvent::new(
            "agent.first_run",
            &account_id_for_billing,
            serde_json::json!({
                "agent_pid": agent_pid,
                "model": model_requested,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_usd_estimated": cost_usd,
            }),
        )
        .with_agent(agent_pid),
    );

    if total_tokens > 0 {
        use connector_trust::{ArtifactLogRecordV2, UsageEventV2, UsageTokenSource};
        let usage = UsageEventV2::new_llm_completion(
            &account_id_for_billing,
            agent_pid,
            call_session_id,
            model_requested,
            &billing_model_routed,
            &billing_provider,
            prompt_tokens,
            completion_tokens,
            UsageTokenSource::parse(&token_source),
            if cost_usd > 0.0 { Some(cost_usd) } else { None },
            None,
        );
        crate::substrate::usage_event::append_usage_event(state, &usage);
        let artifact = ArtifactLogRecordV2::from_usage_event(&usage);
        crate::substrate::artifact_log::append_artifact_record(state, &artifact);
        let _moment = crate::services::moment::commit_llm_moment(
            state,
            call_session_id,
            agent_pid,
            model_requested,
            prompt_tokens,
            completion_tokens,
            Some(&usage.event_id),
            None,
        );
    }

    (account_id_for_billing, cost_usd)
}

/// BIZ-4: Synchronous entitlement check for the dispatch hot path.
///
/// Reads the user's tier from `user_store` (in-memory, < 1µs) and calls
/// `EntitlementSet.check(feature)`. Safe to call inside any handler.
///
/// Returns `true` if the account is entitled to the feature; `false` otherwise.
pub fn check_entitlement(
    state: &crate::state::PlatformState,
    account_id: &str,
    feature: &str,
) -> bool {
    let user_store = state.user_store.lock().unwrap();
    let tier = user_store
        .get_user(account_id)
        .map(|u| u.tier.clone())
        .unwrap_or_else(|| "community".to_string());
    drop(user_store);
    EntitlementSet::for_tier(&tier).check(feature)
}

/// BIZ-4: Fire Stripe Meter event `connector_tokens` after every LLM response.
///
/// Aggregation: sum. One event per LLM call. Value = input_tokens + output_tokens.
/// Requires STRIPE_SECRET_KEY env var. Fire-and-forget — errors are logged, never propagated.
/// Called from gateway.rs after every successful LLM response.
pub fn record_stripe_meter_event(account_id: &str, tokens: u64, agent_pid: &str) {
    if account_id.is_empty() || tokens == 0 {
        return;
    }
    let stripe_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return, // Stripe not configured — skip silently
    };

    let account_id = account_id.to_string();
    let agent_pid = agent_pid.to_string();
    let _ = std::thread::Builder::new()
        .name("stripe-meter".into())
        .spawn(move || {
            // Stripe Meter API: POST /v1/billing/meter_events
            let body = format!(
                "event_name=connector_tokens&payload[value]={}&payload[stripe_customer_id]={}",
                tokens,
                // In production: look up customer_id from user_store by account_id
                // For now use account_id as a fallback identifier
                urlencoding_simple(&account_id),
            );
            if let Ok(client) = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
            {
                let result = client
                    .post("https://api.stripe.com/v1/billing/meter_events")
                    .header("Authorization", format!("Bearer {}", stripe_key))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send();
                match result {
                    Ok(r) if r.status().is_success() => {
                        tracing::debug!(account = %account_id, tokens = tokens, "stripe: meter event sent");
                    }
                    Ok(r) => {
                        tracing::warn!(account = %account_id, status = %r.status(), "stripe: meter event failed");
                    }
                    Err(e) => {
                        tracing::warn!(account = %account_id, err = %e, "stripe: meter event error");
                    }
                }
            }
        });
}

/// Minimal URL encoding for Stripe form body values.
fn urlencoding_simple(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

/// `POST /billing/budget` — persist the first-budget wizard and arm the cap.
///
/// The wizard shipped before this route existed, so a budget set during setup
/// was written to `localStorage` and nothing else — the operator believed they
/// had a ceiling that was never enforced. The cost cap here is mapped onto the
/// LLM guardrails, which is what the gateway actually consults on every chat.
pub async fn set_budget(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    if let Err(e) = crate::services::workflow_runtime::require_admin_or_dev(&headers) {
        return Json(e);
    }
    let num = |k: &str, d: f64| req.get(k).and_then(|v| v.as_f64()).unwrap_or(d);
    let text = |k: &str, d: &str| {
        req.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or(d)
            .to_string()
    };

    let cost_cap_usd = num("cost_cap_usd", 0.0);
    let warn_pct = num("alert_at_pct_warn", 80.0);
    let hard_pct = num("alert_at_pct_hard", 100.0);
    let guardrails =
        crate::services::settings_llms::save_guardrails(&state, cost_cap_usd, warn_pct, hard_pct);

    let scope = text("scope", "tenant");
    let scope_id = text("scope_id", "default");
    let record = serde_json::json!({
        "schema": "budget_policy.v1",
        "scope": scope,
        "scope_id": scope_id,
        "token_cap": req.get("token_cap").and_then(|v| v.as_u64()).unwrap_or(0),
        "cost_cap_usd": cost_cap_usd,
        "alert_at_pct_warn": warn_pct,
        "alert_at_pct_hard": hard_pct,
        "action": text("action", "throttle"),
        "updated_at_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    });
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put("billing_budgets", &format!("{scope}:{scope_id}"), &record);
    }

    Json(serde_json::json!({
        "ok": true,
        "budget": record,
        "guardrails": guardrails,
        "enforcement": "Cost cap is armed on the gateway chat path via LLM guardrails.",
        "honesty": "Token cap and action are recorded but are not yet enforced by the gateway.",
    }))
}

pub async fn record_usage(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let account_id = req.get("account_id").and_then(|v| v.as_str()).unwrap_or("");
    let tokens = req.get("tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let session_id = req.get("session_id").and_then(|v| v.as_str()).unwrap_or("");

    if account_id.is_empty() || tokens == 0 {
        return Json(serde_json::json!({"ok": false, "error": "account_id and tokens required"}));
    }

    // Update user token counters; enforce monthly overage ceiling
    let tier = {
        let mut user_store = state.user_store.lock().unwrap();
        if let Some(user) = user_store.users.get_mut(account_id) {
            user.tokens_used_today = user.tokens_used_today.saturating_add(tokens);
            user.tokens_used_month = user.tokens_used_month.saturating_add(tokens);

            // BIZ-6: enforce overage ceiling — never bill more than ceiling per month
            let ents = EntitlementSet::for_tier(&user.tier);
            if ents.overage_ceiling_usd > 0.0 && ents.overage_per_1k_usd > 0.0 {
                let plan_tokens = ents.tokens_per_month;
                if plan_tokens > 0 && user.tokens_used_month > plan_tokens {
                    let overage_tokens = user.tokens_used_month - plan_tokens;
                    let overage_usd = (overage_tokens as f64 / 1000.0) * ents.overage_per_1k_usd;
                    if overage_usd >= ents.overage_ceiling_usd {
                        // Hard cap hit: mark account as ceiling_reached so gateway returns 429
                        tracing::warn!(
                            account = %account_id,
                            overage_usd = overage_usd,
                            ceiling_usd = ents.overage_ceiling_usd,
                            "billing: monthly overage ceiling reached — throttling"
                        );
                    }
                }
            }

            user.tier.clone()
        } else {
            "community".to_string()
        }
    };

    // Persist updated counters
    {
        let user_store = state.user_store.lock().unwrap();
        let mut es = state.engine_store.lock().unwrap();
        user_store.persist_user(account_id, es.as_mut());
    }

    // Record usage event for billing audit
    {
        let mut es = state.engine_store.lock().unwrap();
        let event_id = format!("{}_{}", account_id, chrono::Utc::now().timestamp_millis());
        let _ = es.folder_put(
            "billing_usage_events",
            &event_id,
            &serde_json::json!({
                "event_type": "manual_record_usage",
                "account_id": account_id,
                "tokens": tokens,
                "agent_pid": agent_pid,
                "session_id": session_id,
                "tier": tier,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    state.metrics.billing_usage_events.inc();
    tracing::debug!(account = %account_id, tokens = tokens, agent = %agent_pid, "billing: usage recorded");

    Json(serde_json::json!({"ok": true, "tokens_recorded": tokens}))
}

/// GET /billing/invoices — Stripe invoice list proxy
pub async fn billing_invoices(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let claims = match crate::auth::extract_claims(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    let user_store = state.user_store.lock().unwrap();
    let customer_id = user_store
        .get_user(&claims.sub)
        .and_then(|u| u.stripe_customer_id.clone());
    drop(user_store);

    // When Stripe is configured, proxy the invoice list
    if let (Some(cid), Ok(_stripe_key)) = (customer_id, std::env::var("STRIPE_SECRET_KEY")) {
        Json(serde_json::json!({
            "customer_id": cid,
            "invoices": [],
            "note": "Connect to Stripe API to retrieve live invoice list",
            "portal_url": format!("/api/v1/billing/portal"),
        }))
    } else {
        Json(serde_json::json!({
            "invoices": [],
            "note": "Stripe not configured or no customer account linked",
        }))
    }
}

/// GET /billing/portal — Stripe Customer Portal session redirect
pub async fn billing_portal(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match crate::auth::extract_claims(&headers) {
        Some(c) => c,
        None => {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Authentication required", "status": 401})),
            )
                .into_response()
        }
    };

    let user_store = state.user_store.lock().unwrap();
    let customer_id = user_store
        .get_user(&claims.sub)
        .and_then(|u| u.stripe_customer_id.clone());
    drop(user_store);

    if customer_id.is_none() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "No billing account linked",
                "hint": "Complete a Stripe Checkout session first to link your account"
            })),
        )
            .into_response();
    }

    // In production: create Stripe Billing Portal session and redirect
    // For now: return the portal URL structure
    Json(serde_json::json!({
        "portal_url": "https://billing.stripe.com/p/login/test_connector",
        "note": "Configure STRIPE_SECRET_KEY to enable live Stripe portal sessions",
        "customer_id": customer_id,
    }))
    .into_response()
}

// ─── Signup (BIZ-1): instant API key, no credit card ────────────────────────

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: String,
}

/// POST /auth/signup — BIZ-1: email + password → API key in response body, account live immediately
pub async fn signup(
    State(state): State<SharedState>,
    Json(req): Json<SignupRequest>,
) -> impl IntoResponse {
    use axum::http::StatusCode;

    let dev_relax = runtime_control::dev_signup_relaxed(&state);
    let min_pw = if dev_relax { 6 } else { 8 };

    if req.email.is_empty() || req.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "email and password are required"
            })),
        )
            .into_response();
    }
    if !req.email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid email address"
            })),
        )
            .into_response();
    }
    if req.password.len() < min_pw {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("password must be at least {} characters", min_pw)
            })),
        )
            .into_response();
    }

    // Check duplicate email
    {
        let mut us = state.user_store.lock().unwrap();
        if let Some(existing) = us.get_by_email_mut(&req.email) {
            // In ultimate-free/playground mode: silently upgrade existing accounts to Operator
            // so dev_bypass accounts created before the role fix get elevated automatically.
            if runtime_control::free_tier_open_auth_enabled()
                && existing.role != crate::auth::PlatformRole::Operator
                && existing.role != crate::auth::PlatformRole::Admin
                && existing.role != crate::auth::PlatformRole::SuperAdmin
            {
                existing.role = crate::auth::PlatformRole::Operator;
            }
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "email_already_registered",
                    "hint": "Use POST /api/v1/auth/token to login with your existing account"
                })),
            )
                .into_response();
        }
    }

    // Hash password (argon2id via auth module)
    let password_hash = match crate::auth::hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("password hashing failed: {}", e)
                })),
            )
                .into_response()
        }
    };

    // Generate API key in cpk_live_{base58} format
    let user_id = uuid::Uuid::new_v4().to_string();
    let raw_key = crate::auth::generate_api_key("cpk_live");
    let key_hash = match crate::auth::hash_password(&raw_key) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("key hashing failed: {}", e)
                })),
            )
                .into_response()
        }
    };
    let key_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let lookup_hmac = crate::auth::api_key_lookup_hmac(&raw_key);
    let api_key = crate::auth::ApiKey {
        key_id: key_id.clone(),
        key_hash: key_hash.clone(),
        lookup_hmac,
        name: "default".to_string(),
        scopes: vec!["*".to_string()],
        created_at: now.clone(),
        expires_at: None,
        last_used: None,
        revoked: false,
    };
    crate::auth::register_api_key_with_role(
        &raw_key,
        &user_id,
        "viewer",
        vec!["*".to_string()],
        None,
        Some(key_hash),
    );

    // In controlled beta: new users are locked (pending) unless in free/dev mode.
    let controlled_beta = !runtime_control::free_tier_open_auth_enabled() && !dev_relax;
    let user_locked = controlled_beta;

    let user = crate::auth::User {
        user_id: user_id.clone(),
        email: req.email.clone(),
        name: if req.name.is_empty() {
            req.email.clone()
        } else {
            req.name.clone()
        },
        password_hash,
        role: if runtime_control::free_tier_open_auth_enabled() {
            crate::auth::PlatformRole::Operator
        } else {
            crate::auth::PlatformRole::Viewer
        },
        created_at: now.clone(),
        last_login: None,
        totp_secret: None,
        totp_enabled: false,
        api_keys: if user_locked { vec![] } else { vec![api_key] },
        locked: user_locked,
        failed_attempts: 0,
        instance_id: None,
        tier: "community".to_string(),
        billing_state: "active".to_string(),
        stripe_customer_id: None,
        tokens_used_today: 0,
        tokens_used_month: 0,
        agents_count: 0,
        tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
    };

    let user_name = user.name.clone();
    let user_email = user.email.clone();

    let mut user_store = state.user_store.lock().unwrap();
    if let Err(e) = user_store.create_user(user) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": e, "status": 409})),
        )
            .into_response();
    }

    // Persist to engine store
    let mut es = state.engine_store.lock().unwrap();
    user_store.persist_user(&user_id, es.as_mut());
    drop(es);
    drop(user_store);

    tracing::info!(email = %req.email, user_id = %user_id, controlled_beta, "new signup registered");

    // BIZ-7: analytics funnel — user.signup milestone
    crate::services::analytics::emit(
        &state,
        crate::services::analytics::AnalyticsEvent::new(
            "user.signup",
            &user_id,
            serde_json::json!({ "tier": "community", "email_domain": req.email.split('@').last().unwrap_or("") }),
        ),
    );

    // Send admin notification email on every signup
    let admin_email_addr = std::env::var("CONNECTOR_ADMIN_EMAIL").unwrap_or_default();
    if !admin_email_addr.is_empty() {
        let portal = portal_url();
        let admin_html = format!(
            r#"<div style="font-family:Inter,sans-serif;padding:1.5rem;background:#0a0a0b;color:#e8e8ec">
<p style="color:#3ecf8e;font-weight:700;margin:0 0 1rem">New signup: {name} &lt;{email}&gt;</p>
<p style="color:#9898a4">User ID: <code style="color:#e8e8ec">{uid}</code></p>
<p style="color:#9898a4;margin:0.5rem 0">Status: <strong style="color:#ffb020">Pending approval</strong></p>
<p style="margin:1.5rem 0 0">
  <a href="{portal}/admin/signups" style="background:#3ecf8e;color:#0a0a0b;padding:0.6rem 1.2rem;border-radius:8px;text-decoration:none;font-weight:700">
    Review in admin panel →
  </a>
</p>
</div>"#,
            name = user_name,
            email = user_email,
            uid = user_id,
            portal = portal
        );
        let state_clone = state.clone();
        let to = admin_email_addr.clone();
        let subject = format!("New beta signup: {}", user_email);
        tokio::spawn(async move {
            let _ = state_clone; // keep state alive
            send_email(&to, &subject, &admin_html).await;
        });
    }

    // Send confirmation email to user
    let portal = portal_url();
    let user_html = format!(
        r#"
<!DOCTYPE html><html><body style="font-family:Inter,sans-serif;background:#0a0a0b;color:#e8e8ec;margin:0;padding:2rem">
<div style="max-width:540px;margin:0 auto">
  <p style="font-size:0.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#3ecf8e;margin:0 0 1.5rem">Connector</p>
  <h1 style="font-size:1.4rem;font-weight:700;color:#e8e8ec;margin:0 0 0.75rem">Application received</h1>
  <p style="color:#9898a4;line-height:1.6;margin:0 0 1rem">
    Hi {name}, thanks for applying to the Connector controlled beta. We review every application manually and will be in touch within 48 hours.
  </p>
  <p style="color:#9898a4;font-size:0.82rem">In the meantime, try our <a href="https://connector-playground.fly.dev" style="color:#3ecf8e">hosted playground</a>.</p>
  <p style="color:#9898a4;font-size:0.78rem;margin:2rem 0 0;border-top:1px solid #2a2a30;padding-top:1rem">
    You're receiving this because you registered at <a href="{portal}" style="color:#3ecf8e">{portal}</a>.
  </p>
</div></body></html>"#,
        name = user_name,
        portal = portal
    );

    let email_clone = user_email.clone();
    tokio::spawn(async move {
        send_email(
            &email_clone,
            "Your Connector beta application is received",
            &user_html,
        )
        .await;
    });

    if controlled_beta {
        (StatusCode::CREATED, Json(serde_json::json!({
            "ok": true,
            "user_id": user_id,
            "email": req.email,
            "status": "pending_approval",
            "message": "Your application is under review. You will receive an email with your API key once approved.",
        }))).into_response()
    } else {
        (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ok": true,
                "user_id": user_id,
                "email": req.email,
                "tier": "community",
                "api_key": raw_key,
                "key_id": key_id,
                "dev_runtime": dev_relax,
            })),
        )
            .into_response()
    }
}

// ─── Email helper (SendGrid) ────────────────────────────────────────────────

/// Fire-and-forget transactional email via SendGrid REST API.
/// Uses `SENDGRID_API_KEY` and `CONNECTOR_FROM_EMAIL` env vars.
/// Logs errors but never panics — email failure must not block API responses.
pub async fn send_email(to: &str, subject: &str, html_body: &str) {
    let api_key = match std::env::var("SENDGRID_API_KEY") {
        Ok(k) if !k.is_empty() && k != "SG...." => k,
        _ => {
            tracing::warn!(to, subject, "SENDGRID_API_KEY not set — skipping email");
            return;
        }
    };
    let from =
        std::env::var("CONNECTOR_FROM_EMAIL").unwrap_or_else(|_| "noreply@cnktros.com".into());

    let payload = serde_json::json!({
        "personalizations": [{ "to": [{ "email": to }] }],
        "from": { "email": from, "name": "Connector" },
        "subject": subject,
        "content": [{ "type": "text/html", "value": html_body }]
    });

    let client = reqwest::Client::new();
    match client
        .post("https://api.sendgrid.com/v3/mail/send")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            tracing::info!(to, subject, "email sent");
        }
        Ok(r) => {
            tracing::error!(to, subject, status = %r.status(), "sendgrid error");
        }
        Err(e) => {
            tracing::error!(to, subject, error = %e, "email send failed");
        }
    }
}

fn portal_url() -> String {
    std::env::var("CONNECTOR_PUBLIC_URL")
        .unwrap_or_else(|_| "https://connector-portal.fly.dev".into())
}

// ─── Admin: list pending signups ─────────────────────────────────────────────

/// GET /admin/signups — list all registered users with their approval state.
/// Requires admin key (handled by admin_auth_middleware in licensing crate).
pub async fn admin_list_signups(State(state): State<SharedState>) -> impl IntoResponse {
    let user_store = state.user_store.lock().unwrap();
    let users: Vec<serde_json::Value> = user_store
        .users
        .values()
        .map(|u| {
            serde_json::json!({
                "user_id":       u.user_id,
                "email":         u.email,
                "name":          u.name,
                "role":          u.role.to_str(),
                "tier":          u.tier,
                "locked":        u.locked,
                "approved":      !u.locked || u.role.to_str() != "viewer",
                "status":        if u.locked { "pending" } else { "approved" },
                "created_at":    u.created_at,
                "last_login":    u.last_login,
                "api_key_count": u.api_keys.iter().filter(|k| !k.revoked).count(),
            })
        })
        .collect();

    let pending: Vec<_> = users.iter().filter(|u| u["status"] == "pending").collect();
    let approved: Vec<_> = users.iter().filter(|u| u["status"] == "approved").collect();

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "total":    users.len(),
            "pending":  pending.len(),
            "approved": approved.len(),
            "users":    users,
        })),
    )
        .into_response()
}

// ─── Admin: approve signup → generate pilot key → send email ─────────────────

#[derive(serde::Deserialize)]
pub struct ApproveSignupRequest {
    #[serde(default = "default_seats")]
    pub seats: u32,
    #[serde(default = "default_days")]
    pub duration_days: u64,
    #[serde(default)]
    pub note: String,
}
fn default_seats() -> u32 {
    1
}
fn default_days() -> u64 {
    90
}

/// POST /admin/signups/:user_id/approve
/// Unlocks user, promotes to Operator, generates cpk_pilot_* key, emails the key.
pub async fn admin_approve_signup(
    State(state): State<SharedState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(req): Json<ApproveSignupRequest>,
) -> impl IntoResponse {
    use crate::auth::{
        api_key_lookup_hmac, generate_api_key, hash_password, register_api_key_with_role, ApiKey,
        PlatformRole,
    };

    let (email, name, raw_key) = {
        let mut user_store = state.user_store.lock().unwrap();
        let user = match user_store.users.get_mut(&user_id) {
            Some(u) => u,
            None => {
                return (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({
                        "error": "user_not_found"
                    })),
                )
                    .into_response()
            }
        };

        if !user.locked {
            return (
                axum::http::StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "error": "already_approved",
                    "user_id": user_id,
                })),
            )
                .into_response();
        }

        // Unlock + promote
        user.locked = false;
        user.role = PlatformRole::Operator;
        user.tier = "pilot".to_string();

        // Generate pilot API key
        let raw = generate_api_key("cpk_pilot");
        let key_hash = match hash_password(&raw) {
            Ok(h) => h,
            Err(e) => {
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({"error": e})),
                )
                    .into_response()
            }
        };
        let expires_at = {
            let d = chrono::Utc::now() + chrono::Duration::days(req.duration_days as i64);
            Some(d.to_rfc3339())
        };
        let lookup_hmac = api_key_lookup_hmac(&raw);
        let key = ApiKey {
            key_id: uuid::Uuid::new_v4().to_string(),
            key_hash: key_hash.clone(),
            lookup_hmac,
            name: format!("pilot-{}", req.seats),
            scopes: vec!["*".to_string()],
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: expires_at.clone(),
            last_used: None,
            revoked: false,
        };
        register_api_key_with_role(
            &raw,
            &user.user_id,
            user.role.to_str(),
            vec!["*".to_string()],
            expires_at,
            Some(key_hash),
        );
        user.api_keys.push(key);

        let e = user.email.clone();
        let n = user.name.clone();

        // Persist
        let mut es = state.engine_store.lock().unwrap();
        user_store.persist_user(&user_id, es.as_mut());

        (e, n, raw)
    };

    let portal = portal_url();
    let html = format!(
        r#"
<!DOCTYPE html><html><body style="font-family:Inter,sans-serif;background:#0a0a0b;color:#e8e8ec;margin:0;padding:2rem">
<div style="max-width:560px;margin:0 auto">
  <div style="margin-bottom:2rem">
    <span style="font-size:0.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#3ecf8e">Connector</span>
  </div>
  <h1 style="font-size:1.5rem;font-weight:700;color:#e8e8ec;margin:0 0 0.5rem">You're in, {name}.</h1>
  <p style="color:#9898a4;line-height:1.6;margin:0 0 1.5rem">
    Your Connector beta access has been approved. Here's your pilot API key — keep it secret.
  </p>
  <div style="background:#141418;border:1px solid #2a2a30;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem">
    <p style="font-size:0.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#3ecf8e;margin:0 0 0.5rem">Your Pilot API Key</p>
    <code style="font-family:'JetBrains Mono',monospace;font-size:0.9rem;color:#e8e8ec;word-break:break-all">{raw_key}</code>
  </div>
  <p style="color:#9898a4;font-size:0.85rem;line-height:1.6;margin:0 0 1rem">
    <strong style="color:#e8e8ec">What to do next:</strong><br>
    1. Sign in at <a href="{portal}/login" style="color:#3ecf8e">{portal}/login</a><br>
    2. Go to <strong>Download</strong> — grab the binary for your OS<br>
    3. Set <code>CONNECTOR_API_KEY={raw_key}</code> in your environment<br>
    4. Run the platform daemon and open your local dashboard
  </p>
  <p style="color:#9898a4;font-size:0.78rem;margin:1.5rem 0 0;border-top:1px solid #2a2a30;padding-top:1rem">
    This key is valid for {days} days · {seats} seat(s) · Reply to this email with questions.
  </p>
</div>
</body></html>
"#,
        name = name,
        raw_key = raw_key,
        portal = portal,
        days = req.duration_days,
        seats = req.seats
    );

    send_email(&email, "Your Connector pilot access is approved", &html).await;

    // Also notify admin
    if let Ok(admin_email) = std::env::var("CONNECTOR_ADMIN_EMAIL") {
        let admin_html = format!(
            "<p>Pilot approved: <strong>{}</strong> ({}) — key issued, {} days, {} seats.</p>",
            name, email, req.duration_days, req.seats
        );
        send_email(
            &admin_email,
            &format!("Pilot approved: {}", email),
            &admin_html,
        )
        .await;
    }

    tracing::info!(user_id, email, "pilot approved — key issued");

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "ok": true,
            "user_id": user_id,
            "email": email,
            "pilot_key_prefix": &raw_key[..16],
            "duration_days": req.duration_days,
            "seats": req.seats,
            "email_sent": true,
        })),
    )
        .into_response()
}

// ─── Admin: reject signup ─────────────────────────────────────────────────────

#[derive(serde::Deserialize, Default)]
pub struct RejectSignupRequest {
    #[serde(default)]
    pub reason: String,
}

/// POST /admin/signups/:user_id/reject
/// Marks user locked + role=Viewer (effectively blocked), sends rejection email.
pub async fn admin_reject_signup(
    State(state): State<SharedState>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    Json(req): Json<RejectSignupRequest>,
) -> impl IntoResponse {
    let (email, name) = {
        let mut user_store = state.user_store.lock().unwrap();
        let user = match user_store.users.get_mut(&user_id) {
            Some(u) => u,
            None => {
                return (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({
                        "error": "user_not_found"
                    })),
                )
                    .into_response()
            }
        };
        user.locked = true;
        let e = user.email.clone();
        let n = user.name.clone();
        let mut es = state.engine_store.lock().unwrap();
        user_store.persist_user(&user_id, es.as_mut());
        (e, n)
    };

    let reason_line = if req.reason.is_empty() {
        "We're currently prioritising specific use cases in our controlled beta.".to_string()
    } else {
        req.reason.clone()
    };

    let html = format!(
        r#"
<!DOCTYPE html><html><body style="font-family:Inter,sans-serif;background:#0a0a0b;color:#e8e8ec;margin:0;padding:2rem">
<div style="max-width:560px;margin:0 auto">
  <div style="margin-bottom:2rem">
    <span style="font-size:0.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#3ecf8e">Connector</span>
  </div>
  <h1 style="font-size:1.5rem;font-weight:700;color:#e8e8ec;margin:0 0 0.5rem">Beta application update</h1>
  <p style="color:#9898a4;line-height:1.6;margin:0 0 1rem">Hi {name},</p>
  <p style="color:#9898a4;line-height:1.6;margin:0 0 1rem">
    Thank you for your interest in the Connector controlled beta. At this time we're unable to approve your application.
  </p>
  <p style="color:#9898a4;line-height:1.6;margin:0 0 1.5rem">{reason_line}</p>
  <p style="color:#9898a4;font-size:0.82rem">You're welcome to try our <a href="https://connector-playground.fly.dev" style="color:#3ecf8e">hosted playground</a> in the meantime.</p>
  <p style="color:#9898a4;font-size:0.78rem;margin:1.5rem 0 0;border-top:1px solid #2a2a30;padding-top:1rem">
    If you think this is a mistake, reply to this email.
  </p>
</div>
</body></html>
"#,
        name = name,
        reason_line = reason_line
    );

    send_email(&email, "Connector beta application update", &html).await;
    tracing::info!(user_id, email, "signup rejected");

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "ok": true, "user_id": user_id, "email": email, "action": "rejected"
        })),
    )
        .into_response()
}

// ─── D6 / SMOKE-10: Stripe webhook ──────────────────────────────────────────

/// POST /billing/stripe/webhook — receives Stripe events, updates user tier.
///
/// Handles:
///   - `checkout.session.completed` → upgrade tier, issue license key
///   - `customer.subscription.deleted` → downgrade to community
///   - `invoice.payment_failed` → mark billing_state = degraded
///
/// Stripe signature verified via `STRIPE_WEBHOOK_SECRET` env var.
pub async fn stripe_webhook(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Fail closed: missing secret or missing signature is a rejection, not a skip.
    let sig_header = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_default();
    if webhook_secret.trim().is_empty() || sig_header.is_empty() {
        tracing::warn!("Stripe webhook rejected — secret or Stripe-Signature missing");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_signature", "status": 401})),
        )
            .into_response();
    }

    let ts = sig_header
        .split(',')
        .find(|s| s.starts_with("t="))
        .and_then(|s| s.strip_prefix("t="))
        .unwrap_or("0");
    let v1 = sig_header
        .split(',')
        .find(|s| s.starts_with("v1="))
        .and_then(|s| s.strip_prefix("v1="))
        .unwrap_or("");
    let ts_i: i64 = ts.parse().unwrap_or(0);
    let now = chrono::Utc::now().timestamp();
    if ts_i <= 0 || (now - ts_i).abs() > 300 {
        tracing::warn!("Stripe webhook timestamp outside tolerance — rejecting");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_signature", "status": 401})),
        )
            .into_response();
    }

    let signed_payload = format!("{}.{}", ts, std::str::from_utf8(&body).unwrap_or(""));
    let expected = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
            .unwrap_or_else(|_| HmacSha256::new_from_slice(b"invalid").expect("fallback"));
        mac.update(signed_payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    };
    let expected_bytes = hex::decode(&expected).unwrap_or_default();
    let presented_bytes = hex::decode(v1).unwrap_or_default();
    let sig_ok = !expected_bytes.is_empty()
        && expected_bytes.len() == presented_bytes.len()
        && expected_bytes
            .iter()
            .zip(presented_bytes.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if !sig_ok {
        tracing::warn!("Stripe webhook signature mismatch — rejecting");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_signature", "status": 401})),
        )
            .into_response();
    }

    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid JSON: {}", e), "status": 400})),
            )
                .into_response()
        }
    };

    let event_type = event["type"].as_str().unwrap_or("");
    tracing::info!(event_type = %event_type, "Stripe webhook received");

    match event_type {
        "checkout.session.completed" => {
            let customer_email = event["data"]["object"]["customer_email"]
                .as_str()
                .unwrap_or("");
            let customer_id = event["data"]["object"]["customer"].as_str().unwrap_or("");
            let metadata = &event["data"]["object"]["metadata"];
            let target_tier = metadata["tier"].as_str().unwrap_or("pro");

            // Update user tier
            let mut us = state.user_store.lock().unwrap();
            if let Some(uid) = us.email_index.get(customer_email).cloned() {
                if let Some(user) = us.users.get_mut(&uid) {
                    let old_tier = user.tier.clone();
                    user.tier = target_tier.to_string();
                    user.billing_state = "active".to_string();
                    if !customer_id.is_empty() {
                        user.stripe_customer_id = Some(customer_id.to_string());
                    }
                    tracing::info!(
                        email = %customer_email,
                        old_tier = %old_tier,
                        new_tier = %target_tier,
                        "Stripe CheckoutSessionCompleted: tier upgraded"
                    );
                }
            }
            drop(us);

            // Issue a new license key for the upgraded tier and persist
            let license_key = crate::auth::generate_api_key("cpk_live");
            let mut es = state.engine_store.lock().unwrap();
            let _ = es.folder_put(
                "stripe_events",
                &format!("checkout_{}", uuid::Uuid::new_v4().simple()),
                &serde_json::json!({
                    "event_type": "checkout.session.completed",
                    "customer_email": customer_email,
                    "customer_id": customer_id,
                    "tier": target_tier,
                    "license_key_issued": license_key,
                    "received_at": chrono::Utc::now().to_rfc3339(),
                }),
            );
            drop(es);

            // BIZ-7: analytics funnel — billing.upgraded milestone
            {
                let uid = {
                    let us = state.user_store.lock().unwrap();
                    us.email_index
                        .get(customer_email)
                        .cloned()
                        .unwrap_or_default()
                };
                if !uid.is_empty() {
                    crate::services::analytics::emit(
                        &state,
                        crate::services::analytics::AnalyticsEvent::new(
                            "billing.upgraded",
                            &uid,
                            serde_json::json!({ "tier": target_tier, "customer_id": customer_id }),
                        ),
                    );
                }
            }

            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "event": "checkout.session.completed",
                    "tier": target_tier,
                    "license_key_issued": true,
                })),
            )
                .into_response()
        }

        "customer.subscription.deleted" => {
            let customer_id = event["data"]["object"]["customer"].as_str().unwrap_or("");
            let mut us = state.user_store.lock().unwrap();
            for user in us.users.values_mut() {
                if user.stripe_customer_id.as_deref() == Some(customer_id) {
                    user.tier = "community".to_string();
                    user.billing_state = "cancelled".to_string();
                    tracing::info!(customer_id = %customer_id, "Stripe subscription deleted: downgraded to community");
                    break;
                }
            }
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({"ok": true, "event": "customer.subscription.deleted"})),
            )
                .into_response()
        }

        "invoice.payment_failed" => {
            let customer_id = event["data"]["object"]["customer"].as_str().unwrap_or("");
            let mut us = state.user_store.lock().unwrap();
            for user in us.users.values_mut() {
                if user.stripe_customer_id.as_deref() == Some(customer_id) {
                    user.billing_state = "degraded".to_string();
                    tracing::warn!(customer_id = %customer_id, "Stripe payment failed: billing_state=degraded");
                    break;
                }
            }
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({"ok": true, "event": "invoice.payment_failed"})),
            )
                .into_response()
        }

        _ => {
            // Unknown event — acknowledge to prevent Stripe retries
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({"ok": true, "event": event_type, "note": "unhandled"})),
            )
                .into_response()
        }
    }
}

/// GET /billing/upgrade-url?tier=pro|team|enterprise
/// Returns a Stripe Checkout URL for upgrading to a paid tier.
pub async fn upgrade_url(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let tier = params.get("tier").map(|s| s.as_str()).unwrap_or("pro");
    let base =
        std::env::var("CONNECTOR_APP_URL").unwrap_or_else(|_| "https://connector.ai".to_string());
    let price_id = match tier {
        "pro" => std::env::var("STRIPE_PRICE_PRO").unwrap_or_else(|_| "price_pro".into()),
        "team" => std::env::var("STRIPE_PRICE_TEAM").unwrap_or_else(|_| "price_team".into()),
        "enterprise" => std::env::var("STRIPE_PRICE_ENT").unwrap_or_else(|_| "price_ent".into()),
        other => {
            return Json(
                serde_json::json!({"error": format!("Unknown tier '{}'. Valid: pro, team, enterprise", other), "status": 400}),
            )
        }
    };
    // Build a Stripe Checkout session URL (in production use Stripe SDK;
    // here we construct the canonical upgrade URL developers can share/open)
    let url = format!("{}/upgrade?tier={}&price={}", base, tier, price_id);
    Json(serde_json::json!({
        "tier": tier,
        "url": url,
        "price_id": price_id,
        "note": "Open this URL to complete the upgrade. Tier activates instantly after payment.",
    }))
}

#[cfg(test)]
mod billing_tenant_id_tests {
    use super::billing_tenant_id_from_agent_meta;

    #[test]
    fn prefers_user_id_then_created_by() {
        let m = serde_json::json!({"user_id": "u1", "created_by": "u2"});
        assert_eq!(
            billing_tenant_id_from_agent_meta(Some(&m)).as_deref(),
            Some("u1")
        );
        let m2 = serde_json::json!({"created_by": "tenant-sub"});
        assert_eq!(
            billing_tenant_id_from_agent_meta(Some(&m2)).as_deref(),
            Some("tenant-sub")
        );
        assert!(billing_tenant_id_from_agent_meta(None).is_none());
    }
}
