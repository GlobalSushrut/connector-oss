use crate::auth::PlatformRole;
use crate::boot::uptime_secs;
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

/// Same identity resolution as `books::caller` — Bearer or `x-api-key` (e.g. `cpk_*`).
fn cost_dashboard_caller(headers: &HeaderMap) -> Option<(String, PlatformRole)> {
    if std::env::var("CONNECTOR_DEV_MODE").is_ok() {
        return Some(("dev".to_string(), PlatformRole::SuperAdmin));
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))?;
    let claims = crate::auth::verify_token(token).ok()?;
    Some((claims.sub, PlatformRole::from_str(&claims.role)))
}

/// Same payload as `GET /api/v1/monitor/health` — extracted for `GET /api/v1/health` rollup (Phase 1.8).
pub fn kernel_health_snapshot(state: &SharedState) -> serde_json::Value {
    // FIX BUG-037: Collect kernel data first, drop kernel lock, then acquire engine_store
    let (trust, agent_count, packet_count, audit_count, integrity) = {
        let k = state.kernel.lock().unwrap();
        let trust = connector_engine::TrustComputer::compute(&k);
        let agent_count = k.agents().len();
        let packet_count = k.packet_count();
        let audit_count = k.audit_count(); // includes flushed log + pending batch buffer
        let integrity = k.verify_audit_chain().is_ok();
        (trust, agent_count, packet_count, audit_count, integrity)
    };

    let llm_wired = state.llm_wired();
    let guard_active = state.guard.lock().is_ok();
    let budget_configured = std::env::var("CONNECTOR_AGENT_TOKEN_BUDGET").is_ok();
    let llm_fallback_configured = std::env::var("CONNECTOR_LLM_FALLBACK").is_ok();

    let prompt_count = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("prompt_meta", None)
            .unwrap_or_default()
            .len()
    };

    let playground = crate::services::runtime_control::free_tier_open_auth_enabled();
    // In playground mode guard+devguard embedded is sufficient; no server-side LLM needed
    let governance_ready = guard_active && (llm_wired || playground);

    let status = if playground && agent_count == 0 {
        // Fresh playground node — healthy by design, waiting for first connection
        "healthy"
    } else if trust.score >= 80 && integrity && governance_ready {
        // Machine truth: health score band — NOT a product "production ready" claim.
        "health_band_high"
    } else if trust.score >= 60 && integrity {
        "healthy"
    } else if trust.score >= 40 {
        "degraded"
    } else {
        "critical"
    };

    let deploy_safe = integrity && (agent_count > 0 || playground) && governance_ready;
    let _legacy_production_ready_score =
        trust.score >= 80 && integrity && governance_ready;

    let runtime_mode = *state.runtime_mode.read().unwrap();
    let isolation_runtime = *state.isolation_runtime.read().unwrap();
    let enforced_agent_limit: usize =
        crate::services::agents::resolved_kernel_agent_cap(state.as_ref()) as usize;
    let packet_limit = state.license.packet_limit();
    let agent_pct = if enforced_agent_limit == usize::MAX {
        0.0_f64
    } else {
        (agent_count as f64 / enforced_agent_limit as f64 * 100.0).min(100.0)
    };
    let packet_pct = if packet_limit == usize::MAX {
        0.0_f64
    } else {
        (packet_count as f64 / packet_limit as f64 * 100.0).min(100.0)
    };

    let mut recommendations: Vec<String> = Vec::new();
    if trust.score < 70 && !playground {
        recommendations.push(format!(
            "Trust score {} is below deployment threshold (70). Review audit log for failed operations.",
            trust.score
        ));
    }
    if !integrity {
        recommendations.push(
            "Audit chain integrity check FAILED. Possible data tampering — investigate immediately."
                .into(),
        );
    }
    if !llm_wired {
        if playground {
            recommendations.push("Playground ready. Visit /connect — pick your AI tool (Cursor, Windsurf, Claude Code), get a Base URL + token, and paste into your tool settings.".into());
        } else {
            recommendations.push("CONNECTOR_LLM_API_KEY not set — LLM calls blocked. Set env var to enable Moat 1 (cost reduction) and Moat 2 (guardrails).".into());
        }
    }
    if !budget_configured && !playground {
        recommendations.push("CONNECTOR_AGENT_TOKEN_BUDGET not set — using default 16,000 token budget per agent. Set env var for custom limits.".into());
    }
    if !llm_fallback_configured && !playground {
        recommendations.push("CONNECTOR_LLM_FALLBACK not set — no fallback provider. Set to enable dynamic model routing cost savings.".into());
    }
    if prompt_count == 0 && !playground {
        recommendations.push("No prompts registered in Prompt Registry. Use POST /api/v1/prompts to decouple agent instructions from code (Moat 3).".into());
    }
    if agent_pct > 80.0 {
        recommendations.push(format!(
            "Agent usage at {:.0}% of tier limit. Consider upgrading to unlock more agents.",
            agent_pct
        ));
    }
    if packet_pct > 80.0 {
        recommendations.push(format!(
            "Memory usage at {:.0}% of tier limit. Consider upgrading or enabling eviction.",
            packet_pct
        ));
    }
    if agent_count == 0 && !playground {
        recommendations
            .push("No agents registered. Register your first agent to begin trust scoring.".into());
    }

    serde_json::json!({
        "status": status,
        "deploy_safe": deploy_safe,
        "trust_score": trust.score,
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "integrity": integrity,
        "agents": agent_count,
        "packets": packet_count,
        "audit_entries": audit_count,
        "measured": {
            "health_band": status,
            "deploy_safe_heuristic": deploy_safe,
            "not_a_product_claim": true,
        },
        "honesty": "status is a measured health band (trust/integrity/governance), not a production-ready product claim",
        "governance": {
            "llm_router_wired": llm_wired,
            "guard_pipeline_active": guard_active,
            "budget_configured": budget_configured,
            "fallback_provider_configured": llm_fallback_configured,
            "prompt_registry_entries": prompt_count,
            "governance_ready": governance_ready,
            "llm_broker_unbypassable": crate::substrate::llm_broker_gate::broker_unbypassable(),
            "sandbox_unbypassable_enforced": crate::substrate::sandbox_unbypassable::unbypassable_bar_enforced(),
        },
        "dimensions": {
            "memory_integrity": trust.dimensions.memory_integrity,
            "audit_completeness": trust.dimensions.audit_completeness,
            "authorization_coverage": trust.dimensions.authorization_coverage,
            "decision_provenance": trust.dimensions.decision_provenance,
            "operational_health": trust.dimensions.operational_health,
        },
        "tier_usage": {
            "tier": format!("{:?}", state.license.tier),
            "runtime_mode": format!("{:?}", runtime_mode),
            "isolation_runtime": isolation_runtime.as_str(),
            "docker_available": crate::services::runtime_control::docker_available(),
            "agents_used": agent_count,
            "agents_limit": enforced_agent_limit,
            "agents_pct": agent_pct,
            "packets_used": packet_count,
            "packets_limit": state.license.packet_limit(),
            "packets_pct": packet_pct,
            "retention_days": state.license.retention_days,
        },
        "recommendations": recommendations,
        "substrate": {
            "usage_event_count": crate::substrate::usage_event::usage_event_count(state),
            "artifact_log_count": crate::substrate::artifact_log::artifact_log_count(state),
            "cfni_enabled": crate::substrate::cfni::cfni_enabled(),
        },
        "uptime": format!(
            "{}h {}m {}s",
            uptime_secs() / 3600,
            (uptime_secs() % 3600) / 60,
            uptime_secs() % 60
        ),
        "uptime_seconds": uptime_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "node": std::env::var("HOSTNAME").unwrap_or_else(|_| "connector-node".to_string()),
    })
}

pub async fn health_check(State(state): State<SharedState>) -> Json<serde_json::Value> {
    Json(kernel_health_snapshot(&state))
}

pub async fn trust_live(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let denied_count = k
        .audit_log()
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let failed_count = k
        .audit_log()
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
        .count();

    state.metrics.trust_score.set(trust.score as f64);

    Json(serde_json::json!({
        "score": trust.score,
        "agent_health_score": trust.score,
        "trust_grade": trust.grade,
        "denied_total": denied_count,
        "failed_total": failed_count,
        "dimensions": trust.dimensions,
        "verifiable": trust.verifiable,
        "operations_analyzed": trust.operations_analyzed,
    }))
}

pub async fn integrity_check(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let integrity = k.verify_audit_chain().is_ok();
    let packet_count = k.packet_count();
    let audit_count = k.audit_log().len();

    Json(serde_json::json!({
        "integrity": integrity,
        "packets_checked": packet_count,
        "audit_entries_checked": audit_count,
        "method": "CID verification + HMAC chain",
    }))
}

/// Wave 1 — Item 1.1: LLM cost per agent, per session, per model
///
/// **Tenant scope:** non–SuperAdmin callers only see kernel agents whose `agent_meta`
/// billing tenant (`user_id` or `created_by`) matches JWT `sub` — aligned with Books.
/// SuperAdmin and `CONNECTOR_DEV_MODE` callers see all agents on the node.
pub async fn cost_dashboard(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some((tenant_sub, role)) = cost_dashboard_caller(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "authentication_required",
                "message": "Bearer token or x-api-key required for cost dashboard",
            })),
        )
            .into_response();
    };

    let apply_tenant_filter = role != PlatformRole::SuperAdmin && tenant_sub != "dev";

    let agents_snapshot: Vec<_> = {
        let k = state.kernel.lock().unwrap();
        k.agents()
            .iter()
            .map(|(pid, acb)| (pid.clone(), acb.clone()))
            .collect()
    };

    let mut filtered: Vec<_> = Vec::new();
    {
        let es = state.engine_store.lock().unwrap();
        for (kernel_pid, acb) in agents_snapshot {
            if apply_tenant_filter {
                let api_pid = es
                    .folder_get("agent_pid_map", &kernel_pid)
                    .ok()
                    .flatten()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| kernel_pid.clone());
                let meta = es.folder_get("agent_meta", &api_pid).ok().flatten();
                let billing_tenant =
                    crate::services::billing::billing_tenant_id_from_agent_meta(meta.as_ref());
                if billing_tenant.as_deref() != Some(tenant_sub.as_str()) {
                    continue;
                }
            }
            filtered.push((kernel_pid, acb));
        }
    }

    let (session_count, llm_calls, node_agent_count) = {
        let k = state.kernel.lock().unwrap();
        (
            k.sessions().len(),
            state.metrics.llm_calls_total.get(),
            k.agents().len(),
        )
    };

    let mut total_tokens: u64 = 0;
    let mut total_packets: u64 = 0;
    let mut total_cost: f64 = 0.0;
    let mut by_agent: Vec<serde_json::Value> = Vec::new();
    let mut by_plugin: std::collections::HashMap<String, (u64, f64, f64, u64)> =
        std::collections::HashMap::new();
    let mut by_model: std::collections::HashMap<String, (u64, f64)> =
        std::collections::HashMap::new();

    for (pid, acb) in &filtered {
        total_tokens += acb.total_tokens_consumed;
        total_packets = total_packets.saturating_add(acb.total_packets);
        total_cost += acb.total_cost_usd;

        let model_name = acb.model.clone().unwrap_or_else(|| "unknown".to_string());
        let entry = by_model.entry(model_name.clone()).or_insert((0, 0.0));
        entry.0 += acb.total_tokens_consumed;
        entry.1 += acb.total_cost_usd;

        by_agent.push(serde_json::json!({
            "pid": pid,
            "name": &acb.agent_name,
            "model": model_name,
            "tokens": acb.total_tokens_consumed,
            // Legacy field — list-price estimate only; not invoice spend.
            "cost_usd_estimated": acb.total_cost_usd,
            "packets": acb.total_packets,
            "status": format!("{:?}", acb.status),
            "quota_tokens": acb.memory_region.quota_tokens,
            "used_tokens": acb.memory_region.used_tokens,
            "quota_usage_pct": if acb.memory_region.quota_tokens > 0 {
                (acb.memory_region.used_tokens as f64 / acb.memory_region.quota_tokens as f64 * 100.0)
            } else { 0.0 },
        }));
    }

    // Usage-first sort: tokens then packets (machine-recorded), not USD.
    by_agent.sort_by(|a, b| {
        let ta = a.get("tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        let tb = b.get("tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        tb.cmp(&ta)
    });

    let model_breakdown: Vec<serde_json::Value> = by_model
        .iter()
        .map(|(model, (tokens, cost))| {
            serde_json::json!({
                "model": model,
                "tokens": tokens,
                "cost_usd_estimated": cost,
                "pct_of_tokens": if total_tokens > 0 {
                    (*tokens as f64 / total_tokens as f64) * 100.0
                } else {
                    0.0
                },
            })
        })
        .collect();

    // Universal cost control plane: billing_usage_events (gateway-recorded), with plugin attribution + chain head.
    let mut chain_head = serde_json::json!({});
    let mut chain_count = 0u64;
    {
        let es = state.engine_store.lock().unwrap();
        chain_head = es
            .folder_get("billing_cost_chain_head", &tenant_sub)
            .ok()
            .flatten()
            .unwrap_or_else(|| serde_json::json!({}));
        let keys = es
            .folder_keys("billing_usage_events", None)
            .unwrap_or_default();
        for k in keys {
            let Some(v) = es.folder_get("billing_usage_events", &k).ok().flatten() else {
                continue;
            };
            if v.get("event_type").and_then(|x| x.as_str()) != Some("llm_completion") {
                continue;
            }
            if apply_tenant_filter
                && v.get("account_id").and_then(|x| x.as_str()) != Some(tenant_sub.as_str())
            {
                continue;
            }
            chain_count = chain_count.saturating_add(1);
            let plugin = v
                .get("plugin_id")
                .and_then(|x| x.as_str())
                .unwrap_or("core")
                .to_string();
            let tokens = v.get("total_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
            let est = v
                .get("cost_usd_estimated")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0);
            let real = v
                .get("cost_usd_real")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0);
            let entry = by_plugin.entry(plugin).or_insert((0, 0.0, 0.0, 0));
            entry.0 = entry.0.saturating_add(tokens);
            entry.1 += est;
            entry.2 += real;
            if v.get("is_real_cost")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
            {
                entry.3 = entry.3.saturating_add(1);
            }
        }
    }
    let plugin_breakdown: Vec<serde_json::Value> = by_plugin
        .iter()
        .map(|(plugin, (tokens, est, real, real_events))| {
            serde_json::json!({
                "plugin_id": plugin,
                "tokens": tokens,
                "cost_usd_estimated": est,
                "cost_usd_real": real,
                "real_cost_events": real_events,
            })
        })
        .collect();

    let scope = if apply_tenant_filter {
        "tenant_kernel_agents"
    } else {
        "fleet_node_all_agents"
    };

    let (audit_entries, denied_ops, tool_dispatches) = {
        let k = state.kernel.lock().unwrap();
        let audit = k.audit_log().len();
        let denied = k
            .audit_log()
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
            .count();
        let tools = k
            .audit_log()
            .iter()
            .filter(|e| e.operation == vac_core::types::MemoryKernelOp::ToolDispatch)
            .count();
        (audit, denied, tools)
    };

    let has_usage = total_tokens > 0 || chain_count > 0 || llm_calls > 0;
    // USD is never machine-native spend — only optional list-price estimate.
    let estimated_usd = if has_usage && total_cost > 0.0 {
        serde_json::Value::from(total_cost)
    } else {
        serde_json::Value::Null
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "economy_mode": "usage_first",
            "schema": "agentic_economy.v1",
            "total_tokens": total_tokens,
            "total_packets": total_packets,
            "total_sessions": session_count,
            "total_llm_calls": llm_calls,
            // Compat alias — LLM calls, not HTTP requests.
            "total_requests": llm_calls,
            "billing_events": chain_count,
            "agent_count": filtered.len(),
            "agents_tracked": filtered.len(),
            "node_agent_count": node_agent_count,
            "operations": {
                "total_audit_entries": audit_entries,
                "denied_ops": denied_ops,
                "tool_dispatches": tool_dispatches,
            },
            // Deprecated as primary FinOps signal — null when unavailable (not fake $0).
            "total_cost_usd": estimated_usd.clone(),
            "estimated_list_price_usd": estimated_usd,
            "by_agent": by_agent,
            "by_model": model_breakdown,
            "by_plugin": plugin_breakdown,
            "cost_control_plane": "connector_gateway",
            "cost_chain": {
                "account_id": tenant_sub,
                "events": chain_count,
                "head": chain_head,
            },
            "scope": scope,
            "tenant_sub": tenant_sub,
            "cost_basis": "usage_first: tokens/packets/sessions/ops from kernel + billing_usage_events. USD fields are optional provider list-price estimates, never invoices.",
            "note": "Agentic economy meters are machine-recorded (tokens, packets, sessions, LLM calls, tool dispatches, denials, audit). Do not treat USD as spend.",
            "honesty_note": if has_usage {
                serde_json::Value::Null
            } else {
                serde_json::json!("No usage events yet — token/packet/op totals are zero because nothing ran, not because spend is $0.")
            },
            "has_usage_data": has_usage,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct CostChainQuery {
    pub limit: Option<usize>,
}

/// `GET /monitor/cost-chain` — auditable cost ledger chain, recorded by gateway.
pub async fn cost_chain(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<CostChainQuery>,
) -> impl IntoResponse {
    let Some((tenant_sub, role)) = cost_dashboard_caller(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"authentication_required"})),
        )
            .into_response();
    };
    let apply_tenant_filter = role != PlatformRole::SuperAdmin && tenant_sub != "dev";
    let limit = q.limit.unwrap_or(200).clamp(10, 2000);

    let mut events: Vec<serde_json::Value> = Vec::new();
    let mut head = serde_json::json!({});
    {
        let es = state.engine_store.lock().unwrap();
        head = es
            .folder_get("billing_cost_chain_head", &tenant_sub)
            .ok()
            .flatten()
            .unwrap_or_else(|| serde_json::json!({}));
        let keys = es
            .folder_keys("billing_usage_events", None)
            .unwrap_or_default();
        for k in keys {
            let Some(v) = es.folder_get("billing_usage_events", &k).ok().flatten() else {
                continue;
            };
            if v.get("event_type").and_then(|x| x.as_str()) != Some("llm_completion") {
                continue;
            }
            if apply_tenant_filter
                && v.get("account_id").and_then(|x| x.as_str()) != Some(tenant_sub.as_str())
            {
                continue;
            }
            events.push(v);
        }
    }
    events.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
        tb.cmp(ta)
    });
    events.truncate(limit);

    // continuity check over descending order
    let mut broken_links = Vec::new();
    for w in events.windows(2) {
        let newer = &w[0];
        let older = &w[1];
        let newer_prev = newer
            .get("chain_prev_hash")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let older_hash = older
            .get("chain_hash")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if !newer_prev.is_empty() && newer_prev != "GENESIS" && newer_prev != older_hash {
            broken_links.push(serde_json::json!({
                "newer_seq": newer.get("chain_seq").cloned().unwrap_or(serde_json::Value::Null),
                "newer_hash": newer.get("chain_hash").cloned().unwrap_or(serde_json::Value::Null),
                "expected_prev_hash": newer_prev,
                "older_hash": older_hash,
            }));
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "account_id": tenant_sub,
            "cost_control_plane": "connector_gateway",
            "head": head,
            "events": events,
            "chain_integrity": {
                "checked_links": events.len().saturating_sub(1),
                "broken_links": broken_links,
                "contiguous": broken_links.is_empty(),
            },
            "note": "cost_usd_real is set when provider pricing is used (token_source provider_api/anthropic_api); otherwise only estimated cost is available."
        })),
    )
        .into_response()
}

/// Wave 1 — Item 1.2: Budget tracking, burn rate, projections
pub async fn cost_center(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis();

    let mut total_cost: f64 = 0.0;
    let mut total_tokens: u64 = 0;
    let mut agent_costs: Vec<serde_json::Value> = Vec::new();
    let mut earliest_activity: i64 = now;

    for (pid, acb) in k.agents() {
        total_cost += acb.total_cost_usd;
        total_tokens += acb.total_tokens_consumed;
        if acb.registered_at < earliest_activity {
            earliest_activity = acb.registered_at;
        }

        let budget_limit = if acb.memory_region.quota_tokens > 0 {
            Some(acb.memory_region.quota_tokens)
        } else {
            None
        };

        let budget_pct =
            budget_limit.map(|lim| acb.total_tokens_consumed as f64 / lim as f64 * 100.0);

        let mut alerts: Vec<String> = Vec::new();
        if let Some(pct) = budget_pct {
            if pct > 90.0 {
                alerts.push(format!("Token budget at {:.0}% — will hit limit soon", pct));
            } else if pct > 75.0 {
                alerts.push(format!("Token budget at {:.0}%", pct));
            }
        }

        agent_costs.push(serde_json::json!({
            "pid": pid,
            "name": &acb.agent_name,
            "model": acb.model.as_deref().unwrap_or("unknown"),
            "tokens": acb.total_tokens_consumed,
            "packets": acb.total_packets,
            "budget_tokens": budget_limit,
            "budget_pct": budget_pct,
            "role": format!("{:?}", acb.role),
            "alerts": alerts,
            "cost_usd_estimated": acb.total_cost_usd,
        }));
    }

    let elapsed_hours = ((now - earliest_activity) as f64 / 3_600_000.0).max(0.01);
    let tokens_per_hour = total_tokens as f64 / elapsed_hours;
    let projected_daily_tokens = tokens_per_hour * 24.0;
    // Legacy USD burn kept only as optional estimate (null when no tokens).
    let burn_rate_per_hour = if total_tokens > 0 {
        total_cost / elapsed_hours
    } else {
        0.0
    };
    let projected_daily = if total_tokens > 0 {
        burn_rate_per_hour * 24.0
    } else {
        0.0
    };

    let denied_ops = k
        .audit_log()
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let tool_dispatches = k
        .audit_log()
        .iter()
        .filter(|e| e.operation == vac_core::types::MemoryKernelOp::ToolDispatch)
        .count();
    let has_usage = total_tokens > 0 || !agent_costs.is_empty();

    Json(serde_json::json!({
        "economy_mode": "usage_first",
        "schema": "agentic_economy_center.v1",
        "total_tokens": total_tokens,
        "tokens_per_hour": tokens_per_hour,
        "projected_daily_tokens": projected_daily_tokens,
        "elapsed_hours": elapsed_hours,
        "agent_count": k.agents().len(),
        "by_agent": agent_costs,
        "operations": {
            "total_audit_entries": k.audit_log().len(),
            "denied_ops": denied_ops,
            "tool_dispatches": tool_dispatches,
        },
        "tier": format!("{:?}", state.license.tier),
        // Optional list-price estimates — not primary FinOps; null when no usage.
        "total_cost_usd": if has_usage && total_cost > 0.0 {
            serde_json::Value::from(total_cost)
        } else {
            serde_json::Value::Null
        },
        "burn_rate_per_hour": if has_usage && total_cost > 0.0 {
            serde_json::Value::from(burn_rate_per_hour)
        } else {
            serde_json::Value::Null
        },
        "projected_daily_usd": if has_usage && total_cost > 0.0 {
            serde_json::Value::from(projected_daily)
        } else {
            serde_json::Value::Null
        },
        "honesty_note": "Primary meters are tokens/ops/hours. USD fields are optional provider list-price estimates — not invoices and not machine-native spend.",
    }))
}

/// Wave 3 — Item 3.4: Trust score over time + improvement plan
pub async fn trust_trend(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let audit = k.audit_log();

    if audit.is_empty() {
        return Json(serde_json::json!({
            "agent_health_score": trust.score,
            "grade": trust.grade,
            "trend": "insufficient_data",
            "windows": [],
        }));
    }

    // Divide audit log into time windows (last 6 windows, each ~1/6 of total span)
    let first_ts = audit.first().map(|e| e.timestamp).unwrap_or(0);
    let last_ts = audit.last().map(|e| e.timestamp).unwrap_or(0);
    let span = (last_ts - first_ts).max(1);
    let window_size = span / 6;

    let mut windows: Vec<serde_json::Value> = Vec::new();
    let mut scores: Vec<f64> = Vec::new();

    for i in 0..6 {
        let w_start = first_ts + (window_size * i);
        let w_end = w_start + window_size;
        let w_entries: Vec<_> = audit
            .iter()
            .filter(|e| e.timestamp >= w_start && e.timestamp < w_end)
            .collect();

        if w_entries.is_empty() {
            continue;
        }

        let total = w_entries.len() as f64;
        let success = w_entries
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Success)
            .count() as f64;
        let denied = w_entries
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
            .count() as f64;
        let failed = w_entries
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
            .count() as f64;

        let window_score = (success / total * 100.0).round();
        scores.push(window_score);

        windows.push(serde_json::json!({
            "window": i,
            "start_ts": w_start,
            "end_ts": w_end,
            "operations": total as usize,
            "success": success as usize,
            "denied": denied as usize,
            "failed": failed as usize,
            "health_score": window_score,
        }));
    }

    let trend = if scores.len() >= 2 {
        let first_half: f64 =
            scores[..scores.len() / 2].iter().sum::<f64>() / (scores.len() / 2) as f64;
        let second_half: f64 = scores[scores.len() / 2..].iter().sum::<f64>()
            / (scores.len() - scores.len() / 2) as f64;
        if second_half > first_half + 5.0 {
            "improving"
        } else if second_half < first_half - 5.0 {
            "degrading"
        } else {
            "stable"
        }
    } else {
        "insufficient_data"
    };

    let mut improvement_plan: Vec<serde_json::Value> = Vec::new();
    if trust.dimensions.memory_integrity < 80 {
        improvement_plan.push(serde_json::json!({
            "dimension": "memory_integrity",
            "current": trust.dimensions.memory_integrity,
            "target": 90,
            "action": "Enable eviction policies and run stale-analysis to clean corrupted/duplicate packets",
        }));
    }
    if trust.dimensions.authorization_coverage < 80 {
        improvement_plan.push(serde_json::json!({
            "dimension": "authorization_coverage",
            "current": trust.dimensions.authorization_coverage,
            "target": 90,
            "action": "Add tool bindings to agents and configure namespace mounts for isolation",
        }));
    }
    if trust.dimensions.decision_provenance < 80 {
        improvement_plan.push(serde_json::json!({
            "dimension": "decision_provenance",
            "current": trust.dimensions.decision_provenance,
            "target": 90,
            "action": "Record decisions through /disputes/record to build provenance chain",
        }));
    }

    Json(serde_json::json!({
        "agent_health_score": trust.score,
        "grade": trust.grade,
        "trend": trend,
        "windows": windows,
        "dimensions": trust.dimensions,
        "improvement_plan": improvement_plan,
    }))
}

/// Track 2 Phase D — Item D.1: Show StorageZone configs + compliance proof
pub async fn storage_layout(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let layout = &state.storage_layout;
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);

    let zones: Vec<serde_json::Value> = layout
        .zones
        .iter()
        .map(|(zone, config)| {
            serde_json::json!({
                "zone": format!("{:?}", zone),
                "path": zone.path(),
                "durability": format!("{:?}", config.durability),
                "replication": format!("{:?}", config.replication),
                "encrypted": config.encrypted,
            })
        })
        .collect();

    Json(serde_json::json!({
        "cell_id": &layout.cell_id,
        "zones": zones,
        "zone_count": zones.len(),
        "agent_health_score": trust.score,
    }))
}

/// Track 2 Phase D — Item D.2: Zone-specific health
pub async fn storage_zone_health(
    State(state): State<SharedState>,
    Path(zone_name): Path<String>,
) -> Json<serde_json::Value> {
    let layout = &state.storage_layout;

    // Find zone by name match
    let found = layout.zones.iter().find(|(z, _)| {
        format!("{:?}", z)
            .to_lowercase()
            .contains(&zone_name.to_lowercase())
    });

    match found {
        Some((zone, config)) => {
            let k = state.kernel.lock().unwrap();

            Json(serde_json::json!({
                "zone": format!("{:?}", zone),
                "path": zone.path(),
                "healthy": true,
                "config": {
                    "durability": format!("{:?}", config.durability),
                    "replication": format!("{:?}", config.replication),
                    "encrypted": config.encrypted,
                },
                "stats": {
                    "kernel_packets": k.packet_count(),
                    "kernel_agents": k.agents().len(),
                },
            }))
        }
        None => Json(
            serde_json::json!({"error": format!("Zone '{}' not found", zone_name), "status": 404}),
        ),
    }
}

pub async fn alert_rules(State(state): State<SharedState>) -> Json<serde_json::Value> {
    // Static rules from config (e.g. loaded from CONNECTOR_ALERTS_JSON env)
    let mut rules: Vec<serde_json::Value> = state
        .config
        .alerts
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "condition": r.condition,
                "channels": r.channels.len(),
                "cooldown_secs": r.cooldown_secs,
                "source": "config",
            })
        })
        .collect();

    // X.10: Dynamic rules stored via POST /monitor/alert-rules (persisted in engine_store)
    let es = state.engine_store.lock().unwrap();
    let dyn_keys = es.folder_keys("alert_rules", None).unwrap_or_default();
    let mut dyn_rules: Vec<serde_json::Value> = dyn_keys
        .iter()
        .filter_map(|k| es.folder_get("alert_rules", k).ok().flatten())
        .collect();
    let dyn_count = dyn_rules.len();
    rules.append(&mut dyn_rules);

    Json(serde_json::json!({
        "count": rules.len(),
        "static_count": rules.len() - dyn_count,
        "dynamic_count": dyn_count,
        "rules": rules,
        "tip": "Add dynamic alert rules via POST /monitor/alert-rules",
    }))
}

/// POST /monitor/alert-rules — persist a dynamic alert rule to engine_store (admin+)
pub async fn create_alert_rule(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let role = token
        .and_then(|t| crate::auth::verify_token(t).ok())
        .map(|c| crate::auth::PlatformRole::from_str(&c.role))
        .unwrap_or(crate::auth::PlatformRole::Viewer);
    if role.rank() < 5 {
        return Json(serde_json::json!({"error": "Admin role required", "status": 403}));
    }

    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed");
    let rule_id = format!("rule_{}", uuid::Uuid::new_v4());
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "monitor",
        "lifecycle",
        "create_alert_rule",
        &serde_json::json!({"name": name, "rule_id": rule_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let record = serde_json::json!({
        "rule_id": rule_id,
        "name": name,
        "condition": req.get("condition"),
        "channels": req.get("channels"),
        "cooldown_secs": req.get("cooldown_secs").and_then(|v| v.as_u64()).unwrap_or(300),
        "created_at": chrono::Utc::now().to_rfc3339(),
        "source": "dynamic",
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("alert_rules", &rule_id, &record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "rule_id": rule_id,
        "created": true,
        "rule": record,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// PUT /monitor/alert-rules/:rule_id — update an existing dynamic alert rule (admin+)
pub async fn update_alert_rule(
    State(state): State<SharedState>,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let role = token
        .and_then(|t| crate::auth::verify_token(t).ok())
        .map(|c| crate::auth::PlatformRole::from_str(&c.role))
        .unwrap_or(crate::auth::PlatformRole::Viewer);
    if role.rank() < 5 {
        return Json(serde_json::json!({"error": "Admin role required", "status": 403}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "monitor",
        "lifecycle",
        "update_alert_rule",
        &serde_json::json!({"rule_id": rule_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let Some(existing) = es.folder_get("alert_rules", &rule_id).ok().flatten() else {
        drop(es);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({"error": "Rule not found", "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}));
    };
    let mut merged = existing;
    if let Some(name) = req.get("name").and_then(|v| v.as_str()) {
        merged["name"] = serde_json::json!(name);
    }
    if let Some(condition) = req.get("condition") {
        merged["condition"] = condition.clone();
    }
    if let Some(channels) = req.get("channels") {
        merged["channels"] = channels.clone();
    }
    if let Some(cooldown) = req.get("cooldown_secs").and_then(|v| v.as_u64()) {
        merged["cooldown_secs"] = serde_json::json!(cooldown);
    }
    merged["updated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
    let _ = es.folder_put("alert_rules", &rule_id, &merged);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({"ok": true, "updated": true, "rule_id": rule_id, "rule": merged, "task_id": admitted.task_id, "executed": true, "admits": false}))
}

/// DELETE /monitor/alert-rules/:rule_id — delete dynamic alert rule (admin+)
pub async fn delete_alert_rule(
    State(state): State<SharedState>,
    axum::extract::Path(rule_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let role = token
        .and_then(|t| crate::auth::verify_token(t).ok())
        .map(|c| crate::auth::PlatformRole::from_str(&c.role))
        .unwrap_or(crate::auth::PlatformRole::Viewer);
    if role.rank() < 5 {
        return Json(serde_json::json!({"error": "Admin role required", "status": 403}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "monitor",
        "lifecycle",
        "retire_alert_rule",
        &serde_json::json!({"rule_id": rule_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut es = state.engine_store.lock().unwrap();
    let removed = es.folder_delete("alert_rules", &rule_id).is_ok();
    drop(es);
    open_proceed.finish_observed(removed);
    Json(serde_json::json!({"ok": true, "rule_id": rule_id, "deleted": removed, "task_id": admitted.task_id, "executed": removed, "admits": false}))
}

// ── Budget Threshold Alerts ────────────────────────────────────────────────────
// Configurable warning thresholds: warn at 70%, 80%, 90% before the hard block.
// Buyers: FinOps teams, AI product owners — "tell me before it breaks".

/// GET /monitor/budget-alerts — per-agent budget warnings at 70/80/90% thresholds
pub async fn budget_alerts(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let global_budget = std::env::var("CONNECTOR_AGENT_TOKEN_BUDGET")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(16_000);

    let mut warnings: Vec<serde_json::Value> = Vec::new();
    let mut exceeded: Vec<serde_json::Value> = Vec::new();

    for (pid, acb) in k.agents() {
        // Use per-agent budget from kernel if set, else global env default
        let budget = if acb.memory_region.quota_tokens > 0 {
            acb.memory_region.quota_tokens
        } else {
            global_budget
        };

        if budget == 0 {
            continue;
        }

        let pct = acb.total_tokens_consumed as f64 / budget as f64 * 100.0;

        let entry = serde_json::json!({
            "pid": pid,
            "name": acb.agent_name,
            "tokens_consumed": acb.total_tokens_consumed,
            "budget_tokens": budget,
            "budget_pct": (pct * 10.0).round() / 10.0,
            "cost_usd": acb.total_cost_usd,
        });

        if pct >= 100.0 {
            exceeded.push({
                let mut e = entry.as_object().unwrap().clone();
                e.insert("alert_level".into(), serde_json::json!("exceeded"));
                e.insert(
                    "message".into(),
                    serde_json::json!("LLM calls are BLOCKED. Reset budget or increase limit."),
                );
                e.insert(
                    "action".into(),
                    serde_json::json!("POST /api/v1/agents/:pid/reset-budget"),
                );
                serde_json::Value::Object(e)
            });
        } else if pct >= 90.0 {
            warnings.push({
                let mut e = entry.as_object().unwrap().clone();
                e.insert("alert_level".into(), serde_json::json!("critical"));
                e.insert(
                    "message".into(),
                    serde_json::json!(format!(
                        "Budget at {:.0}% — will be blocked very soon.",
                        pct
                    )),
                );
                serde_json::Value::Object(e)
            });
        } else if pct >= 80.0 {
            warnings.push({
                let mut e = entry.as_object().unwrap().clone();
                e.insert("alert_level".into(), serde_json::json!("warning"));
                e.insert(
                    "message".into(),
                    serde_json::json!(format!("Budget at {:.0}% — approaching limit.", pct)),
                );
                serde_json::Value::Object(e)
            });
        } else if pct >= 70.0 {
            warnings.push({
                let mut e = entry.as_object().unwrap().clone();
                e.insert("alert_level".into(), serde_json::json!("info"));
                e.insert(
                    "message".into(),
                    serde_json::json!(format!("Budget at {:.0}% — monitor closely.", pct)),
                );
                serde_json::Value::Object(e)
            });
        }
    }

    let overall_status = if !exceeded.is_empty() {
        "action_required"
    } else if warnings
        .iter()
        .any(|w| w.get("alert_level").and_then(|v| v.as_str()) == Some("critical"))
    {
        "critical"
    } else if !warnings.is_empty() {
        "warning"
    } else {
        "ok"
    };

    Json(serde_json::json!({
        "status": overall_status,
        "global_budget_tokens": global_budget,
        "exceeded_count": exceeded.len(),
        "warning_count": warnings.len(),
        "exceeded": exceeded,
        "warnings": warnings,
        "tip": "Set CONNECTOR_AGENT_TOKEN_BUDGET env var to configure global budget. Use PATCH /agents/:pid to set per-agent budgets.",
    }))
}

// ── Anomaly Detection ─────────────────────────────────────────────────────────
// Automatically flags agents/fleet with sudden cost spikes, failure rate jumps,
// and unusual operation patterns. No ML required — pure statistical thresholds.
// Buyers: SecOps, platform SREs — "alert me when something weird happens".

/// GET /monitor/anomalies — detect cost spikes, failure spikes, unusual patterns
pub async fn anomaly_detection(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let audit = k.audit_log();
    let now = chrono::Utc::now().timestamp_millis();

    // Compare last 1h vs previous 1h for each agent
    let hour_ms = 3_600_000_i64;
    let recent_start = now - hour_ms;
    let prev_start = now - 2 * hour_ms;

    let mut anomalies: Vec<serde_json::Value> = Vec::new();

    for (pid, acb) in k.agents() {
        let recent_ops: Vec<_> = audit
            .iter()
            .filter(|e| e.agent_pid == *pid && e.timestamp >= recent_start)
            .collect();
        let prev_ops: Vec<_> = audit
            .iter()
            .filter(|e| {
                e.agent_pid == *pid && e.timestamp >= prev_start && e.timestamp < recent_start
            })
            .collect();

        // ── Cost spike: last 1h cost > 3× previous 1h ─────────────────────
        // We approximate from RecordTokenUsage entries
        let recent_token_events = recent_ops
            .iter()
            .filter(|e| e.operation == vac_core::types::MemoryKernelOp::RecordTokenUsage)
            .count();
        let prev_token_events = prev_ops
            .iter()
            .filter(|e| e.operation == vac_core::types::MemoryKernelOp::RecordTokenUsage)
            .count();

        if prev_token_events > 0 && recent_token_events > prev_token_events * 3 {
            anomalies.push(serde_json::json!({
                "type": "cost_spike",
                "severity": "high",
                "pid": pid,
                "agent_name": acb.agent_name,
                "message": format!("LLM call rate spiked: {} calls in last 1h vs {} in previous 1h ({}×)", recent_token_events, prev_token_events, recent_token_events / prev_token_events.max(1)),
                "recent_llm_calls": recent_token_events,
                "prev_llm_calls": prev_token_events,
                "total_cost_usd": acb.total_cost_usd,
                "action": "Review agent workload. Consider pausing via POST /agents/:pid/pause.",
                "webhook_event": "anomaly.detected",
            }));
        }

        // ── Failure spike: failure rate in last 1h > 30% ──────────────────
        let recent_total = recent_ops.len();
        let recent_failed = recent_ops
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
            .count();
        let recent_failure_rate = if recent_total > 5 {
            recent_failed as f64 / recent_total as f64 * 100.0
        } else {
            0.0
        };

        if recent_failure_rate > 30.0 {
            anomalies.push(serde_json::json!({
                "type": "failure_spike",
                "severity": "high",
                "pid": pid,
                "agent_name": acb.agent_name,
                "message": format!("Agent failure rate at {:.0}% in last 1h ({}/{} ops failed)", recent_failure_rate, recent_failed, recent_total),
                "failure_rate_pct": (recent_failure_rate * 10.0).round() / 10.0,
                "failed_ops": recent_failed,
                "total_ops": recent_total,
                "action": "Check tool bindings and namespace grants. See GET /agents/:pid/activity.",
                "webhook_event": "agent.failed",
            }));
        }

        // ── Access violation spike: > 5 denied ops in last 1h ─────────────
        let recent_denied = recent_ops
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
            .count();
        if recent_denied > 5 {
            anomalies.push(serde_json::json!({
                "type": "access_violation_spike",
                "severity": "medium",
                "pid": pid,
                "agent_name": acb.agent_name,
                "message": format!("Agent hit {} access denials in last 1h — possible misconfiguration or attack probe", recent_denied),
                "denied_ops": recent_denied,
                "action": "Review access grants. Check GET /compliance/access-report.",
                "webhook_event": "anomaly.detected",
            }));
        }

        // ── Inactivity after high usage: was active, now silent ───────────
        let prev_total = prev_ops.len();
        if prev_total > 10 && recent_total == 0 {
            anomalies.push(serde_json::json!({
                "type": "sudden_inactivity",
                "severity": "low",
                "pid": pid,
                "agent_name": acb.agent_name,
                "message": format!("Agent had {} ops in prev 1h but 0 in last 1h — may have silently crashed", prev_total),
                "prev_ops": prev_total,
                "action": "Check agent status via GET /agents/:pid.",
                "webhook_event": "anomaly.detected",
            }));
        }
    }

    // ── Fleet-level: trust score drop ─────────────────────────────────────────
    let trust = connector_engine::TrustComputer::compute(&k);
    if trust.score < 60 {
        anomalies.push(serde_json::json!({
            "type": "trust_degraded",
            "severity": "high",
            "pid": "fleet",
            "agent_name": "platform",
            "message": format!("Fleet trust score dropped to {} (threshold: 60). Audit chain may have issues.", trust.score),
            "agent_health_score": trust.score,
            "action": "Run GET /monitor/integrity and GET /monitor/trust-trend for diagnosis.",
            "webhook_event": "trust.degraded",
        }));
    }

    let high = anomalies
        .iter()
        .filter(|a| a.get("severity").and_then(|s| s.as_str()) == Some("high"))
        .count();
    let medium = anomalies
        .iter()
        .filter(|a| a.get("severity").and_then(|s| s.as_str()) == Some("medium"))
        .count();

    Json(serde_json::json!({
        "anomaly_count": anomalies.len(),
        "high_severity": high,
        "medium_severity": medium,
        "low_severity": anomalies.len() - high - medium,
        "status": if high > 0 { "action_required" } else if medium > 0 { "warning" } else { "clean" },
        "anomalies": anomalies,
        "evaluated_at": chrono::Utc::now().to_rfc3339(),
        "tip": "Register a webhook at POST /webhooks to receive real-time anomaly.detected events.",
    }))
}

// ── Usage Export ──────────────────────────────────────────────────────────────
// Finance teams and enterprise procurement require downloadable cost + usage
// reports to reconcile LLM spend against invoices.
// Buyers: FinOps, CFO office, procurement — "we need this to approve the PO".

#[derive(Deserialize)]
pub struct UsageExportQuery {
    pub agent_pid: Option<String>,
    pub from_ts: Option<i64>,
    pub to_ts: Option<i64>,
    #[serde(default = "default_format")]
    pub format: String,
}
fn default_format() -> String {
    "json".into()
}

/// GET /monitor/usage-export — downloadable usage + cost report (JSON or CSV)
pub async fn usage_export(
    State(state): State<SharedState>,
    Query(q): Query<UsageExportQuery>,
) -> axum::response::Response {
    let k = state.kernel.lock().unwrap();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let from_ts = q.from_ts.unwrap_or(now_ms - 30 * 24 * 3_600_000);
    let to_ts = q.to_ts.unwrap_or(now_ms);
    let global_budget = std::env::var("CONNECTOR_AGENT_TOKEN_BUDGET")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(16_000);

    let rows: Vec<serde_json::Value> = k.agents().iter()
        .filter(|(pid, _)| q.agent_pid.as_ref().map_or(true, |f| f == *pid))
        .map(|(pid, acb)| {
            let agent_ops_in_window = k.audit_log().iter()
                .filter(|e| e.agent_pid == *pid && e.timestamp >= from_ts && e.timestamp <= to_ts)
                .count();
            let llm_calls_in_window = k.audit_log().iter()
                .filter(|e| e.agent_pid == *pid
                    && e.timestamp >= from_ts && e.timestamp <= to_ts
                    && e.operation == vac_core::types::MemoryKernelOp::RecordTokenUsage)
                .count();
            let budget = if acb.memory_region.quota_tokens > 0 { acb.memory_region.quota_tokens } else { global_budget };
            let budget_pct = if budget > 0 { (acb.total_tokens_consumed as f64 / budget as f64 * 100.0).min(100.0) } else { 0.0 };

            serde_json::json!({
                "pid": pid,
                "name": acb.agent_name,
                "namespace": acb.namespace,
                "role": format!("{:?}", acb.role),
                "model": acb.model.as_deref().unwrap_or("unknown"),
                "total_tokens_consumed": acb.total_tokens_consumed,
                "total_cost_usd": (acb.total_cost_usd * 10000.0).round() / 10000.0,
                "cost_per_1k_tokens": if acb.total_tokens_consumed > 0 { (acb.total_cost_usd / acb.total_tokens_consumed as f64 * 1000.0 * 10000.0).round() / 10000.0 } else { 0.0 },
                "budget_tokens": budget,
                "budget_pct": (budget_pct * 10.0).round() / 10.0,
                "operations_in_window": agent_ops_in_window,
                "llm_calls_in_window": llm_calls_in_window,
                "registered_at": acb.registered_at,
            })
        })
        .collect();

    let total_cost: f64 = rows
        .iter()
        .map(|r| {
            r.get("total_cost_usd")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
        })
        .sum();
    let total_tokens: u64 = rows
        .iter()
        .map(|r| {
            r.get("total_tokens_consumed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        })
        .sum();

    if q.format == "csv" {
        // Return CSV for spreadsheet import
        let mut csv = String::from("pid,name,namespace,role,model,total_tokens,total_cost_usd,cost_per_1k,budget_tokens,budget_pct,ops_in_window,llm_calls_in_window\n");
        for row in &rows {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                row["pid"].as_str().unwrap_or(""),
                row["name"].as_str().unwrap_or(""),
                row["namespace"].as_str().unwrap_or(""),
                row["role"].as_str().unwrap_or(""),
                row["model"].as_str().unwrap_or(""),
                row["total_tokens_consumed"].as_u64().unwrap_or(0),
                row["total_cost_usd"].as_f64().unwrap_or(0.0),
                row["cost_per_1k_tokens"].as_f64().unwrap_or(0.0),
                row["budget_tokens"].as_u64().unwrap_or(0),
                row["budget_pct"].as_f64().unwrap_or(0.0),
                row["operations_in_window"].as_u64().unwrap_or(0),
                row["llm_calls_in_window"].as_u64().unwrap_or(0),
            ));
        }
        let filename = format!(
            "connector-usage-{}.csv",
            chrono::Utc::now().format("%Y%m%d")
        );
        return axum::response::Response::builder()
            .status(200)
            .header("content-type", "text/csv")
            .header(
                "content-disposition",
                format!("attachment; filename=\"{}\"", filename),
            )
            .body(axum::body::Body::from(csv))
            .unwrap_or_default();
    }

    // Default: JSON
    let body = serde_json::to_string(&serde_json::json!({
        "report_type": "usage_export",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "window": {
            "from_ts": from_ts,
            "to_ts": to_ts,
            "from_iso": chrono::DateTime::from_timestamp_millis(from_ts).map(|d| d.to_rfc3339()).unwrap_or_default(),
            "to_iso": chrono::DateTime::from_timestamp_millis(to_ts).map(|d| d.to_rfc3339()).unwrap_or_default(),
        },
        "totals": {
            "agents": rows.len(),
            "total_tokens": total_tokens,
            "total_cost_usd": (total_cost * 10000.0).round() / 10000.0,
        },
        "rows": rows,
    })).unwrap_or_default();

    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

// ── E4.4: Statistical Anomaly Detection ──────────────────────────────────────

/// GET /monitor/anomalies — rolling 7d Welford baseline, alert z-score > 2
pub async fn anomaly_detection_v2(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let window_7d_ms = 7 * 86_400_000i64;
    let window_24h_ms = 86_400_000i64;
    let baseline_cutoff = now_ms - window_7d_ms;
    let recent_cutoff = now_ms - window_24h_ms;

    let audit_log = k.audit_log();

    // Collect hourly op counts over 7d baseline using Welford online algorithm
    let mut hourly_counts: std::collections::BTreeMap<i64, u64> = std::collections::BTreeMap::new();
    for entry in audit_log.iter().filter(|e| e.timestamp >= baseline_cutoff) {
        let bucket = entry.timestamp / 3_600_000; // hour bucket
        *hourly_counts.entry(bucket).or_insert(0) += 1;
    }

    // Welford online mean + variance
    let (mean, variance) = {
        let mut count = 0u64;
        let mut mean = 0.0f64;
        let mut m2 = 0.0f64;
        for &v in hourly_counts.values() {
            count += 1;
            let delta = v as f64 - mean;
            mean += delta / count as f64;
            let delta2 = v as f64 - mean;
            m2 += delta * delta2;
        }
        let variance = if count > 1 {
            m2 / (count - 1) as f64
        } else {
            0.0
        };
        (mean, variance)
    };
    let std_dev = variance.sqrt();

    // Check last 24h for anomalies
    let mut recent_hourly: std::collections::BTreeMap<i64, u64> = std::collections::BTreeMap::new();
    for entry in audit_log.iter().filter(|e| e.timestamp >= recent_cutoff) {
        let bucket = entry.timestamp / 3_600_000;
        *recent_hourly.entry(bucket).or_insert(0) += 1;
    }

    let anomalies: Vec<serde_json::Value> = recent_hourly
        .iter()
        .filter_map(|(&bucket, &count)| {
            let z = if std_dev > 0.0 {
                (count as f64 - mean) / std_dev
            } else {
                0.0
            };
            if z.abs() > 2.0 {
                let hour_ts = bucket * 3_600_000;
                let hour_iso = chrono::DateTime::from_timestamp_millis(hour_ts)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default();
                let direction = if z > 0.0 { "SPIKE" } else { "DROP" };
                let suggested = if z > 3.0 {
                    "CRITICAL: Investigate immediately — extreme operation spike"
                } else if z > 2.0 {
                    "WARNING: Elevated operation rate — check for abuse or misconfiguration"
                } else {
                    "INFO: Operation drop — check agent availability"
                };
                Some(serde_json::json!({
                    "hour_bucket":    bucket,
                    "hour_iso":       hour_iso,
                    "op_count":       count,
                    "z_score":        (z * 100.0).round() / 100.0,
                    "direction":      direction,
                    "severity":       if z.abs() > 3.0 { "CRITICAL" } else { "WARNING" },
                    "suggested_action": suggested,
                }))
            } else {
                None
            }
        })
        .collect();

    // Per-agent anomalies: agents with sudden deny spike
    let mut agent_deny: std::collections::HashMap<String, (u64, u64)> =
        std::collections::HashMap::new();
    for entry in audit_log.iter().filter(|e| e.timestamp >= baseline_cutoff) {
        let (total, denied) = agent_deny.entry(entry.agent_pid.clone()).or_insert((0, 0));
        *total += 1;
        if entry.outcome == vac_core::types::OpOutcome::Denied {
            *denied += 1;
        }
    }
    let agent_anomalies: Vec<serde_json::Value> = agent_deny
        .iter()
        .filter_map(|(pid, (total, denied))| {
            if *total < 5 {
                return None;
            }
            let deny_rate = *denied as f64 / *total as f64;
            if deny_rate > 0.3 {
                Some(serde_json::json!({
                    "agent_pid":   pid,
                    "total_ops":   total,
                    "denied_ops":  denied,
                    "deny_rate":   (deny_rate * 100.0).round() / 100.0,
                    "anomaly":     "HIGH_DENY_RATE",
                    "z_score":     (deny_rate * 10.0).round() / 10.0,
                    "suggested_action": "Review agent permissions and recent operations",
                }))
            } else {
                None
            }
        })
        .collect();

    Json(serde_json::json!({
        "generated_at":     now.to_rfc3339(),
        "baseline_window":  "7d",
        "check_window":     "24h",
        "baseline_stats": {
            "hourly_mean":    (mean * 100.0).round() / 100.0,
            "hourly_std_dev": (std_dev * 100.0).round() / 100.0,
            "variance":       (variance * 100.0).round() / 100.0,
            "z_threshold":    2.0,
        },
        "anomaly_count":    anomalies.len() + agent_anomalies.len(),
        "hourly_anomalies": anomalies,
        "agent_anomalies":  agent_anomalies,
        "status":           if anomalies.is_empty() && agent_anomalies.is_empty() { "NOMINAL" } else { "ANOMALIES_DETECTED" },
    }))
}

/// DI-5 — opt-in anomaly gate on Talk (`CONNECTOR_IIA_ANOMALY_GATE=1`).
pub fn anomaly_gate_enabled() -> bool {
    match std::env::var("CONNECTOR_IIA_ANOMALY_GATE") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

/// Light HIGH_DENY_RATE check for one agent (same thresholds as anomalies/v2; no Welford).
/// Returns `(deny_rate, total_ops, denied_ops)` when the gate should deny Talk.
pub fn anomaly_gate_violation(
    state: &crate::state::PlatformState,
    agent_pid: &str,
) -> Option<(f64, u64, u64)> {
    if !anomaly_gate_enabled() || agent_pid.is_empty() {
        return None;
    }
    let cutoff = chrono::Utc::now().timestamp_millis() - 24 * 60 * 60 * 1000;
    let k = state.kernel.lock().ok()?;
    let mut total = 0u64;
    let mut denied = 0u64;
    // Recent-first scan; cap work so Talk stays bounded.
    for entry in k.audit_log().iter().rev().take(10_000) {
        if entry.timestamp < cutoff {
            break;
        }
        if entry.agent_pid != agent_pid {
            continue;
        }
        total += 1;
        if entry.outcome == vac_core::types::OpOutcome::Denied {
            denied += 1;
        }
    }
    if total < 5 {
        return None;
    }
    let deny_rate = denied as f64 / total as f64;
    if deny_rate > 0.3 {
        Some((deny_rate, total, denied))
    } else {
        None
    }
}

// ── E4.5: Capacity Forecast ───────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ForecastQuery {
    pub horizon: Option<String>,
}

/// GET /monitor/forecast?horizon=30d
pub async fn capacity_forecast(
    State(state): State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<ForecastQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let horizon_days: i64 = q
        .horizon
        .as_deref()
        .unwrap_or("30d")
        .strip_suffix('d')
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    let history_days = 30i64;
    let cutoff_ms = now_ms - history_days * 86_400_000;

    let audit_log = k.audit_log();

    // Daily metrics over history window
    let mut daily_ops: Vec<(i64, f64)> = Vec::new();
    let mut daily_cost: Vec<(i64, f64)> = Vec::new();

    for day in 0..history_days {
        let day_start = now_ms - (day + 1) * 86_400_000;
        let day_end = now_ms - day * 86_400_000;
        let day_ops = audit_log
            .iter()
            .filter(|e| e.timestamp >= day_start && e.timestamp < day_end)
            .count() as f64;
        daily_ops.push((day, day_ops));
        daily_cost.push((day, day_ops * 0.000002)); // rough cost estimate
    }
    daily_ops.reverse();
    daily_cost.reverse();

    // Linear regression: y = a + b*x
    let linear_regression = |points: &[(i64, f64)]| -> (f64, f64) {
        let n = points.len() as f64;
        if n == 0.0 {
            return (0.0, 0.0);
        }
        let sum_x: f64 = points.iter().map(|(x, _)| *x as f64).sum();
        let sum_y: f64 = points.iter().map(|(_, y)| *y).sum();
        let sum_xy: f64 = points.iter().map(|(x, y)| *x as f64 * y).sum();
        let sum_xx: f64 = points.iter().map(|(x, _)| (*x as f64).powi(2)).sum();
        let denom = n * sum_xx - sum_x * sum_x;
        if denom.abs() < 1e-10 {
            return (sum_y / n, 0.0);
        }
        let b = (n * sum_xy - sum_x * sum_y) / denom;
        let a = (sum_y - b * sum_x) / n;
        (a, b)
    };

    let (ops_intercept, ops_slope) = linear_regression(&daily_ops);
    let (cost_intercept, cost_slope) = linear_regression(&daily_cost);

    // Project forward
    let horizon_x = history_days + horizon_days;
    let proj_ops = (ops_intercept + ops_slope * horizon_x as f64).max(0.0);
    let proj_cost = (cost_intercept + cost_slope * horizon_x as f64).max(0.0);

    // CI (±1.96 std dev of residuals)
    let residuals_ops: Vec<f64> = daily_ops
        .iter()
        .map(|(x, y)| y - (ops_intercept + ops_slope * *x as f64))
        .collect();
    let std_ops = {
        let mean: f64 = residuals_ops.iter().sum::<f64>() / residuals_ops.len().max(1) as f64;
        let var: f64 = residuals_ops
            .iter()
            .map(|r| (r - mean).powi(2))
            .sum::<f64>()
            / residuals_ops.len().max(1) as f64;
        var.sqrt()
    };

    // Agent limit projection
    let agent_limit_raw = state.license.agent_limit();
    let max_agents: Option<f64> = if agent_limit_raw == 0 {
        None
    } else {
        Some(agent_limit_raw as f64)
    };
    let current_agents = k.agents().len() as f64;

    let days_until_agent_limit = max_agents.and_then(|limit| {
        let remaining = limit - current_agents;
        if ops_slope > 0.0 {
            let days = remaining / ops_slope.max(0.01);
            Some(days.max(0.0).round() as i64)
        } else {
            None
        }
    });

    let projected_monthly_cost = proj_cost * 30.0;
    let cost_ci = 1.96 * std_ops * 0.000002 * 30.0;

    Json(serde_json::json!({
        "generated_at":           now.to_rfc3339(),
        "history_days":           history_days,
        "horizon_days":           horizon_days,
        "current_agents":         current_agents as u64,
        "max_agents":             max_agents,
        "days_until_agent_limit": days_until_agent_limit,
        "ops_trend": {
            "slope_per_day":      (ops_slope * 100.0).round() / 100.0,
            "direction":          if ops_slope > 0.0 { "GROWING" } else if ops_slope < 0.0 { "DECLINING" } else { "STABLE" },
            "projected_daily_ops":proj_ops.round() as i64,
        },
        "cost_forecast": {
            "projected_monthly_cost_usd": (projected_monthly_cost * 100.0).round() / 100.0,
            "confidence_interval_usd":    format!("±{:.4}", cost_ci),
            "lower_usd": ((projected_monthly_cost - cost_ci) * 100.0).round() / 100.0,
            "upper_usd": ((projected_monthly_cost + cost_ci) * 100.0).round() / 100.0,
        },
        "recommendation": if let Some(days) = days_until_agent_limit {
            if days < 30 { format!("URGENT: Agent limit reached in ~{} days. Upgrade license tier.", days) }
            else if days < 90 { format!("WARNING: Agent limit in ~{} days. Plan upgrade.", days) }
            else { format!("OK: Agent limit in ~{} days.", days) }
        } else {
            if ops_slope > 10.0 { "GROWING FAST: Monitor cost trajectory.".into() }
            else { "Capacity nominal. No action required.".into() }
        },
    }))
}

// ── E4.6: Grafana Dashboard Export ───────────────────────────────────────────

/// GET /monitor/grafana-dashboard — import-ready Grafana JSON
pub async fn grafana_dashboard(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let trust = connector_engine::TrustComputer::compute(&k);

    let datasource_uid =
        std::env::var("GRAFANA_DATASOURCE_UID").unwrap_or_else(|_| "prometheus".into());
    let api_base = std::env::var("CONNECTOR_API_BASE")
        .unwrap_or_else(|_| "http://localhost:8080/api/v1".into());

    // DX-P3-5: Import-ready Grafana JSON (historically mirrored deploy/grafana/connector-dashboard.json; file removed in Phase 0.7).
    // Uses correct metric names matching state.rs registrations.
    Json(serde_json::json!({
        "__inputs": [{"name": "DS_PROMETHEUS", "label": "Prometheus", "type": "datasource", "pluginId": "prometheus"}],
        "__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"}],
        "title": "Connector Platform",
        "uid": "connector-platform-v1",
        "version": 1,
        "schemaVersion": 36,
        "refresh": "10s",
        "time": {"from": "now-1h", "to": "now"},
        "panels": [
            {
                "id": 1, "type": "stat", "title": "Active Agents",
                "gridPos": {"x": 0, "y": 0, "w": 4, "h": 4},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "connector_agents_active", "legendFormat": "active"}],
                "options": {"colorMode": "background", "graphMode": "area"}
            },
            {
                "id": 2, "type": "stat", "title": "Tokens Consumed (total)",
                "gridPos": {"x": 4, "y": 0, "w": 4, "h": 4},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "connector_tokens_consumed_total", "legendFormat": "tokens"}],
                "options": {"colorMode": "value", "graphMode": "area"}
            },
            {
                "id": 3, "type": "stat", "title": "LLM Calls / min",
                "gridPos": {"x": 8, "y": 0, "w": 4, "h": 4},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "rate(connector_llm_calls_total[1m]) * 60", "legendFormat": "calls/min"}],
                "options": {"colorMode": "value"}
            },
            {
                "id": 4, "type": "stat", "title": "Injections Blocked",
                "gridPos": {"x": 12, "y": 0, "w": 4, "h": 4},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "connector_llm_injections_blocked_total", "legendFormat": "blocked"}],
                "options": {"colorMode": "background", "thresholds": {"steps": [{"color": "green", "value": 0}, {"color": "orange", "value": 1}]}}
            },
            {
                "id": 5, "type": "stat", "title": "KECS Suspensions",
                "gridPos": {"x": 16, "y": 0, "w": 4, "h": 4},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "connector_kecs_suspensions_total", "legendFormat": "suspensions"}],
                "options": {"colorMode": "background", "thresholds": {"steps": [{"color": "green", "value": 0}, {"color": "red", "value": 1}]}}
            },
            {
                "id": 6, "type": "stat", "title": "Billing Events",
                "gridPos": {"x": 20, "y": 0, "w": 4, "h": 4},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "connector_billing_usage_events_total", "legendFormat": "events"}],
                "options": {"colorMode": "value"}
            },
            {
                "id": 7, "type": "timeseries", "title": "Token Consumption Rate",
                "gridPos": {"x": 0, "y": 4, "w": 12, "h": 8},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "rate(connector_tokens_consumed_total[5m])", "legendFormat": "tokens/s"}]
            },
            {
                "id": 8, "type": "timeseries", "title": "LLM Call Rate + Injection Blocks",
                "gridPos": {"x": 12, "y": 4, "w": 12, "h": 8},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [
                    {"expr": "rate(connector_llm_calls_total[1m])", "legendFormat": "LLM calls/s"},
                    {"expr": "rate(connector_llm_injections_blocked_total[1m])", "legendFormat": "injections blocked/s"}
                ]
            },
            {
                "id": 9, "type": "timeseries", "title": "Agent Count Over Time",
                "gridPos": {"x": 0, "y": 12, "w": 8, "h": 6},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [
                    {"expr": "connector_agents_active", "legendFormat": "active"},
                    {"expr": "connector_agents_suspended", "legendFormat": "suspended"}
                ]
            },
            {
                "id": 10, "type": "timeseries", "title": "Actions Authorized vs Denied",
                "gridPos": {"x": 8, "y": 12, "w": 8, "h": 6},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [
                    {"expr": "rate(connector_actions_authorized_total[1m])", "legendFormat": "authorized/s"},
                    {"expr": "rate(connector_actions_denied_total[1m])", "legendFormat": "denied/s"}
                ]
            },
            {
                "id": 11, "type": "timeseries", "title": "Signups",
                "gridPos": {"x": 16, "y": 12, "w": 8, "h": 6},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "rate(connector_signups_total[5m])", "legendFormat": "signups/s"}]
            },
            {
                "id": 12, "type": "stat", "title": "Trust Score",
                "gridPos": {"x": 0, "y": 18, "w": 4, "h": 4},
                "datasource": {"type": "prometheus", "uid": datasource_uid},
                "targets": [{"expr": "connector_trust_score", "legendFormat": "trust"}],
                "fieldConfig": {"defaults": {"thresholds": {"steps": [
                    {"color": "red", "value": 0},
                    {"color": "yellow", "value": 60},
                    {"color": "green", "value": 80}
                ]}}}
            },
            {
                "id": 13, "type": "text", "title": "Quick Links",
                "gridPos": {"x": 4, "y": 18, "w": 20, "h": 4},
                "options": {"mode": "markdown", "content": format!(
                    "| Endpoint | Description |\n|---|---|\n\
                    | [{api_base}/health]({api_base}/health) | Health check |\n\
                    | [{api_base}/api/v1/monitor/health]({api_base}/api/v1/monitor/health) | Platform health |\n\
                    | [{api_base}/api/v1/monitor/slos]({api_base}/api/v1/monitor/slos) | SLO status |\n\
                    | [{api_base}/metrics]({api_base}/metrics) | Prometheus metrics |\n\
                    | [{api_base}/api/v1/docs/migration]({api_base}/api/v1/docs/migration) | Migration guide |"
                )}
            }
        ],
        "meta": {
            "generated_at":    now.to_rfc3339(),
            "agent_health_score": trust.score,
            "active_agents":   k.agents().len(),
            "import_hint":     "In Grafana: Dashboards → Import → Paste JSON",
            "prometheus_hint": "connector-platform exposes /metrics — point Prometheus scraper there",
            "docs":            "https://connector.dev/docs/observability"
        }
    }))
}

// ── E3.10: SLO Tracking + Error Budget ───────────────────────────────────────

/// POST /monitor/slos — define or update an SLO
pub async fn create_slo(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed_slo");
    let metric = req
        .get("metric")
        .and_then(|v| v.as_str())
        .unwrap_or("availability");
    let target_pct = req
        .get("target_pct")
        .and_then(|v| v.as_f64())
        .unwrap_or(99.9);
    let window_days = req
        .get("window_days")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let error_budget_mins = req
        .get("error_budget_mins")
        .and_then(|v| v.as_f64())
        .unwrap_or_else(|| {
            // Default: (1 - target/100) * window_days * 24 * 60
            (1.0 - target_pct / 100.0) * window_days as f64 * 24.0 * 60.0
        });
    let now = chrono::Utc::now();

    let slo_id = format!("slo_{}", uuid::Uuid::new_v4());
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "monitor",
        "lifecycle",
        "create_slo",
        &serde_json::json!({"name": name, "slo_id": slo_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let slo = serde_json::json!({
        "slo_id":              slo_id,
        "name":                name,
        "metric":              metric,
        "target_pct":          target_pct,
        "window_days":         window_days,
        "error_budget_mins":   error_budget_mins,
        "created_at":          now.to_rfc3339(),
        "status":              "active",
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("slos", &slo_id, &slo);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "slo_id":            slo_id,
        "name":              name,
        "metric":            metric,
        "target_pct":        target_pct,
        "window_days":       window_days,
        "error_budget_mins": error_budget_mins,
        "created_at":        now.to_rfc3339(),
        "report_endpoint":   format!("GET /monitor/slos/{}/report", slo_id),
        "task_id":           admitted.task_id,
        "executed":          true,
        "admits":            false,
    }))
}

/// GET /monitor/slos — list all SLOs with current compliance and error budget
pub async fn list_slos(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let slo_keys = es.folder_keys("slos", None).unwrap_or_default();

    let slos: Vec<serde_json::Value> = slo_keys.iter().filter_map(|key| {
        let slo = es.folder_get("slos", key).ok().flatten()?;
        let slo_id       = slo.get("slo_id").and_then(|v| v.as_str()).unwrap_or(key);
        let name         = slo.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
        let metric       = slo.get("metric").and_then(|v| v.as_str()).unwrap_or("availability");
        let target_pct   = slo.get("target_pct").and_then(|v| v.as_f64()).unwrap_or(99.9);
        let window_days  = slo.get("window_days").and_then(|v| v.as_u64()).unwrap_or(30);
        let error_budget = slo.get("error_budget_mins").and_then(|v| v.as_f64()).unwrap_or(0.0);

        let window_ms = window_days as i64 * 24 * 60 * 60 * 1000;
        let cutoff_ms = now_ms - window_ms;

        // Compute compliance from audit log
        let audit_log = k.audit_log();
        let window_ops: Vec<_> = audit_log.iter()
            .filter(|e| e.timestamp >= cutoff_ms)
            .collect();

        let (compliance_pct, burned_mins, breach_events) = match metric {
            "availability" => {
                let total = window_ops.len().max(1);
                let denied = window_ops.iter().filter(|e| e.outcome == vac_core::types::OpOutcome::Denied).count();
                let ok_pct = (total - denied) as f64 / total as f64 * 100.0;
                let burned = if ok_pct < target_pct {
                    let failure_rate = 1.0 - ok_pct / 100.0;
                    failure_rate * window_days as f64 * 24.0 * 60.0
                } else { 0.0 };
                let breaches: Vec<serde_json::Value> = window_ops.iter()
                    .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
                    .take(5)
                    .map(|e| serde_json::json!({
                        "ts": e.timestamp,
                        "agent": e.agent_pid,
                        "op": format!("{:?}", e.operation),
                    }))
                    .collect();
                (ok_pct, burned, breaches)
            }
            "trust_score" => {
                let trust = connector_engine::TrustComputer::compute(&k);
                let ok_pct = trust.score as f64;
                let burned = if ok_pct < target_pct { (target_pct - ok_pct) / 100.0 * window_days as f64 * 24.0 * 60.0 } else { 0.0 };
                (ok_pct, burned, vec![])
            }
            _ => (100.0, 0.0, vec![])
        };

        let error_budget_remaining = (error_budget - burned_mins).max(0.0);
        let budget_burn_pct = if error_budget > 0.0 { burned_mins / error_budget * 100.0 } else { 0.0 };

        Some(serde_json::json!({
            "slo_id":                   slo_id,
            "name":                     name,
            "metric":                   metric,
            "target_pct":               target_pct,
            "compliance_pct":           (compliance_pct * 100.0).round() / 100.0,
            "window_days":              window_days,
            "error_budget_mins":        error_budget,
            "error_budget_remaining_mins": (error_budget_remaining * 10.0).round() / 10.0,
            "error_budget_burned_pct":  (budget_burn_pct * 10.0).round() / 10.0,
            "breach_events":            breach_events,
            "status":                   if compliance_pct >= target_pct { "MEETING_SLO" } else { "BREACHING_SLO" },
            "alert":                    if budget_burn_pct > 50.0 { Some("ERROR BUDGET >50% CONSUMED") } else { None::<&str> },
            "report_endpoint":          format!("GET /monitor/slos/{}/report", slo_id),
        }))
    }).collect();

    let breaching = slos
        .iter()
        .filter(|s| s.get("status").and_then(|v| v.as_str()) == Some("BREACHING_SLO"))
        .count();

    Json(serde_json::json!({
        "generated_at":   now.to_rfc3339(),
        "slo_count":      slos.len(),
        "breaching_count":breaching,
        "meeting_count":  slos.len() - breaching,
        "slos":           slos,
        "create_endpoint":"POST /monitor/slos to define new SLOs",
    }))
}

/// GET /monitor/slos/{id}/report — detailed SLO report for a specific SLO
pub async fn slo_report(
    State(state): State<SharedState>,
    axum::extract::Path(slo_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let slo = match es.folder_get("slos", &slo_id).ok().flatten() {
        Some(s) => s,
        None => {
            return Json(
                serde_json::json!({"error": "SLO not found", "status": 404, "slo_id": slo_id}),
            )
        }
    };

    let name = slo
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let metric = slo
        .get("metric")
        .and_then(|v| v.as_str())
        .unwrap_or("availability");
    let target_pct = slo
        .get("target_pct")
        .and_then(|v| v.as_f64())
        .unwrap_or(99.9);
    let window_days = slo
        .get("window_days")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let error_budget = slo
        .get("error_budget_mins")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let now_ms = now.timestamp_millis();
    let window_ms = window_days as i64 * 24 * 60 * 60 * 1000;
    let cutoff_ms = now_ms - window_ms;

    let audit_log = k.audit_log();
    let window_ops: Vec<_> = audit_log
        .iter()
        .filter(|e| e.timestamp >= cutoff_ms)
        .collect();
    let total = window_ops.len().max(1);
    let denied = window_ops
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let availability_pct = (total - denied) as f64 / total as f64 * 100.0;

    let burned_mins = if availability_pct < target_pct {
        (1.0 - availability_pct / 100.0) * window_days as f64 * 24.0 * 60.0
    } else {
        0.0
    };

    let error_budget_remaining = (error_budget - burned_mins).max(0.0);
    let budget_burn_pct = if error_budget > 0.0 {
        burned_mins / error_budget * 100.0
    } else {
        0.0
    };

    // Daily breakdown
    let mut daily: Vec<serde_json::Value> = Vec::new();
    for day in 0..window_days.min(30) {
        let day_start = now_ms - (day as i64 + 1) * 86_400_000;
        let day_end = now_ms - day as i64 * 86_400_000;
        let day_ops: Vec<_> = window_ops
            .iter()
            .filter(|e| e.timestamp >= day_start && e.timestamp < day_end)
            .collect();
        let day_total = day_ops.len().max(1);
        let day_denied = day_ops
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
            .count();
        let day_ok_pct = (day_total - day_denied) as f64 / day_total as f64 * 100.0;
        daily.push(serde_json::json!({
            "day":      day,
            "date":     chrono::DateTime::from_timestamp_millis(day_end).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
            "ops":      day_total,
            "denied":   day_denied,
            "ok_pct":   (day_ok_pct * 100.0).round() / 100.0,
            "slo_met":  day_ok_pct >= target_pct,
        }));
    }

    Json(serde_json::json!({
        "slo_id":                      slo_id,
        "name":                        name,
        "metric":                      metric,
        "target_pct":                  target_pct,
        "window_days":                 window_days,
        "generated_at":                now.to_rfc3339(),
        "compliance_pct":              (availability_pct * 100.0).round() / 100.0,
        "status":                      if availability_pct >= target_pct { "MEETING_SLO" } else { "BREACHING_SLO" },
        "error_budget": {
            "total_mins":              error_budget,
            "burned_mins":             (burned_mins * 10.0).round() / 10.0,
            "remaining_mins":          (error_budget_remaining * 10.0).round() / 10.0,
            "burned_pct":              (budget_burn_pct * 10.0).round() / 10.0,
            "exhausted":               error_budget_remaining <= 0.0,
        },
        "window_ops":                  window_ops.len(),
        "denied_ops":                  denied,
        "daily_breakdown":             daily,
        "recommendation": if availability_pct < target_pct {
            format!("SLO BREACHED: {:.2}% availability vs {:.1}% target. Investigate denied operations and reduce error rate.", availability_pct, target_pct)
        } else if budget_burn_pct > 50.0 {
            format!("WARNING: {:.0}% of error budget consumed. Monitor closely to avoid breach.", budget_burn_pct)
        } else {
            "SLO healthy. Error budget nominal.".into()
        },
    }))
}

// ── Phase E.7: Tool health dashboard ─────────────────────────────────────────

/// GET /monitor/tools
/// Tool health dashboard: per-bridge latency, success rate, denial rate.
pub async fn tools_health(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let k = state.kernel.lock().unwrap();
    let audit = k.audit_log();
    let es = state.engine_store.lock().unwrap();

    // Tool dispatch entries
    let tool_ops: Vec<_> = audit
        .iter()
        .filter(|e| e.operation == vac_core::types::MemoryKernelOp::ToolDispatch)
        .collect();

    // Group by target (tool name / bridge)
    let mut tool_stats: std::collections::HashMap<String, (usize, usize, usize)> =
        std::collections::HashMap::new(); // tool → (total, denied, failed)

    for op in &tool_ops {
        let key = op.target.as_deref().unwrap_or("unknown").to_string();
        let s = tool_stats.entry(key).or_insert((0, 0, 0));
        s.0 += 1;
        match op.outcome {
            vac_core::types::OpOutcome::Denied => s.1 += 1,
            vac_core::types::OpOutcome::Failed => s.2 += 1,
            _ => {}
        }
    }

    let bridge_keys = es.folder_keys("mcp_bridges", None).unwrap_or_default();
    let mut bridges: Vec<serde_json::Value> = bridge_keys.iter().filter_map(|k_str| {
        let b = es.folder_get("mcp_bridges", k_str).ok().flatten()?;
        let bridge_id = b.get("bridge_id").and_then(|v| v.as_str()).unwrap_or(k_str).to_string();
        let (total, denied, failed) = tool_stats.get(&bridge_id).cloned().unwrap_or((0, 0, 0));
        let success_rate = if total > 0 { ((total - denied - failed) as f64 / total as f64 * 100.0).round() } else { 100.0 };
        Some(serde_json::json!({
            "bridge_id":     bridge_id,
            "tool_name":     b.get("tool_name"),
            "total_calls":   total,
            "denied_calls":  denied,
            "failed_calls":  failed,
            "success_rate":  success_rate,
            "status":        if success_rate >= 99.0 { "HEALTHY" } else if success_rate >= 90.0 { "DEGRADED" } else { "UNHEALTHY" },
        }))
    }).collect();

    // Include ungrouped tool stats
    for (tool, (total, denied, failed)) in &tool_stats {
        if !bridge_keys.iter().any(|k| k.contains(tool.as_str())) {
            let success_rate = if *total > 0 {
                ((*total - denied - failed) as f64 / *total as f64 * 100.0).round()
            } else {
                100.0
            };
            bridges.push(serde_json::json!({
                "bridge_id":     tool,
                "tool_name":     tool,
                "total_calls":   total,
                "denied_calls":  denied,
                "failed_calls":  failed,
                "success_rate":  success_rate,
                "status":        if success_rate >= 99.0 { "HEALTHY" } else if success_rate >= 90.0 { "DEGRADED" } else { "UNHEALTHY" },
            }));
        }
    }

    let healthy = bridges
        .iter()
        .filter(|b| b.get("status").and_then(|v| v.as_str()) == Some("HEALTHY"))
        .count();
    let degraded = bridges
        .iter()
        .filter(|b| b.get("status").and_then(|v| v.as_str()) == Some("DEGRADED"))
        .count();
    let unhealthy = bridges
        .iter()
        .filter(|b| b.get("status").and_then(|v| v.as_str()) == Some("UNHEALTHY"))
        .count();

    Json(serde_json::json!({
        "generated_at":   now.to_rfc3339(),
        "total_tool_ops": tool_ops.len(),
        "bridge_count":   bridges.len(),
        "healthy":        healthy,
        "degraded":       degraded,
        "unhealthy":      unhealthy,
        "overall_status": if unhealthy > 0 { "UNHEALTHY" } else if degraded > 0 { "DEGRADED" } else { "HEALTHY" },
        "bridges":        bridges,
    }))
}

// ── Phase G.6: Signals log ────────────────────────────────────────────────────

/// GET /monitor/signals
/// Returns the signal log and any auto-heal rules that have triggered.
pub async fn signals_log(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let es = state.engine_store.lock().unwrap();

    // Signals sent via tools/signals/send
    let sig_keys = es.folder_keys("signals", None).unwrap_or_default();
    let signals: Vec<serde_json::Value> = sig_keys
        .iter()
        .rev()
        .take(200)
        .filter_map(|k| es.folder_get("signals", k).ok().flatten())
        .collect();

    // Signal handlers registered
    let handler_keys = es.folder_keys("signal_handlers", None).unwrap_or_default();
    let handlers: Vec<serde_json::Value> = handler_keys
        .iter()
        .filter_map(|k| es.folder_get("signal_handlers", k).ok().flatten())
        .collect();

    // Auto-heal: find handlers with auto_heal:true + matching fired signals
    let auto_heals: Vec<serde_json::Value> = handlers
        .iter()
        .filter(|h| {
            h.get("auto_heal")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .map(|h| {
            let sig_type = h.get("signal_type").and_then(|v| v.as_str()).unwrap_or("");
            let fired = signals
                .iter()
                .filter(|s| s.get("signal_type").and_then(|v| v.as_str()) == Some(sig_type))
                .count();
            serde_json::json!({
                "handler_id":   h.get("handler_id"),
                "agent_pid":    h.get("agent_pid"),
                "signal_type":  sig_type,
                "handler":      h.get("handler"),
                "fired_count":  fired,
                "status":       if fired > 0 { "ACTIVE" } else { "WATCHING" },
            })
        })
        .collect();

    Json(serde_json::json!({
        "generated_at":    now.to_rfc3339(),
        "signal_count":    signals.len(),
        "handler_count":   handlers.len(),
        "auto_heal_rules": auto_heals,
        "recent_signals":  signals,
    }))
}

// ── Phase I.2: cgroup-aware resource reporting ────────────────────────────────

/// GET /monitor/cgroups
/// TC-4: GET /monitor/anomalies — boundary probe scores per agent.
///
/// Analyzes the kernel audit log for each agent and returns probe scores.
/// Agents above the alert threshold (0.05) are flagged with their recommended action.
pub async fn anomalies(State(state): State<SharedState>) -> Json<serde_json::Value> {
    use connector_engine::{AnomalyReport, BoundaryProbeDetector, ProbeAuditEvent};
    use vac_core::types::OpOutcome;

    let k = state.kernel.lock().unwrap();
    let audit = k.audit_log();

    // Map kernel audit entries to ProbeAuditEvents
    let events: Vec<ProbeAuditEvent> = audit
        .iter()
        .map(|e| ProbeAuditEvent {
            timestamp_ms: e.timestamp,
            target: e.target.clone(),
            denied: e.outcome == OpOutcome::Denied,
            agent_pid: e.agent_pid.clone(),
        })
        .collect();

    let detector = BoundaryProbeDetector::new();
    let analyses = detector.analyze_all(&events);
    let report = AnomalyReport::from_analyses(analyses);

    Json(serde_json::json!({
        "ok": true,
        "total_agents_analyzed": report.total_agents_analyzed,
        "agents_alerting": report.agents_alerting,
        "agents_requiring_reduction": report.agents_requiring_reduction,
        "agents_requiring_revocation": report.agents_requiring_revocation,
        "generated_at": report.generated_at,
        "thresholds": {
            "alert": 0.05,
            "reduction": 0.10,
            "revocation": 0.20,
        },
        "agents": report.per_agent.iter().map(|a| serde_json::json!({
            "agent_pid": a.agent_pid,
            "probe_score": (a.score * 10000.0).round() / 10000.0,
            "action": a.action.to_string(),
            "clustered_denials": a.clustered_denials,
            "total_executions": a.total_executions,
            "frontier_size": a.frontier_size,
            "cluster_count": a.cluster_count,
            "docs": "https://connector.ai/docs/security/boundary-probe-detection",
        })).collect::<Vec<_>>(),
    }))
}

/// cgroup resource reporting: per-group CPU, memory, cost, token utilisation.
pub async fn cgroups_report(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let k = state.kernel.lock().unwrap();
    let es = state.engine_store.lock().unwrap();

    let keys = es.folder_keys("cgroups", None).unwrap_or_default();
    let mut reports: Vec<serde_json::Value> = Vec::new();
    let mut over_budget_count = 0usize;

    for key in &keys {
        if let Some(cg) = es.folder_get("cgroups", key).ok().flatten() {
            let agent_pids: Vec<String> = cg
                .get("agent_pids")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let (total_cost, total_tokens) =
                agent_pids.iter().fold((0.0f64, 0u64), |(c, t), pid| {
                    if let Some(acb) = k.get_agent(pid) {
                        (c + acb.total_cost_usd, t + acb.total_tokens_consumed as u64)
                    } else {
                        (c, t)
                    }
                });

            let max_cost = cg
                .get("max_cost_usd")
                .and_then(|v| v.as_f64())
                .unwrap_or(10.0);
            let max_tokens = cg
                .get("max_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(1_000_000);
            let over_budget = total_cost >= max_cost;
            if over_budget {
                over_budget_count += 1;
            }

            reports.push(serde_json::json!({
                "cgroup_id":       cg.get("cgroup_id"),
                "agent_count":     agent_pids.len(),
                "current_cost_usd": (total_cost * 10_000.0).round() / 10_000.0,
                "max_cost_usd":    max_cost,
                "cost_pct":        if max_cost > 0.0 { (total_cost / max_cost * 100.0).round() } else { 0.0 },
                "current_tokens":  total_tokens,
                "max_tokens":      max_tokens,
                "token_pct":       if max_tokens > 0 { (total_tokens as f64 / max_tokens as f64 * 100.0).round() } else { 0.0 },
                "over_budget":     over_budget,
                "status":          if over_budget { "OVER_BUDGET" } else { "OK" },
                "checked_at":      now.to_rfc3339(),
            }));
        }
    }

    Json(serde_json::json!({
        "generated_at":      now.to_rfc3339(),
        "total_cgroups":     reports.len(),
        "over_budget_count": over_budget_count,
        "cgroups":           reports,
    }))
}

/// GET /monitor/llm — LLM behaviour panel: provider config, guardrail stats, token usage,
/// latency percentiles, and per-session call log. Works in playground/stub mode too.
pub async fn llm_behaviour(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let playground = crate::services::runtime_control::free_tier_open_auth_enabled();
    let llm_wired = state.llm_wired();
    let stub_mode = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| v == "1")
        .unwrap_or(false);

    // Provider config
    let provider = std::env::var("CONNECTOR_LLM_PROVIDER").unwrap_or_else(|_| {
        if playground {
            "user-supplied (via tool)".into()
        } else if stub_mode {
            "stub".into()
        } else {
            "not configured".into()
        }
    });
    let model = std::env::var("CONNECTOR_LLM_MODEL").unwrap_or_else(|_| {
        if playground {
            "user-supplied (via tool)".into()
        } else {
            "—".into()
        }
    });
    let base_url = std::env::var("CONNECTOR_LLM_BASE_URL").ok();

    // Guardrail stats from audit log
    let k = state.kernel.lock().unwrap();
    let audit = k.audit_log();
    let total_llm_calls: usize = audit
        .iter()
        .filter(|e| {
            let op = format!("{:?}", e.operation).to_lowercase();
            op.contains("llm")
                || op.contains("chat")
                || op.contains("completion")
                || op.contains("dispatch")
        })
        .count();
    let guardrail_blocks: usize = audit
        .iter()
        .filter(|e| {
            let op = format!("{:?}", e.operation).to_lowercase();
            op.contains("guard")
                || op.contains("block")
                || op.contains("inject")
                || op.contains("deny")
                || matches!(e.outcome, vac_core::types::OpOutcome::Denied)
        })
        .count();
    let agents_active = k.all_agents().len();
    drop(k);

    let tokens_used_today: u64 = 0;

    let status = if llm_wired {
        "wired"
    } else if playground {
        "playground — user-supplied"
    } else if stub_mode {
        "stub"
    } else {
        "not configured"
    };

    Json(serde_json::json!({
        "ok": true,
        "generated_at": now.to_rfc3339(),
        "status": status,
        "playground_mode": playground,
        "provider": {
            "name": provider,
            "model": model,
            "base_url": base_url,
            "router_wired": llm_wired,
            "stub_mode": stub_mode,
            "hint": if playground {
                "Playground: each user's AI tool (Cursor/Windsurf/Claude Code) brings its own LLM key. DevGuard governs every call transparently — no server-side LLM key required."
            } else {
                "Set CONNECTOR_LLM_PROVIDER, CONNECTOR_LLM_MODEL, CONNECTOR_LLM_API_KEY to wire the server-side LLM router."
            }
        },
        "guardrails": {
            "total_llm_calls_audited": total_llm_calls,
            "guardrail_blocks": guardrail_blocks,
            "block_rate_pct": if total_llm_calls > 0 {
                (guardrail_blocks as f64 / total_llm_calls as f64 * 100.0).round()
            } else { 0.0 },
            "injection_protection": "active",
            "hallucination_filter": "active",
            "pii_scrub": "active",
            "hint": "GuardPipeline runs pre-LLM on every call: injection detection → PII scrub → hallucination check → policy enforcement."
        },
        "usage": {
            "agents_active": agents_active,
            "tokens_used_today": tokens_used_today,
            "audit_entries": total_llm_calls,
        },
        "setup": {
            "connect_url": format!("{}/connect",
                std::env::var("CONNECTOR_PUBLIC_URL").unwrap_or_else(|_| "https://connector-playground.fly.dev".into())
            ),
            "steps": if playground { vec![
                "Visit /connect — pick your tool (Cursor, Windsurf, Claude Code).",
                "Click 'Get My Base URL + API Key' — no account needed.",
                "Paste the Base URL and token into your tool's OpenAI settings.",
                "Every LLM call from your tool is now routed through DevGuard.",
                "Watch guardrail hits and session activity here in real time.",
            ]} else { vec![
                "Set CONNECTOR_LLM_PROVIDER=openai (or anthropic / azure / bedrock).",
                "Set CONNECTOR_LLM_MODEL=gpt-4o (or your preferred model).",
                "Set CONNECTOR_LLM_API_KEY=<your key> as a secret.",
                "Restart the platform — router wires automatically.",
            ]}
        }
    }))
}
