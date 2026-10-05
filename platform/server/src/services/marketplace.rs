//! # Agent Marketplace Service — Discovery, Index, Service Contracts
//!
//! Surfaces `connector_engine::agent_index::AgentIndex`,
//! `connector_engine::discovery::QueryEngine`, and
//! `connector_engine::service_contract::ServiceContract`.
//!
//! Routes:
//!   POST /marketplace/contracts           — publish a ServiceContract
//!   GET  /marketplace/contracts           — list all contracts
//!   GET  /marketplace/contracts/{id}      — contract details
//!   POST /marketplace/discover            — intent-based discovery
//!   GET  /marketplace/index               — browse agent index
//!   GET  /marketplace/index/{pid}         — agent capabilities
//!   POST /marketplace/index/{pid}/health  — update health metrics
//!   GET  /marketplace/rankings            — top agents by composite score

use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use connector_engine::agent_index::{AgentHealth, HealthStatus};
use connector_engine::discovery::{IntentQuery, QueryEngine};
use connector_engine::service_contract::{
    CapabilitySpec, PricingModel, ServiceContract, ServiceLevelAgreement,
};
use serde::Deserialize;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Deserialize)]
pub struct PublishContractRequest {
    pub agent_pid: String,
    pub capabilities: Vec<CapabilitySpecReq>,
    pub max_latency_ms: u64,
    pub availability_pct: f64,
    pub max_error_rate_pct: Option<f64>,
    pub max_concurrent: Option<u32>,
    pub pricing_type: String,
    pub cost_per_call: Option<u64>,
    pub cost_per_input_token: Option<u64>,
    pub cost_per_output_token: Option<u64>,
    pub stake: Option<u64>,
}

#[derive(Deserialize)]
pub struct CapabilitySpecReq {
    pub domain: String,
    pub action: String,
    pub version: Option<String>,
}

/// POST /marketplace/contracts — publish a ServiceContract.
pub async fn publish_contract(
    State(state): State<SharedState>,
    Json(req): Json<PublishContractRequest>,
) -> Json<serde_json::Value> {
    let caps: Vec<CapabilitySpec> = req
        .capabilities
        .iter()
        .map(|c| CapabilitySpec {
            domain: c.domain.clone(),
            action: c.action.clone(),
            version: c.version.clone().unwrap_or_else(|| "1.0".into()),
            parameters: vec![],
        })
        .collect();

    let sla = ServiceLevelAgreement {
        max_latency_ms: req.max_latency_ms,
        availability_pct: req.availability_pct,
        max_error_rate_pct: req.max_error_rate_pct.unwrap_or(1.0),
        max_concurrent: req.max_concurrent.unwrap_or(100),
    };

    let pricing = match req.pricing_type.as_str() {
        "per_token" => PricingModel::PerToken {
            cost_per_input_token: req.cost_per_input_token.unwrap_or(1),
            cost_per_output_token: req.cost_per_output_token.unwrap_or(3),
        },
        _ => PricingModel::PerInvocation {
            cost_per_call: req.cost_per_call.unwrap_or(100),
        },
    };

    let now = now_ms();
    let contract = ServiceContract {
        contract_id: format!("ctr_{}", uuid::Uuid::new_v4()),
        provider_pid: req.agent_pid.clone(),
        provider_did: None,
        capabilities: caps,
        input_schema: vec![],
        output_schema: vec![],
        sla,
        pricing,
        stake_amount: req.stake.unwrap_or(0),
        published_at: now,
        expires_at: now + 86_400_000 * 365,
        attestation: None,
    };

    let rep = {
        let rep_engine = state.reputation.lock().unwrap();
        rep_engine.score_for(&req.agent_pid, now)
    };

    let mut idx = state.agent_index.lock().unwrap();
    idx.index_agent(&req.agent_pid, contract, rep, now_ms());

    Json(serde_json::json!({
        "ok": true,
        "agent_pid": req.agent_pid,
        "capability_count": req.capabilities.len(),
        "indexed_at": now_iso(),
        "reputation_score": rep,
    }))
}

/// GET /marketplace/contracts — list all contracts.
pub async fn list_contracts(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let idx = state.agent_index.lock().unwrap();
    let contracts: Vec<serde_json::Value> = idx
        .all_entries()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "agent_pid": e.agent_pid,
                "contract": e.contract,
                "reputation_score": e.reputation_score,
                "is_active": e.is_active,
                "last_indexed_at": e.last_indexed_at,
            })
        })
        .collect();
    Json(serde_json::json!({
        "contract_count": idx.total_count(),
        "active_count": idx.active_count(),
        "contracts": contracts,
        "note": "Use /marketplace/discover for intent-based ranked search."
    }))
}

/// GET /marketplace/contracts/{pid} — get contract details for an agent.
pub async fn get_contract(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let idx = state.agent_index.lock().unwrap();
    match idx.get_entry(&pid) {
        Some(e) => Json(serde_json::json!({
            "agent_pid": e.agent_pid,
            "capabilities": e.contract.capabilities.iter().map(|c| serde_json::json!({
                "domain": c.domain, "action": c.action, "version": c.version,
            })).collect::<Vec<_>>(),
            "sla": {"max_latency_ms": e.contract.sla.max_latency_ms,
                "availability_pct": e.contract.sla.availability_pct,
                "max_error_rate_pct": e.contract.sla.max_error_rate_pct},
            "pricing": format!("{:?}", e.contract.pricing),
            "stake_amount": e.contract.stake_amount,
            "reputation_score": e.reputation_score,
            "health": {"status": format!("{:?}", e.health.status),
                "avg_latency_ms": e.health.avg_latency_ms,
                "error_rate_pct": e.health.error_rate_pct},
            "is_active": e.is_active,
        })),
        None => Json(
            serde_json::json!({"error": "Agent not found in marketplace index", "status": 404}),
        ),
    }
}

#[derive(Deserialize)]
pub struct DiscoverRequest {
    pub domain: String,
    pub action: String,
    pub max_latency_ms: Option<u64>,
    pub min_availability_pct: Option<f64>,
    pub max_cost_per_call: Option<u64>,
    pub min_trust_score: Option<f64>,
    pub max_results: Option<usize>,
}

/// POST /marketplace/discover — intent-based discovery: "I need X with Y guarantees."
pub async fn discover(
    State(state): State<SharedState>,
    Json(req): Json<DiscoverRequest>,
) -> Json<serde_json::Value> {
    let idx = state.agent_index.lock().unwrap();
    let query = IntentQuery {
        requester_pid: "platform".into(),
        domain: req.domain.clone(),
        action: req.action.clone(),
        max_latency_ms: req.max_latency_ms,
        min_availability_pct: req.min_availability_pct,
        max_cost_per_call: req.max_cost_per_call,
        min_trust_score: req.min_trust_score,
        max_results: req.max_results.unwrap_or(10),
    };
    let result = QueryEngine::search(&idx, &query);

    let providers: Vec<serde_json::Value> = result
        .providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "agent_pid": p.agent_pid,
                "composite_score": p.composite_score,
            })
        })
        .collect();

    Json(serde_json::json!({
        "query": {"domain": req.domain, "action": req.action},
        "total_indexed": result.total_indexed,
        "matched": result.matched,
        "returned": providers.len(),
        "providers": providers,
        "discovered_at": now_iso(),
    }))
}

/// GET /marketplace/index — browse the full agent index.
pub async fn browse_index(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let idx = state.agent_index.lock().unwrap();
    let agents: Vec<serde_json::Value> = idx
        .all_entries()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "agent_pid": e.agent_pid,
                "reputation_score": e.reputation_score,
                "is_active": e.is_active,
                "last_indexed_at": e.last_indexed_at,
                "health": e.health,
            })
        })
        .collect();
    Json(serde_json::json!({
        "agent_count": idx.total_count(),
        "active_count": idx.active_count(),
        "capability_count": idx.capability_count(),
        "capability_keys": idx.all_capability_keys(),
        "agents": agents,
    }))
}

/// GET /marketplace/index/{pid} — agent capabilities.
pub async fn agent_capabilities(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let idx = state.agent_index.lock().unwrap();
    match idx.get_entry(&pid) {
        Some(e) => {
            let caps: Vec<serde_json::Value> = e
                .contract
                .capabilities
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "domain": c.domain, "action": c.action, "version": c.version,
                        "key": c.capability_key(),
                    })
                })
                .collect();
            Json(
                serde_json::json!({"agent_pid": pid, "capabilities": caps, "reputation": e.reputation_score}),
            )
        }
        None => Json(serde_json::json!({"error": "Agent not indexed", "status": 404})),
    }
}

#[derive(Deserialize)]
pub struct UpdateHealthRequest {
    pub status: String,
    pub avg_latency_ms: Option<u64>,
    pub error_rate_pct: Option<f64>,
}

/// POST /marketplace/index/{pid}/health — update health metrics for an agent.
pub async fn update_health(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<UpdateHealthRequest>,
) -> Json<serde_json::Value> {
    let mut idx = state.agent_index.lock().unwrap();
    let status = match req.status.to_lowercase().as_str() {
        "healthy" => HealthStatus::Healthy,
        "degraded" => HealthStatus::Degraded,
        "down" => HealthStatus::Down,
        _ => HealthStatus::Unknown,
    };
    let health = AgentHealth {
        status,
        uptime_pct: 100.0,
        avg_latency_ms: req.avg_latency_ms.unwrap_or(0),
        error_rate_pct: req.error_rate_pct.unwrap_or(0.0),
        last_check_at: now_ms(),
        consecutive_failures: 0,
    };
    idx.update_health(&pid, health);
    Json(
        serde_json::json!({"ok": true, "agent_pid": pid, "health": req.status, "updated_at": now_iso()}),
    )
}

/// GET /marketplace/rankings — top agents by composite score.
pub async fn rankings(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let idx = state.agent_index.lock().unwrap();
    // AgentIndex has no ranked_all — use ranked_providers on empty domain/action for all
    let ranked = idx.ranked_providers("", "");
    let items: Vec<serde_json::Value> = ranked
        .iter()
        .enumerate()
        .map(|(i, r)| {
            serde_json::json!({
                "rank": i + 1,
                "agent_pid": r.agent_pid,
                "composite_score": r.composite_score,
            })
        })
        .collect();
    Json(serde_json::json!({"count": items.len(), "rankings": items}))
}

// =============================================================================
// AMA-9: Tool + Agent marketplace listings with pagination + search
// =============================================================================

#[derive(Deserialize)]
pub struct MarketplaceListQuery {
    /// Full-text search term (matches tool_id / name / description)
    pub q: Option<String>,
    /// Pagination: page number (1-based)
    pub page: Option<usize>,
    /// Pagination: items per page (default 20, max 100)
    pub limit: Option<usize>,
    /// Filter by category / domain
    pub category: Option<String>,
}

/// GET /marketplace/tools — paginated tool listing with search.
///
/// Returns registered tool descriptors stored via `POST /marketplace/tools/register`.
/// Tool descriptor format: `{ tool_id, name, action, schema, endpoint, auth, category, version }`.
pub async fn list_tools(
    State(state): State<SharedState>,
    Query(q): Query<MarketplaceListQuery>,
) -> Json<serde_json::Value> {
    use connector_engine::engine_store::EngineStore;
    let search = q.q.as_deref().unwrap_or("").to_lowercase();
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(20).min(100);
    let category = q.category.as_deref().unwrap_or("");

    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys("marketplace_tools", None)
        .unwrap_or_default();
    let mut tools: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("marketplace_tools", k).ok().flatten())
        .filter(|t| {
            let text = format!(
                "{} {} {} {}",
                t.get("tool_id").and_then(|v| v.as_str()).unwrap_or(""),
                t.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                t.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                t.get("action").and_then(|v| v.as_str()).unwrap_or(""),
            )
            .to_lowercase();
            let cat = t.get("category").and_then(|v| v.as_str()).unwrap_or("");
            (search.is_empty() || text.contains(&search))
                && (category.is_empty() || cat.eq_ignore_ascii_case(category))
        })
        .collect();

    let total = tools.len();
    let offset = (page - 1) * limit;
    tools = tools.into_iter().skip(offset).take(limit).collect();

    Json(serde_json::json!({
        "ok": true,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) / limit.max(1),
        "tools": tools,
    }))
}

/// POST /marketplace/tools/register — register a tool descriptor.
///
/// Body: `{ tool_id, name, action, schema, endpoint, auth, category?, version?, description? }`
pub async fn register_tool(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use connector_engine::engine_store::EngineStore;
    let tool_id = match body.get("tool_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": {"code": "tool_id_required", "message": "tool_id is required"}
            }))
        }
    };
    let mut record = body.clone();
    if let Some(obj) = record.as_object_mut() {
        obj.insert("registered_at".into(), serde_json::json!(now_iso()));
    }
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("marketplace_tools", &tool_id, &record);
    Json(serde_json::json!({"ok": true, "tool_id": tool_id, "registered_at": now_iso()}))
}

/// GET /marketplace/agents — paginated agent listing from the agent index + kernel.
///
/// Returns all registered agents with capabilities, health, and reputation score.
pub async fn list_marketplace_agents(
    State(state): State<SharedState>,
    Query(q): Query<MarketplaceListQuery>,
) -> Json<serde_json::Value> {
    let search = q.q.as_deref().unwrap_or("").to_lowercase();
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(20).min(100);
    let category = q.category.as_deref().unwrap_or("").to_lowercase();

    // Pull from kernel ACB list
    let all_agents: Vec<serde_json::Value> = {
        let k = state.kernel.lock().unwrap();
        let idx = state.agent_index.lock().unwrap();
        k.all_agents()
            .iter()
            .filter_map(|acb| {
                let name = acb.agent_name.to_lowercase();
                let ns = acb.namespace.to_lowercase();
                let role = format!("{:?}", acb.role).to_lowercase();
                let text = format!("{} {} {}", name, ns, role);
                if !search.is_empty() && !text.contains(&search) {
                    return None;
                }
                if !category.is_empty() && !role.contains(&category) {
                    return None;
                }
                let rep = idx
                    .get_entry(&acb.agent_pid)
                    .map(|e| e.reputation_score)
                    .unwrap_or(0.5);
                Some(serde_json::json!({
                    "agent_pid":    acb.agent_pid,
                    "name":         acb.agent_name,
                    "role":         format!("{:?}", acb.role),
                    "namespace":    acb.namespace,
                    "status":       format!("{:?}", acb.status),
                    "model":        acb.model,
                    "framework":    acb.framework,
                    "reputation":   (rep * 1000.0).round() / 1000.0,
                    "capabilities": acb.capabilities,
                    "registered_at": acb.registered_at,
                }))
            })
            .collect()
    };

    let total = all_agents.len();
    let offset = (page - 1) * limit;
    let page_agents: Vec<_> = all_agents.into_iter().skip(offset).take(limit).collect();

    Json(serde_json::json!({
        "ok": true,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) / limit.max(1),
        "agents": page_agents,
    }))
}

// =============================================================================
// AMA-9: Module registry — installed_modules table (via engine_store folder)
// =============================================================================

/// POST /marketplace/modules/install — install a tool or agent module.
///
/// Body: `{ module_id, type: "tool"|"agent", version, manifest_cid?, source_url? }`
/// Persists to `installed_modules` folder (SQLite-backed via engine_store).
pub async fn install_module(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use connector_engine::engine_store::EngineStore;
    let module_id = match body.get("module_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": {"code": "module_id_required", "message": "module_id is required"}
            }))
        }
    };
    let module_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("tool");
    let version = body
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.1.0");
    let manifest_cid = body
        .get("manifest_cid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let source_url = body
        .get("source_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let record = serde_json::json!({
        "module_id":     module_id,
        "type":          module_type,
        "version":       version,
        "manifest_cid":  manifest_cid,
        "source_url":    source_url,
        "installed_at":  now_iso(),
        "installed_at_ms": now_ms(),
        "status":        "installed",
    });

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("installed_modules", &module_id, &record);

    Json(serde_json::json!({
        "ok": true,
        "module_id": module_id,
        "type": module_type,
        "version": version,
        "installed_at": now_iso(),
    }))
}

/// GET /marketplace/modules — list all installed modules with pagination.
pub async fn list_modules(
    State(state): State<SharedState>,
    Query(q): Query<MarketplaceListQuery>,
) -> Json<serde_json::Value> {
    use connector_engine::engine_store::EngineStore;
    let search = q.q.as_deref().unwrap_or("").to_lowercase();
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(20).min(100);
    let type_filter = q.category.as_deref().unwrap_or(""); // reuse category field for type filter

    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys("installed_modules", None)
        .unwrap_or_default();
    let mut modules: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("installed_modules", k).ok().flatten())
        .filter(|m| {
            let text = format!(
                "{} {} {}",
                m.get("module_id").and_then(|v| v.as_str()).unwrap_or(""),
                m.get("type").and_then(|v| v.as_str()).unwrap_or(""),
                m.get("version").and_then(|v| v.as_str()).unwrap_or(""),
            )
            .to_lowercase();
            let mtype = m.get("type").and_then(|v| v.as_str()).unwrap_or("");
            (search.is_empty() || text.contains(&search))
                && (type_filter.is_empty() || mtype.eq_ignore_ascii_case(type_filter))
        })
        .collect();

    let total = modules.len();
    let offset = (page - 1) * limit;
    modules = modules.into_iter().skip(offset).take(limit).collect();

    Json(serde_json::json!({
        "ok": true,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) / limit.max(1),
        "modules": modules,
    }))
}

/// DELETE /marketplace/modules/:module_id — uninstall a module.
pub async fn uninstall_module(
    State(state): State<SharedState>,
    Path(module_id): Path<String>,
) -> Json<serde_json::Value> {
    use connector_engine::engine_store::EngineStore;
    let mut es = state.engine_store.lock().unwrap();
    let existed = es
        .folder_get("installed_modules", &module_id)
        .ok()
        .flatten()
        .is_some();
    let _ = es.folder_delete("installed_modules", &module_id);
    Json(serde_json::json!({
        "ok": existed,
        "module_id": module_id,
        "uninstalled_at": now_iso(),
    }))
}
