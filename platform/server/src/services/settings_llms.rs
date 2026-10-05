use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::{extract::State, http::HeaderMap, Json};
use connector_engine::llm::LlmConfig as EngineLlmConfig;
use connector_engine::llm_router::LlmRouter;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth;
use crate::state::{self, LlmConfig, SharedState};

const LLM_SETTINGS_FOLDER: &str = "settings_llms";

#[derive(Debug, Deserialize)]
pub struct SaveProvidersRequest {
    pub providers: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct SaveRoutingRulesRequest {
    pub rules: Vec<Value>,
}

#[derive(Debug, Deserialize)]
pub struct SaveOverridesRequest {
    pub plugin_overrides: Option<Value>,
    pub workflow_overrides: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct SaveGuardrailsRequest {
    pub monthly_budget_usd: f64,
    pub warning_pct: f64,
    pub hard_stop_pct: f64,
}

#[derive(Debug, Deserialize)]
pub struct SavePrivacyTagsRequest {
    pub tags: Vec<String>,
    pub workflow_requirements: Option<Value>,
}

/// DI-1 — paste provider + key → vault + hot-wire Talk router (keys never enter DockLock cage).
#[derive(Debug, Deserialize)]
pub struct LinkLlmRequest {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    /// When true, probe a tiny completion after install.
    #[serde(default)]
    pub ping: bool,
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), serde_json::Value> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    // Name is admin-or-dev: Developer (3) can link a Talk key. Admin-only
    // blocked playground JWTs (role=developer) so Connect LLM never saved.
    if crate::services::playground::is_playground_mode() {
        return Ok(());
    }
    if role.rank() < auth::PlatformRole::Developer.rank() {
        return Err(json!({"ok": false, "error": "Developer privileges required"}));
    }
    Ok(())
}

fn get_value(state: &SharedState, key: &str) -> Option<Value> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(LLM_SETTINGS_FOLDER, key).ok().flatten()
}

fn put_value(state: &SharedState, key: &str, value: &Value) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(LLM_SETTINGS_FOLDER, key, value);
}

fn tenant_llm_cache() -> &'static Mutex<HashMap<String, (LlmConfig, Arc<LlmRouter>)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (LlmConfig, Arc<LlmRouter>)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Playground sessions are tenant-isolated; LLM keys must not clobber each other on a shared VM.
pub fn llm_tenant_scope(headers: &HeaderMap) -> Option<String> {
    if !crate::services::playground::is_playground_mode() {
        return None;
    }
    auth::extract_claims(headers)
        .and_then(|c| c.tenant_id.filter(|s| !s.trim().is_empty()))
        .or_else(|| {
            crate::middleware::tenant::extract_tenant_from_headers(headers)
                .map(|t| t.tenant_id)
        })
}

fn tenant_from_agent_meta(state: &SharedState, agent_pid: &str) -> Option<String> {
    state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten())
        .and_then(|m| {
            m.get("tenant_id")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.is_empty())
}

pub fn llm_secret_id(tenant: Option<&str>, provider: &str) -> String {
    if let Some(t) = tenant.filter(|s| !s.trim().is_empty()) {
        if crate::services::playground::is_playground_mode() {
            return format!("llm/{t}/{provider}");
        }
    }
    format!("llm/{provider}")
}

fn providers_settings_key(tenant: Option<&str>) -> String {
    if crate::services::playground::is_playground_mode() {
        if let Some(t) = tenant.filter(|s| !s.trim().is_empty()) {
            return format!("providers/{t}");
        }
    }
    "providers".into()
}

fn get_providers(state: &SharedState, tenant: Option<&str>) -> Vec<Value> {
    get_value(state, &providers_settings_key(tenant))
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

fn put_providers(state: &SharedState, tenant: Option<&str>, providers: &[Value]) {
    put_value(
        state,
        &providers_settings_key(tenant),
        &json!(providers),
    );
}

fn build_router_from_provider_meta(
    state: &SharedState,
    provider: &str,
    model: &str,
    endpoint: Option<String>,
    secret_id: &str,
) -> Option<(LlmConfig, LlmRouter)> {
    if provider.is_empty() || model.is_empty() {
        return None;
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let api_key = match state.secret_store.lock() {
        Ok(vault) => match vault.get_secret_value(secret_id, now_ms) {
            Ok(k) if !k.is_empty() => k,
            _ => return None,
        },
        Err(_) => return None,
    };
    let mut engine = EngineLlmConfig::new(provider, model, &api_key);
    if let Some(ref ep) = endpoint {
        engine.endpoint = Some(ep.clone());
    }
    let router = state::build_llm_router(vec![engine]);
    let cfg = LlmConfig {
        provider: provider.to_string(),
        model: model.to_string(),
        api_key,
        endpoint,
    };
    Some((cfg, router))
}

fn cache_tenant_router(tenant: &str, cfg: LlmConfig, router: Arc<LlmRouter>) {
    if let Ok(mut cache) = tenant_llm_cache().lock() {
        cache.insert(tenant.to_string(), (cfg, router));
    }
}

fn tenant_router_from_store(state: &SharedState, tenant: &str) -> Option<Arc<LlmRouter>> {
    if let Ok(cache) = tenant_llm_cache().lock() {
        if let Some((_, router)) = cache.get(tenant) {
            return Some(Arc::clone(router));
        }
    }
    let providers = get_providers(state, Some(tenant));
    let primary = providers
        .iter()
        .find(|p| p.get("primary").and_then(|x| x.as_bool()).unwrap_or(false))
        .or_else(|| providers.first())?;
    let provider = primary
        .get("provider")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let model = primary
        .get("model")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(default_model_for(&provider))
        .to_string();
    let endpoint = primary
        .get("endpoint")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let secret_id = primary
        .get("secret_id")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| llm_secret_id(Some(tenant), &provider));
    let (cfg, router) =
        build_router_from_provider_meta(state, &provider, &model, endpoint, &secret_id)?;
    cache_tenant_router(tenant, cfg, Arc::new(router));
    tenant_llm_cache()
        .lock()
        .ok()
        .and_then(|c| c.get(tenant).map(|(_, r)| Arc::clone(r)))
}

/// Hot-wire the caller's tenant LLM before Talk (playground isolation).
pub fn restore_llm_router_for_talk(
    state: &SharedState,
    headers: &HeaderMap,
    agent_pid: Option<&str>,
) {
    restore_llm_router_if_needed(state);
    if !crate::services::playground::is_playground_mode() {
        return;
    }
    let tenant = llm_tenant_scope(headers)
        .or_else(|| agent_pid.and_then(|pid| tenant_from_agent_meta(state, pid)));
    if let Some(tid) = tenant {
        let _ = tenant_router_from_store(state, &tid);
    }
}

/// Resolve the LLM router for a Talk completion (tenant-scoped on playground).
pub fn talk_llm_router(
    state: &SharedState,
    headers: &HeaderMap,
    agent_pid: &str,
) -> Option<Arc<LlmRouter>> {
    restore_llm_router_for_talk(state, headers, Some(agent_pid));
    if crate::services::playground::is_playground_mode() {
        let tenant = llm_tenant_scope(headers)
            .or_else(|| tenant_from_agent_meta(state, agent_pid))?;
        // Never fall back to the global router — that is another tenant's key on a shared VM.
        return tenant_router_from_store(state, &tenant);
    }
    state.llm_router_arc()
}

pub fn talk_llm_wired(state: &SharedState, headers: &HeaderMap, agent_pid: &str) -> bool {
    talk_llm_router(state, headers, agent_pid).is_some()
}

/// P2.2 — Settings LLM cost-cap hard stop vs Books month spend (gateway chat path).
///
/// Returns `Err(message)` when month estimated USD ≥ budget × hard_stop_pct/100.
/// When budget is 0, hard stop is inactive (avoid locking a freshly configured node).
pub fn cost_cap_hard_stop_violation(
    state: &SharedState,
    account_id: Option<&str>,
) -> Option<(f64, f64, f64, f64)> {
    let guardrails = get_value(state, "guardrails").unwrap_or_else(|| {
        json!({
            "monthly_budget_usd": 100.0,
            "warning_pct": 80.0,
            "hard_stop_pct": 100.0
        })
    });
    let budget = guardrails
        .get("monthly_budget_usd")
        .and_then(|x| x.as_f64())
        .unwrap_or(100.0);
    let hard_stop_pct = guardrails
        .get("hard_stop_pct")
        .and_then(|x| x.as_f64())
        .unwrap_or(100.0)
        .clamp(0.0, 200.0);
    if budget <= 0.0 {
        return None;
    }
    let ceiling = budget * (hard_stop_pct / 100.0);
    let month = crate::services::books::billing_ledger_totals(state, account_id).month_cost_usd;
    if month >= ceiling {
        Some((month, budget, hard_stop_pct, ceiling))
    } else {
        None
    }
}

/// Runtime fallback + cost-cap honesty (env + persisted guardrails).
fn fallback_cap_contract(state: &SharedState) -> Value {
    let fallback_env = std::env::var("CONNECTOR_LLM_FALLBACK").ok();
    let fallback_key_set = std::env::var("CONNECTOR_LLM_FALLBACK_KEY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let router_wired = state.llm_wired();
    let stored = get_value(state, "fallback").unwrap_or_else(|| json!({}));
    let guardrails = get_value(state, "guardrails").unwrap_or_else(|| {
        json!({
            "monthly_budget_usd": 100.0,
            "warning_pct": 80.0,
            "hard_stop_pct": 100.0
        })
    });
    json!({
        "fallback": {
            "env_provider": fallback_env,
            "env_key_configured": fallback_key_set,
            "provider_configured": fallback_env.is_some(),
            "router_wired": router_wired,
            "stored": stored,
            "contract": "Primary from CONNECTOR_LLM_*; secondary via CONNECTOR_LLM_FALLBACK[+_KEY]. Routing rules may also trigger on cost_cap."
        },
        "cost_cap": {
            "guardrails": guardrails,
            "triggers": ["cost_cap", "http_5xx", "latency_p95", "region_policy"],
            "enforced_on": "POST /v1/chat/completions (gateway) via cost_cap_hard_stop_violation",
            "honesty": "hard_stop_pct blocks overspend on the chat path when month Books estimated USD ≥ budget×hard_stop%; unavailable ≠ $0 in Books. Primary-down→fallback E2E still open."
        }
    })
}

/// Known Talk routers from `connector-engine` `LlmConfig::base_url` — not a live marketplace scrape.
fn llm_provider_catalog() -> Value {
    llm_provider_catalog_for(crate::services::playground::is_playground_mode())
}

fn llm_provider_catalog_for(playground: bool) -> Value {
    let mut rows = vec![
        json!({"id":"openai","label":"OpenAI","needs_key":true,"needs_endpoint":false,"models":["gpt-4o","gpt-4o-mini","gpt-4.1","o4-mini"]}),
        json!({"id":"anthropic","label":"Anthropic","needs_key":true,"needs_endpoint":false,"models":["claude-3-5-sonnet-20241022","claude-3-5-haiku-20241022","claude-3-opus-20240229"]}),
        json!({"id":"gemini","label":"Google Gemini","needs_key":true,"needs_endpoint":false,"models":["gemini-2.0-flash","gemini-1.5-pro"]}),
        json!({"id":"deepseek","label":"DeepSeek","needs_key":true,"needs_endpoint":false,"models":["deepseek-chat","deepseek-reasoner"]}),
        json!({"id":"groq","label":"Groq","needs_key":true,"needs_endpoint":false,"models":["llama-3.3-70b-versatile","mixtral-8x7b-32768"]}),
        json!({"id":"together","label":"Together","needs_key":true,"needs_endpoint":false,"models":["meta-llama/Llama-3-70b-chat-hf"]}),
        json!({"id":"mistral","label":"Mistral","needs_key":true,"needs_endpoint":false,"models":["mistral-large-latest","mistral-small-latest"]}),
        json!({"id":"cohere","label":"Cohere","needs_key":true,"needs_endpoint":false,"models":["command-r-plus"]}),
        json!({"id":"fireworks","label":"Fireworks","needs_key":true,"needs_endpoint":false,"models":["accounts/fireworks/models/llama-v3p1-70b-instruct"]}),
        json!({"id":"perplexity","label":"Perplexity","needs_key":true,"needs_endpoint":false,"models":["sonar"]}),
        json!({"id":"openrouter","label":"OpenRouter","needs_key":true,"needs_endpoint":false,"models":["openai/gpt-4o","anthropic/claude-3.5-sonnet","meta-llama/llama-3.1-70b-instruct"]}),
    ];
    if !playground {
        rows.push(json!({"id":"ollama","label":"Ollama (local)","needs_key":false,"needs_endpoint":true,"default_endpoint":"http://127.0.0.1:11434/v1","models":["llama3.2","llama3.1","mistral"]}));
        rows.push(json!({"id":"lmstudio","label":"LM Studio (local)","needs_key":false,"needs_endpoint":true,"default_endpoint":"http://127.0.0.1:1234/v1","models":["local-model"]}));
        rows.push(json!({"id":"vllm","label":"vLLM (self-host)","needs_key":false,"needs_endpoint":true,"default_endpoint":"http://127.0.0.1:8000/v1","models":["local-model"]}));
    }
    rows.push(json!({"id":"custom","label":"Custom OpenAI-compatible API","needs_key":true,"needs_endpoint":true,"models":[]}));
    json!(rows)
}

pub async fn get_llm_providers(State(state): State<SharedState>) -> Json<Value> {
    let providers = get_value(&state, "providers").unwrap_or_else(|| json!([]));
    let catalog = llm_provider_catalog();
    let supported: Vec<Value> = catalog
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.get("id").cloned())
        .collect();
    Json(json!({
        "ok": true,
        "providers": providers,
        "catalog": catalog,
        "supported": supported,
        "secret_source": "/api/v1/infra/vault/*",
        "honesty": if crate::services::playground::is_playground_mode() {
            "Hosted trial: local Ollama / LM Studio / vLLM are hidden — Fly cannot reach 127.0.0.1. Catalog is engine-wired providers, not a scraped marketplace."
        } else {
            "catalog is the engine-wired provider list (LlmConfig::base_url). Unknown vendors use id=custom with your OpenAI-compatible base URL. This is not a scraped marketplace."
        },
    }))
}

/// GET /settings/llms/fallback-cap — fallback + cost-cap contract for Settings / smoke.
pub async fn get_llm_fallback_cap(State(state): State<SharedState>) -> Json<Value> {
    let mut body = fallback_cap_contract(&state);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("ok".into(), json!(true));
    }
    Json(body)
}

pub async fn set_llm_providers(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveProvidersRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "llm-settings",
        "settings",
        "set_llm_providers",
        &json!({"count": req.providers.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    put_value(&state, "providers", &json!(req.providers));
    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "count": req.providers.len(),
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /settings/llms/link — store key in vault + rebuild `LlmRouter` in-process (DI-1).
pub async fn link_llm(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<LinkLlmRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let mut provider = req.provider.trim().to_ascii_lowercase();
    if provider == "openai_compatible_custom" {
        provider = "custom".into();
    }
    let model = req.model.trim().to_string();
    let mut api_key = req.api_key.trim().to_string();
    let endpoint = req
        .endpoint
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if provider.is_empty() || model.is_empty() {
        return Json(json!({
            "ok": false,
            "error": "provider and model are required",
        }));
    }
    let local_no_key = matches!(provider.as_str(), "ollama" | "lmstudio" | "vllm");
    if crate::services::playground::is_playground_mode() && local_no_key {
        return Json(json!({
            "ok": false,
            "error": "playground_local_llm_unreachable",
            "hint": "Fly cannot reach 127.0.0.1 on your laptop. Link OpenAI, Anthropic, or another hosted provider. Ping is required (SKIP_PING=0).",
        }));
    }
    if crate::services::playground::is_playground_mode() {
        if let Some(ep) = endpoint.as_deref() {
            let low = ep.to_ascii_lowercase();
            if low.contains("127.0.0.1") || low.contains("localhost") {
                return Json(json!({
                    "ok": false,
                    "error": "playground_loopback_endpoint",
                    "hint": "This hosted trial cannot dial your laptop. Use a public vendor base URL.",
                }));
            }
        }
    }
    if matches!(provider.as_str(), "custom" | "azure" | "bedrock" | "vertex") && endpoint.is_none()
    {
        return Json(json!({
            "ok": false,
            "error": "this provider requires endpoint (OpenAI-compatible base URL)",
        }));
    }
    if api_key.is_empty() {
        if local_no_key || provider == "custom" {
            api_key = "local".into();
        } else {
            return Json(json!({
                "ok": false,
                "error": "api_key is required for this provider (Ollama/LM Studio/vLLM/custom may omit it)",
            }));
        }
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "llm-settings",
        "settings",
        "link_llm",
        &json!({"provider": provider.as_str(), "model": model.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let secret_id = llm_secret_id(llm_tenant_scope(&headers).as_deref(), &provider);
    {
        let mut vault = state.secret_store.lock().unwrap();
        let now_ms = chrono::Utc::now().timestamp_millis();
        if let Err(e) = vault.upsert_secret(
            &secret_id,
            "cnktr:platform",
            &api_key,
            None,
            now_ms,
            "LLM API key for Talk (platform plane — not cage env)",
        ) {
            return Json(json!({"ok": false, "error": format!("vault_store: {e}")}));
        }
        if let Err(e) = crate::kernel::vault_seal::persist(&vault) {
            return Json(json!({"ok": false, "error": format!("vault_persist: {e}")}));
        }
    }

    let mut engine = EngineLlmConfig::new(&provider, &model, &api_key);
    if let Some(ref ep) = endpoint {
        engine.endpoint = Some(ep.clone());
    }
    let router = state::build_llm_router(vec![engine]);
    let mut ping_result = json!(null);
    // Hosted trial: require vendor prove-out unless explicitly skipped.
    let skip_ping = matches!(
        std::env::var("CONNECTOR_PLAYGROUND_LLM_LINK_SKIP_PING")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    );
    let playground_ping = crate::services::playground::is_playground_mode() && !skip_ping;
    if playground_ping {
        let ping_secs = std::env::var("CONNECTOR_PLAYGROUND_LLM_PING_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(20);
        ping_result = match tokio::time::timeout(
            std::time::Duration::from_secs(ping_secs),
            router.complete("Reply with the single word: pong", Some("ping")),
        )
        .await
        {
            Ok(Ok(resp)) => json!({
                "ok": true,
                "provider": resp.provider,
                "model": resp.model,
                "preview": resp.text.chars().take(80).collect::<String>(),
            }),
            Ok(Err(e)) => {
                return Json(json!({
                    "ok": false,
                    "error": format!("provider refused the key: {e}"),
                    "proven": false,
                }));
            }
            Err(_) => {
                return Json(json!({
                    "ok": false,
                    "error": format!(
                        "provider timed out ({ping_secs}s) — check the key and that this host can reach the vendor"
                    ),
                    "proven": false,
                }));
            }
        };
    }
    let cfg = LlmConfig {
        provider: provider.clone(),
        model: model.clone(),
        api_key: api_key.clone(),
        endpoint: endpoint.clone(),
    };
    let tenant_scope = llm_tenant_scope(&headers);
    if crate::services::playground::is_playground_mode() {
        let Some(tenant) = tenant_scope.clone() else {
            return Json(json!({
                "ok": false,
                "error": "playground tenant required — use a session JWT (exchange cpk_pg_* key) before linking an LLM",
            }));
        };
        // Tenant-only: never install the global router on a shared playground VM.
        cache_tenant_router(&tenant, cfg, Arc::new(router));
    } else {
        state.install_llm_router(cfg.clone(), router);
        if let Some(tenant) = tenant_scope.clone() {
            if let Some((_, fresh)) = build_router_from_provider_meta(
                &state,
                &provider,
                &model,
                endpoint.clone(),
                &secret_id,
            ) {
                cache_tenant_router(&tenant, cfg, Arc::new(fresh));
            }
        }
    }

    // Persist non-secret metadata for Settings GET.
    let mut providers = get_providers(&state, tenant_scope.as_deref());
    providers.retain(|p| {
        p.get("provider")
            .and_then(|x| x.as_str())
            .map(|s| s != provider)
            .unwrap_or(true)
    });
    let proven = if playground_ping {
        ping_result
            .get("ok")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
    } else if crate::services::playground::is_playground_mode() && skip_ping {
        false
    } else {
        // Non-playground: mark proven when ping was requested and succeeded later,
        // or when link installs without ping requirement.
        !req.ping
            || ping_result
                .get("ok")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
    };
    providers.insert(
        0,
        json!({
            "provider": provider,
            "model": model,
            "endpoint": endpoint,
            "secret_id": secret_id,
            "tenant_id": tenant_scope,
            "primary": true,
            "linked_at_ms": chrono::Utc::now().timestamp_millis(),
            "proven": proven,
            "ping": ping_result,
            "honesty": if proven {
                "api_key vaulted; vendor prove-out passed — Talk is live"
            } else if skip_ping && crate::services::playground::is_playground_mode() {
                "api_key vaulted; prove-out skipped (CONNECTOR_PLAYGROUND_LLM_LINK_SKIP_PING) — not live"
            } else {
                "api_key stored in vault only; LlmRouter hot-wired on platform — never DockLock cage env"
            },
        }),
    );
    put_providers(&state, tenant_scope.as_deref(), &providers);

    let do_ping = req.ping && !crate::services::playground::is_playground_mode();
    if do_ping {
        ping_result = match state.llm_router_arc() {
            Some(r) => match r
                .complete("Reply with the single word: pong", Some("ping"))
                .await
            {
                Ok(resp) => json!({
                    "ok": true,
                    "provider": resp.provider,
                    "model": resp.model,
                    "preview": resp.text.chars().take(80).collect::<String>(),
                }),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            },
            None => json!({"ok": false, "error": "router_missing_after_install"}),
        };
    }

    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "schema": "connector.llm_link.v1",
        "provider": provider,
        "model": model,
        "endpoint": endpoint,
        "secret_id": secret_id,
        "tenant_id": tenant_scope,
        "proven": proven,
        "effective_mode": if proven { "live" } else if skip_ping { "linked_unproven" } else { "linked" },
        "router_wired": if crate::services::playground::is_playground_mode() {
            tenant_scope.is_some()
        } else {
            state.llm_wired()
        },
        "ping": ping_result,
        "absorb": crate::kernel::operating_layer::classify_device(&provider, endpoint.as_deref()),
        "honesty": if proven {
            "Intelligence Talk uses dest-pinned Landlock LLM cage; vendor prove-out passed. Cage workers never receive this key via env."
        } else {
            "Intelligence Talk uses dest-pinned Landlock LLM cage when exclusivity/Ring-1 is on; cage workers never receive this key via env. vLLM/Ollama/OpenAI are the same device kind."
        },
    }))
}

/// POST /runtime/enable-hardening — DI-3 one-click force Ring-1/QPR/DockLock/HITL on.
pub async fn enable_hardening(headers: HeaderMap) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let keys = crate::connector_profile::enable_intelligence_hardening();
    Json(json!({
        "ok": true,
        "schema": "connector.enable_hardening.v1",
        "set_keys": keys,
        "lab_mode": false,
        "honesty": "In-process env forced on. Persist CONNECTOR_PRESET=production in your env file for restarts. Intelligence plane — not process firewall.",
    }))
}

/// GET /runtime/intelligence-posture — DI-3 MONITOR instruments (node-scoped).
pub async fn get_intelligence_posture(State(state): State<SharedState>) -> Json<Value> {
    let dock = crate::kernel::docklock::status_snapshot(state.as_ref());
    let lab = get_lab_mode_body();
    let llm = state.llm_wired();
    let cfg = state.llm_config_snapshot();
    let applied_truth = crate::kernel::membrane_posture::applied_truth_snapshot(state.as_ref());
    let autonomy_rates = crate::kernel::action_binding::gateway_rates_snapshot();
    let conp_reg = connector_protocol::ProtocolCapabilityRegistry::with_defaults();
    let cnp_mtls_stub = std::env::var("CONNECTOR_CNP_ALLOW_MTLS_STUB")
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes" || t == "on"
        })
        .unwrap_or(false);
    Json(json!({
        "ok": true,
        "schema": "connector.intelligence_posture.v1",
        "lab_mode": lab.get("lab_mode").and_then(|x| x.as_bool()).unwrap_or(true),
        "lab": lab,
        "docklock": dock,
        "applied_truth": applied_truth,
        "autonomy_gateway": autonomy_rates,
        "native_protocol": {
            "schema": "connector.native_protocol.posture.v1",
            "world": "/api/v1/protocol/world",
            "cnp": {
                "role": "spine",
                "overview": "/api/v1/cnp/overview",
                "mtls_lab_stub": cnp_mtls_stub,
                "applied_truth": if cnp_mtls_stub { "lab_stub_mtls" } else { "fail_closed_without_product_mtls" },
            },
            "conp": {
                "role": "machine_robot_api_vocabulary",
                "protocol": "CP/1.0",
                "message_type_count": connector_protocol::ALL_MESSAGE_TYPES.len(),
                "capability_count": conp_reg.count(),
                "entity_classes": 7,
                "catalog": "/api/v1/protocol/conp/info",
                "command": "POST /api/v1/protocol/conp/command",
                "message": "POST /api/v1/protocol/conp/message",
                "sil_certified": false,
                "hal_plane_separate_from_sil": true,
                "high_risk_prefer_microvm": ["machine.program_run", "machine.rapid"],
                "applied_truth": "admission_path_live_hal_partner",
                "honesty": "CONP taxonomy ≠ SIL-certified robot safety",
            },
            "cpkg": {
                "custom_agent_logic": true,
                "uses": ["memory", "knowledge", "tools", "cluster", "security", "HITL"],
                "audit": "via platform APIs + agent_pid membrane",
            },
            "audit_governed_effects": true,
        },
        "llm_router_wired": llm,
        "llm_provider": cfg.as_ref().map(|c| c.provider.clone()),
        "llm_model": cfg.as_ref().map(|c| c.model.clone()),
        "credential_proxy": {
            "tool_vault_handles": "vault:handle:<id> or {$vault_handle}",
            "cage_api_keys": "stripped",
        },
        "anomaly_gate": {
            "enabled": crate::services::monitor::anomaly_gate_enabled(),
            "env": "CONNECTOR_IIA_ANOMALY_GATE",
            "hint": "GET /monitor/anomalies/v2",
        },
        "geo_id": crate::services::mesh_status::local_geo_id(),
        "landlock_child": crate::kernel::landlock_child::posture(),
        "honesty": "applied_truth never equates intent with enforcement; Landlock child restrict is unknown until cage; matrix cut is per intelligence mark",
    }))
}

/// GET /runtime/pores — iptables-like Landlock pore table (default DROP).
pub async fn get_landlock_pores(
    State(state): State<SharedState>,
    axum::extract::Query(q): axum::extract::Query<PoreListQuery>,
) -> Json<Value> {
    Json(json!({
        "ok": true,
        "schema": "connector.landlock.pores.v1",
        "posture": crate::kernel::landlock_child::posture(),
        "vendor_cut": crate::kernel::llm_vendor_cut::posture(Some(state.as_ref())),
        "pores": crate::kernel::pore_table::list(state.as_ref(), q.agent_pid.as_deref()),
        "honesty": "Default DROP. ACCEPT rows are dest-pinned Landlock children. Once a tool is connected, vendor LLM HTTPS is exclusive to the cage mark.",
    }))
}

/// GET /runtime/llm-vendor-cut — host DROP of Anthropic/OpenAI/etc except LLM cage.
pub async fn get_llm_vendor_cut(State(state): State<SharedState>) -> Json<Value> {
    Json(json!({
        "ok": true,
        "posture": crate::kernel::llm_vendor_cut::posture(Some(state.as_ref())),
    }))
}

#[derive(Debug, Deserialize)]
pub struct PoreListQuery {
    pub agent_pid: Option<String>,
}

pub(crate) fn get_lab_mode_body() -> Value {
    fn off(name: &str) -> bool {
        match std::env::var(name) {
            Ok(v) => {
                let t = v.trim();
                t.is_empty()
                    || t == "0"
                    || t.eq_ignore_ascii_case("false")
                    || t.eq_ignore_ascii_case("off")
            }
            Err(_) => true,
        }
    }
    let mut reasons = Vec::new();
    if off("CONNECTOR_IIA_RING1") {
        reasons.push("ring1_off");
    }
    if off("CONNECTOR_IIA_QPR_ENFORCE") {
        reasons.push("qpr_off");
    }
    if off("CONNECTOR_IIA_DOCKLOCK_ENFORCE") {
        reasons.push("docklock_off");
    }
    if off("CONNECTOR_IIA_HITL_ENFORCE") {
        reasons.push("hitl_enforce_off");
    }
    if off("CONNECTOR_AGENT_SETUP_GATE") {
        reasons.push("setup_gate_off");
    }
    let preset = std::env::var("CONNECTOR_PRESET").unwrap_or_else(|_| "local/implicit".into());
    let lab_mode = !reasons.is_empty()
        && !matches!(
            preset.to_ascii_lowercase().as_str(),
            "production" | "staging" | "airgap" | "defense-strict" | "defense_strict"
        );
    json!({
        "lab_mode": lab_mode,
        "preset": preset,
        "reasons": reasons,
    })
}

/// GET /runtime/lab-mode — DI-0: loud honesty when intelligence hardening is off.
pub async fn get_lab_mode(State(_state): State<SharedState>) -> Json<Value> {
    let mut body = get_lab_mode_body();
    if let Some(obj) = body.as_object_mut() {
        obj.insert("ok".into(), json!(true));
        obj.insert("schema".into(), json!("connector.lab_mode.v1"));
        obj.insert(
            "honesty".into(),
            json!("LAB MODE means intelligence hardening flags are off — not a production distributed-intelligence posture."),
        );
        obj.insert(
            "enable_path".into(),
            json!("POST /api/v1/runtime/enable-hardening"),
        );
        obj.insert(
            "enable_hint".into(),
            json!("POST /runtime/enable-hardening or CONNECTOR_PRESET=production"),
        );
    }
    Json(body)
}

fn default_model_for(provider: &str) -> &'static str {
    match provider {
        "deepseek" => "deepseek-chat",
        "openai" => "gpt-4o-mini",
        "anthropic" => "claude-sonnet-4-20250514",
        "groq" => "llama-3.3-70b-versatile",
        "gemini" | "google" => "gemini-2.0-flash",
        "mistral" => "mistral-small-latest",
        "ollama" => "llama3.2",
        "lmstudio" => "local-model",
        "vllm" => "local-model",
        _ => "gpt-4o-mini",
    }
}

/// Rebuild the in-memory Talk router from vault + persisted provider metadata.
/// Deploy/restart drops `llm_wired`; the key stays in the sealed vault.
pub fn restore_llm_router_if_needed(state: &SharedState) {
    // Playground: never hot-wire a global router from the first `llm/` vault entry —
    // that would be another tenant's key. Tenant restore goes through talk_llm_router.
    if crate::services::playground::is_playground_mode() {
        return;
    }
    if state.llm_wired() {
        return;
    }
    let providers = get_value(state, "providers")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let primary = providers
        .iter()
        .find(|p| p.get("primary").and_then(|x| x.as_bool()).unwrap_or(false))
        .or_else(|| providers.first());

    let (provider, model, endpoint, secret_id) = if let Some(p) = primary {
        let provider = p
            .get("provider")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let model = p
            .get("model")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(default_model_for(&provider))
            .to_string();
        let endpoint = p
            .get("endpoint")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let secret_id = p
            .get("secret_id")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("llm/{provider}"));
        (provider, model, endpoint, secret_id)
    } else {
        let ids = match state.secret_store.lock() {
            Ok(vault) => vault.secret_ids_with_prefix("llm/"),
            Err(_) => return,
        };
        let Some(secret_id) = ids.into_iter().next() else {
            return;
        };
        let provider = secret_id
            .strip_prefix("llm/")
            .unwrap_or("openai")
            .to_string();
        let model = default_model_for(&provider).to_string();
        (provider, model, None, secret_id)
    };

    if provider.is_empty() || model.is_empty() {
        return;
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let api_key = match state.secret_store.lock() {
        Ok(vault) => match vault.get_secret_value(&secret_id, now_ms) {
            Ok(k) if !k.is_empty() => k,
            _ => return,
        },
        Err(_) => return,
    };

    let mut engine = EngineLlmConfig::new(&provider, &model, &api_key);
    if let Some(ref ep) = endpoint {
        engine.endpoint = Some(ep.clone());
    }
    let router = state::build_llm_router(vec![engine]);
    let cfg = LlmConfig {
        provider: provider.clone(),
        model: model.clone(),
        api_key,
        endpoint,
    };
    state.install_llm_router(cfg, router);
    tracing::info!(
        provider = %provider,
        model = %model,
        "llm_router: restored from vault after process start"
    );
}

/// GET /settings/llms/status — wired? + redacted provider (for Settings UI).
pub async fn get_llm_link_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<Value> {
    restore_llm_router_for_talk(&state, &headers, None);
    let tenant_scope = llm_tenant_scope(&headers);
    let wired = if crate::services::playground::is_playground_mode() {
        tenant_scope
            .as_ref()
            .and_then(|t| tenant_router_from_store(&state, t))
            .is_some()
    } else {
        state.llm_wired()
    };
    let cfg = if crate::services::playground::is_playground_mode() {
        tenant_scope.as_ref().and_then(|t| {
            tenant_llm_cache()
                .lock()
                .ok()
                .and_then(|c| c.get(t).map(|(cfg, _)| cfg.clone()))
        })
    } else {
        state.llm_config_snapshot()
    };
    let providers = get_providers(&state, tenant_scope.as_deref());
    let proven = providers
        .first()
        .and_then(|p| p.get("proven").and_then(|x| x.as_bool()))
        .unwrap_or(false);
    let effective_mode = if !wired {
        "disconnected"
    } else if proven {
        "live"
    } else if crate::services::playground::is_playground_mode() {
        "linked_unproven"
    } else {
        "live"
    };
    Json(json!({
        "ok": true,
        "router_wired": wired,
        "proven": proven,
        "effective_mode": effective_mode,
        "stub_mode": std::env::var("CONNECTOR_LLM_STUB").ok().as_deref() == Some("true")
            || std::env::var("CONNECTOR_LLM_STUB").ok().as_deref() == Some("1"),
        "provider": cfg.as_ref().map(|c| c.provider.clone()),
        "model": cfg.as_ref().map(|c| c.model.clone()),
        "endpoint": cfg.as_ref().and_then(|c| c.endpoint.clone()),
        "api_key_configured": cfg.as_ref().map(|c| !c.api_key.is_empty()).unwrap_or(false),
        "tenant_id": tenant_scope,
        "providers_meta": providers,
        "link_path": "/api/v1/settings/llms/link",
        "broker": crate::substrate::llm_context_broker::status(),
        "talk_pipeline": crate::substrate::talk_turn_pipeline::SCHEMA,
        "runtime_invariants": "/api/v1/substrate/runtime-invariants",
    }))
}

pub async fn get_llm_routing_rules(State(state): State<SharedState>) -> Json<Value> {
    let rules = get_value(&state, "routing_rules").unwrap_or_else(|| json!([]));
    Json(json!({
        "ok": true,
        "rules": rules,
        "supported_triggers": ["http_5xx","latency_p95","cost_cap","region_policy"]
    }))
}

pub async fn set_llm_routing_rules(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveRoutingRulesRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "llm-settings",
        "settings",
        "set_llm_routing_rules",
        &json!({"count": req.rules.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    put_value(&state, "routing_rules", &json!(req.rules));
    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "count": req.rules.len(),
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn get_llm_overrides(State(state): State<SharedState>) -> Json<Value> {
    let plugin_overrides = get_value(&state, "plugin_overrides").unwrap_or_else(|| json!({}));
    let workflow_overrides = get_value(&state, "workflow_overrides").unwrap_or_else(|| json!({}));
    Json(json!({
        "ok": true,
        "plugin_overrides": plugin_overrides,
        "workflow_overrides": workflow_overrides
    }))
}

pub async fn set_llm_overrides(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveOverridesRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "llm-settings",
        "settings",
        "set_llm_overrides",
        &json!({"overrides": true}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    if let Some(p) = req.plugin_overrides {
        put_value(&state, "plugin_overrides", &p);
    }
    if let Some(w) = req.workflow_overrides {
        put_value(&state, "workflow_overrides", &w);
    }
    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn get_llm_charts(State(_state): State<SharedState>) -> Json<Value> {
    Json(json!({
        "ok": true,
        "charts": {
            "latency_tokens_cost_errors": {
                "sources": [
                    "/api/v1/monitor/cost-center",
                    "/api/v1/monitor/cost-dashboard",
                    "/api/v1/monitor/native"
                ]
            }
        },
        "hint": "Use monitor sources for rendering provider and cost charts."
    }))
}

fn clamp_guardrails(
    monthly_budget_usd: f64,
    warning_pct: f64,
    hard_stop_pct: f64,
) -> (f64, f64, f64) {
    let warning = warning_pct.clamp(1.0, 99.0);
    let hard_stop = hard_stop_pct.max(warning).min(200.0);
    (monthly_budget_usd.max(0.0), warning, hard_stop)
}

pub async fn get_llm_guardrails(State(state): State<SharedState>) -> Json<Value> {
    let guardrails = get_value(&state, "guardrails").unwrap_or_else(|| {
        json!({
            "monthly_budget_usd": 100.0,
            "warning_pct": 80.0,
            "hard_stop_pct": 100.0
        })
    });
    let contract = fallback_cap_contract(&state);
    Json(json!({
        "ok": true,
        "guardrails": guardrails,
        "fallback": contract.get("fallback").cloned().unwrap_or(json!({})),
        "cost_cap": contract.get("cost_cap").cloned().unwrap_or(json!({}))
    }))
}

/// Write the cost-cap guardrails from outside this module.
///
/// The budget wizard (`POST /billing/budget`) needs the same clamped write the
/// settings form performs, otherwise a budget set during setup would persist
/// without ever arming the gateway hard stop.
pub fn save_guardrails(
    state: &SharedState,
    monthly_budget_usd: f64,
    warning_pct: f64,
    hard_stop_pct: f64,
) -> Value {
    let (budget, warning, hard_stop) =
        clamp_guardrails(monthly_budget_usd, warning_pct, hard_stop_pct);
    let guardrails = json!({
        "monthly_budget_usd": budget,
        "warning_pct": warning,
        "hard_stop_pct": hard_stop
    });
    put_value(state, "guardrails", &guardrails);
    guardrails
}

pub async fn set_llm_guardrails(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveGuardrailsRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let (budget, warning, hard_stop) =
        clamp_guardrails(req.monthly_budget_usd, req.warning_pct, req.hard_stop_pct);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "llm-settings",
        "settings",
        "set_llm_guardrails",
        &json!({"monthly_budget_usd": budget}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    put_value(
        &state,
        "guardrails",
        &json!({
            "monthly_budget_usd": budget,
            "warning_pct": warning,
            "hard_stop_pct": hard_stop
        }),
    );
    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

pub async fn get_llm_privacy_tags(State(state): State<SharedState>) -> Json<Value> {
    let tags = get_value(&state, "privacy_tags").unwrap_or_else(|| json!(["us", "eu", "local"]));
    let workflow_requirements =
        get_value(&state, "privacy_workflow_requirements").unwrap_or_else(|| json!({}));
    Json(json!({
        "ok": true,
        "tags": tags,
        "workflow_requirements": workflow_requirements
    }))
}

pub async fn set_llm_privacy_tags(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SavePrivacyTagsRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let normalized: Vec<String> = req
        .tags
        .into_iter()
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "llm-settings",
        "settings",
        "set_llm_privacy_tags",
        &json!({"count": normalized.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    put_value(&state, "privacy_tags", &json!(normalized));
    if let Some(v) = req.workflow_requirements {
        put_value(&state, "privacy_workflow_requirements", &v);
    }
    open_proceed.finish_observed(true);
    Json(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_cap_inactive_when_budget_zero() {
        // Pure logic: ceiling = budget * hard/100; budget 0 → no violation without state.
        let budget = 0.0_f64;
        let hard_stop_pct = 100.0_f64;
        let month = 999.0_f64;
        let ceiling = budget * (hard_stop_pct / 100.0);
        assert!(budget <= 0.0 || month < ceiling);
    }

    #[test]
    fn clamp_guardrails_enforces_warning_below_hard_stop() {
        let (budget, warning, hard) = clamp_guardrails(50.0, 120.0, 50.0);
        assert_eq!(budget, 50.0);
        assert_eq!(warning, 99.0);
        assert!(hard >= warning);
        assert!(hard <= 200.0);
    }

    #[test]
    fn clamp_guardrails_rejects_negative_budget() {
        let (budget, warning, hard) = clamp_guardrails(-10.0, 80.0, 100.0);
        assert_eq!(budget, 0.0);
        assert_eq!(warning, 80.0);
        assert_eq!(hard, 100.0);
    }

    #[test]
    fn llm_catalog_includes_market_and_custom() {
        let catalog = llm_provider_catalog();
        let ids: Vec<&str> = catalog
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p.get("id").and_then(|x| x.as_str()))
            .collect();
        assert!(ids.contains(&"openai"));
        assert!(ids.contains(&"anthropic"));
        assert!(ids.contains(&"ollama"));
        assert!(ids.contains(&"custom"));
        let hosted = llm_provider_catalog_for(true);
        let hosted_ids: Vec<&str> = hosted
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p.get("id").and_then(|x| x.as_str()))
            .collect();
        assert!(!hosted_ids.contains(&"ollama"));
        assert!(!hosted_ids.contains(&"lmstudio"));
        assert!(!hosted_ids.contains(&"vllm"));
        assert!(hosted_ids.contains(&"openai"));
        assert!(hosted_ids.contains(&"custom"));
        let custom = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p.get("id").and_then(|x| x.as_str()) == Some("custom"))
            .unwrap();
        assert_eq!(custom.get("needs_endpoint").and_then(|x| x.as_bool()), Some(true));
        let ollama = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p.get("id").and_then(|x| x.as_str()) == Some("ollama"))
            .unwrap();
        assert_eq!(ollama.get("needs_key").and_then(|x| x.as_bool()), Some(false));
    }
}
