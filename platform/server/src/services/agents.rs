//! # Agent Registry — Lifecycle Management
//!
//! Platform teams managing 50+ agents need a proper CRUD registry, not just
//! debug views. This service provides first-class agent management:
//! create, list, get, update (budget/instructions/model), terminate, archive.
//!
//! ## Agent Lifecycle States
//!
//! ```text
//! ┌──────────┐   start   ┌─────────┐   pause   ┌────────┐
//! │Registered├──────────►│ Running ├──────────►│ Paused │
//! └──────────┘           └────┬────┘           └───┬────┘
//!                             │                    │
//!                             │ freeze             │ resume
//!                             ▼                    │
//!                        ┌────────┐               │
//!                        │ Frozen │◄──────────────┘
//!                        └───┬────┘
//!                            │ thaw
//!                            ▼
//!                        ┌─────────┐
//!                        │ Running │
//!                        └─────────┘
//!
//!   Any state ──kill──► Terminated (permanent, agent removed)
//! ```
//!
//! ## Lifecycle Operations — Clear Distinctions
//!
//! | Operation | Effect | Reversible | State Preserved | Use Case |
//! |-----------|--------|------------|-----------------|----------|
//! | **start** | Boot agent from registered → running | N/A | N/A | Initial activation |
//! | **pause** | Stop LLM dispatch, keep state in memory | ✓ resume | ✓ In-memory | Temporary disable, debugging |
//! | **freeze** | Suspend + snapshot context to disk | ✓ thaw | ✓ On-disk | Long-term suspend, migration |
//! | **kill** | Forceful termination, remove agent | ✗ | ✗ | Shutdown, cleanup, emergencies |
//!
//! ## Source of truth (P5.3)
//!
//! Live agent catalog = **VAC kernel ACBs** via this module (`services::agents`).
//! `agent_lifecycle::AgentRegistry` is orphaned (not on `PlatformState`) and must
//! not be merged into list/register responses. Deploy manifests live in
//! `services::registry::AgentRegistry` (separate concern).
//!
//! ## Routes
//!   POST   /agents                    — register a new agent
//!   GET    /agents                    — list all agents with health + cost summary (kernel SoT)
//!   GET    /agents/sot-status         — product SoT + dual-registry honesty
//!   GET    /agents/:pid               — full agent detail
//!   PATCH  /agents/:pid               — update budget / model / instructions
//!   DELETE /agents/:pid               — terminate + archive agent (graceful)
//!   POST   /agents/:pid/start         — boot agent: registered → running
//!   POST   /agents/:pid/pause         — pause: stop LLM dispatch, keep in memory
//!   POST   /agents/:pid/resume        — resume: re-enable after pause
//!   POST   /agents/:pid/freeze        — freeze: snapshot + suspend (for migration/long-term)
//!   POST   /agents/:pid/thaw          — thaw: restore snapshot + resume
//!   POST   /agents/:pid/kill          — kill: forceful termination (emergency/shutdown)
//!   POST   /agents/:pid/reset-budget  — reset token counter for new billing period
//!   GET    /agents/:pid/cost          — cost breakdown for this agent
//!   GET    /agents/:pid/activity      — recent audit log entries for this agent

use crate::auth::{verify_token, PlatformRole};
use crate::services::runtime_control::{self, RuntimeMode};
use crate::services::webhooks;
use crate::state::{PlatformState, SharedState};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    Json,
};
use connector_engine::engine_store::EngineStore;
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt as _;
use uuid::Uuid;
use vac_core::cid::compute_cid;
use vac_core::kernel::{SyscallPayload, SyscallRequest};
use vac_core::types::{
    AgentRole, AgentStatus, CognitivePath, MemPacket, MemoryKernelOp, MemoryType, PacketType,
    Source, SourceKind,
};

// ── Auth helper ───────────────────────────────────────────────────────────────

fn finite_f64(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn persist_instruction_packet(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    instructions: &str,
    actor: &str,
    tags: Vec<String>,
) {
    if instructions.trim().is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "kind": "agent_instructions",
        "instructions": instructions,
        "agent_pid": agent_pid,
        "namespace": namespace,
        "actor": actor,
    });
    let payload_cid = match compute_cid(&payload) {
        Ok(cid) => cid,
        Err(_) => return,
    };
    let mut packet = MemPacket::new(
        PacketType::Input,
        payload,
        payload_cid,
        agent_pid.to_string(),
        "agent-registry".to_string(),
        Source {
            kind: SourceKind::SelfSource,
            principal_id: actor.to_string(),
        },
        chrono::Utc::now().timestamp_millis(),
    )
    .with_namespace(namespace.to_string())
    .with_tags(tags)
    .with_session(format!("agent-config-{}", agent_pid));
    packet.memory_type = MemoryType::Procedural;
    packet.abstraction_level = 2;
    packet.cognitive_path = Some(CognitivePath::memory(agent_pid, &MemoryType::Procedural));
    packet.metadata.insert(
        "virtualization_scope".into(),
        serde_json::Value::String("private_agent_memory".into()),
    );
    packet.metadata.insert(
        "source_service".into(),
        serde_json::Value::String("agents_registry".into()),
    );
    let mut kernel = state.kernel.lock().unwrap();
    let _ = kernel.dispatch(SyscallRequest {
        agent_pid: agent_pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite { packet },
        reason: Some("agent_instruction_persist".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
}

pub(crate) fn agent_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn looks_like_agent_pid(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("agent")
        || t.starts_with("agt_")
        || t.starts_with("pid:")
        || t.starts_with("cnktr:agent:")
}

/// Agent-bound callers (header or Service token) may only access their own pid.
/// Missing header is not ambient access for Service. Developer+ may inspect.
pub(crate) fn require_self_or_operator(
    headers: &axum::http::HeaderMap,
    target_pid: &str,
    isolation_error: &str,
) -> Result<(String, PlatformRole), serde_json::Value> {
    let Some((sub, role)) = caller(headers) else {
        return Err(serde_json::json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    let target = target_pid.trim();
    let hdr = agent_header(headers);
    if let Some(ref a) = hdr {
        if a != target {
            return Err(serde_json::json!({
                "ok": false,
                "error": isolation_error,
                "status": 403,
                "honesty": "Agent A cannot access Agent B. Isolated by default.",
            }));
        }
    }
    if role == PlatformRole::Service {
        let bound = hdr.as_deref().unwrap_or(sub.as_str());
        if bound != target && sub != target {
            return Err(serde_json::json!({
                "ok": false,
                "error": isolation_error,
                "status": 403,
                "honesty": "Service tokens are bound to one intelligence. Omit-header is not ambient ACS.",
            }));
        }
    } else if role.rank() < 3 {
        if let Some(pid) = hdr.clone().or_else(|| {
            if looks_like_agent_pid(&sub) {
                Some(sub.clone())
            } else {
                None
            }
        }) {
            if pid != target {
                return Err(serde_json::json!({
                    "ok": false,
                    "error": isolation_error,
                    "status": 403,
                    "honesty": "Agent A cannot access Agent B. Isolated by default.",
                }));
            }
        }
    }
    Ok((sub, role))
}

pub(crate) fn caller(headers: &axum::http::HeaderMap) -> Option<(String, PlatformRole)> {
    if runtime_control::dev_auth_bypass_allowed() {
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

/// FIX BUG-002 through BUG-006, BUG-015: Consistent PID resolution helper.
/// Resolves a user-supplied identifier to (kernel_pid, api_pid).
///
/// Accepts:
///   - `pid:NNNNNN` (direct kernel PID)
///   - `agent_xxx` / `agent/xxx` (api_pid forms)
///   - `my-agent-name` (logical name — searches agent_meta entries)
///
/// If nothing matches, returns the input unchanged so downstream code can 404.
/// Resolve API/kernel PID pair (shared with intelligence authority gate).
pub(crate) fn resolve_kernel_pid(state: &SharedState, input: &str) -> (String, String) {
    let trimmed = input
        .trim_start_matches("agent/")
        .trim_start_matches("agent_");

    // Fast path: direct kernel PID
    if input.starts_with("pid:") {
        let k = state.kernel.lock().unwrap();
        if k.get_agent(input).is_some() {
            return (input.to_string(), input.to_string());
        }
    }

    let mut es = state.engine_store.lock().unwrap();

    // 1. Try the input as-is in agent_meta
    if let Some(m) = es.folder_get("agent_meta", input).ok().flatten() {
        let kpid = m
            .get("kernel_pid")
            .and_then(|v| v.as_str())
            .unwrap_or(input)
            .to_string();
        return (kpid, input.to_string());
    }

    // 2. Try stripped form (agent_xxx -> xxx)
    if trimmed != input {
        if let Some(m) = es.folder_get("agent_meta", trimmed).ok().flatten() {
            let kpid = m
                .get("kernel_pid")
                .and_then(|v| v.as_str())
                .unwrap_or(trimmed)
                .to_string();
            return (kpid, trimmed.to_string());
        }
    }

    // 3. Search by logical name across all agent_meta entries
    if let Ok(keys) = es.folder_keys("agent_meta", None) {
        for api_pid in keys.iter() {
            if let Some(meta) = es.folder_get("agent_meta", api_pid).ok().flatten() {
                let name = meta.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if name == trimmed || name == input {
                    let kpid = meta
                        .get("kernel_pid")
                        .and_then(|v| v.as_str())
                        .unwrap_or(api_pid)
                        .to_string();
                    return (kpid, api_pid.clone());
                }
            }
        }
    }

    // 4. Fallback: input unchanged (caller will 404)
    (input.to_string(), input.to_string())
}

/// Public wrapper so other services can resolve agent identifiers consistently.
pub fn resolve_kernel_pid_pub(state: &SharedState, input: &str) -> (String, String) {
    resolve_kernel_pid(state, input)
}

/// Map legacy `ns:` and `/m/` forms to canonical `m/...` private memory namespaces.
pub fn normalize_memory_namespace(ns: &str) -> String {
    let t = ns.trim();
    if t.is_empty() {
        return "m/default".to_string();
    }
    if let Some(rest) = t.strip_prefix("ns:") {
        let r = rest.trim().trim_start_matches('/');
        return if r.is_empty() {
            "m/default".to_string()
        } else {
            format!("m/{}", r)
        };
    }
    if let Some(rest) = t.strip_prefix("/m/") {
        let r = rest.trim().trim_start_matches('/');
        return if r.is_empty() {
            "m/default".to_string()
        } else {
            format!("m/{}", r)
        };
    }
    // Legacy Talk alias → canonical private memory
    if let Some(rest) = t.strip_prefix("gateway/") {
        let r = rest.trim().trim_start_matches('/');
        return if r.is_empty() {
            "m/default".to_string()
        } else {
            format!("m/{}", r)
        };
    }
    if t.starts_with("m/") {
        t.to_string()
    } else {
        format!("m/{}", t.trim_start_matches('/'))
    }
}

/// Canonical durable VAC namespace for an agent: `m/{kernel_pid}`.
pub fn canonical_agent_memory_namespace(kernel_pid: &str) -> String {
    normalize_memory_namespace(&format!("m/{}", kernel_pid.trim()))
}

/// Namespaces to read during gateway→m/ migration (canonical first, then legacy).
pub fn memory_namespace_dual_read(kernel_pid: &str, api_pid: &str) -> Vec<String> {
    let mut out = vec![canonical_agent_memory_namespace(kernel_pid)];
    let legacy = format!("gateway/{}", api_pid.trim());
    if !out.iter().any(|n| n == &legacy) {
        out.push(legacy);
    }
    if api_pid != kernel_pid {
        let legacy_k = format!("gateway/{}", kernel_pid.trim());
        if !out.iter().any(|n| n == &legacy_k) {
            out.push(legacy_k);
        }
        let m_api = canonical_agent_memory_namespace(api_pid);
        if !out.iter().any(|n| n == &m_api) {
            out.push(m_api);
        }
    }
    out
}

#[cfg(test)]
mod memory_ns_tests {
    use super::*;

    #[test]
    fn gateway_alias_normalizes_to_m() {
        assert_eq!(normalize_memory_namespace("gateway/agent-1"), "m/agent-1");
        assert_eq!(canonical_agent_memory_namespace("agent-1"), "m/agent-1");
    }

    #[test]
    fn dual_read_lists_canonical_first() {
        let v = memory_namespace_dual_read("k1", "api1");
        assert_eq!(v[0], "m/k1");
        assert!(v.contains(&"gateway/api1".to_string()));
    }
}

/// Effective kernel agent cap: runtime policy for mode/tier, intersected with license `max_agents`
/// in pilots/production. **Dev runtime** is always capped at [`runtime_control::DEV_RUNTIME_FREE_AGENT_MAX`]
/// regardless of license (free internal tier).
pub(crate) fn resolved_kernel_agent_cap(state: &PlatformState) -> u32 {
    let runtime_mode = *state.runtime_mode.read().unwrap();
    let policy = {
        let mut es = state.engine_store.lock().unwrap();
        runtime_control::load_runtime_policy(&**es)
    };
    let tier = format!("{:?}", state.license.tier).to_lowercase();
    let policy_cap = runtime_control::effective_agent_limit(runtime_mode, &tier, &policy);
    // Hosted trial: Indie license is 3 agents for the whole node. Each
    // visitor gets 3 session agents, so the kernel pool must be larger.
    if crate::services::playground::is_playground_mode() {
        return crate::services::playground::kernel_agent_pool_cap();
    }
    match runtime_mode {
        RuntimeMode::Dev => {
            let cap = runtime_control::dev_runtime_agent_cap();
            if std::env::var("CONNECTOR_DEV_AGENT_CAP").is_ok() {
                cap.max(1)
            } else {
                policy_cap.min(cap).max(1)
            }
        }
        _ => match state.license.max_agents {
            Some(n) => policy_cap.min(n as u32).max(1),
            None => policy_cap,
        },
    }
}

/// Push the HTTP-layer agent cap into the Ring-0 kernel so `AgentRegister` cannot bypass limits.
pub fn sync_kernel_agent_registration_cap(state: &PlatformState) {
    let cap = resolved_kernel_agent_cap(state);
    let mut k = state.kernel.lock().unwrap();
    k.set_agent_registration_cap(Some(cap));
}

/// When multi-tenant headers identify a tenant, cap agents by **min**(kernel cap, `TenantContext.agent_limit`) — BF2-B01.
pub(crate) fn resolved_kernel_agent_cap_with_tenant(
    state: &PlatformState,
    tenant: Option<&crate::middleware::TenantContext>,
) -> u32 {
    let base = resolved_kernel_agent_cap(state);
    match tenant {
        Some(t) => base.min(t.agent_limit.max(1)),
        None => base,
    }
}

/// Tenant for agent caps when `CONNECTOR_MULTI_TENANT` is set (same extraction as `tenant_middleware`).
pub(crate) fn tenant_from_headers_for_cap(
    headers: &HeaderMap,
) -> Option<crate::middleware::TenantContext> {
    if crate::services::playground::is_playground_mode()
        || std::env::var("CONNECTOR_MULTI_TENANT").is_ok()
    {
        crate::middleware::tenant::extract_tenant_from_headers(headers)
    } else {
        None
    }
}

/// When `CONNECTOR_MULTI_TENANT` is set, tenant identification is **required** on HTTP entry points that mutate agents.
pub(crate) fn require_multi_tenant_context(
    headers: &HeaderMap,
) -> Result<Option<crate::middleware::TenantContext>, String> {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_ok() {
        crate::middleware::tenant::extract_tenant_from_headers(headers).ok_or_else(|| {
            "Multi-tenant mode requires X-Tenant-ID, JWT tenant_id claim, or tenant-bound API key".to_string()
        })
        .map(Some)
    } else {
        Ok(None)
    }
}

/// Prefix memory namespace with tenant control-plane path when not in default-tenant mode (BF2-R01/B01).
/// Lookup v1-style `agent_*` id from `agent_pid_map` when present (BF2-F01).
pub(crate) fn api_pid_for_kernel_pid<S: EngineStore + ?Sized>(
    es: &mut S,
    kernel_pid: &str,
) -> Option<String> {
    es.folder_get("agent_pid_map", kernel_pid)
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
}

pub(crate) fn tenant_scoped_memory_namespace(
    tenant: Option<&crate::middleware::TenantContext>,
    memory_ns: &str,
) -> String {
    let memory_ns = memory_ns.trim();
    let normalized = if memory_ns.is_empty() {
        "m/default".to_string()
    } else if memory_ns.starts_with("m/") || memory_ns.starts_with("/m/") {
        memory_ns.trim_start_matches('/').to_string()
    } else {
        format!("m/{}", memory_ns.trim_start_matches('/'))
    };
    match tenant {
        Some(t) if t.source != crate::middleware::TenantSource::Default => {
            t.prefix_namespace(&normalized)
        }
        _ => normalized,
    }
}

/// Resolve KECS payload whether producers wrote `agent_kecs` (v1 / pipeline) or `kecs_data` (v2).
pub(crate) fn folder_get_kecs_unified(
    es: &mut Box<dyn EngineStore + Send>,
    kernel_pid: &str,
) -> Option<serde_json::Value> {
    es.folder_get("agent_kecs", kernel_pid)
        .ok()
        .flatten()
        .or_else(|| es.folder_get("kecs_data", kernel_pid).ok().flatten())
}

/// Find an active kernel slot matching a logical agent name (manifest / registration name).
/// Kernel PIDs are opaque (`agent_0`, …); callers must not use `get_agent(manifest_name)`.
pub(crate) fn kernel_pid_for_agent_name(
    kernel: &vac_core::kernel::MemoryKernel,
    logical_name: &str,
) -> Option<String> {
    kernel
        .agents()
        .values()
        .find(|a| {
            a.agent_name == logical_name
                && !matches!(
                    a.status,
                    AgentStatus::Terminated | AgentStatus::Completed | AgentStatus::Failed
                )
        })
        .map(|a| a.agent_pid.clone())
}

/// Ensure `agent_pid_map` + `agent_meta` exist for kernel agents created outside POST /api/v1/agents.
pub(crate) fn ensure_agent_store_mapping(
    state: &SharedState,
    kernel_pid: &str,
    logical_name: &str,
    namespace: &str,
    model: Option<&str>,
    role_label: &str,
    extra: Option<serde_json::Value>,
) -> String {
    let mut es = state.engine_store.lock().unwrap();
    let api_pid = match es.folder_get("agent_pid_map", kernel_pid).ok().flatten() {
        Some(v) => v.as_str().map(|s| s.to_string()).unwrap_or_default(),
        None => String::new(),
    };
    let api_pid = if api_pid.is_empty() {
        let new_api = format!("agent_{}", Uuid::new_v4().to_string().replace('-', ""));
        let _ = es.folder_put("agent_pid_map", kernel_pid, &serde_json::json!(&new_api));
        new_api
    } else {
        api_pid
    };

    let mut meta = es
        .folder_get("agent_meta", &api_pid)
        .ok()
        .flatten()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    meta.insert("pid".into(), serde_json::json!(&api_pid));
    meta.insert("kernel_pid".into(), serde_json::json!(kernel_pid));
    meta.insert("name".into(), serde_json::json!(logical_name));
    meta.insert("namespace".into(), serde_json::json!(namespace));
    if let Some(m) = model {
        meta.insert("model".into(), serde_json::json!(m));
    }
    meta.insert("role".into(), serde_json::json!(role_label));
    if let Some(ex) = extra {
        if let Some(o) = ex.as_object() {
            for (k, v) in o {
                meta.insert(k.clone(), v.clone());
            }
        }
    }
    let _ = es.folder_put("agent_meta", &api_pid, &serde_json::Value::Object(meta));
    api_pid
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct ListAgentsQuery {
    /// Filter agents: over_budget | paused | degraded | healthy | all (default: all)
    #[serde(default)]
    pub filter: Option<String>,
    /// Filter by namespace
    pub namespace: Option<String>,
    /// Filter by status string (Running, Suspended, Terminated)
    pub status: Option<String>,
}

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterAgentRequest {
    pub name: String,
    pub namespace: Option<String>,
    pub role: Option<String>,
    pub model: Option<String>,
    pub instructions: Option<String>,
    pub token_budget: Option<u64>,
    pub tags: Option<Vec<String>>,
    /// If true, agent requires HIPAA compliance — dispatch blocked without accepted BAA
    #[serde(default)]
    pub hipaa: bool,
    /// Kernel or API pid of parent agent (progeny tree).
    #[serde(default)]
    pub parent_pid: Option<String>,
    /// IIA foundation: e.g. `FINANCE_AGENT_ACUME`
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub geo_id: Option<String>,
    #[serde(default)]
    pub master_agent_id: Option<String>,
    #[serde(default)]
    pub knowledge_base_id: Option<String>,
}

/// Reject empty / "general-purpose" charters. An agent without a job is not admitted.
pub(crate) fn charter_purpose(raw: Option<&str>) -> Result<String, &'static str> {
    let p = raw
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("purpose_required")?;
    if is_placeholder_purpose(p) {
        return Err("purpose_required");
    }
    Ok(p.to_string())
}

fn is_placeholder_purpose(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "general" | "general-purpose" | "n/a" | "none" | "todo"
    ) || l.starts_with("general-purpose")
        || l.starts_with("general purpose")
}

fn default_register_capabilities(role: AgentRole) -> Vec<String> {
    match role {
        AgentRole::Admin | AgentRole::Writer | AgentRole::ToolAgent => vec![
            "read".into(),
            "write".into(),
            "llm".into(),
            "chat".into(),
            "tool".into(),
            "memory".into(),
        ],
        _ => vec!["read".into(), "llm".into(), "chat".into(), "memory".into()],
    }
}

/// Repair Talk identity for an already-seeded playground agent (principal + activation).
pub fn ensure_talk_identity(state: &SharedState, api_pid: &str) {
    if crate::kernel::agent_principal::load_principal(state.as_ref(), api_pid).is_some() {
        if crate::services::playground::is_playground_mode() {
            let _ = crate::kernel::agent_identity_envelope::force_activate_playground(state.as_ref(), api_pid);
        } else if !crate::kernel::agent_identity_envelope::setup_gate_enabled() {
            let _ = crate::kernel::agent_identity_envelope::activate_agent(state.as_ref(), api_pid);
        }
        return;
    }
    let meta = match state.engine_store.lock() {
        Ok(es) => es.folder_get("agent_meta", api_pid).ok().flatten(),
        Err(_) => None,
    };
    let Some(meta) = meta else {
        return;
    };
    let name = meta
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("Demo");
    let namespace = meta
        .get("namespace")
        .and_then(|x| x.as_str())
        .unwrap_or("m/demo");
    let tag = meta
        .get("tags")
        .and_then(|t| t.as_array())
        .and_then(|a| a.iter().filter_map(|x| x.as_str()).find(|t| *t != "playground" && *t != "ready"))
        .unwrap_or("demo");
    let _ = crate::kernel::agent_principal::mint_at_register(
        state.as_ref(),
        crate::kernel::agent_principal::MintPrincipalParams {
            api_pid,
            agent_name: name,
            issuer: "cnktr:org:connector-node",
            model_ref: None,
            purpose: vec!["chat".into(), "llm".into()],
            capabilities: default_register_capabilities(AgentRole::Writer),
            namespace,
            master_agent_id: None,
            geo_id: None,
            knowledge_base_id: None,
        },
    );
    let _ = crate::kernel::agent_identity_envelope::bootstrap_agent_identity(
        state.as_ref(),
        api_pid,
        name,
        namespace,
        &format!("playground:{tag}"),
        None,
    );
    if crate::services::playground::is_playground_mode() {
        let _ = crate::kernel::agent_identity_envelope::force_activate_playground(state.as_ref(), api_pid);
    }
}

fn restore_playground_agent_into_kernel(
    state: &SharedState,
    api_pid: &str,
) -> Result<String, String> {
    let meta = {
        let es = state
            .engine_store
            .lock()
            .map_err(|_| "engine lock".to_string())?;
        es.folder_get("agent_meta", api_pid).ok().flatten()
    };
    let Some(meta) = meta else {
        return Err("agent_meta missing".into());
    };
    let status = meta
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if status == "terminated" || meta.get("terminated_at").is_some() {
        return Err("agent terminated".into());
    }
    let old_kernel = meta
        .get("kernel_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !old_kernel.is_empty() {
        let k = state
            .kernel
            .lock()
            .map_err(|_| "kernel lock".to_string())?;
        if k.agents().contains_key(&old_kernel) {
            ensure_talk_identity(state, api_pid);
            return Ok(old_kernel);
        }
    }

    let name = meta
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Demo")
        .to_string();
    let namespace = meta
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("m/demo")
        .to_string();
    let instructions = meta
        .get("instructions")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let created_by = meta
        .get("created_by")
        .and_then(|v| v.as_str())
        .or_else(|| meta.get("user_id").and_then(|v| v.as_str()))
        .unwrap_or("playground")
        .to_string();
    let tenant_id = meta
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::system("playground-rehydrate");
    let kernel_pid = crate::substrate::agent_progeny::register_with_progeny(
        state,
        crate::substrate::agent_progeny::KernelRegisterParams {
            agent_name: &name,
            namespace: &namespace,
            role: Some("writer".into()),
            model: None,
            framework: None,
            parent_kernel_pid: None,
            reason: format!("playground rehydrate {api_pid}"),
        },
        &actor,
    )
    .map_err(|e| e.message().to_string())?;

    {
        let mut es = state
            .engine_store
            .lock()
            .map_err(|_| "engine lock".to_string())?;
        let mut obj = meta.as_object().cloned().unwrap_or_default();
        obj.insert("kernel_pid".into(), serde_json::json!(kernel_pid));
        let _ = es.folder_put("agent_meta", api_pid, &serde_json::Value::Object(obj));
        if !old_kernel.is_empty() && old_kernel != kernel_pid {
            let _ = es.folder_delete("agent_pid_map", &old_kernel);
        }
        let _ = es.folder_put("agent_pid_map", &kernel_pid, &serde_json::json!(api_pid));
    }

    persist_instruction_packet(
        state,
        &kernel_pid,
        &namespace,
        &instructions,
        &created_by,
        vec!["agent_instruction".into(), "playground".into(), name],
    );
    ensure_talk_identity(state, api_pid);
    tracing::info!(
        api_pid,
        kernel_pid,
        tenant_id,
        "playground: rehydrated agent into kernel"
    );
    Ok(kernel_pid)
}

fn agent_meta_pids_for_tenant(state: &SharedState, tenant_id: &str) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(keys) = es.folder_keys("agent_meta", None) else {
        return Vec::new();
    };
    keys.into_iter()
        .filter(|k| {
            es.folder_get("agent_meta", k)
                .ok()
                .flatten()
                .and_then(|m| {
                    let tenant_ok = m
                        .get("tenant_id")
                        .and_then(|v| v.as_str())
                        .map(|t| t == tenant_id)
                        .unwrap_or(false);
                    let dead = m
                        .get("status")
                        .and_then(|v| v.as_str())
                        .map(|s| s.eq_ignore_ascii_case("terminated"))
                        .unwrap_or(false)
                        || m.get("terminated_at").is_some();
                    Some(tenant_ok && !dead)
                })
                .unwrap_or(false)
        })
        .collect()
}

fn ensure_session_agents_live(
    state: &SharedState,
    session_id: &str,
    tenant_id: &str,
    remembered: &[String],
) {
    let mut pids = remembered.to_vec();
    for pid in agent_meta_pids_for_tenant(state, tenant_id) {
        if !pids.iter().any(|p| p == &pid) {
            pids.push(pid);
        }
    }

    let mut live: Vec<String> = Vec::new();
    for pid in &pids {
        if restore_playground_agent_into_kernel(state, pid).is_ok() {
            live.push(pid.clone());
        }
    }

    if live.is_empty()
        && !crate::services::playground::session_cleared_by_user(
            &state.playground_sessions,
            session_id,
        )
    {
        let seed_demo = std::env::var("CONNECTOR_PLAYGROUND_SEED_DEMO")
            .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
            .unwrap_or(true);
        if seed_demo {
            let agents = provision_playground_demo(state, tenant_id, session_id);
            live = agents
                .iter()
                .filter_map(|a| a.get("pid").and_then(|x| x.as_str()).map(str::to_string))
                .collect();
        }
    }

    if !live.is_empty() {
        crate::services::playground::sync_session_agent_pids(
            &state.playground_sessions,
            session_id,
            &live,
        );
    }
}

/// After deploy/restart the kernel is empty; sessions + agent_meta persist.
/// Re-bind each live playground session's demo into the kernel so Run/Talk work.
pub fn rehydrate_playground_runtime(state: &SharedState) {
    if !crate::services::playground::is_playground_mode() {
        return;
    }
    crate::services::settings_llms::restore_llm_router_if_needed(state);
    let targets =
        crate::services::playground::live_session_agent_targets(&state.playground_sessions);
    for (session_id, tenant_id, pids) in targets {
        ensure_session_agents_live(state, &session_id, &tenant_id, &pids);
    }
}

/// Rehydrate the caller's playground session (list/Talk after a deploy).
pub fn ensure_playground_session_agents(state: &SharedState, headers: &axum::http::HeaderMap) {
    if !crate::services::playground::is_playground_mode() {
        return;
    }
    crate::services::settings_llms::restore_llm_router_if_needed(state);
    let Some(session_id) =
        crate::services::playground::playground_session_id_from_headers(headers)
    else {
        return;
    };
    let (tenant_id, pids) = {
        let Ok(sessions) = state.playground_sessions.lock() else {
            return;
        };
        match sessions.get(&session_id) {
            Some(s) => (s.tenant_id.clone(), s.agent_pids.clone()),
            None => return,
        }
    };
    ensure_session_agents_live(state, &session_id, &tenant_id, &pids);
}

/// Re-bind one playground agent after a deploy (Talk path).
pub fn ensure_playground_agent_live(state: &SharedState, api_pid: &str) {
    if !crate::services::playground::is_playground_mode() || api_pid.trim().is_empty() {
        return;
    }
    crate::services::settings_llms::restore_llm_router_if_needed(state);
    if let Err(e) = restore_playground_agent_into_kernel(state, api_pid) {
        tracing::warn!(api_pid, error = %e, "playground: could not rehydrate agent for Talk");
    }
    ensure_playground_talk_lane(state, api_pid);
    ensure_playground_tool_lane(state, api_pid);
}

/// Mint demo tool addresses + world grants so CNP/CLS/MCP can run on playground.
pub fn ensure_playground_tool_lane(state: &SharedState, api_pid: &str) {
    if !crate::services::playground::is_playground_mode() || api_pid.trim().is_empty() {
        return;
    }
    crate::services::playground_demo::install_mcp_tools();
    let demo_tools = crate::services::playground_demo::all_demo_tool_names();
    for &address in demo_tools {
        if crate::kernel::address_contracts::load_rules(state.as_ref(), address).is_none() {
            let rules = crate::kernel::address_contracts::AddressRulesContractV1 {
                schema: crate::kernel::address_contracts::RULES_SCHEMA.into(),
                address: address.into(),
                default_effect: "allow".into(),
                tools: vec![],
                allowed_tools: vec!["*".into()],
                denied_tools: vec![],
                contract_version: 1,
            };
            let _ = crate::kernel::address_contracts::save_rules(state.as_ref(), &rules);
        }
        if crate::kernel::address_contracts::load_hitl(state.as_ref(), address).is_none()
            || crate::services::playground::is_playground_mode()
        {
            let hitl = crate::kernel::address_contracts::AddressHitlContractV1 {
                schema: crate::kernel::address_contracts::HITL_SCHEMA.into(),
                address: address.into(),
                default_policy: "none".into(),
                tools: vec![],
                contract_version: 1,
            };
            let _ = crate::kernel::address_contracts::save_hitl(state.as_ref(), &hitl);
        }
        let grant = crate::kernel::world_gateway::WorldGrantV1 {
            agent_pid: api_pid.to_string(),
            address: address.to_string(),
            address_type: "tool".into(),
            access: vec!["*".into()],
            effect: "allow".into(),
            layer: "app".into(),
            app_allow: vec!["*".into()],
            cone_ask: vec![],
            justification: Some(
                "playground demo tool lane — trial-only Cone/App grant for hosted try.cnktros.com"
                    .into(),
            ),
            params: serde_json::json!({}),
            note: Some("ensure_playground_tool_lane".into()),
        };
        let _ = crate::kernel::world_gateway::put_grant(state.as_ref(), &grant);
    }
    // Mint a soft-broker generation so tool effects can assert_live_for_agent without prior Talk.
    if crate::substrate::llm_context_broker::broker_enforced() {
        if let Ok(ctx) = crate::substrate::agentic_context::require_or_hitl(state, api_pid) {
            let _ = crate::substrate::llm_context_broker::inject_for_talk(state, api_pid, &ctx);
        }
    }
}

/// Mint Talk lane prerequisites for hosted playground (address DAC + identity).
pub fn ensure_playground_talk_lane(state: &SharedState, api_pid: &str) {
    if !crate::services::playground::is_playground_mode() || api_pid.trim().is_empty() {
        return;
    }
    ensure_talk_identity(state, api_pid);
    let namespace = format!("gateway/{api_pid}");
    let address = format!("llm:{namespace}");
    if crate::kernel::address_contracts::load_rules(state.as_ref(), &address).is_none() {
        let rules = crate::kernel::address_contracts::AddressRulesContractV1 {
            schema: crate::kernel::address_contracts::RULES_SCHEMA.into(),
            address: address.clone(),
            default_effect: "allow".into(),
            tools: vec![],
            allowed_tools: vec!["llm.chat".into()],
            denied_tools: vec![],
            contract_version: 1,
        };
        let _ = crate::kernel::address_contracts::save_rules(state.as_ref(), &rules);
    }
    if crate::kernel::address_contracts::load_hitl(state.as_ref(), &address).is_none() {
        let hitl = crate::kernel::address_contracts::AddressHitlContractV1 {
            schema: crate::kernel::address_contracts::HITL_SCHEMA.into(),
            address: address.clone(),
            default_policy: "none".into(),
            tools: vec![],
            contract_version: 1,
        };
        let _ = crate::kernel::address_contracts::save_hitl(state.as_ref(), &hitl);
    }
    // Address identity graph — key must match identity_stack::graph_key (preserve : /).
    {
        let graph_key = crate::substrate::identity_stack::graph_key(&address);
        let legacy_key = crate::substrate::identity_stack::graph_key_legacy_underscores(&address);
        if let Ok(mut es) = state.engine_store.lock() {
            let existing = es
                .folder_get(
                    crate::substrate::identity_stack::ADDRESS_GRAPH_FOLDER,
                    &graph_key,
                )
                .ok()
                .flatten();
            if existing.is_none() {
                let doc = serde_json::json!({
                    "nodes": [
                        {"node_id": address, "kind": "llm_address"},
                        {"node_id": api_pid, "kind": "agent"}
                    ],
                    "edges": [
                        {"from_node_id": api_pid, "to_node_id": address, "rel": "talks_as"}
                    ]
                });
                let _ = es.folder_put(
                    crate::substrate::identity_stack::ADDRESS_GRAPH_FOLDER,
                    &graph_key,
                    &doc,
                );
                // Keep legacy underscore key readable by older inspect paths.
                let _ = es.folder_put(
                    crate::substrate::identity_stack::ADDRESS_GRAPH_FOLDER,
                    &legacy_key,
                    &doc,
                );
            }
            // Minimal IntelligenceSpec for output-contract / character.
            if es
                .folder_get(crate::kernel::intelligence_spec::SPEC_FOLDER, api_pid)
                .ok()
                .flatten()
                .is_none()
            {
                let purpose = es
                    .folder_get("agent_meta", api_pid)
                    .ok()
                    .flatten()
                    .and_then(|m| {
                        m.get("purpose")
                            .or_else(|| m.get("instructions"))
                            .and_then(|x| x.as_str())
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| "Playground demo Talk agent".into());
                let name = es
                    .folder_get("agent_meta", api_pid)
                    .ok()
                    .flatten()
                    .and_then(|m| m.get("name").and_then(|x| x.as_str()).map(str::to_string))
                    .unwrap_or_else(|| "Demo".into());
                let _ = es.folder_put(
                    crate::kernel::intelligence_spec::SPEC_FOLDER,
                    api_pid,
                    &serde_json::json!({
                        "apiVersion": "connector.ai/v1",
                        "kind": "Intelligence",
                        "metadata": { "name": name, "agent_pid": api_pid },
                        "spec": {
                            "class": "app",
                            "purpose": purpose,
                            "harden": false
                        }
                    }),
                );
            }
        }
    }
    seed_playground_last_memory(state, api_pid, &namespace);
    ensure_playground_admit_lane(state, api_pid);
}

/// Mint Admit lane pillars (`tool:workbench.admit`) so Workbench Admit matches Talk readiness.
pub fn ensure_playground_admit_lane(state: &SharedState, api_pid: &str) {
    if !crate::services::playground::is_playground_mode() || api_pid.trim().is_empty() {
        return;
    }
    let address = "tool:workbench.admit".to_string();
    if crate::kernel::address_contracts::load_rules(state.as_ref(), &address).is_none() {
        let rules = crate::kernel::address_contracts::AddressRulesContractV1 {
            schema: crate::kernel::address_contracts::RULES_SCHEMA.into(),
            address: address.clone(),
            default_effect: "allow".into(),
            tools: vec![],
            allowed_tools: vec![
                "workbench.admit".into(),
                "tool.dispatch".into(),
            ],
            denied_tools: vec![],
            contract_version: 1,
        };
        let _ = crate::kernel::address_contracts::save_rules(state.as_ref(), &rules);
    }
    if crate::kernel::address_contracts::load_hitl(state.as_ref(), &address).is_none()
        || crate::services::playground::is_playground_mode()
    {
        let hitl = crate::kernel::address_contracts::AddressHitlContractV1 {
            schema: crate::kernel::address_contracts::HITL_SCHEMA.into(),
            address: address.clone(),
            default_policy: "none".into(),
            tools: vec![],
            contract_version: 1,
        };
        let _ = crate::kernel::address_contracts::save_hitl(state.as_ref(), &hitl);
    }
    if let Ok(mut es) = state.engine_store.lock() {
        let graph_key = crate::substrate::identity_stack::graph_key(&address);
        let legacy_key = crate::substrate::identity_stack::graph_key_legacy_underscores(&address);
        let existing = es
            .folder_get(
                crate::substrate::identity_stack::ADDRESS_GRAPH_FOLDER,
                &graph_key,
            )
            .ok()
            .flatten();
        if existing.is_none() {
            let doc = serde_json::json!({
                "nodes": [
                    {"node_id": address, "kind": "tool_address"},
                    {"node_id": api_pid, "kind": "agent"}
                ],
                "edges": [
                    {"from_node_id": api_pid, "to_node_id": address, "rel": "may_admit"}
                ]
            });
            let _ = es.folder_put(
                crate::substrate::identity_stack::ADDRESS_GRAPH_FOLDER,
                &graph_key,
                &doc,
            );
            let _ = es.folder_put(
                crate::substrate::identity_stack::ADDRESS_GRAPH_FOLDER,
                &legacy_key,
                &doc,
            );
        }
    }
}

/// Bootstrap one memory packet so identity-stack `last_memory` is satisfied for Talk.
fn seed_playground_last_memory(state: &SharedState, api_pid: &str, talk_ns: &str) {
    let snap = crate::substrate::identity_stack::inspect(
        state,
        api_pid,
        talk_ns,
        &crate::services::admission::AdmissionOp::LlmChat,
    );
    if snap.has_last_memory {
        return;
    }
    let (kernel_pid, _) = resolve_kernel_pid(state, api_pid);
    let agent_ns = {
        let k = match state.kernel.lock() {
            Ok(k) => k,
            Err(_) => return,
        };
        k.get_agent(&kernel_pid)
            .or_else(|| k.get_agent(api_pid))
            .map(|a| a.namespace.clone())
            .unwrap_or_else(|| format!("m/{api_pid}"))
    };
    let payload = serde_json::json!({
        "kind": "playground_talk_bootstrap",
        "text": "Playground Talk identity bootstrap — last_memory pillar.",
        "agent_pid": api_pid,
        "tags": ["playground", "identity_stack", "last_memory"],
    });
    let payload_cid = match compute_cid(&payload) {
        Ok(cid) => cid,
        Err(_) => return,
    };
    let mut packet = MemPacket::new(
        PacketType::Input,
        payload,
        payload_cid,
        api_pid.to_string(),
        "playground-talk-lane".to_string(),
        Source {
            kind: SourceKind::SelfSource,
            principal_id: api_pid.to_string(),
        },
        chrono::Utc::now().timestamp_millis(),
    )
    .with_namespace(agent_ns)
    .with_tags(vec![
        "playground".into(),
        "identity_stack".into(),
        "last_memory".into(),
    ])
    .with_session(format!("playground-talk-{api_pid}"));
    packet.memory_type = MemoryType::Episodic;
    packet.abstraction_level = 1;
    packet.cognitive_path = Some(CognitivePath::memory(api_pid, &MemoryType::Episodic));
    packet.metadata.insert(
        "source_service".into(),
        serde_json::Value::String("ensure_playground_talk_lane".into()),
    );
    let mut kernel = match state.kernel.lock() {
        Ok(k) => k,
        Err(_) => return,
    };
    let _ = kernel.dispatch(SyscallRequest {
        agent_pid: kernel_pid,
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite { packet },
        reason: Some("playground_last_memory_bootstrap".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
}

/// Drop kernel registrations whose agent_meta was purged (playground session churn).
pub fn compact_orphan_kernel_agents(state: &SharedState) {
    if !crate::services::playground::is_playground_mode() {
        return;
    }
    let kernel_pids: Vec<String> = {
        let k = state.kernel.lock().unwrap();
        k.all_agents()
            .into_iter()
            .map(|a| a.agent_pid.clone())
            .collect()
    };
    let mut removed = 0_u32;
    for kpid in kernel_pids {
        let still_live = {
            let es = state.engine_store.lock().unwrap();
            let api = es
                .folder_get("agent_pid_map", &kpid)
                .ok()
                .flatten()
                .and_then(|v| v.as_str().map(str::to_string));
            if let Some(api) = api {
                es.folder_get("agent_meta", &api).ok().flatten().is_some()
            } else {
                es.folder_get("agent_meta", &kpid).ok().flatten().is_some()
            }
        };
        if !still_live {
            let mut k = state.kernel.lock().unwrap();
            if k.remove_agent(&kpid).is_some() {
                removed = removed.saturating_add(1);
            }
        }
    }
    if removed > 0 {
        tracing::info!(
            removed,
            cap = crate::services::playground::kernel_agent_pool_cap(),
            "playground: compacted orphan kernel agent registrations"
        );
    }
}

/// Remove playground agents (kernel + meta) not tied to a live session.
pub fn compact_stale_playground_agents(state: &SharedState) -> u32 {
    if !crate::services::playground::is_playground_mode() {
        return 0;
    }
    let protected =
        crate::services::playground::protected_playground_agent_pids(&state.playground_sessions);
    let mut stale_api: Vec<String> = Vec::new();
    {
        let es = state.engine_store.lock().unwrap();
        let Ok(keys) = es.folder_keys("agent_meta", None) else {
            return 0;
        };
        for api_pid in keys {
            if protected.contains(&api_pid) {
                continue;
            }
            let Some(meta) = es.folder_get("agent_meta", &api_pid).ok().flatten() else {
                continue;
            };
            let playground = meta
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|tags| tags.iter().any(|t| t.as_str() == Some("playground")))
                .unwrap_or(false);
            let pg_tenant = meta
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .map(|t| t.starts_with("pg-"))
                .unwrap_or(false);
            if playground || pg_tenant {
                stale_api.push(api_pid);
            }
        }
    }
    let mut removed = 0_u32;
    for api_pid in stale_api {
        crate::services::playground::purge_playground_agent(state, &api_pid);
        removed = removed.saturating_add(1);
    }
    let kernel_pids: Vec<String> = {
        let k = state.kernel.lock().unwrap();
        k.all_agents()
            .into_iter()
            .map(|a| a.agent_pid.clone())
            .collect()
    };
    for kpid in kernel_pids {
        let api_pid = {
            let es = state.engine_store.lock().unwrap();
            es.folder_get("agent_pid_map", &kpid)
                .ok()
                .flatten()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| kpid.clone())
        };
        if protected.contains(&api_pid) {
            continue;
        }
        let mut k = state.kernel.lock().unwrap();
        if k.remove_agent(&kpid).is_some() {
            removed = removed.saturating_add(1);
        }
    }
    if removed > 0 {
        tracing::info!(
            removed,
            protected = protected.len(),
            cap = crate::services::playground::kernel_agent_pool_cap(),
            "playground: compacted stale kernel agents outside live sessions"
        );
    }
    removed
}

/// Mint one demo Talk agent for a playground session (tenant-isolated).
pub fn provision_playground_demo(
    state: &SharedState,
    tenant_id: &str,
    created_by: &str,
) -> Vec<serde_json::Value> {
    match register_playground_agent(
        state,
        tenant_id,
        created_by,
        "BankOps",
        "demo",
        "You are BankOps, a governed fraud/ops intelligence on this Connector playground tenant. You handle a commercial checking book: score wires, place holds, and APPROVE/DECLINE/REVIEW — but only through Connector Admit (bank_score_tx, bank_hold_funds, bank_decide, bank_ledger). Never claim you wired Fed funds or filed SAR. If SpendCease/Cease fires, you cannot continue that generation — admit is dead. Institutions (DevGuard, TraceTramp, WitnessCtl) sit on the OS — they are not you. Also support Isolate (ungranted DROP), Prove (receipts). Do not claim Firecracker-by-default or other visitors' sessions.",
    ) {
        Ok(v) => vec![v],
        Err(e) => {
            tracing::warn!(tenant_id, error = %e, "playground: failed to provision demo agent");
            Vec::new()
        }
    }
}

/// Mint the three ready trial agents for a playground session.
/// DevGuard / TraceTramp / WitnessCtl — real kernel Is, tenant-scoped.
/// Opt-in via CONNECTOR_PLAYGROUND_SEED_TRIO=1 (lab); production playground uses demo.
pub fn provision_playground_trio(
    state: &SharedState,
    tenant_id: &str,
    created_by: &str,
) -> Vec<serde_json::Value> {
    const TRIO: [(&str, &str, &str); 3] = [
        (
            "DevGuard",
            "devguard",
            "Guard coding-agent actions. Refuse file, command, secret, and git effects that leave the lane.",
        ),
        (
            "TraceTramp",
            "tracetramp",
            "Record who did what. Build the execution graph for every admitted call.",
        ),
        (
            "WitnessCtl",
            "witnessctl",
            "Seal a hash-chained receipt for every admitted action. Evidence a reviewer can inspect.",
        ),
    ];
    let mut out = Vec::with_capacity(3);
    for (name, tag, instructions) in TRIO {
        match register_playground_agent(state, tenant_id, created_by, name, tag, instructions) {
            Ok(v) => out.push(v),
            Err(e) => {
                tracing::warn!(tenant_id, name, error = %e, "playground: failed to provision trial agent");
            }
        }
    }
    out
}

fn register_playground_agent(
    state: &SharedState,
    tenant_id: &str,
    created_by: &str,
    name: &str,
    tag: &str,
    instructions: &str,
) -> Result<serde_json::Value, String> {
    let tenant_ctx = crate::middleware::TenantContext::from_id(
        tenant_id,
        crate::middleware::TenantSource::Header,
    );
    let namespace = tenant_ctx.prefix_namespace(&format!("m/{tag}"));
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::system("playground");
    let kernel_pid = crate::substrate::agent_progeny::register_with_progeny(
        state,
        crate::substrate::agent_progeny::KernelRegisterParams {
            agent_name: name,
            namespace: &namespace,
            role: Some("writer".into()),
            model: None,
            framework: None,
            parent_kernel_pid: None,
            reason: format!("playground trio for {tenant_id}"),
        },
        &actor,
    )
    .map_err(|e| e.message().to_string())?;
    let api_pid = format!("agent_{}", uuid::Uuid::new_v4().as_simple());
    {
        let mut es = state
            .engine_store
            .lock()
            .map_err(|_| "engine lock".to_string())?;
        let _ = es.folder_put(
            "agent_meta",
            &api_pid,
            &serde_json::json!({
                "pid": api_pid,
                "kernel_pid": kernel_pid,
                "name": name,
                "namespace": namespace,
                "role": "writer",
                "purpose": instructions,
                "instructions": instructions,
                "token_budget": 16_000,
                "tags": ["playground", "ready", tag],
                "user_id": created_by,
                "created_by": created_by,
                "created_at": chrono::Utc::now().to_rfc3339(),
                "paused": false,
                "tenant_id": tenant_id,
            }),
        );
        let _ = es.folder_put("agent_pid_map", &kernel_pid, &serde_json::json!(api_pid));
    }
    persist_instruction_packet(
        state,
        &kernel_pid,
        &namespace,
        instructions,
        created_by,
        vec!["agent_instruction".into(), "playground".into(), name.into()],
    );
    let _ = crate::kernel::agent_principal::mint_at_register(
        state.as_ref(),
        crate::kernel::agent_principal::MintPrincipalParams {
            api_pid: &api_pid,
            agent_name: name,
            issuer: "cnktr:org:connector-node",
            model_ref: None,
            purpose: vec!["chat".into(), "llm".into()],
            capabilities: default_register_capabilities(AgentRole::Writer),
            namespace: &namespace,
            master_agent_id: None,
            geo_id: None,
            knowledge_base_id: None,
        },
    );
    let _ = crate::kernel::agent_identity_envelope::bootstrap_agent_identity(
        state.as_ref(),
        &api_pid,
        name,
        &namespace,
        &format!("playground:{tag}"),
        None,
    );
    if crate::services::playground::is_playground_mode() {
        let _ = crate::kernel::agent_identity_envelope::force_activate_playground(state.as_ref(), &api_pid);
    }
    Ok(serde_json::json!({
        "pid": api_pid,
        "name": name,
        "workflow": tag,
        "instructions": instructions,
        "namespace": namespace,
        "ready": true,
    }))
}

#[derive(Deserialize)]
pub struct UpdateAgentRequest {
    pub model: Option<String>,
    pub instructions: Option<String>,
    pub token_budget: Option<u64>,
    pub tags: Option<Vec<String>>,
}

// ── Agent slot limit (kernel) — shared by HTTP register, pipelines, protocols ─

pub(crate) fn kernel_agent_in_scope(
    namespace: &str,
    tenant: Option<&crate::middleware::TenantContext>,
) -> bool {
    match tenant {
        Some(t) if t.source != crate::middleware::TenantSource::Default => {
            t.is_namespace_allowed(namespace)
                && !crate::middleware::tenant::references_other_tenant_namespace(namespace, t)
        }
        _ => true,
    }
}

/// Multi-tenant guard for memory read paths (recall/search/packet).
pub(crate) fn assert_namespace_readable(
    headers: &axum::http::HeaderMap,
    namespace: &str,
) -> Result<(), axum::Json<serde_json::Value>> {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_err() {
        return Ok(());
    }
    let tenant = tenant_from_headers_for_cap(headers);
    if kernel_agent_in_scope(namespace, tenant.as_ref()) {
        Ok(())
    } else {
        Err(axum::Json(serde_json::json!({
            "ok": false,
            "error": "tenant_namespace_forbidden",
            "message": "Namespace not readable for verified tenant context",
            "namespace": namespace,
        })))
    }
}

fn count_kernel_agents_in_scope(
    k: &vac_core::kernel::MemoryKernel,
    tenant: Option<&crate::middleware::TenantContext>,
) -> u32 {
    k.agents()
        .values()
        .filter(|acb| {
            !matches!(
                acb.status,
                AgentStatus::Terminated | AgentStatus::Completed | AgentStatus::Failed
            ) && kernel_agent_in_scope(&acb.namespace, tenant)
        })
        .count() as u32
}

/// Remove terminal agents; in **Dev** optionally remove oldest `Suspended` until under `limit`
/// when `CONNECTOR_DEV_EJECT_SUSPENDED=1` or `true`.
/// Returns kernel PIDs that were evicted (for diagnostics only).
fn recycle_kernel_agents_for_new_registration(
    k: &mut vac_core::kernel::MemoryKernel,
    limit: u32,
    runtime_mode: RuntimeMode,
    tenant: Option<&crate::middleware::TenantContext>,
) -> Vec<String> {
    let mut evicted = Vec::new();

    let dead: Vec<String> = k
        .agents()
        .iter()
        .filter(|(_, acb)| {
            kernel_agent_in_scope(&acb.namespace, tenant)
                && matches!(
                    acb.status,
                    AgentStatus::Terminated | AgentStatus::Completed | AgentStatus::Failed
                )
        })
        .map(|(p, _)| p.clone())
        .collect();
    for p in dead {
        k.remove_agent(&p);
    }

    if count_kernel_agents_in_scope(k, tenant) < limit {
        return evicted;
    }

    let dev_eject_suspended = std::env::var("CONNECTOR_DEV_EJECT_SUSPENDED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if matches!(runtime_mode, RuntimeMode::Dev) && dev_eject_suspended {
        let mut suspended: Vec<(String, i64)> = k
            .agents()
            .iter()
            .filter(|(_, a)| {
                kernel_agent_in_scope(&a.namespace, tenant)
                    && matches!(a.status, AgentStatus::Suspended)
            })
            .map(|(pid, a)| (pid.clone(), a.last_active_at))
            .collect();
        suspended.sort_by_key(|(_, ts)| *ts);
        for (pid, _) in suspended {
            if count_kernel_agents_in_scope(k, tenant) < limit {
                break;
            }
            evicted.push(pid.clone());
            k.remove_agent(&pid);
        }
    }

    evicted
}

/// Enforce runtime agent **kernel** count before `AgentRegister` from non-HTTP paths.
pub(crate) fn kernel_agent_limit_gate(
    state: &PlatformState,
    tenant: Option<&crate::middleware::TenantContext>,
) -> Result<(), serde_json::Value> {
    let runtime_mode = *state.runtime_mode.read().unwrap();
    let tier = format!("{:?}", state.license.tier).to_lowercase();
    let limit = resolved_kernel_agent_cap_with_tenant(state, tenant);

    let mut k = state.kernel.lock().unwrap();
    if count_kernel_agents_in_scope(&k, tenant) < limit {
        return Ok(());
    }

    recycle_kernel_agents_for_new_registration(&mut k, limit, runtime_mode, tenant);
    let new_count = count_kernel_agents_in_scope(&k, tenant);
    let tier_label = match runtime_mode {
        RuntimeMode::Dev => "dev",
        RuntimeMode::Pilots => "pilots",
        RuntimeMode::Production => tier.as_str(),
    };
    let suspended_left: Vec<String> = k
        .agents()
        .iter()
        .filter(|(_, a)| {
            kernel_agent_in_scope(&a.namespace, tenant)
                && matches!(a.status, AgentStatus::Suspended)
        })
        .map(|(p, _)| p.clone())
        .take(5)
        .collect();
    drop(k);

    if new_count >= limit {
        Err(crate::services::billing::agent_limit_body(
            tier_label,
            new_count,
            limit,
            &suspended_left,
        ))
    } else {
        Ok(())
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /agents — register a new agent
/// Required role: developer+
pub async fn register_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterAgentRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 3 {
        return Json(
            serde_json::json!({"error": "Developer role or higher required", "status": 403}),
        );
    }

    let purpose = match charter_purpose(req.purpose.as_deref()) {
        Ok(p) => p,
        Err(_) => {
            return Json(serde_json::json!({
                "error": "purpose_required",
                "message": "Name the job this agent is for. Empty or general-purpose is not a charter.",
                "status": 400,
            }));
        }
    };

    let playground_sid = crate::services::playground::playground_session_id_from_headers(&headers);
    if let Some(sid) = playground_sid.as_deref() {
        if let Err(j) =
            crate::services::playground::check_agent_cap(&state.playground_sessions, sid)
        {
            return Json(j);
        }
    }

    // Use proper namespace type prefix: /m/ for private agent memory
    // This integrates with the NamespaceType system in namespace_types.rs:
    //   /m/ = Memory (private agent data, SecurityLevel::Standard)
    //   /k/ = Knowledge (shared knowledge bases, SecurityLevel::Protected)
    //   /a/ = Agent (control plane, SecurityLevel::Control)
    //   /t/ = Tool (tool I/O, SecurityLevel::ToolIO)
    // Legacy "ns:" prefix doesn't map to any NamespaceType and bypasses MAC guards.
    let tenant_cap = tenant_from_headers_for_cap(&headers);
    let namespace_raw = req
        .namespace
        .clone()
        .unwrap_or_else(|| format!("m/{}", req.name));
    let namespace = tenant_scoped_memory_namespace(tenant_cap.as_ref(), &namespace_raw);
    {
        let es = state.engine_store.lock().unwrap();
        if let Ok(keys) = es.folder_keys("agent_meta", None) {
            for k in keys {
                if let Ok(Some(m)) = es.folder_get("agent_meta", &k) {
                    let ns = m.get("namespace").and_then(|x| x.as_str()).unwrap_or("");
                    if !ns.is_empty() && ns == namespace {
                        return Json(serde_json::json!({
                            "ok": false,
                            "error": "namespace_in_use",
                            "namespace": namespace,
                            "status": 409,
                            "honesty": "VAC RAG is namespace-keyed. Two agents cannot share a memory namespace.",
                        }));
                    }
                }
            }
        }
    }

    if let Err(j) = kernel_agent_limit_gate(state.as_ref(), tenant_cap.as_ref()) {
        return Json(j);
    }

    let api_pid = format!(
        "agent_{}",
        uuid::Uuid::new_v4().to_string().replace('-', "")
    );
    let admitted = match crate::substrate::pate::admit_register(
        &state,
        &api_pid,
        &serde_json::json!({
            "name": req.name,
            "namespace": namespace,
            "purpose": purpose,
        }),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let role_label = req.role.as_deref().unwrap_or("reader");
    let agent_role = match role_label {
        "admin" => AgentRole::Admin,
        "writer" => AgentRole::Writer,
        "reader" => AgentRole::Reader,
        "auditor" => AgentRole::Auditor,
        "tool" => AgentRole::ToolAgent,
        _ => AgentRole::Reader,
    };

    // Register via kernel syscall — creates ACB + progeny link when parent_pid set
    let parent_kernel = req
        .parent_pid
        .as_deref()
        .map(|p| resolve_kernel_pid(&state, p).0);

    let kernel_pid = match crate::substrate::agent_progeny::register_with_progeny(
        &state,
        crate::substrate::agent_progeny::KernelRegisterParams {
            agent_name: &req.name,
            namespace: &namespace,
            role: Some(format!("{:?}", agent_role).to_lowercase()),
            model: req.model.clone(),
            framework: None,
            parent_kernel_pid: parent_kernel.as_deref(),
            reason: format!("registered by user:{}", user_id),
        },
        &crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
            &user_id,
            role,
            "http:register",
        ),
    ) {
        Ok(p) => p,
        Err(e) => {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "error": "Agent registration failed",
                "code": "progeny_denied",
                "message": e.message(),
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }));
        }
    };

    // Store extra metadata (tags, created_by) in engine_store keyed by api_pid
    {
        let mut es = state.engine_store.lock().unwrap();
        let _r1 = es.folder_put(
            "agent_meta",
            &api_pid,
            &serde_json::json!({
                "pid": api_pid,
                "kernel_pid": kernel_pid,
                "name": req.name,
                "namespace": namespace,
                "role": role_label,
                "purpose": purpose,
                "model": req.model,
                "instructions": req.instructions,
                "token_budget": req.token_budget.unwrap_or(16_000),
                "tags": req.tags.clone().unwrap_or_default(),
                "user_id": user_id,
                "created_by": user_id,
                "created_at": chrono::Utc::now().to_rfc3339(),
                "paused": false,
                "parent_kernel_pid": parent_kernel,
            }),
        );
        // Forward mapping: kernel_pid → api_pid (for list_agents to emit api_pid)
        let _ = es.folder_put("agent_pid_map", &kernel_pid, &serde_json::json!(api_pid));
        // HIPAA flag: stored so gateway can check without holding kernel lock
        if req.hipaa {
            let _ = es.folder_put("agent_hipaa_flags", &api_pid, &serde_json::json!(true));
        }
    }

    // BIZ-7: analytics funnel — agent.registered milestone
    crate::services::analytics::emit(
        &state,
        crate::services::analytics::AnalyticsEvent::new(
            "agent.registered",
            &user_id,
            serde_json::json!({
                "agent_pid": api_pid,
                "namespace": namespace,
                "model": req.model,
                "role": role_label,
            }),
        )
        .with_agent(&api_pid),
    );

    if let Some(instructions) = req.instructions.as_deref() {
        persist_instruction_packet(
            &state,
            &kernel_pid,
            &namespace,
            instructions,
            &user_id,
            vec![
                "agent_instruction".into(),
                "private".into(),
                req.name.clone(),
            ],
        );
    }

    // IIA P10.2 — mint Intelligence Principal + signed contract at register.
    let purpose_vec = vec![purpose.clone()];
    let iia_principal = crate::kernel::agent_principal::mint_at_register(
        state.as_ref(),
        crate::kernel::agent_principal::MintPrincipalParams {
            api_pid: &api_pid,
            agent_name: &req.name,
            issuer: "cnktr:org:connector-node",
            model_ref: req.model.as_deref(),
            purpose: purpose_vec.clone(),
            capabilities: default_register_capabilities(agent_role),
            namespace: &namespace,
            master_agent_id: req.master_agent_id.clone(),
            geo_id: req.geo_id.clone(),
            knowledge_base_id: req.knowledge_base_id.clone(),
        },
    )
    .ok();
    let foundation =
        crate::kernel::agent_foundation::load_foundation_block(state.as_ref(), &api_pid);

    // P10.10 — identity setup + auto-activate (unless CONNECTOR_AGENT_SETUP_GATE=1).
    let acume = purpose_vec
        .first()
        .cloned()
        .unwrap_or_else(|| format!("agent:{}", req.name));
    let _ = crate::kernel::agent_identity_envelope::bootstrap_agent_identity(
        state.as_ref(),
        &api_pid,
        &req.name,
        &namespace,
        &acume,
        req.knowledge_base_id.as_deref(),
    );

    if let Some(sid) = playground_sid.as_deref() {
        crate::services::playground::record_agent_created(
            &state.playground_sessions,
            sid,
            Some(&api_pid),
        );
    }

    state.refresh_health_snapshot();
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "pid": api_pid,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "kernel_pid": kernel_pid,
        "name": req.name,
        "namespace": namespace,
        "role": role_label,
        "purpose": purpose,
        "model": req.model,
        "token_budget": req.token_budget.unwrap_or(16_000),
        "registered": true,
        "created_by": user_id,
        "iia_v2": iia_principal.is_some(),
        "principal_id": iia_principal.as_ref().map(|p| &p.principal_id),
        "agent_intelligence_hash": foundation.as_ref().map(|f| &f.agent_intelligence_hash),
        "foundation_id": foundation.as_ref().map(|f| &f.foundation_id),
        "handshake_proof_receipt_id": foundation.as_ref().map(|f| &f.handshake_proof_receipt_id),
        "who_am_i_hint": "GET /api/v1/runtime/self?agent_pid=<pid>",
        "identity_envelope_hint": format!("GET /api/v1/agents/{}/identity-envelope", api_pid),
        "setup_gate": crate::kernel::agent_identity_envelope::setup_gate_enabled(),
    }))
}

/// GET /agents — list all agents with summary metrics
/// Supports ?filter=over_budget|paused|degraded|healthy|all and ?namespace=X
pub async fn list_agents(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ListAgentsQuery>,
) -> Json<serde_json::Value> {
    if caller(&headers).is_none() {
        return Json(serde_json::json!({"error": "Authentication required", "status": 401}));
    }
    ensure_playground_session_agents(&state, &headers);

    // FIX BUG-007: Collect kernel data first, then drop kernel lock before acquiring engine_store
    let (agents_data, audit_data, total_cost, namespace_packet_counts) = {
        let k = state.kernel.lock().unwrap();
        let agents: Vec<_> = k
            .agents()
            .iter()
            .map(|(pid, acb)| (pid.clone(), acb.clone()))
            .collect();
        let audit: Vec<_> = k.audit_log().iter().cloned().collect();
        let total_cost: f64 = k.agents().values().map(|a| a.total_cost_usd).sum();
        // Collect packet counts per namespace
        let mut ns_packets: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (_, acb) in k.agents().iter() {
            ns_packets.insert(
                acb.namespace.clone(),
                k.packets_in_namespace(&acb.namespace).len(),
            );
        }
        (agents, audit, total_cost, ns_packets)
    };
    // kernel lock dropped here

    let mut es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let budget = crate::services::multiagent::agent_token_budget();
    let total_cost = finite_f64(total_cost);

    let filter = q.filter.as_deref().unwrap_or("all");
    let ns_filter = q.namespace.as_deref();
    let status_filter = q.status.as_deref();
    let tenant = tenant_from_headers_for_cap(&headers);

    // FIX BUG-007: Use collected agents_data instead of k.agents()
    let agents: Vec<serde_json::Value> = agents_data
        .iter()
        .filter_map(|(kernel_pid, acb)| {
            if !kernel_agent_in_scope(&acb.namespace, tenant.as_ref()) {
                return None;
            }
            // Namespace filter
            if let Some(ns) = ns_filter {
                if !acb.namespace.contains(ns) {
                    return None;
                }
            }
            // Status filter (matches agent status string)
            if let Some(s) = status_filter {
                let acb_status = format!("{:?}", acb.status).to_lowercase();
                if !acb_status.contains(&s.to_lowercase()) {
                    return None;
                }
            }
            Some((kernel_pid.clone(), acb.clone()))
        })
        .map(|(kernel_pid, acb)| {
            // Map kernel_pid back to api_pid for the REST response
            let api_pid = es
                .folder_get("agent_pid_map", &kernel_pid)
                .ok()
                .flatten()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| kernel_pid.clone());
            let meta: Option<serde_json::Value> =
                es.folder_get("agent_meta", &api_pid).ok().flatten();
            // Fetch KECS score for maturity level
            let kecs_data = folder_get_kecs_unified(&mut *es, &kernel_pid);
            let kecs_score = kecs_data
                .as_ref()
                .and_then(|k| k.get("kecs").and_then(|v| v.as_f64()))
                .map(finite_f64)
                .unwrap_or(0.5);
            let maturity_level = match kecs_score {
                s if s >= 0.85 => "expert",
                s if s >= 0.70 => "proficient",
                s if s >= 0.55 => "competent",
                s if s >= 0.40 => "developing",
                _ => "novice",
            };
            let tags = meta
                .as_ref()
                .and_then(|m| m.get("tags"))
                .cloned()
                .unwrap_or(serde_json::json!([]));
            let paused = meta
                .as_ref()
                .and_then(|m| m.get("paused"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let quarantined = meta
                .as_ref()
                .and_then(|m| m.get("quarantined"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let quarantine_hitl_id = meta
                .as_ref()
                .and_then(|m| m.get("quarantine_hitl_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let instructions = meta
                .as_ref()
                .and_then(|m| m.get("instructions"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // FIX BUG-007: Use collected audit_data instead of audit
            let agent_ops: Vec<_> = audit_data
                .iter()
                .filter(|e| e.agent_pid == *kernel_pid)
                .collect();
            let total_ops = agent_ops.len();
            let failed = agent_ops
                .iter()
                .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
                .count();
            let denied = agent_ops
                .iter()
                .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
                .count();
            let success_rate = if total_ops > 0 {
                (total_ops - failed - denied) as f64 / total_ops as f64 * 100.0
            } else {
                100.0
            };
            let success_rate = finite_f64(success_rate);

            // Recent activity: operations in last 1h
            let one_hour_ago = now - 3_600_000;
            let recent_ops = agent_ops
                .iter()
                .filter(|e| e.timestamp > one_hour_ago)
                .count();

            let budget_pct = if budget > 0 {
                (acb.total_tokens_consumed as f64 / budget as f64 * 100.0).min(100.0)
            } else {
                0.0
            };
            let budget_pct = finite_f64(budget_pct);
            let cost_usd = finite_f64(acb.total_cost_usd);

            // FIX BUG-010: Check kernel acb.status first before other status checks
            let kernel_status = format!("{:?}", acb.status).to_lowercase();
            let status = if kernel_status == "terminated" {
                "terminated"
            } else if quarantined {
                "quarantined"
            } else if kernel_status == "suspended" {
                "suspended"
            } else if paused {
                "paused"
            } else if acb.total_tokens_consumed >= budget {
                "budget_exceeded"
            } else if success_rate < 80.0 {
                "degraded"
            } else {
                "healthy"
            };

            // Apply ?filter= server-side after computing status
            let keep = match filter {
                "over_budget" => status == "budget_exceeded",
                "paused" => paused,
                "quarantined" => quarantined,
                "degraded" => status == "degraded",
                "healthy" => status == "healthy",
                _ => true, // "all" or unrecognised
            };
            if !keep {
                return serde_json::json!(null);
            }

            serde_json::json!({
                "pid": api_pid,
                "name": acb.agent_name,
                "namespace": acb.namespace,
                "role": format!("{:?}", acb.role),
                "model": acb.model,
                "status": status,
                "paused": paused,
                "quarantined": quarantined,
                "quarantine_hitl_id": quarantine_hitl_id,
                "tags": tags,
                "instructions_set": instructions.is_some(),
                "kecs_score": (kecs_score * 1000.0).round() / 1000.0,
                "maturity_level": maturity_level,
                "metrics": {
                    "total_operations": total_ops,
                    "success_rate": (success_rate * 10.0).round() / 10.0,
                    "recent_ops_1h": recent_ops,
                    "cost_usd": cost_usd,
                    "tokens_consumed": acb.total_tokens_consumed,
                    "budget_tokens": budget,
                    "budget_pct": (budget_pct * 10.0).round() / 10.0,
                    "packets": namespace_packet_counts.get(&acb.namespace).copied().unwrap_or(0),
                },
                "registered_at": acb.registered_at,
            })
        })
        .collect();

    // Remove null sentinels inserted by the filter
    let agents: Vec<serde_json::Value> = agents.into_iter().filter(|v| !v.is_null()).collect();

    let healthy = agents
        .iter()
        .filter(|a| a.get("status").and_then(|s| s.as_str()) == Some("healthy"))
        .count();

    Json(serde_json::json!({
        "total_agents": agents.len(),
        "healthy": healthy,
        "degraded": agents.len() - healthy,
        "total_fleet_cost_usd": (total_cost * 100.0).round() / 100.0,
        "filter_applied": filter,
        // P5.3 — list prefers single product SoT (VAC kernel ACBs); orphan registries not merged.
        "source_of_truth": "vac_kernel_acb",
        "product_sot": "services::agents + vac_kernel_acb",
        "dual_registry": false,
        "agents": agents,
    }))
}

/// GET /agents/sot-status — which registry is product SoT + honesty if dual.
pub async fn agents_sot_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "schema": "agents.sot_status.v1",
        "product_sot": "services::agents + vac_kernel_acb",
        "list_api": "GET /api/v1/agents",
        "list_source": "vac_kernel_acb",
        "dual_registry": false,
        "honesty": {
            "dual": false,
            "note": "Live list/register/terminate use services::agents → VAC kernel ACBs only. agent_lifecycle::AgentRegistry is orphaned (not wired to PlatformState) and is not a second product catalog.",
            "orphaned": [
                "agent_lifecycle::AgentRegistry (in-memory tree; not on PlatformState)"
            ],
            "parallel_non_product": [
                "crate::agents::* (deprecated planners — do not wire to HTTP)",
                "services::agent_resource_manager (unwired quota helper)",
                "services::registry::AgentRegistry (deploy manifests — not live ACBs)"
            ],
            "residency_migrate": "partial — /agents/:pid/residency + migrate hooks exist; cross-cell needs vac-cluster soak",
        },
        "endpoints": {
            "list": "GET /api/v1/agents",
            "lifecycle_contract": "GET /api/v1/agents/lifecycle/standard",
            "progeny_tree": "GET /api/v1/agents/progeny/tree",
            "sot_status": "GET /api/v1/agents/sot-status",
        },
    }))
}

/// GET /agents/:pid — full agent detail
pub async fn get_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if caller(&headers).is_none() {
        return Json(serde_json::json!({"error": "Authentication required", "status": 401}));
    }

    // Resolve input (pid, api_pid, or logical name) → (kernel_pid, api_pid)
    let (kernel_pid, api_pid) = resolve_kernel_pid(&state, &pid);
    let (meta, kecs_data) = {
        let mut es = state.engine_store.lock().unwrap();
        let m = es.folder_get("agent_meta", &api_pid).ok().flatten();
        let kecs = folder_get_kecs_unified(&mut *es, &kernel_pid);
        (m, kecs)
    };

    let (acb, total_ops, failed, denied, success_rate, tool_dispatches, budget_pct, packets) = {
        let k = state.kernel.lock().unwrap();

        let acb = match k.get_agent(&kernel_pid) {
            Some(a) => a.clone(),
            None => return Json(serde_json::json!({"error": "Agent not found", "status": 404})),
        };

        let budget = crate::services::multiagent::agent_token_budget();

        let audit = k.audit_log();
        let agent_ops: Vec<_> = audit
            .iter()
            .filter(|e| e.agent_pid == kernel_pid)
            .cloned()
            .collect();
        let total_ops = agent_ops.len();
        let failed = agent_ops
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
            .count();
        let denied = agent_ops
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
            .count();
        let success_rate = if total_ops > 0 {
            (total_ops - failed - denied) as f64 / total_ops as f64 * 100.0
        } else {
            100.0
        };

        let tool_dispatches: Vec<serde_json::Value> = agent_ops
            .iter()
            .filter(|e| e.operation == MemoryKernelOp::ToolDispatch)
            .map(|e| {
                serde_json::json!({
                    "tool": e.target,
                    "outcome": format!("{:?}", e.outcome),
                    "timestamp": e.timestamp,
                })
            })
            .take(20)
            .collect();

        let budget_pct = if budget > 0 {
            (acb.total_tokens_consumed as f64 / budget as f64 * 100.0).min(100.0)
        } else {
            0.0
        };

        let packets = k.packets_in_namespace(&acb.namespace).len();
        (
            acb,
            total_ops,
            failed,
            denied,
            success_rate,
            tool_dispatches,
            budget_pct,
            packets,
        )
    };

    let budget = crate::services::multiagent::agent_token_budget();

    let context_budget = {
        let ctx = state.context_mgr.lock().unwrap();
        ctx.get_budget(&kernel_pid).map(|b| {
            serde_json::json!({
                "max_tokens": b.max_tokens,
                "used_tokens": b.used_tokens(),
                "remaining_tokens": b.budget_remaining(),
                "utilization_pct": if b.max_tokens > 0 {
                    (b.pressure() * 100.0 * 10.0).round() / 10.0
                } else { 0.0 },
                "system_tokens": b.system_tokens,
                "history_tokens": b.history_tokens,
                "document_tokens": b.document_tokens,
                "tool_tokens": b.tool_tokens,
                "needs_eviction": b.needs_eviction(),
            })
        })
    };

    // Extract KECS components
    let kecs_score = kecs_data
        .as_ref()
        .and_then(|k| k.get("kecs").and_then(|v| v.as_f64()))
        .unwrap_or(0.5);
    let k_vn = kecs_data
        .as_ref()
        .and_then(|k| k.get("k_vn").and_then(|v| v.as_f64()));
    let s_renyi = kecs_data
        .as_ref()
        .and_then(|k| k.get("s_renyi").and_then(|v| v.as_f64()));
    let k_topo = kecs_data
        .as_ref()
        .and_then(|k| k.get("k_topo").and_then(|v| v.as_f64()));
    let maturity_level = match kecs_score {
        s if s >= 0.85 => "expert",
        s if s >= 0.70 => "proficient",
        s if s >= 0.55 => "competent",
        s if s >= 0.40 => "developing",
        _ => "novice",
    };

    Json(serde_json::json!({
        "pid": pid,
        "name": acb.agent_name,
        "namespace": acb.namespace,
        "role": format!("{:?}", acb.role),
        "status": format!("{:?}", acb.status),
        "model": acb.model,
        "registered_at": acb.registered_at,
        "meta": meta,
        "memory": {
            "packets": packets,
            "quota_tokens": acb.memory_region.quota_tokens,
            "used_tokens": acb.memory_region.used_tokens,
            "namespace_sealed": acb.memory_region.sealed,
        },
        "context_budget": context_budget,
        "cost": {
            "total_cost_usd": acb.total_cost_usd,
            "total_tokens_consumed": acb.total_tokens_consumed,
            "budget_tokens": budget,
            "budget_pct": (budget_pct * 10.0).round() / 10.0,
            "budget_status": if acb.total_tokens_consumed >= budget { "exceeded" } else if budget_pct > 80.0 { "warning" } else { "ok" },
        },
        "capabilities": acb.tool_bindings.iter().map(|tb| {
            let actions = if tb.allowed_actions.is_empty() {
                "*".to_string()
            } else {
                tb.allowed_actions.join(", ")
            };
            format!("{} ({})", tb.tool_id, actions)
        }).collect::<Vec<String>>(),
        "operations": {
            "total": total_ops,
            "failed": failed,
            "denied": denied,
            "success_rate": (success_rate * 10.0).round() / 10.0,
            "tool_bindings": acb.tool_bindings.len(),
            "recent_tool_dispatches": tool_dispatches,
        },
        "kecs": {
            "score": (kecs_score * 1000.0).round() / 1000.0,
            "maturity_level": maturity_level,
            "components": {
                "k_vn": k_vn.map(|v| (v * 1000.0).round() / 1000.0),
                "s_renyi": s_renyi.map(|v| (v * 1000.0).round() / 1000.0),
                "k_topo": k_topo.map(|v| (v * 1000.0).round() / 1000.0),
            },
            "formula": "KECS = 0.4×K_vn + 0.4×S_renyi + 0.2×K_topo",
        },
        "health_metrics": {
            "cpu_percent": serde_json::Value::Null,
            "cpu_available": false,
            "note": "Host CPU is not sampled in-process; use node_exporter or cgroup metrics (BF2-F02 / BUG-SOE-12)"
        },
    }))
}

/// PATCH /agents/:pid — update agent metadata, model, budget, instructions
/// Required role: operator+
pub async fn update_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    // Resolve api_pid → kernel_pid and verify agent exists
    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    {
        let k = state.kernel.lock().unwrap();
        if k.get_agent(&kernel_pid).is_none() {
            return Json(serde_json::json!({"error": "Agent not found", "status": 404}));
        }
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "update_agent",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // Update budget in kernel via SetTokenBudget syscall if provided
    if let Some(budget) = req.token_budget {
        let mut k = state.kernel.lock().unwrap();
        k.dispatch(SyscallRequest {
            agent_pid: kernel_pid.clone(),
            operation: MemoryKernelOp::SetTokenBudget,
            payload: SyscallPayload::SetTokenBudget {
                budget: vac_core::types::TokenBudget {
                    agent_pid: kernel_pid.clone(),
                    daily_limit: budget,
                    hourly_limit: budget / 24,
                    burst_limit: budget / 10,
                    used_today: 0,
                    used_this_hour: 0,
                    cost_center: format!("agent:{}", pid),
                    reset_at_daily: 0,
                    reset_at_hourly: 0,
                    enforce: true,
                },
            },
            reason: Some(format!("budget updated by user:{}", user_id)),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
    }

    // Update engine_store metadata
    let mut es = state.engine_store.lock().unwrap();
    let existing = es
        .folder_get("agent_meta", &pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"pid": pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();

    if let Some(model) = &req.model {
        meta.insert("model".into(), serde_json::json!(model));
        // A20: mind is replaceable — update principal.model_ref without touching grants.
        let _ = crate::kernel::agent_principal::set_model_ref(state.as_ref(), &pid, model);
    }
    if let Some(instructions) = &req.instructions {
        meta.insert("instructions".into(), serde_json::json!(instructions));
    }
    if let Some(budget) = req.token_budget {
        meta.insert("token_budget".into(), serde_json::json!(budget));
    }
    if let Some(tags) = &req.tags {
        meta.insert("tags".into(), serde_json::json!(tags));
    }
    meta.insert("updated_by".into(), serde_json::json!(user_id));
    meta.insert(
        "updated_at".into(),
        serde_json::json!(chrono::Utc::now().to_rfc3339()),
    );

    let _ = es.folder_put("agent_meta", &pid, &serde_json::Value::Object(meta));
    drop(es);

    if let Some(instructions) = req.instructions.as_deref() {
        let namespace = existing
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("m/unknown");
        persist_instruction_packet(
            &state,
            &kernel_pid,
            namespace,
            instructions,
            &user_id,
            vec![
                "agent_instruction".into(),
                "private".into(),
                "updated".into(),
            ],
        );
    }

    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "pid": pid,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "updated": true,
        "model": req.model,
        "token_budget": req.token_budget,
        "instructions_updated": req.instructions.is_some(),
        "updated_by": user_id,
    }))
}

/// DELETE /agents/:pid — terminate and archive agent
/// Required role: admin+
pub async fn terminate_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 5,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    if state
        .kernel
        .lock()
        .unwrap()
        .get_agent(&kernel_pid)
        .is_none()
    {
        return Json(serde_json::json!({"error": "Agent not found", "status": 404}));
    }
    if crate::services::playground::is_playground_mode() {
        if let Some(tenant) = tenant_from_headers_for_cap(&headers) {
            let ns = {
                let k = state.kernel.lock().unwrap();
                k.get_agent(&kernel_pid)
                    .map(|a| a.namespace.clone())
                    .unwrap_or_default()
            };
            if !kernel_agent_in_scope(&ns, Some(&tenant)) {
                return Json(serde_json::json!({
                    "error": "Agent not found",
                    "status": 404
                }));
            }
        }
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "terminate",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:terminate",
    );
    let terminated_pids = crate::substrate::agent_progeny::terminate_with_progeny_as(
        &state,
        &kernel_pid,
        &format!("terminated by user:{user_id}"),
        &actor,
    );
    let terminated = terminated_pids.contains(&kernel_pid);

    // FIX BUG-001: Update engine_store metadata to reflect terminated state
    if terminated {
        let _ = crate::kernel::intelligence_purge::purge_intelligence(
            state.as_ref(),
            &pid,
            &kernel_pid,
        );
        let mut es = state.engine_store.lock().unwrap();
        // Update agent_meta with terminated status
        if let Ok(Some(mut meta)) = es.folder_get("agent_meta", &pid) {
            meta["status"] = serde_json::json!("Terminated");
            meta["terminated_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
            meta["terminated_by"] = serde_json::json!(user_id);
            let _ = es.folder_put("agent_meta", &pid, &meta);
        }
        if let Some(sid) =
            crate::services::playground::playground_session_id_from_headers(&headers)
        {
            crate::services::playground::record_agent_deleted(
                &state.playground_sessions,
                &sid,
                &pid,
            );
        }
        // Archive to terminated_agents folder
        let _ = es.folder_put(
            "terminated_agents",
            &pid,
            &serde_json::json!({
                "pid": pid,
                "kernel_pid": kernel_pid,
                "terminated_at": chrono::Utc::now().to_rfc3339(),
                "terminated_by": user_id,
            }),
        );
    }

    state.refresh_health_snapshot();
    state.cells.remove(&pid);
    open_proceed.finish_observed(terminated);

    Json(serde_json::json!({
        "pid": pid,
        "task_id": admitted.task_id,
        "executed": terminated,
        "admits": false,
        "terminated": terminated,
        "terminated_subtree": terminated_pids,
        "terminated_by": user_id,
        "terminated_at": chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /agents/lifecycle/standard — kernel progeny lifecycle contract.
pub async fn lifecycle_standard() -> Json<serde_json::Value> {
    Json(crate::substrate::agent_progeny::lifecycle_standard_json())
}

/// GET /agents/progeny/tree — kernel-authoritative progeny forest.
pub async fn progeny_tree(State(state): State<SharedState>) -> Json<serde_json::Value> {
    Json(crate::substrate::agent_progeny::progeny_forest(&state))
}

/// GET /agents/:pid/progeny — subtree for one agent.
pub async fn agent_progeny(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (kernel_pid, _) = resolve_kernel_pid(&state, &pid);
    Json(crate::substrate::agent_progeny::agent_progeny_detail(
        &state,
        &kernel_pid,
    ))
}

/// DELETE /agents — terminate and archive ALL agents (destructive!)
/// Required role: admin+
pub async fn terminate_all_agents(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 5,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    // Collect all kernel PIDs and api_pids
    let kernel_pids: Vec<String> = {
        let k = state.kernel.lock().unwrap();
        k.agents().keys().cloned().collect()
    };
    let api_pids: Vec<String> = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("agent_meta", None).unwrap_or_default()
    };

    let mut terminated_count = 0usize;
    let mut failed_count = 0usize;
    let now = chrono::Utc::now().to_rfc3339();
    let subject = kernel_pids
        .first()
        .cloned()
        .or_else(|| api_pids.first().cloned())
        .unwrap_or_default();
    if subject.is_empty() {
        return Json(serde_json::json!({
            "ok": true,
            "terminated": 0,
            "executed": false,
            "admits": false,
            "force_removed": 0,
            "api_meta_cleared": 0,
            "terminated_by": user_id,
        }));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &subject,
        "lifecycle",
        "terminate_all",
        &serde_json::json!({"agents": kernel_pids.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:bulk_terminate",
    );
    let reason = format!("bulk termination by user:{user_id}");

    for kpid in &kernel_pids {
        if state.kernel.lock().unwrap().get_agent(kpid).is_none() {
            continue;
        }
        let killed = crate::substrate::agent_progeny::terminate_with_progeny_as(
            &state,
            kpid,
            &reason,
            &actor,
        );
        if killed.is_empty() {
            failed_count += 1;
        } else {
            terminated_count += killed.len();
        }
    }

    // Archive all engine_store metadata
    {
        let mut es = state.engine_store.lock().unwrap();
        for api_pid in &api_pids {
            if let Ok(Some(mut meta)) = es.folder_get("agent_meta", api_pid) {
                meta["status"] = serde_json::json!("Terminated");
                meta["terminated_at"] = serde_json::json!(now);
                meta["terminated_by"] = serde_json::json!(user_id);
                let _ = es.folder_put("terminated_agents", api_pid, &meta);
            }
            let _ = es.folder_delete("agent_meta", api_pid);
            let _ = es.folder_delete("agent_cost_ledger", api_pid);
        }
    }

    state.refresh_health_snapshot();
    for api_pid in &api_pids {
        state.cells.remove(api_pid);
    }
    open_proceed.finish_observed(terminated_count > 0 || !api_pids.is_empty());

    Json(serde_json::json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": terminated_count > 0 || !api_pids.is_empty(),
        "admits": false,
        "terminated": terminated_count,
        "force_removed": failed_count,
        "api_meta_cleared": api_pids.len(),
        "terminated_by": user_id,
        "terminated_at": now,
    }))
}

/// POST /agents/:pid/reset-budget — reset token counter for a new billing period
/// Required role: operator+
pub async fn reset_budget(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "reset_budget",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let meta = es.folder_get("agent_meta", &pid).ok().flatten();
    let budget = meta
        .as_ref()
        .and_then(|m| m.get("token_budget"))
        .and_then(|v| v.as_u64())
        .unwrap_or(crate::services::multiagent::agent_token_budget());
    drop(es);

    let mut k = state.kernel.lock().unwrap();
    if k.get_agent(&pid).is_none() {
        drop(k);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({"error": "Agent not found", "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}));
    }

    k.dispatch(SyscallRequest {
        agent_pid: pid.clone(),
        operation: MemoryKernelOp::SetTokenBudget,
        payload: SyscallPayload::SetTokenBudget {
            budget: vac_core::types::TokenBudget {
                agent_pid: pid.clone(),
                daily_limit: budget,
                hourly_limit: budget / 24,
                burst_limit: budget / 10,
                used_today: 0,
                used_this_hour: 0,
                cost_center: format!("agent:{}", pid),
                reset_at_daily: 0,
                reset_at_hourly: 0,
                enforce: true,
            },
        },
        reason: Some(format!("budget reset by user:{}", user_id)),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    drop(k);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "pid": pid,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "budget_reset": true,
        "new_budget": budget,
        "reset_by": user_id,
        "reset_at": chrono::Utc::now().to_rfc3339(),
    }))
}

/// PATCH /agents/:pid/budget — update token_budget fields live without restart
pub async fn update_budget(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Operator role or higher required", "status": 403}),
        );
    }

    let new_limit = match body
        .get("tokens")
        .and_then(|v| v.as_u64())
        .or_else(|| body.get("token_budget").and_then(|v| v.as_u64()))
        .or_else(|| body.get("daily_limit").and_then(|v| v.as_u64()))
    {
        Some(v) => v,
        None => {
            return Json(
                serde_json::json!({"error": "tokens or daily_limit required", "status": 400}),
            )
        }
    };
    let enforce = body
        .get("enforce")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "update_budget",
        &serde_json::json!({"pid": pid, "tokens": new_limit}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut k = state.kernel.lock().unwrap();
    if k.get_agent(&pid).is_none() {
        drop(k);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({"error": "Agent not found", "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}));
    }

    let (used_today, used_hour) = k
        .get_agent(&pid)
        .and_then(|a| {
            a.token_budget
                .as_ref()
                .map(|b| (b.used_today, b.used_this_hour))
        })
        .unwrap_or((0, 0));

    k.dispatch(SyscallRequest {
        agent_pid: pid.clone(),
        operation: MemoryKernelOp::SetTokenBudget,
        payload: SyscallPayload::SetTokenBudget {
            budget: vac_core::types::TokenBudget {
                agent_pid: pid.clone(),
                daily_limit: new_limit,
                hourly_limit: new_limit / 24,
                burst_limit: new_limit / 10,
                used_today,
                used_this_hour: used_hour,
                cost_center: format!("agent:{}", pid),
                reset_at_daily: 0,
                reset_at_hourly: 0,
                enforce,
            },
        },
        reason: Some(format!("budget update by user:{}", user_id)),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    drop(k);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "pid": pid,
        "token_budget": new_limit,
        "enforce": enforce,
        "updated_by": user_id,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    }))
}

/// POST /agents/:pid/start — boot agent from registered → running phase
/// Required role: operator+
pub async fn start_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    // Resolve kernel_pid from engine_store if this is an API pid
    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);

    // TG-0 + harden: fail-closed membrane / exclusivity / sandbox for real augmented env
    if let Err(e) =
        crate::substrate::harden_posture::assert_harden_ready_for_start(state.as_ref(), &pid)
    {
        return Json(e);
    }

    // F3: sealed regimes never auto-start
    if let Err(e) = crate::substrate::cvr::assert_may_auto_start(state.as_ref(), &pid) {
        return Json(e);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "start",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // CVR: bind ExecutionBody (AgentCell / MicroCell) — agent ≠ body
    let execution_body = match crate::substrate::cvr::bind_on_start(state.as_ref(), &pid) {
        Ok(b) => b.to_json(),
        Err(e) => return Json(e),
    };

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:start",
    );
    match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Start,
        &actor,
        &Default::default(),
        &format!("started by user:{user_id}"),
    ) {
        Ok(receipt) => {
            open_proceed.finish_observed(true);
            let new_status = state
                .kernel
                .lock()
                .ok()
                .and_then(|k| k.get_agent(&receipt.kernel_pid).map(|a| format!("{:?}", a.status)))
                .unwrap_or_else(|| "Running".into());
            Json(serde_json::json!({
                "ok": true,
                "pid": pid,
                "kernel_pid": receipt.kernel_pid,
                "current_status": new_status,
                "started_by": user_id,
                "lifecycle_grant": receipt.grant_id,
                "membrane": "tg0_applied_truth_gate",
                "execution_body": execution_body,
                "isolation": crate::substrate::cvr::posture_for_agent(state.as_ref(), &pid),
            }))
        }
        Err(e) => Json(e.to_json()),
    }
}

/// POST /agents/:pid/kill — FORCEFUL TERMINATION (emergency/shutdown)
///
/// **KILL vs PAUSE vs FREEZE:**
/// - **kill**: Permanent termination. Agent is removed from kernel. NOT reversible.
///   Use for: system shutdown, cleanup, emergency stop, removing broken agents.
/// - **pause**: Temporary stop. Agent stays in memory, can resume instantly.
///   Use for: debugging, temporary disable, quick maintenance.
/// - **freeze**: Long-term suspend. Context saved to disk, agent suspended.
///   Use for: migration, long maintenance, resource conservation.
///
/// Required role: operator+
pub async fn kill_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "kill_agent",
        &serde_json::json!({"pid": pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let _ = crate::kernel::aios::interrupt_generation(&pid, None);

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:kill",
    );
    let killed = match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Stop,
        &actor,
        &Default::default(),
        &format!("killed by user:{user_id}"),
    ) {
        Ok(_) => true,
        Err(e) => {
            crate::kernel::docklock::append_cage_runtime_log(
                state.as_ref(),
                &pid,
                "agent_kill_failed",
                &format!("by={user_id} detail={}", e.message()),
            );
            open_proceed.finish_observed(false);
            return Json(e.to_json());
        }
    };

    if killed {
        let _ = crate::kernel::intelligence_purge::purge_intelligence(
            state.as_ref(),
            &pid,
            &kernel_pid,
        );
        let mut es = state.engine_store.lock().unwrap();
        if let Ok(Some(mut meta)) = es.folder_get("agent_meta", &pid) {
            meta["status"] = serde_json::json!("Killed");
            meta["killed_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
            meta["killed_by"] = serde_json::json!(user_id);
            let _ = es.folder_put("agent_meta", &pid, &meta);
        }
    }

    crate::kernel::docklock::append_cage_runtime_log(
        state.as_ref(),
        &pid,
        if killed { "agent_kill" } else { "agent_kill_failed" },
        &format!("by={user_id}"),
    );

    open_proceed.finish_observed(killed);
    Json(serde_json::json!({
        "ok": killed,
        "pid": pid,
        "kernel_pid": kernel_pid,
        "killed": killed,
        "killed_by": user_id,
        "killed_at": chrono::Utc::now().to_rfc3339(),
        "task_id": admitted.task_id,
        "executed": killed,
        "admits": false,
    }))
}

/// POST /agents/:pid/operator-stop — A27: stop + regime/Φ only (no CoT / transcript).
pub async fn operator_stop(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, _role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };
    let (_kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "operator_stop",
        &serde_json::json!({"pid": pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let _ = crate::kernel::aios::interrupt_generation(&pid, None);
    let dim = crate::substrate::dim::persist::load(state.as_ref(), &pid);
    let view = dim.operator_view();
    // Stop the MicroCell before the kernel syscall so a stuck terminate
    // cannot skip the destroy stage of the lifecycle evidence.
    let cvr = crate::substrate::cvr::apply_stop(&state, &pid, &user_id);
    // Soft stop first; do not dump messages.
    let stopped = crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Stop,
        &crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
            &user_id,
            PlatformRole::Operator,
            "http:operator-stop",
        ),
        &Default::default(),
        "operator_stop",
    )
    .is_ok();
    open_proceed.finish_observed(stopped);
    Json(serde_json::json!({
        "ok": stopped,
        "schema": "connector.operator_stop.v1",
        "pid": pid,
        "stopped": stopped,
        "task_id": admitted.task_id,
        "executed": stopped,
        "admits": false,
        "regime": view.get("regime"),
        "homeodynamic_potential": view.get("homeodynamic_potential"),
        "degraded": view.get("degraded"),
        "cvr_lifecycle": cvr,
        "honesty": "No CoT / transcript — regime and Φ only",
    }))
}

/// POST /agents/:pid/reset — LINUX-STYLE HARD RESET (kill + reinitialize)
///
/// **RESET — Like `kill -9 && restart` in Linux:**
/// - Terminates agent completely (like kill)
/// - Removes from kernel registry immediately
/// - Clears agent metadata for fresh reuse
/// - Next register_agent will reuse this slot
///
/// Use for: Dev mode agent recycling, freeing up slots when at limit
///
/// Required role: operator+
pub async fn reset_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    let old_status = state
        .kernel
        .lock()
        .unwrap()
        .get_agent(&kernel_pid)
        .map(|a| format!("{:?}", a.status));

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "reset_agent",
        &serde_json::json!({"pid": pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:reset",
    );
    // A denied stop must not fall through to wiping the slot.
    if let Err(e) = crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Stop,
        &actor,
        &Default::default(),
        &format!("reset by user:{user_id} (Linux-style SIGTERM)"),
    ) {
        open_proceed.finish_observed(false);
        return Json(e.to_json());
    }

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_delete("agent_meta", &pid);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "ok": true,
        "pid": pid,
        "kernel_pid": kernel_pid,
        "previous_status": old_status,
        "reset_by": user_id,
        "reset_at": chrono::Utc::now().to_rfc3339(),
        "message": "Agent reset complete. Slot freed for reuse (like Linux process termination).",
        "hint": "Create new agent now - slot is available",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /agents/:pid/freeze — LONG-TERM SUSPEND with state preservation
///
/// **FREEZE vs PAUSE vs KILL:**
/// - **freeze**: Saves context snapshot to disk, then suspends. For long-term.
///   Use for: migration, long maintenance windows, resource conservation, hibernation.
///   Reversible via `/thaw` which restores the snapshot.
/// - **pause**: Quick stop, state stays in memory. For short-term.
///   Use for: debugging, quick disable, immediate maintenance.
///   Reversible via `/resume` (instant).
/// - **kill**: Permanent termination, agent removed. NOT reversible.
///   Use for: shutdown, cleanup, emergency stop.
///
/// Required role: operator+
pub async fn freeze_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    let previous_status = state
        .kernel
        .lock()
        .unwrap()
        .get_agent(&kernel_pid)
        .map(|a| format!("{:?}", a.status))
        .unwrap_or_else(|| "Unknown".into());

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "freeze_agent",
        &serde_json::json!({"pid": pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let snapshot_result = {
        let mut k = state.kernel.lock().unwrap();
        if k.get_agent(&kernel_pid).is_none() {
            drop(k);
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({"error": "Agent not found", "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}));
        }
        k.dispatch(SyscallRequest {
            agent_pid: kernel_pid.clone(),
            operation: MemoryKernelOp::ContextSnapshot,
            payload: SyscallPayload::Empty,
            reason: Some(format!("freeze snapshot by user:{user_id}")),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        })
    };

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:freeze",
    );
    let frozen = match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Freeze,
        &actor,
        &Default::default(),
        &format!("frozen by user:{user_id}"),
    ) {
        Ok(_) => true,
        Err(e) => {
            open_proceed.finish_observed(false);
            return Json(e.to_json());
        }
    };

    let new_status = state
        .kernel
        .lock()
        .unwrap()
        .get_agent(&kernel_pid)
        .map(|a| format!("{:?}", a.status))
        .unwrap_or_else(|| previous_status.clone());

    if frozen {
        let mut es = state.engine_store.lock().unwrap();
        if let Ok(Some(mut meta)) = es.folder_get("agent_meta", &pid) {
            meta["status"] = serde_json::json!("Frozen");
            meta["frozen_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
            meta["frozen_by"] = serde_json::json!(user_id);
            meta["snapshot_taken"] =
                serde_json::json!(snapshot_result.outcome == vac_core::types::OpOutcome::Success);
            let _ = es.folder_put("agent_meta", &pid, &meta);
        }
    }

    open_proceed.finish_observed(frozen);
    Json(serde_json::json!({
        "ok": frozen,
        "pid": pid,
        "kernel_pid": kernel_pid,
        "previous_status": previous_status,
        "current_status": new_status,
        "frozen": frozen,
        "snapshot_taken": snapshot_result.outcome == vac_core::types::OpOutcome::Success,
        "frozen_by": user_id,
        "frozen_at": chrono::Utc::now().to_rfc3339(),
        "task_id": admitted.task_id,
        "executed": frozen,
        "admits": false,
    }))
}

/// POST /agents/:pid/thaw — RESTORE from freeze (loads snapshot from disk)
///
/// **THAW vs RESUME:**
/// - **thaw**: Restore from `/freeze`. Loads context snapshot from disk, then resumes.
///   Use after: `/freeze` — for migration, long maintenance, hibernation.
///   Slower: Disk I/O to restore saved state.
/// - **resume**: Instant resume from `/pause`. State was kept in memory.
///   Use after: `/pause` — for quick debugging, temporary disable.
///   Fast: No disk I/O, immediate restart.
///
/// If agent was paused (not frozen), use `/resume` instead.
///
/// Required role: operator+
pub async fn thaw_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    let previous_status = state
        .kernel
        .lock()
        .unwrap()
        .get_agent(&kernel_pid)
        .map(|a| format!("{:?}", a.status))
        .unwrap_or_else(|| "Unknown".into());

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "thaw_agent",
        &serde_json::json!({"pid": pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let restore_result = {
        let mut k = state.kernel.lock().unwrap();
        if k.get_agent(&kernel_pid).is_none() {
            drop(k);
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({"error": "Agent not found", "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}));
        }
        k.dispatch(SyscallRequest {
            agent_pid: kernel_pid.clone(),
            operation: MemoryKernelOp::ContextRestore,
            payload: SyscallPayload::Empty,
            reason: Some(format!("thaw restore by user:{user_id}")),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        })
    };

    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:thaw",
    );
    let thawed = match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Thaw,
        &actor,
        &Default::default(),
        &format!("thawed by user:{user_id}"),
    ) {
        Ok(_) => true,
        Err(e) => {
            open_proceed.finish_observed(false);
            return Json(e.to_json());
        }
    };

    let new_status = state
        .kernel
        .lock()
        .unwrap()
        .get_agent(&kernel_pid)
        .map(|a| format!("{:?}", a.status))
        .unwrap_or_else(|| previous_status.clone());

    if thawed {
        let mut es = state.engine_store.lock().unwrap();
        if let Ok(Some(mut meta)) = es.folder_get("agent_meta", &pid) {
            meta["status"] = serde_json::json!("Running");
            meta["thawed_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
            meta["thawed_by"] = serde_json::json!(user_id);
            let _ = es.folder_put("agent_meta", &pid, &meta);
        }
    }

    open_proceed.finish_observed(thawed);
    Json(serde_json::json!({
        "ok": thawed,
        "pid": pid,
        "kernel_pid": kernel_pid,
        "previous_status": previous_status,
        "current_status": new_status,
        "thawed": thawed,
        "context_restored": restore_result.outcome == vac_core::types::OpOutcome::Success,
        "thawed_by": user_id,
        "thawed_at": chrono::Utc::now().to_rfc3339(),
        "task_id": admitted.task_id,
        "executed": thawed,
        "admits": false,
    }))
}

/// GET /agents/:pid/cost — cost breakdown for this agent
pub async fn agent_cost(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if caller(&headers).is_none() {
        return Json(serde_json::json!({"error": "Authentication required", "status": 401}));
    }

    let (kernel_pid, api_pid) = resolve_kernel_pid(&state, &pid);
    let budget = crate::services::multiagent::agent_token_budget();

    // Primary: engine_store cost ledger (written by gateway on every LLM call)
    let ledger = {
        let mut es = state.engine_store.lock().unwrap();
        // Try api_pid first, then kernel_pid
        es.folder_get("agent_cost_ledger", &api_pid)
            .ok()
            .flatten()
            .or_else(|| {
                es.folder_get("agent_cost_ledger", &kernel_pid)
                    .ok()
                    .flatten()
            })
    };

    if let Some(ref l) = ledger {
        let total_cost = l
            .get("total_cost_usd")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let total_tokens = l.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        let total_prompt = l
            .get("total_prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total_compl = l
            .get("total_completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let call_count = l.get("call_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let model = l.get("model").and_then(|v| v.as_str()).unwrap_or("unknown");
        let provider = l
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let first_call_at = l
            .get("first_call_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let last_call_at = l.get("last_call_at").and_then(|v| v.as_str()).unwrap_or("");
        let calls = l
            .get("calls")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        let budget_pct = if budget > 0 {
            (total_tokens as f64 / budget as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        let cost_per_1k = if total_tokens > 0 {
            total_cost / total_tokens as f64 * 1000.0
        } else {
            0.0
        };

        return Json(serde_json::json!({
            "pid":                      pid,
            "total_cost_usd":           total_cost,
            "total_tokens":             total_tokens,
            "total_prompt_tokens":      total_prompt,
            "total_completion_tokens":  total_compl,
            "call_count":               call_count,
            "cost_per_1k_tokens":       (cost_per_1k * 1_000_000.0).round() / 1_000_000.0,
            "model":                    model,
            "provider":                 provider,
            "budget_tokens":            budget,
            "budget_pct":               (budget_pct * 10.0).round() / 10.0,
            "budget_status":            if total_tokens >= budget { "exceeded" } else if budget_pct > 80.0 { "warning" } else { "ok" },
            "first_call_at":            first_call_at,
            "last_call_at":             last_call_at,
            "calls":                    calls,
        }));
    }

    // Fallback: SOE kernel ACB (for agents registered directly with the kernel)
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a,
        None => {
            return Json(
                serde_json::json!({"error": "No cost data found for agent", "status": 404}),
            )
        }
    };
    let budget_pct = if budget > 0 {
        (acb.total_tokens_consumed as f64 / budget as f64 * 100.0).min(100.0)
    } else {
        0.0
    };
    let usage_events: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == kernel_pid && e.operation == MemoryKernelOp::RecordTokenUsage)
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "detail": e.reason,
                "outcome": format!("{:?}", e.outcome),
            })
        })
        .take(50)
        .collect();
    Json(serde_json::json!({
        "pid":             pid,
        "name":            acb.agent_name,
        "model":           acb.model,
        "total_cost_usd":  acb.total_cost_usd,
        "total_tokens":    acb.total_tokens_consumed,
        "call_count":      usage_events.len(),
        "budget_tokens":   budget,
        "budget_pct":      (budget_pct * 10.0).round() / 10.0,
        "budget_status":   if acb.total_tokens_consumed >= budget { "exceeded" } else if budget_pct > 80.0 { "warning" } else { "ok" },
        "cost_per_1k_tokens": if acb.total_tokens_consumed > 0 { acb.total_cost_usd / acb.total_tokens_consumed as f64 * 1000.0 } else { 0.0 },
        "calls":           usage_events,
    }))
}

#[derive(serde::Deserialize, Default)]
pub struct AgentActivityQuery {
    /// If true, stream new events as Server-Sent Events (text/event-stream)
    #[serde(default)]
    pub follow: Option<bool>,
    /// Maximum entries to return (default 100)
    pub limit: Option<usize>,
    /// Only return entries after this epoch-millisecond timestamp
    pub since_ms: Option<i64>,
}

/// GET /agents/:pid/activity — recent audit log for this agent
/// ?follow=true  → Server-Sent Events stream (text/event-stream)
/// ?limit=N      → cap number of entries returned (default 100)
/// ?since_ms=T   → only entries after T ms epoch
/// GET /agents/:pid/cage-runtime — DockLock cage env + runtime log (≠ audit activity).
pub async fn agent_cage_runtime(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    if caller(&headers).is_none() {
        return Json(
            serde_json::json!({"ok": false, "error": "Authentication required", "status": 401}),
        );
    }
    let (_kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    let isolation = crate::kernel::isolation_tiers::isolation_for_agent(state.as_ref(), &pid);
    let dock = crate::kernel::docklock::status_snapshot(state.as_ref());
    let lines = crate::kernel::docklock::list_cage_runtime_log(state.as_ref(), &pid, 100);
    // Latest persisted cage env for this agent (if any quantum row mentions agent_pid).
    let cage_env_keys = {
        let es = state.engine_store.lock().unwrap();
        let keys = es
            .folder_keys(crate::kernel::docklock::IIA_CAGE_ENV_FOLDER, None)
            .unwrap_or_default();
        let mut found = serde_json::Value::Null;
        for k in keys.into_iter().rev().take(20) {
            if let Ok(Some(v)) = es.folder_get(crate::kernel::docklock::IIA_CAGE_ENV_FOLDER, &k) {
                if v.get("agent_pid").and_then(|x| x.as_str()) == Some(pid.as_str()) {
                    let env_keys: Vec<String> = v
                        .get("env")
                        .and_then(|e| e.as_object())
                        .map(|m| m.keys().cloned().collect())
                        .unwrap_or_default();
                    found = serde_json::json!({
                        "quantum_id": v.get("quantum_id"),
                        "env_keys": env_keys,
                        "network_default": v.get("network_default"),
                        "honesty": "Values redacted — keys only; secrets never in cage env",
                    });
                    break;
                }
            }
        }
        found
    };
    Json(serde_json::json!({
        "ok": true,
        "schema": "connector.cage.runtime.v1",
        "pid": pid,
        "isolation": isolation,
        "docklock": dock,
        "cage_env": cage_env_keys,
        "runtime_log": lines,
        "honesty": "This stream is cage/runtime — distinct from GET /agents/:pid/activity (kernel audit)",
    }))
}

pub async fn agent_activity(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Query(q): Query<AgentActivityQuery>,
) -> Response {
    if caller(&headers).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Authentication required", "status": 401})),
        )
            .into_response();
    }

    // Resolve kernel_pid from api_pid
    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);

    {
        let k = state.kernel.lock().unwrap();
        if k.get_agent(&kernel_pid).is_none() {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found", "status": 404})),
            )
                .into_response();
        }
    }

    let limit = q.limit.unwrap_or(100);
    let since = q.since_ms.unwrap_or(0);
    let follow = q.follow.unwrap_or(false);

    if follow {
        // CLI-P2-3: SSE stream — poll audit log every 1s, emit new events
        let state = state.clone();
        let pid_clone = pid.clone();
        let kernel_pid_clone = kernel_pid.clone();
        let stream = async_stream::stream! {
            let mut last_seen: i64 = since.max(chrono::Utc::now().timestamp_millis() - 5_000);
            loop {
                let events: Vec<String> = {
                    let k = state.kernel.lock().unwrap();
                    k.audit_log().iter()
                        .filter(|e| e.agent_pid == kernel_pid_clone && e.timestamp > last_seen)
                        .map(|e| {
                            let json = serde_json::json!({
                                "pid":       &pid_clone,
                                "timestamp": e.timestamp,
                                "operation": format!("{:?}", e.operation),
                                "outcome":   format!("{:?}", e.outcome),
                                "target":    e.target,
                                "reason":    e.reason,
                                "audit_id":  e.audit_id,
                            });
                            serde_json::to_string(&json).unwrap_or_default()
                        })
                        .collect()
                };

                for ev in &events {
                    // Update last_seen from event data
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(ev) {
                        if let Some(ts) = v.get("timestamp").and_then(|t| t.as_i64()) {
                            if ts > last_seen { last_seen = ts; }
                        }
                    }
                    let sse = format!("data: {}\n\n", ev);
                    yield Ok::<_, std::convert::Infallible>(sse);
                }

                // Heartbeat every 5s so clients detect dead connections
                if events.is_empty() {
                    yield Ok::<_, std::convert::Infallible>(":heartbeat\n\n".to_string());
                }

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        };

        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("X-Accel-Buffering", "no")
            .body(axum::body::Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // Non-streaming JSON response
    let entries: Vec<serde_json::Value> = {
        let k = state.kernel.lock().unwrap();
        k.audit_log()
            .iter()
            .filter(|e| e.agent_pid == kernel_pid && e.timestamp > since)
            .rev()
            .take(limit)
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp,
                    "operation": format!("{:?}", e.operation),
                    "outcome":   format!("{:?}", e.outcome),
                    "target":    e.target,
                    "reason":    e.reason,
                    "audit_id":  e.audit_id,
                })
            })
            .collect()
    };

    Json(serde_json::json!({
        "pid":                pid,
        "total_entries_shown": entries.len(),
        "since_ms":           since,
        "activity":           entries,
    }))
    .into_response()
}

/// POST /agents/:pid/signal — unified signal dispatch (AIOS-A2)
///
/// Body: `{ "signal": "Suspend" | "Resume" | "Terminate", "reason": "optional" }`
/// Required role: operator+ (admin for Terminate)
pub async fn send_agent_signal(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let signal = match body.get("signal").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "missing 'signal' field",
                "valid": ["Suspend", "Resume", "Terminate"]
            }))
        }
    };

    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers,
        if signal == "Terminate" { 5 } else { 4 },
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };
    let (kernel_pid, api_pid) = resolve_kernel_pid(&state, &pid);
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("operator signal")
        .to_string();

    let lifecycle_op = match signal.as_str() {
        "Suspend" => crate::services::intelligence_authority::LifecycleOp::SignalSuspend,
        "Resume" => crate::services::intelligence_authority::LifecycleOp::SignalResume,
        "Terminate" => crate::services::intelligence_authority::LifecycleOp::SignalTerminate,
        _ => {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("unknown signal '{}'", signal),
                "valid": ["Suspend", "Resume", "Terminate"]
            }))
        }
    };

    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &kernel_pid,
        "agent.signal",
        &signal,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "status": 403,
            "honesty": "TG-0/C9 — signal requires charter action agent.signal",
        }));
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &api_pid,
        "lifecycle",
        "operator_signal",
        &serde_json::json!({"pid": api_pid, "signal": signal}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:signal",
    );
    match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &api_pid,
        lifecycle_op,
        &actor,
        &Default::default(),
        &reason,
    ) {
        Ok(receipt) => {
            if matches!(signal.as_str(), "Terminate") {
                let mut es = state.engine_store.lock().unwrap();
                let existing = es
                    .folder_get("agent_meta", &api_pid)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| serde_json::json!({}));
                let mut meta = existing.as_object().cloned().unwrap_or_default();
                meta.insert("terminated".into(), serde_json::json!(true));
                meta.insert("terminated_by".into(), serde_json::json!(user_id.clone()));
                meta.insert(
                    "terminated_at".into(),
                    serde_json::json!(chrono::Utc::now().to_rfc3339()),
                );
                meta.insert("termination_reason".into(), serde_json::json!(reason));
                let _ = es.folder_put("agent_meta", &api_pid, &serde_json::Value::Object(meta));
            }
            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "ok": true,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "pid": api_pid,
                "kernel_pid": receipt.kernel_pid,
                "signal": signal,
                "by": user_id,
                "lifecycle_grant": receipt.grant_id,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(e.to_json())
        }
    }
}

/// POST /agents/:pid/pause — QUICK TEMPORARY STOP (state stays in memory)
///
/// **PAUSE vs FREEZE vs KILL:**
/// - **pause**: Quick stop, state stays in memory. Instant resume.
///   Use for: debugging, temporary disable, quick maintenance, testing.
///   Reversible via `/resume` (instant, no disk I/O).
/// - **freeze**: Long-term suspend, context saved to disk.
///   Use for: migration, long maintenance, hibernation.
///   Reversible via `/thaw` (restores from disk).
/// - **kill**: Permanent termination, agent removed. NOT reversible.
///   Use for: shutdown, cleanup, emergency stop.
///
/// Required role: operator+
pub async fn pause_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);

    {
        let k = state.kernel.lock().unwrap();
        if k.get_agent(&kernel_pid).is_none() {
            return Json(serde_json::json!({"error": "Agent not found", "status": 404}));
        }
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "pause",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:pause",
    );
    // Contain the MicroCell before the kernel syscall. A stuck AgentSuspend
    // must not leave the guest running or skip the lifecycle evidence.
    let cvr = crate::substrate::cvr::apply_pause(&state, &pid, &user_id);
    match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Pause,
        &actor,
        &Default::default(),
        &format!("paused by user:{user_id}"),
    ) {
        Ok(_) => {
            // SpendCease: Stop/pause must fence generation + void ctx_tok (model cannot keep spending).
            let cease = crate::substrate::spend_cease::kernel_cease(
                &state,
                &pid,
                connector_trust::CeaseReason::UserStop,
            )
            .ok();
            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "pid": pid,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "paused": true,
                "paused_by": user_id,
                "cvr_lifecycle": cvr,
                "spend_cease": cease,
            }))
        }
        Err(e) => {
            let mut body = e.to_json();
            if let Some(obj) = body.as_object_mut() {
                obj.insert("cvr_lifecycle".into(), cvr);
                obj.insert("task_id".into(), serde_json::json!(admitted.task_id));
                obj.insert("executed".into(), serde_json::json!(false));
                obj.insert("admits".into(), serde_json::json!(false));
            }
            open_proceed.finish_observed(false);
            Json(body)
        }
    }
}

/// GET /api/v1/agents/:pid/expometer — authority + world/LLM exposure snapshot.
pub async fn agent_expometer(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (_kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    Json(crate::substrate::expometer::snapshot(&state, &pid))
}

/// POST /api/v1/agents/:pid/cease — SpendCease kernel stop (fence + void ctx_tok + reap).
/// Does not rely on the LLM obeying; admit paths for the ceased generation die.
pub async fn cease_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };
    let (_kernel_pid, pid) = resolve_kernel_pid(&state, &pid);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "cease",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match crate::substrate::spend_cease::kernel_cease(
        &state,
        &pid,
        connector_trust::CeaseReason::UserStop,
    ) {
        Ok(receipt) => {
            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "ok": true,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "pid": pid,
                "ceased_by": user_id,
                "role": role,
                "spend_cease": receipt,
                "honesty": "model_desire_irrelevant_admit_path_dead",
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(serde_json::json!({
                "ok": false,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
                "error": e,
                "status": 500,
            }))
        }
    }
}

/// POST /agents/:pid/clearance — set MAC Guard security clearance for an agent (AIOS-A2 / S2)
/// Required role: admin+
/// Body: { "level": "standard" | "protected" | "control" | "kernel" | "public" | "tool_io" }
pub async fn set_clearance(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(serde_json::json!({
            "error": "Admin role or higher required to change security clearance",
            "hint": "Clearance changes affect MAC Guard access control — only admins can modify.",
            "status": 403
        }));
    }

    let level_str = body.get("level").and_then(|v| v.as_str()).unwrap_or("");
    let clearance = match level_str.to_lowercase().as_str() {
        "public" => vac_core::namespace_types::SecurityLevel::Public,
        "tool_io" => vac_core::namespace_types::SecurityLevel::ToolIO,
        "standard" => vac_core::namespace_types::SecurityLevel::Standard,
        "protected" => vac_core::namespace_types::SecurityLevel::Protected,
        "control" => vac_core::namespace_types::SecurityLevel::Control,
        "kernel" => vac_core::namespace_types::SecurityLevel::Kernel,
        _ => {
            return Json(serde_json::json!({
                "error": "invalid_clearance_level",
                "message": format!("'{}' is not a valid clearance level.", level_str),
                "valid_levels": ["public", "tool_io", "standard", "protected", "control", "kernel"],
                "hint": "Default is 'standard'. Use 'protected' for knowledge-base agents, 'control' for orchestrators.",
                "status": 400
            }))
        }
    };

    // FIX BUG-003: Resolve API PID to kernel PID
    let (kernel_pid, _) = resolve_kernel_pid(&state, &pid);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "set_clearance",
        &serde_json::json!({"pid": pid, "level": level_str}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let changed = {
        let mut k = state.kernel.lock().unwrap();
        match k.agents_mut().get_mut(&kernel_pid) {
            Some(acb) => {
                let prev = acb.security_clearance;
                acb.security_clearance = clearance;
                Some(prev)
            }
            None => None,
        }
    };
    let Some(prev) = changed else {
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "error": "agent_not_found",
            "pid": pid,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
            "hint": format!("Register agent first: POST /api/v1/agents with name={}", pid),
            "status": 404
        }));
    };
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "pid": pid,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "clearance_changed": true,
                "previous": format!("{}", prev),
                "new": format!("{}", clearance),
                "changed_by": user_id,
        "effect": format!(
            "Agent {} can now read/write namespaces up to level {} (was {}).",
            pid, clearance, prev
        )
    }))
}

/// POST /agents/:pid/resume — INSTANT RESUME from pause (no disk I/O)
///
/// **RESUME vs THAW:**
/// - **resume**: Instant resume from `/pause`. State was kept in memory.
///   Use after: `/pause` — for quick debugging, temporary disable.
///   Fast: No disk I/O, immediate restart.
/// - **thaw**: Restore from `/freeze`. Loads context snapshot from disk.
///   Use after: `/freeze` — for migration, long maintenance, hibernation.
///   Slower: Disk I/O to restore saved state.
///
/// If agent was frozen (not paused), use `/thaw` instead.
///
/// Required role: operator+
pub async fn resume_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (kernel_pid, pid) = resolve_kernel_pid(&state, &pid);

    {
        let k = state.kernel.lock().unwrap();
        if k.get_agent(&kernel_pid).is_none() {
            return Json(serde_json::json!({"error": "Agent not found", "status": 404}));
        }
    }

    // F3: quarantine/stop cannot be bypassed via /resume
    if let Err(e) = crate::substrate::cvr::regime::assert_may_resume(state.as_ref(), &pid, false) {
        return Json(e);
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "resume",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &user_id,
        role,
        "http:resume",
    );
    match crate::substrate::agent_lifecycle_gate::dispatch_lifecycle(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Resume,
        &actor,
        &Default::default(),
        &format!("resumed by user:{user_id}"),
    ) {
        Ok(receipt) => {
            let cvr = crate::substrate::cvr::lifecycle::apply_resume(&state, &pid, &user_id);
            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "pid": pid,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "paused": false,
                "resumed_by": user_id,
                "kernel_resume": format!("{:?}", receipt.outcome),
                "cvr_lifecycle": cvr,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(e.to_json())
        }
    }
}

/// POST /agents/:pid/quarantine — operator containment (blocks effects + execution authority)
pub async fn quarantine_agent_endpoint(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (_, pid) = resolve_kernel_pid(&state, &pid);
    let reason = body
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("operator quarantine")
        .to_string();

    if let Err(v) = crate::services::intelligence_authority::require_lifecycle_transition(
        &state,
        &pid,
        crate::services::intelligence_authority::LifecycleOp::Quarantine,
        &user_id,
        role,
        &crate::services::intelligence_authority::LifecycleOpts {
            reason: Some(reason.clone()),
            ..Default::default()
        },
    ) {
        return Json(v);
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "quarantine",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    crate::services::admission::operator_quarantine_agent(&state, &pid, &reason, &user_id);
    let cvr = crate::substrate::cvr::apply_quarantine(&state, &pid, &user_id, &reason);

    let hitl_id = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("agent_meta", &pid)
            .ok()
            .flatten()
            .and_then(|m| {
                m.get("quarantine_hitl_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
    };

    let quarantined = cvr.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
    open_proceed.finish_observed(quarantined);
    Json(serde_json::json!({
        "ok": quarantined,
        "task_id": admitted.task_id,
        "executed": quarantined,
        "admits": false,
        "pid": pid,
        "quarantined": true,
        "reason": reason,
        "quarantined_by": user_id,
        "quarantine_hitl_id": hitl_id,
        "cvr_lifecycle": cvr,
        "honesty": "All admission paths blocked until HITL unquarantine or admin force. Quarantine freezes AgentCell + cuts egress.",
        "hint": "Approve pending HITL action=unquarantine on Fix/Manage (or admin force). Direct unquarantine without HITL returns lifecycle_escalate.",
    }))
}

/// POST /agents/:pid/unquarantine  — release agent from quarantine
///
/// Called by operators or HITL approve flow to allow a quarantined agent
/// to resume operations. Clears quarantine flags in agent_meta and records
/// an audit entry.
pub async fn unquarantine_agent_endpoint(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let (_, api_pid) = resolve_kernel_pid(&state, &pid);
    let force = body
        .as_ref()
        .and_then(|b| b.get("force"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if let Err(v) = crate::services::intelligence_authority::require_lifecycle_transition(
        &state,
        &api_pid,
        crate::services::intelligence_authority::LifecycleOp::Unquarantine,
        &user_id,
        role,
        &crate::services::intelligence_authority::LifecycleOpts {
            force,
            ..Default::default()
        },
    ) {
        return Json(v);
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &api_pid,
        "lifecycle",
        "unquarantine",
        &serde_json::json!({"pid": api_pid, "force": force}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    crate::services::admission::unquarantine_agent(&state, &api_pid, &user_id);
    let cvr = crate::substrate::cvr::lifecycle::apply_resume_ex(&state, &api_pid, &user_id, true);
    let resume = crate::substrate::llm_agent_sandbox::load_slot(&state, &api_pid)
        .map(|s| s.to_json())
        .unwrap_or(serde_json::json!({ "open": true, "note": "slot opens on next talk" }));

    let released = cvr.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
    open_proceed.finish_observed(released);
    Json(serde_json::json!({
        "ok": released,
        "task_id": admitted.task_id,
        "executed": released,
        "admits": false,
        "status": 200,
        "pid": api_pid,
        "quarantined": false,
        "unquarantined_by": user_id,
        "force": force,
        "message": "agent resumed — normal operations (HTTP 200) restored after human approval",
        "broker_sandbox": resume,
        "cvr_lifecycle": cvr,
        "hint": "Next talk mints a fresh broker epoch; 409/499 bypass remains impossible.",
    }))
}

/// POST /agents/:pid/trust  — set trust override level (high|medium|low)
pub async fn set_trust_override(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(
            serde_json::json!({"error": "Admin role required for trust override", "status": 403}),
        );
    }
    let level = body
        .get("trust_level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");
    let kecs = match level {
        "high" => 0.90f64,
        "low" => 0.35f64,
        _ => 0.65f64, // medium
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "set_trust_level",
        &serde_json::json!({"pid": pid.as_str(), "trust_level": level}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut es = state.engine_store.lock().unwrap();
    let existing = es
        .folder_get("agent_meta", &pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({"pid": pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();
    meta.insert("trust_override".into(), serde_json::json!(level));
    meta.insert("trust_kecs".into(), serde_json::json!(kecs));
    meta.insert("trust_set_by".into(), serde_json::json!(user_id));
    meta.insert(
        "trust_set_at".into(),
        serde_json::json!(chrono::Utc::now().to_rfc3339()),
    );
    let _ = es.folder_put("agent_meta", &pid, &serde_json::Value::Object(meta));
    drop(es);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "pid": pid,
        "trust_level": level,
        "agent_health_score": kecs,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /agents/:pid/reflect — trigger memory reflection run
pub async fn trigger_reflect(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (_user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(serde_json::json!({"error": "Operator role required", "status": 403}));
    }
    let force = body.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "run_reflection",
        &serde_json::json!({"pid": pid.as_str(), "force": force}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // If forced, temporarily zero out the action counter to bypass the threshold
    if force {
        let mut k = state.kernel.lock().unwrap();
        if let Some(acb) = k.agents_mut().get_mut(&pid) {
            acb.actions_since_reflection = 100; // hit threshold
        }
    }

    let (reflected, reflection_cid, packets_reviewed) = {
        let mut k = state.kernel.lock().unwrap();
        let before_cid = k
            .get_agent(&pid)
            .map(|a| a.last_reflection_cid.clone())
            .unwrap_or_default();
        let did_reflect = k.run_reflection(&pid);
        let after_cid = k
            .get_agent(&pid)
            .map(|a| a.last_reflection_cid.clone())
            .unwrap_or(before_cid);
        let packets = k
            .get_agent(&pid)
            .and_then(|a| {
                // actions_since_reflection was reset to 0; total_packets is a proxy
                Some(a.total_packets)
            })
            .unwrap_or(0);
        (did_reflect, after_cid, packets)
    };

    let promoted_knowledge = if reflected {
        let packets = {
            let k = state.kernel.lock().unwrap();
            let namespace = k
                .get_agent(&pid)
                .map(|a| a.namespace.clone())
                .unwrap_or_else(|| format!("m/{}", pid));
            k.packets_in_namespace(&namespace)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        if !packets.is_empty() {
            let mut knot = state.knot.lock().unwrap();
            let before = knot.node_count();
            knot.ingest_packets(&packets, 0);
            let after = knot.node_count();
            serde_json::json!({
                "promoted": true,
                "packets_ingested": packets.len(),
                "entities_before": before,
                "entities_after": after,
                "entities_added": after.saturating_sub(before),
            })
        } else {
            serde_json::json!({"promoted": false, "reason": "no_packets"})
        }
    } else {
        serde_json::json!({"promoted": false, "reason": "reflection_not_run"})
    };

    // BIZ-7: analytics
    if reflected {
        crate::services::analytics::emit(
            &state,
            crate::services::analytics::AnalyticsEvent::new(
                "reflection.written",
                &pid,
                serde_json::json!({"reflection_cid": reflection_cid, "forced": force}),
            )
            .with_agent(&pid),
        );
    }

    let next_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();

    open_proceed.finish_observed(reflected || force);
    Json(serde_json::json!({
        "pid": pid,
        "reflected": reflected,
        "reflection_cid": reflection_cid,
        "packets_reviewed": packets_reviewed,
        "promoted_knowledge": promoted_knowledge,
        "forced": force,
        "next_reflection_at": next_at,
        "task_id": admitted.task_id,
        "executed": reflected || force,
        "admits": false,
    }))
}

/// POST /agents/:pid/migrate — migrate agent to another cell
///
/// B6: Uses real kernel `export_agent_snapshot` to produce a CID-addressed
/// snapshot, records a structured `KernelAuditEntry` with source_cell,
/// target_cell, snapshot_cid, and migration_ms, and persists the updated
/// AgentControlBlock to the kernel_store.
pub async fn migrate_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    use vac_core::types::{MemoryKernelOp, OpOutcome};

    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(
            serde_json::json!({"error": "Admin role required for migration", "status": 403}),
        );
    }

    let target_cell_id = match body.get("target_cell_id").and_then(|v| v.as_str()) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => {
            return Json(serde_json::json!({"error": "target_cell_id is required", "status": 400}))
        }
    };

    // FIX BUG-005: Resolve API PID to kernel PID
    let (kernel_pid, _) = resolve_kernel_pid(&state, &pid);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "migrate_agent",
        &serde_json::json!({"pid": pid.as_str(), "target_cell": target_cell_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let source_cell_id = state
        .config
        .cell_id
        .clone()
        .unwrap_or_else(|| "cell-0".to_string());

    let start = std::time::Instant::now();

    // ── 1. Export real CID-addressed snapshot from the kernel ────────────────
    let snapshot_result = {
        let k = state.kernel.lock().unwrap();
        k.export_agent_snapshot(&kernel_pid)
    };

    let snapshot = match snapshot_result {
        Ok(s) => s,
        Err(e) => {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "error": format!("snapshot export failed: {}", e),
                "pid": pid,
                "status": 500,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }))
        }
    };

    let snapshot_cid = match snapshot.snapshot_cid.as_ref().map(|c| c.to_string()) {
        Some(cid) => cid,
        None => {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "error": "snapshot CID missing after export",
                "status": 500,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }))
        }
    };

    let migration_ms = start.elapsed().as_millis() as u64;

    // ── 2. Emit structured migration audit entry in the kernel chain ─────────
    {
        let mut k = state.kernel.lock().unwrap();
        k.record_audit_event(
            MemoryKernelOp::ContextRestore,
            &kernel_pid,
            Some(format!(
                "migrate:source_cell={},target_cell={},snapshot_cid={},migration_ms={}",
                source_cell_id, target_cell_id, snapshot_cid, migration_ms
            )),
            OpOutcome::Success,
            Some(format!(
                "Agent migrated by {} from {} to {}",
                user_id, source_cell_id, target_cell_id
            )),
            None,
            Some(migration_ms * 1000),
            None,
        );
        k.flush_audit_batch();
    }

    // ── 3. Persist agent ACB to kernel_store with updated cell metadata ──────
    {
        let k = state.kernel.lock().unwrap();
        if let Some(acb) = k.get_agent(&kernel_pid).cloned() {
            let mut ks = state.kernel_store.lock().unwrap();
            let _ = ks.store_agent(&acb);
        }
    }

    // ── 4. Record migration metadata in engine_store for operator queries ────
    {
        let mut es = state.engine_store.lock().unwrap();
        let existing = es
            .folder_get("agent_meta", &pid)
            .ok()
            .flatten()
            .unwrap_or_else(|| serde_json::json!({"pid": pid}));
        let mut meta = existing.as_object().cloned().unwrap_or_default();
        meta.insert("cell_id".into(), serde_json::json!(target_cell_id));
        meta.insert(
            "source_cell_id".into(),
            serde_json::json!(source_cell_id.clone()),
        );
        meta.insert("migrated_by".into(), serde_json::json!(user_id));
        meta.insert(
            "migrated_at".into(),
            serde_json::json!(chrono::Utc::now().to_rfc3339()),
        );
        meta.insert(
            "snapshot_cid".into(),
            serde_json::json!(snapshot_cid.clone()),
        );
        meta.insert("migration_ms".into(), serde_json::json!(migration_ms));
        let _ = es.folder_put("agent_meta", &pid, &serde_json::Value::Object(meta));
    }
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "pid": pid,
        "source_cell": source_cell_id,
        "target_cell": target_cell_id,
        "snapshot_cid": snapshot_cid,
        "migration_ms": migration_ms,
        "snapshot_audit_entries": snapshot.audit_entries.len(),
        "snapshot_memory_packets": snapshot.memory_packets.len(),
        "status": "completed",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /agents/:pid/skills — procedural skill cache (MEM-2)
pub async fn agent_skills(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (_user_id, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };

    // Aggregate tool call outcomes from audit log to build skill profile
    let skills: Vec<serde_json::Value> = {
        use connector_engine::engine_store::AuditFilter;
        let mut es = state.engine_store.lock().unwrap();
        let filter = AuditFilter {
            agent_pid: Some(pid.clone()),
            limit: Some(1000),
            ..Default::default()
        };
        let entries = es.query_audit(&filter).unwrap_or_default();

        let mut tool_stats: std::collections::HashMap<String, (u64, u64, u64)> = Default::default();
        for entry in &entries {
            if entry.action.starts_with("tool:") {
                let tool = entry.action.trim_start_matches("tool:");
                let ok = entry.verdict.as_deref().unwrap_or("") == "allowed";
                let lat = entry
                    .details
                    .as_ref()
                    .and_then(|d| d.get("latency_ms"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(50);
                let e = tool_stats.entry(tool.to_string()).or_insert((0, 0, 0));
                e.0 += 1;
                if ok {
                    e.1 += 1;
                }
                e.2 += lat;
            }
        }
        tool_stats
            .into_iter()
            .map(|(tool, (total, success, lat_sum))| {
                let success_rate = if total > 0 {
                    success as f64 / total as f64
                } else {
                    0.0
                };
                let avg_latency = if total > 0 { lat_sum / total } else { 0 };
                serde_json::json!({
                    "tool_name": tool,
                    "call_count": total,
                    "success_rate": success_rate,
                    "avg_latency_ms": avg_latency,
                    "preferred_params": null,
                })
            })
            .collect()
    };

    Json(serde_json::json!({
        "pid": pid,
        "skills": skills,
        "skill_count": skills.len(),
        "bound_skills": crate::kernel::intelligence_spec::load_bound_skills(state.as_ref(), &pid),
        "honesty": "bound_skills = declared typed capabilities (IntelligenceSpec); skills = learned procedural cache",
    }))
}

/// GET /agents/:pid/residency — B14 data residency compliance status for an agent.
///
/// Returns:
///   - `residency_region`: required region from manifest (`spec.residency.region`)
///   - `cell_region`: current cell's region (`CONNECTOR_CELL_REGION` env var)
///   - `compliant`: true if cell_region matches residency_region or allow_regions
///   - `allow_regions`: additional allowed regions for this agent
///   - `violations`: list of audit entries recording residency blocks
pub async fn agent_residency(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
) -> impl IntoResponse {
    let (_user_id, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Authentication required", "status": 401})),
            )
                .into_response()
        }
    };

    let cell_region = std::env::var("CONNECTOR_CELL_REGION").unwrap_or_default();

    let (residency_region, allow_regions) = {
        let k = state.kernel.lock().unwrap();
        k.get_agent(&pid)
            .map(|acb| {
                (
                    acb.residency_region.clone(),
                    acb.residency_allow_regions.clone(),
                )
            })
            .unwrap_or_default()
    };

    let compliant = residency_region.is_empty()
        || cell_region.is_empty()
        || residency_region == cell_region
        || allow_regions.iter().any(|r| r == &cell_region);

    // Pull residency violation entries from audit log
    let violations: Vec<serde_json::Value> = {
        use connector_engine::engine_store::AuditFilter;
        let mut es = state.engine_store.lock().unwrap();
        let filter = AuditFilter {
            agent_pid: Some(pid.clone()),
            limit: Some(50),
            ..Default::default()
        };
        es.query_audit(&filter)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| {
                e.action.contains("residency")
                    || e.verdict.as_deref().unwrap_or("").contains("residency")
            })
            .map(|e| {
                serde_json::json!({
                    "timestamp_ms": e.timestamp,
                    "action":       e.action,
                    "detail":       e.details,
                })
            })
            .collect()
    };

    Json(serde_json::json!({
        "pid":              pid,
        "residency_region": residency_region,
        "cell_region":      cell_region,
        "allow_regions":    allow_regions,
        "compliant":        compliant,
        "violation_count":  violations.len(),
        "recent_violations": violations,
        "note": if residency_region.is_empty() {
            "No residency constraint configured. Set spec.residency.region in connector.yaml."
        } else if cell_region.is_empty() {
            "CONNECTOR_CELL_REGION not set — residency enforcement inactive."
        } else if compliant {
            "Compliant: agent is running in an allowed region."
        } else {
            "NON-COMPLIANT: agent is running outside its allowed region(s)."
        },
    }))
    .into_response()
}

// ── B8: SSE agent event stream ────────────────────────────────────────────────

/// GET /agents/:pid/events — Server-Sent Events stream of audit log entries.
///
/// Polls the audit log every second and streams new entries as SSE events.
/// Client connects once; events arrive as `data: <json>\n\n`.
///
/// Headers required: `Authorization: Bearer <token>` (or dev mode).
/// Query params:
///   - `since_ms` — only events after this unix-ms timestamp (default: now)
pub async fn agent_event_stream(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if caller(&headers).is_none() {
        return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    }

    let since_start = params
        .get("since_ms")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        });

    let state_clone = state.clone();
    let pid_clone = pid.clone();

    let interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let interval_stream = IntervalStream::new(interval);

    // FIX BUG-022: Track by timestamp AND seen event IDs to avoid missing events with same millisecond
    let cursor = Arc::new(Mutex::new(since_start));
    let seen_ids: Arc<Mutex<std::collections::HashSet<String>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));

    let stream = interval_stream.map(move |_| {
        let current_cursor = *cursor.lock().unwrap();
        let mut new_cursor = current_cursor;
        let mut seen = seen_ids.lock().unwrap();

        let events: Vec<serde_json::Value> = {
            use connector_engine::engine_store::AuditFilter;
            if let Ok(es) = state_clone.engine_store.lock() {
                // FIX BUG-022: Use >= instead of > to catch events at same millisecond
                let filter = AuditFilter {
                    agent_pid: Some(pid_clone.clone()),
                    from_ms: Some(current_cursor as i64),
                    limit: Some(50),
                    ..Default::default()
                };
                let entries = es.query_audit(&filter).unwrap_or_default();
                entries
                    .into_iter()
                    .filter_map(|e| {
                        // FIX BUG-022: Deduplicate by event ID (using action + timestamp as proxy)
                        let agent_pid_str = e.agent_pid.as_deref().unwrap_or("");
                        let event_id = format!("{}:{}:{}", agent_pid_str, e.action, e.timestamp);
                        if seen.contains(&event_id) {
                            return None;
                        }
                        seen.insert(event_id);

                        if e.timestamp as u64 > new_cursor {
                            new_cursor = e.timestamp as u64;
                        }
                        Some(serde_json::json!({
                            "type":        "audit",
                            "pid":         pid_clone,
                            "action":      e.action,
                            "outcome":     e.verdict,
                            "timestamp_ms": e.timestamp,
                            "details":     e.details,
                        }))
                    })
                    .collect()
            } else {
                vec![]
            }
        };

        // Prune old seen IDs to prevent memory leak (keep only recent ones)
        if seen.len() > 1000 {
            seen.clear();
        }
        drop(seen);

        *cursor.lock().unwrap() = new_cursor;

        // Emit a heartbeat even if no events (keeps connection alive, SSE keepalive handles it too)
        if events.is_empty() {
            let heartbeat = serde_json::json!({ "type": "heartbeat", "pid": pid_clone });
            Ok::<Event, Infallible>(
                Event::default()
                    .event("heartbeat")
                    .data(heartbeat.to_string()),
            )
        } else {
            let batch = serde_json::json!({ "type": "events", "events": events });
            Ok::<Event, Infallible>(Event::default().event("events").data(batch.to_string()))
        }
    });

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── B9: HITL (Human-in-the-Loop) approval gate ───────────────────────────────
//
// Agents with irreversible actions (delete, export, payment) can pause and
// submit a HITL approval request. An operator must approve or deny before the
// agent continues.
//
// Routes:
//   GET  /agents/:pid/hitl/pending              — list pending approval requests
//   POST /agents/:pid/hitl/:request_id/approve  — approve a pending request
//   POST /agents/:pid/hitl/:request_id/deny     — deny a pending request

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct HitlRequest {
    pub request_id: String,
    pub agent_pid: String,
    pub action: String,
    pub description: String,
    pub created_at: u64,
    pub timeout_at: Option<u64>,
    pub status: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<u64>,
    /// TG-1: SHA-256 hex of canonical ActionBinding (absent = legacy vibes HITL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_digest: Option<String>,
    /// TG-1: timeout never auto-allows (always true for digest-bound).
    #[serde(default = "hitl_fail_closed_default")]
    pub fail_closed_on_timeout: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_id: Option<String>,
}

fn hitl_fail_closed_default() -> bool {
    true
}

// In-process cache + durable engine_store folder (survives restart).
const HITL_FOLDER: &str = "iia_hitl_requests";

lazy_static::lazy_static! {
    static ref HITL_STORE: Mutex<HashMap<String, HitlRequest>> = Mutex::new(HashMap::new());
    static ref HITL_HYDRATED: Mutex<bool> = Mutex::new(false);
}

fn hitl_persist(state: &SharedState, req: &HitlRequest) {
    if let Ok(mut es) = state.engine_store.lock() {
        if let Ok(v) = serde_json::to_value(req) {
            let _ = es.folder_put(HITL_FOLDER, &req.request_id, &v);
        }
    }
}

/// Load durable HITL rows into memory once per process (merge, don't wipe).
pub fn hitl_ensure_hydrated(state: &SharedState) {
    {
        let done = HITL_HYDRATED.lock().unwrap();
        if *done {
            return;
        }
    }
    let keys = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(HITL_FOLDER, None).unwrap_or_default()
    };
    let mut store = HITL_STORE.lock().unwrap();
    for k in keys {
        let es = state.engine_store.lock().unwrap();
        if let Ok(Some(v)) = es.folder_get(HITL_FOLDER, &k) {
            if let Ok(req) = serde_json::from_value::<HitlRequest>(v) {
                store.entry(req.request_id.clone()).or_insert(req);
            }
        }
    }
    *HITL_HYDRATED.lock().unwrap() = true;
}

/// Read-only snapshot of in-memory HITL store (for authority gate checks).
pub fn hitl_store_snapshot() -> std::collections::HashMap<String, HitlRequest> {
    HITL_STORE.lock().unwrap().clone()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn hitl_timeout_ms() -> u64 {
    std::env::var("CONNECTOR_HITL_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(900)
        .saturating_mul(1000)
}

fn emit_hitl_webhook(
    state: &SharedState,
    event_type: &str,
    request: &HitlRequest,
    detail: serde_json::Value,
) {
    let payload = serde_json::json!({
        "request_id": request.request_id,
        "agent_pid": request.agent_pid,
        "action": request.action,
        "description": request.description,
        "status": request.status,
        "created_at": request.created_at,
        "timeout_at": request.timeout_at,
        "decided_by": request.decided_by,
        "decided_at": request.decided_at,
        "action_digest": request.action_digest,
        "policy_version": request.policy_version,
        "contract_digest": request.contract_digest,
        "fail_closed_on_timeout": request.fail_closed_on_timeout,
        "consumed_at": request.consumed_at,
        "resolution_id": request.resolution_id,
        "detail": detail,
    });
    let mut es = state.engine_store.lock().unwrap();
    webhooks::emit_event(&mut **es, event_type, payload);
}

fn expire_hitl_requests_matching(
    state: &SharedState,
    agent_pid: Option<&str>,
    request_id: Option<&str>,
) -> Vec<HitlRequest> {
    let now_ms = now_ms();
    let mut expired = Vec::new();
    {
        let mut store = HITL_STORE.lock().unwrap();
        for req in store.values_mut() {
            if req.status != "pending" {
                continue;
            }
            if agent_pid.map(|pid| req.agent_pid != pid).unwrap_or(false) {
                continue;
            }
            if request_id.map(|rid| req.request_id != rid).unwrap_or(false) {
                continue;
            }
            if req.timeout_at.unwrap_or(u64::MAX) > now_ms {
                continue;
            }
            req.status = "timed_out".to_string();
            req.decided_by = Some("system".to_string());
            req.decided_at = Some(now_ms);
            expired.push(req.clone());
        }
    }

    for req in &expired {
        hitl_persist(state, req);
        emit_hitl_webhook(
            state,
            "hitl.timed_out",
            req,
            serde_json::json!({
                "reason": "approval timeout exceeded"
            }),
        );
    }

    expired
}

pub fn sweep_expired_hitl_requests(state: &SharedState) -> usize {
    expire_hitl_requests_matching(state, None, None).len()
}

/// B17: POST /agents/:pid/hitl — create a HITL request (UI demos + tests).
#[derive(Debug, Deserialize)]
pub struct HitlCreateBody {
    pub action: String,
    pub description: Option<String>,
    /// TG-1: optional digest-bound fields (military-grade path).
    pub action_digest: Option<String>,
    pub binding: Option<serde_json::Value>,
    pub policy_version: Option<String>,
    pub contract_digest: Option<String>,
}

pub async fn hitl_create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<HitlCreateBody>,
) -> impl IntoResponse {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Authentication required", "status": 401})),
            )
                .into_response()
        }
    };
    if role.rank() < 3 {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "developer_required", "status": 403})),
        )
            .into_response();
    }
    let _ = user_id;
    let action = body.action.trim();
    if action.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "action_required", "status": 400})),
        )
            .into_response();
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "lifecycle",
        "create_hitl",
        &serde_json::json!({"pid": pid.as_str(), "action": action}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let description = body
        .description
        .unwrap_or_else(|| format!("HITL request for {action} (created by operator)"));

    // Prefer explicit digest; else derive from ActionBinding JSON if provided.
    let mut action_digest = body.action_digest.clone();
    let mut policy_version = body.policy_version.clone();
    let mut contract_digest = body.contract_digest.clone();
    if action_digest.is_none() {
        if let Some(ref b) = body.binding {
            if let Ok(binding) =
                serde_json::from_value::<crate::kernel::action_binding::ActionBinding>(b.clone())
            {
                action_digest = Some(binding.digest_hex());
                if policy_version.is_none() {
                    policy_version = Some(binding.policy_version.clone());
                }
                if contract_digest.is_none() {
                    contract_digest = binding.contract_digest.clone();
                }
            }
        }
    }

    let request_id = if let Some(ref digest) = action_digest {
        hitl_submit_bound(
            &pid,
            action,
            &description,
            digest,
            body.binding.clone(),
            policy_version,
            contract_digest,
            Some(&state),
        )
    } else {
        hitl_submit_with_state(&pid, action, &description, Some(&state))
    };
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "pid": pid,
        "request_id": request_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "action": action,
        "action_digest": action_digest,
        "status": "pending",
        "fail_closed_on_timeout": true,
        "approve_url": format!("/api/v1/agents/{pid}/hitl/{request_id}/approve"),
        "deny_url": format!("/api/v1/agents/{pid}/hitl/{request_id}/deny"),
    }))
    .into_response()
}

/// Pending HITL requests for identity envelope posture.
pub fn hitl_pending_count(agent_pid: &str) -> u64 {
    HITL_STORE
        .lock()
        .unwrap()
        .values()
        .filter(|r| r.agent_pid == agent_pid && r.status == "pending")
        .count() as u64
}

/// B19: count HITL decisions (approved/denied) in a time window for scorecards.
pub fn hitl_decisions_in_window(agent_pid: &str, from_ms: i64, to_ms: i64) -> (usize, usize) {
    let from = from_ms.max(0) as u64;
    let to = to_ms.max(0) as u64;
    let store = HITL_STORE.lock().unwrap();
    let mut approved = 0usize;
    let mut denied = 0usize;
    for r in store.values() {
        if r.agent_pid != agent_pid {
            continue;
        }
        let decided = r.decided_at.unwrap_or(r.created_at);
        if decided < from || decided > to {
            continue;
        }
        match r.status.as_str() {
            "approved" => approved += 1,
            "denied" => denied += 1,
            _ => {}
        }
    }
    (approved, denied)
}

/// GET /agents/:pid/hitl/pending — list all pending HITL requests for an agent.
pub async fn hitl_pending(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> impl IntoResponse {
    let (user_id, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Authentication required", "status": 401})),
            )
                .into_response()
        }
    };
    let _ = user_id;

    hitl_ensure_hydrated(&state);
    let _ = expire_hitl_requests_matching(&state, Some(&pid), None);

    let pending: Vec<HitlRequest> = HITL_STORE
        .lock()
        .unwrap()
        .values()
        .filter(|r| r.agent_pid == pid && r.status == "pending")
        .cloned()
        .collect();

    Json(serde_json::json!({
        "pid": pid,
        "pending": pending,
        "count": pending.len(),
    }))
    .into_response()
}

/// POST /agents/:pid/hitl/:request_id/approve — approve a pending HITL request.
pub async fn hitl_approve(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, request_id)): Path<(String, String)>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Authentication required", "status": 401})),
            )
                .into_response()
        }
    };

    if role.rank() < PlatformRole::Operator.rank() {
        // Playground session owners are JWT role=developer but must approve HITL for their agents.
        let playground_ok = crate::services::playground::is_playground_mode()
            && crate::services::playground::playground_session_id_from_headers(&headers).is_some();
        if !playground_ok {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Operator role required to approve HITL requests"
                })),
            )
                .into_response();
        }
    }

    let note = body
        .as_ref()
        .and_then(|b| b.get("note"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let now_ms = now_ms();

    let admitted = match crate::substrate::pate::admit_human_close(
        &state,
        &pid,
        "approve_hitl",
        &serde_json::json!({"pid": pid.as_str(), "request_id": request_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    hitl_ensure_hydrated(&state);
    let _ = expire_hitl_requests_matching(&state, Some(&pid), Some(&request_id));

    let mut store = HITL_STORE.lock().unwrap();
    match store.get_mut(&request_id) {
        Some(req) if req.agent_pid == pid && req.status == "pending" => {
            let resolution_id = format!("res_{}", Uuid::new_v4());
            req.status = "approved".to_string();
            req.decided_by = Some(user_id.clone());
            req.decided_at = Some(now_ms);
            req.resolution_id = Some(resolution_id.clone());
            let action = req.action.clone();
            let req_snapshot = req.clone();
            drop(store);
            hitl_persist(&state, &req_snapshot);

            // ── ADMISSION GATE: Unquarantine on HITL approve ─────────────
            // If this HITL request was for unquarantine, release the agent.
            if action == "unquarantine" {
                crate::services::admission::unquarantine_agent(&state, &pid, &user_id);
                let _ = crate::substrate::cvr::lifecycle::apply_resume_ex(
                    &state, &pid, &user_id, true,
                );
            }

            emit_hitl_webhook(
                &state,
                "hitl.approved",
                &req_snapshot,
                serde_json::json!({
                    "note": note,
                    "approved_by": user_id,
                    "action_digest": req_snapshot.action_digest,
                    "resolution_id": resolution_id,
                }),
            );
            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "ok": true,
                "status": 200,
                "request_id": request_id,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "status_hitl": "approved",
                "decided_by": req_snapshot.decided_by,
                "action": action,
                "action_digest": req_snapshot.action_digest,
                "policy_version": req_snapshot.policy_version,
                "resolution_id": resolution_id,
                "note": note,
                "timeout_at": req_snapshot.timeout_at,
                "fail_closed_on_timeout": req_snapshot.fail_closed_on_timeout,
                "quarantine_released": action == "unquarantine",
                "human_approval_cleared": action == "unquarantine",
                "http_resume": 200,
                "message": if action == "unquarantine" {
                    "agent resumed — LLM talk returns to normal HTTP 200 after human approval"
                } else {
                    "HITL approved"
                },
                "broker_note": "409/499 cannot be bypassed; sandbox reopened on new epoch",
                "honesty": "TG-1 — approval is digest-bound; execute path must consume once after revalidate",
            })).into_response()
        }
        Some(req) if req.status == "timed_out" => (
            StatusCode::GONE,
            Json(serde_json::json!({
                "error": "hitl_timed_out_fail_closed",
                "status": "timed_out",
                "fail_closed_on_timeout": req.fail_closed_on_timeout,
                "honesty": "Timeout never auto-allows",
            })),
        )
            .into_response(),
        Some(req) if req.status != "pending" => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("Request already {}", req.status)
            })),
        )
            .into_response(),
        _ => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "HITL request not found for this agent"
            })),
        )
            .into_response(),
    }
}

/// POST /agents/:pid/hitl/:request_id/deny — deny a pending HITL request.
pub async fn hitl_deny(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, request_id)): Path<(String, String)>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Authentication required", "status": 401})),
            )
                .into_response()
        }
    };

    if role.rank() < PlatformRole::Operator.rank() {
        let playground_ok = crate::services::playground::is_playground_mode()
            && crate::services::playground::playground_session_id_from_headers(&headers).is_some();
        if !playground_ok {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Operator role required to deny HITL requests"
                })),
            )
                .into_response();
        }
    }

    let reason = body
        .as_ref()
        .and_then(|b| b.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or("No reason provided")
        .to_string();

    let now_ms = now_ms();

    let admitted = match crate::substrate::pate::admit_human_close(
        &state,
        &pid,
        "deny_hitl",
        &serde_json::json!({"pid": pid.as_str(), "request_id": request_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    hitl_ensure_hydrated(&state);
    let _ = expire_hitl_requests_matching(&state, Some(&pid), Some(&request_id));

    let mut store = HITL_STORE.lock().unwrap();
    match store.get_mut(&request_id) {
        Some(req) if req.agent_pid == pid && req.status == "pending" => {
            req.status = "denied".to_string();
            req.decided_by = Some(user_id.clone());
            req.decided_at = Some(now_ms);
            let action = req.action.clone();
            let req_snapshot = req.clone();
            drop(store);
            hitl_persist(&state, &req_snapshot);
            emit_hitl_webhook(
                &state,
                "hitl.denied",
                &req_snapshot,
                serde_json::json!({
                    "reason": reason,
                    "denied_by": user_id,
                }),
            );
            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "ok": true,
                "request_id": request_id,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "status": "denied",
                "decided_by": req_snapshot.decided_by,
                "action": action,
                "reason": reason,
                "timeout_at": req_snapshot.timeout_at,
            }))
            .into_response()
        }
        Some(req) if req.status != "pending" => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("Request already {}", req.status)
            })),
        )
            .into_response(),
        _ => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "HITL request not found for this agent"
            })),
        )
            .into_response(),
    }
}

/// Submit a new HITL approval request (called from agent dispatch layer).
/// Returns the `request_id` the agent should poll.
pub fn hitl_submit(agent_pid: &str, action: &str, description: &str) -> String {
    hitl_submit_with_state(agent_pid, action, description, None)
}

/// Submit a new HITL approval request with optional SharedState for webhook delivery.
///
/// When `state` is provided:
/// 1. Fires `hitl.requested` via the generic webhook subsystem (`webhooks::emit_event`)
/// 2. POSTs a JSON payload to `CONNECTOR_APPROVAL_WEBHOOK_URL` env var (if set) for
///    direct out-of-band operator notification without requiring webhook registration.
pub fn hitl_submit_with_state(
    agent_pid: &str,
    action: &str,
    description: &str,
    state: Option<&SharedState>,
) -> String {
    hitl_submit_bound(agent_pid, action, description, "", None, None, None, state)
}

/// TG-1: create digest-bound HITL (empty digest → legacy unbound request).
pub fn hitl_submit_bound(
    agent_pid: &str,
    action: &str,
    description: &str,
    action_digest: &str,
    binding: Option<serde_json::Value>,
    policy_version: Option<String>,
    contract_digest: Option<String>,
    state: Option<&SharedState>,
) -> String {
    // Reuse pending request for same agent+digest (idempotent Ask).
    if !action_digest.is_empty() {
        let _ = expire_hitl_requests_matching_local(Some(agent_pid), None);
        let store = HITL_STORE.lock().unwrap();
        if let Some(existing) = store.values().find(|r| {
            r.agent_pid == agent_pid
                && r.status == "pending"
                && r.action_digest.as_deref() == Some(action_digest)
        }) {
            return existing.request_id.clone();
        }
    }

    let request_id = Uuid::new_v4().to_string();
    let now_ms = now_ms();
    let timeout_at = Some(now_ms.saturating_add(hitl_timeout_ms()));
    let bound = !action_digest.is_empty();

    let req = HitlRequest {
        request_id: request_id.clone(),
        agent_pid: agent_pid.to_string(),
        action: action.to_string(),
        description: description.to_string(),
        created_at: now_ms,
        timeout_at,
        status: "pending".to_string(),
        decided_by: None,
        decided_at: None,
        action_digest: if bound {
            Some(action_digest.to_string())
        } else {
            None
        },
        binding,
        policy_version,
        contract_digest,
        fail_closed_on_timeout: true,
        consumed_at: None,
        resolution_id: None,
    };
    HITL_STORE
        .lock()
        .unwrap()
        .insert(request_id.clone(), req.clone());

    if let Some(state) = state {
        hitl_ensure_hydrated(state);
        hitl_persist(state, &req);
        emit_hitl_webhook(
            state,
            "hitl.requested",
            &req,
            serde_json::json!({
                "approve_url": format!("/api/v1/agents/{}/hitl/{}/approve", agent_pid, request_id),
                "deny_url":    format!("/api/v1/agents/{}/hitl/{}/deny",    agent_pid, request_id),
                "timeout_secs": hitl_timeout_ms() / 1000,
                "action_digest": req.action_digest,
            }),
        );

        deliver_hitl_direct_webhook(&req);
    }

    request_id
}

/// Local expire helper without SharedState (webhook skipped) for submit_bound reuse scan.
fn expire_hitl_requests_matching_local(
    agent_pid: Option<&str>,
    request_id: Option<&str>,
) -> Vec<HitlRequest> {
    let now_ms = now_ms();
    let mut expired = Vec::new();
    let mut store = HITL_STORE.lock().unwrap();
    for req in store.values_mut() {
        if req.status != "pending" {
            continue;
        }
        if agent_pid.map(|pid| req.agent_pid != pid).unwrap_or(false) {
            continue;
        }
        if request_id.map(|rid| req.request_id != rid).unwrap_or(false) {
            continue;
        }
        if req.timeout_at.unwrap_or(u64::MAX) > now_ms {
            continue;
        }
        req.status = "timed_out".to_string();
        req.decided_by = Some("system".to_string());
        req.decided_at = Some(now_ms);
        expired.push(req.clone());
    }
    expired
}

/// Lookup HITL request status for Workbench resume gating (None = unknown).
pub fn hitl_status(agent_pid: &str, request_id: &str) -> Option<String> {
    let store = HITL_STORE.lock().ok()?;
    store.get(request_id).and_then(|r| {
        if r.agent_pid == agent_pid {
            Some(r.status.clone())
        } else {
            None
        }
    })
}

/// Workbench helper: mark a pending HITL request approved/denied without HTTP auth context.
pub fn hitl_mark_resolved(
    agent_pid: &str,
    request_id: &str,
    status: &str,
    decided_by: &str,
) -> bool {
    let now = now_ms();
    let mut store = HITL_STORE.lock().unwrap();
    if let Some(req) = store.get_mut(request_id) {
        if req.agent_pid == agent_pid && req.status == "pending" {
            req.status = status.to_string();
            req.decided_by = Some(decided_by.to_string());
            req.decided_at = Some(now);
            return true;
        }
    }
    false
}

/// TG-1: one-time consume of an approved digest-bound HITL after revalidation.
///
/// Fail-closed: timeout, digest mismatch, policy/contract drift, already consumed → Err.
pub fn hitl_consume_for_action(
    state: Option<&SharedState>,
    agent_pid: &str,
    action_digest: &str,
    expected_policy_version: Option<&str>,
    expected_contract_digest: Option<&str>,
) -> Result<HitlRequest, String> {
    if action_digest.is_empty() {
        return Err("action_digest_required".into());
    }
    if let Some(st) = state {
        hitl_ensure_hydrated(st);
    }
    let _ = expire_hitl_requests_matching_local(Some(agent_pid), None);
    let now = now_ms();
    let mut store = HITL_STORE.lock().unwrap();

    let key = store
        .iter()
        .find(|(_, r)| {
            r.agent_pid == agent_pid
                && r.status == "approved"
                && r.consumed_at.is_none()
                && r.action_digest.as_deref() == Some(action_digest)
        })
        .map(|(k, _)| k.clone());

    let Some(key) = key else {
        return Err("hitl_approval_not_found".into());
    };

    let req = store
        .get_mut(&key)
        .ok_or_else(|| "hitl_approval_not_found".to_string())?;

    if req.timeout_at.unwrap_or(u64::MAX) <= now {
        req.status = "timed_out".to_string();
        let snap = req.clone();
        drop(store);
        if let Some(st) = state {
            hitl_persist(st, &snap);
        }
        return Err("hitl_timed_out_fail_closed".into());
    }

    if let Some(exp) = expected_policy_version {
        if req.policy_version.as_deref().unwrap_or("") != exp {
            return Err("hitl_policy_version_mismatch".into());
        }
    }
    if let Some(exp) = expected_contract_digest {
        if req.contract_digest.as_deref().unwrap_or("") != exp {
            return Err("hitl_contract_digest_mismatch".into());
        }
    }
    if req.action_digest.as_deref() != Some(action_digest) {
        return Err("hitl_action_digest_mismatch".into());
    }

    req.consumed_at = Some(now);
    req.status = "consumed".to_string();
    if req.resolution_id.is_none() {
        req.resolution_id = Some(format!("res_{}", Uuid::new_v4()));
    }
    let snap = req.clone();
    drop(store);
    if let Some(st) = state {
        hitl_persist(st, &snap);
    }
    Ok(snap)
}

#[cfg(test)]
mod hitl_binding_tests {
    use super::*;

    #[test]
    fn digest_a_cannot_execute_as_digest_b() {
        let dig_a = "a".repeat(64);
        let dig_b = "b".repeat(64);
        let id = hitl_submit_bound(
            "agent_t",
            "tool.dispatch",
            "test",
            &dig_a,
            None,
            Some("1".into()),
            Some("cd".into()),
            None,
        );
        {
            let mut store = HITL_STORE.lock().unwrap();
            let r = store.get_mut(&id).unwrap();
            r.status = "approved".to_string();
            r.decided_by = Some("op".into());
            r.decided_at = Some(now_ms());
        }
        assert!(hitl_consume_for_action(None, "agent_t", &dig_b, Some("1"), Some("cd")).is_err());
        assert!(hitl_consume_for_action(None, "agent_t", &dig_a, Some("1"), Some("cd")).is_ok());
        // One-time consume
        assert!(hitl_consume_for_action(None, "agent_t", &dig_a, Some("1"), Some("cd")).is_err());
    }

    #[test]
    fn policy_version_change_invalidates() {
        let dig = "c".repeat(64);
        let id = hitl_submit_bound(
            "agent_p",
            "tool.dispatch",
            "test",
            &dig,
            None,
            Some("1".into()),
            Some("cd".into()),
            None,
        );
        {
            let mut store = HITL_STORE.lock().unwrap();
            let r = store.get_mut(&id).unwrap();
            r.status = "approved".to_string();
        }
        assert_eq!(
            hitl_consume_for_action(None, "agent_p", &dig, Some("2"), Some("cd")).unwrap_err(),
            "hitl_policy_version_mismatch"
        );
    }

    #[test]
    fn timeout_fails_closed_never_consumes() {
        let dig = "d".repeat(64);
        let id = hitl_submit_bound(
            "agent_to",
            "tool.dispatch",
            "test",
            &dig,
            None,
            Some("1".into()),
            Some("cd".into()),
            None,
        );
        {
            let mut store = HITL_STORE.lock().unwrap();
            let r = store.get_mut(&id).unwrap();
            r.status = "approved".to_string();
            r.timeout_at = Some(1); // already expired
        }
        assert_eq!(
            hitl_consume_for_action(None, "agent_to", &dig, Some("1"), Some("cd")).unwrap_err(),
            "hitl_timed_out_fail_closed"
        );
    }
}

/// Deliver HITL payload to `CONNECTOR_APPROVAL_WEBHOOK_URL` via a blocking HTTP POST.
///
/// This is a *fire-and-forget* best-effort delivery — failures are logged but do not
/// block the agent. Uses `reqwest::blocking` so we stay inside a sync fn.
fn deliver_hitl_direct_webhook(req: &HitlRequest) {
    let url = match std::env::var("CONNECTOR_APPROVAL_WEBHOOK_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return,
    };

    let payload = serde_json::json!({
        "event":       "hitl.requested",
        "request_id":  req.request_id,
        "agent_pid":   req.agent_pid,
        "action":      req.action,
        "description": req.description,
        "status":      req.status,
        "created_at":  req.created_at,
        "timeout_at":  req.timeout_at,
        "approve_url": format!("/api/v1/agents/{}/hitl/{}/approve", req.agent_pid, req.request_id),
        "deny_url":    format!("/api/v1/agents/{}/hitl/{}/deny",    req.agent_pid, req.request_id),
    });

    // Best-effort: log delivery failures but never panic / block agent dispatch.
    match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .and_then(|c| c.post(&url).json(&payload).send())
    {
        Ok(r) => {
            if !r.status().is_success() {
                tracing::warn!(
                    "HITL webhook delivery to {} returned status {}",
                    url,
                    r.status()
                );
            }
        }
        Err(e) => {
            tracing::warn!("HITL webhook delivery to {} failed: {}", url, e);
        }
    }
}

// =============================================================================
// CMD-1: Agent clone — fork(2) analog
// =============================================================================

/// POST /agents/{pid}/clone — fork agent: copy ACB, new PID, parent_pid set.
///
/// Child inherits: name, role, namespace, tool_bindings, execution_policy.
/// Child starts in `Registered` state with 50% of parent's remaining token budget.
pub async fn clone_agent(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (caller_user_id, role) = match crate::services::intelligence_authority::require_lifecycle_actor(
        &headers, 4,
    ) {
        Ok(c) => c,
        Err(v) => return Json(v),
    };

    let new_name = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // FIX BUG-006: Resolve API PID to kernel PID
    let (kernel_pid, _) = resolve_kernel_pid(&state, &pid);

    // Fetch parent ACB from kernel
    let parent_acb = {
        let k = state.kernel.lock().unwrap();
        k.get_agent(&kernel_pid).cloned()
    };

    let parent = match parent_acb {
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": {"code": "agent_not_found", "message": format!("agent {} not found", pid), "status": 404}
            }))
        }
        Some(a) => a,
    };

    let tenant_cap = tenant_from_headers_for_cap(&headers);
    if let Err(j) = kernel_agent_limit_gate(state.as_ref(), tenant_cap.as_ref()) {
        return Json(j);
    }

    // Build new agent name
    let child_name = new_name.unwrap_or_else(|| format!("{}-clone", parent.agent_name));

    // Token budget: 50% of parent remaining by default
    let budget_slice = body.get("token_budget").and_then(|v| v.as_u64());
    let parent_remaining = {
        parent
            .token_budget
            .as_ref()
            .map(|b| b.daily_limit.saturating_sub(b.used_today))
            .unwrap_or(100_000)
    };
    let child_budget = budget_slice.unwrap_or(parent_remaining / 2);
    let parent_namespace = parent.namespace.clone();
    let parent_role = format!("{:?}", parent.role);
    let parent_model = parent.model.clone();
    let parent_framework = parent.framework.clone();

    // Register child via kernel progeny (parent = kernel_pid)
    let actor = crate::substrate::agent_lifecycle_gate::LifecycleActor::operator(
        &caller_user_id,
        role,
        "http:clone",
    );
    let child_kernel_pid = match crate::substrate::agent_progeny::register_with_progeny(
        &state,
        crate::substrate::agent_progeny::KernelRegisterParams {
            agent_name: &child_name,
            namespace: &parent_namespace,
            role: Some(parent_role.clone()),
            model: parent_model.clone(),
            framework: parent_framework.clone(),
            parent_kernel_pid: Some(&kernel_pid),
            reason: format!("clone of {}", pid),
        },
        &actor,
    ) {
        Ok(p) => p,
        Err(e) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": {"code": "clone_failed", "message": e.message(), "status": 403}
            }));
        }
    };

    let child_pid = format!(
        "agent_{}",
        uuid::Uuid::new_v4().to_string().replace('-', "")
    );

    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            "agent_meta",
            &child_pid,
            &serde_json::json!({
                "pid": child_pid,
                "kernel_pid": child_kernel_pid,
                "parent_kernel_pid": kernel_pid,
                "parent_pid": pid,
                "cloned_from": pid,
                "child_name": child_name,
                "token_budget_initial": child_budget,
                "cloned_at": chrono::Utc::now().to_rfc3339(),
                "user_id": caller_user_id,
                "created_by": caller_user_id,
            }),
        );
        let _ = es.folder_put(
            "agent_pid_map",
            &child_kernel_pid,
            &serde_json::json!(child_pid),
        );
    }

    Json(serde_json::json!({
        "ok": true,
        "child_pid": child_pid,
        "kernel_pid": child_kernel_pid,
        "parent_pid": pid,
        "parent_kernel_pid": kernel_pid,
        "name": child_name,
        "namespace": parent_namespace,
        "role": parent_role,
        "token_budget": child_budget,
        "state": "active",
        "cloned_at": chrono::Utc::now().to_rfc3339(),
    }))
}

#[cfg(test)]
mod charter_tests {
    use super::charter_purpose;

    #[test]
    fn rejects_empty_and_generic() {
        assert!(charter_purpose(None).is_err());
        assert!(charter_purpose(Some("")).is_err());
        assert!(charter_purpose(Some("  ")).is_err());
        assert!(charter_purpose(Some("general")).is_err());
        assert!(charter_purpose(Some("General-purpose foo assistant")).is_err());
        assert_eq!(
            charter_purpose(Some("Guard src/ writes for junior Cursor")).unwrap(),
            "Guard src/ writes for junior Cursor"
        );
    }
}
