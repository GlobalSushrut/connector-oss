//! Operating layer — this is the AIOS architecture.
//!
//! Connector does not implement LangGraph, Crew, vLLM, or Ollama.
//! Those products do what they do. This module is what Connector *is*:
//!
//!   APP / DEVICE  →  three sockets  →  operate (admit, WM, stop)  →  host
//!
//! Kernel types: I, A, WM packet, grant, device URL.
//! Kernel never: LangGraph, Crew, VllmScheduler, OllamaClient, LLM-as-CPU.
//!
//! CPU is CPU. GPU is GPU. Intelligence is chartered I (Albus SP·WM·VJ·BG).
//! Newell 1982 knowledge level · Albus 1991 · Engler 1995 sit-beneath.

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use super::nsfs;
use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.operating_layer.v1";

/// The only three ways an app or device talks to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socket {
    /// POST /v1/chat/completions — OpenAI SDK, LangGraph, Crew, vLLM, Ollama.
    Completion,
    /// POST /kernel/syscall — WM, interrupt, access. Framework-blind ABI.
    Syscall,
    /// CONP + grant + portal — robots, A2A, MCP bind.
    World,
}

impl Socket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completion => "completion",
            Self::Syscall => "syscall",
            Self::World => "world",
        }
    }
}

/// Types the kernel is allowed to name. Anything else is a vendor leak.
pub const KERNEL_SEES: &[&str] = &["I", "A", "WM packet", "grant", "device URL"];

/// If these strings appear as types under kernel/, universality has failed.
pub const KERNEL_NEVER: &[&str] = &[
    "LangGraph",
    "Crew",
    "VllmScheduler",
    "OllamaClient",
    "AutoGen",
    "StateGraph",
];

struct CrossingLog {
    entries: VecDeque<Value>,
}

fn log() -> &'static Mutex<CrossingLog> {
    static L: OnceLock<Mutex<CrossingLog>> = OnceLock::new();
    L.get_or_init(|| {
        Mutex::new(CrossingLog {
            entries: VecDeque::with_capacity(256),
        })
    })
}

/// Record one crossing. Completion, syscall, and world all go here.
pub fn record(socket: Socket, agent_pid: &str, op: &str, ok: bool, detail: &Value) {
    if let Ok(mut s) = log().lock() {
        s.entries.push_back(json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "socket": socket.as_str(),
            "agent_pid": agent_pid,
            "op": op,
            "ok": ok,
            "detail": detail,
        }));
        while s.entries.len() > 256 {
            s.entries.pop_front();
        }
    }
}

pub fn recent(limit: usize) -> Vec<Value> {
    let n = limit.max(1).min(256);
    log()
        .lock()
        .map(|s| s.entries.iter().rev().take(n).cloned().collect())
        .unwrap_or_default()
}

pub fn recent_json(limit: usize) -> Value {
    json!({
        "ok": true,
        "schema": SCHEMA,
        "crossings": recent(limit),
    })
}

/// Architecture the claim ABI and ACS expose. Not a vendor list.
pub fn spec() -> Value {
    json!({
        "schema": SCHEMA,
        "role": "manage + operate; apps and devices interchangeable",
        "sockets": {
            "completion": "POST /v1/chat/completions",
            "syscall": "POST /kernel/syscall",
            "world": "CONP + grant + portal"
        },
        "kernel_sees": KERNEL_SEES,
        "kernel_never_sees": KERNEL_NEVER,
        "universality": "swap vLLM↔Ollama↔OpenAI and LangGraph↔Crew without changing μ",
        "albus": ["SP", "WM", "VJ", "BG-socket"],
        "kinds": {
            "cpu": "device",
            "gpu": "device",
            "intelligence": "chartered I"
        },
        "wm": {
            "sot": ["/m/core", "/m/recall", "/k"],
            "rag": "cache of VAC packets — never SoT",
            "fleet_share": "share portal only, never ambient /k"
        },
        "absorb": absorb_catalog(),
        "fleet": {
            "unit": "many I cells",
            "concurrency": "parallel across I; per-I inflight cap on thinking",
            "not": "one LangGraph supervisor"
        }
    })
}

/// How the outside AI world enters the node. Future vendors use the same rows.
pub fn absorb_catalog() -> Value {
    json!({
        "device": {
            "kernel_kind": "openai_compat_url",
            "bind": "connectorctl llm link / POST /settings/llms/link",
            "known": [
                "openai", "anthropic", "azure", "bedrock", "vertex",
                "ollama", "vllm", "lmstudio", "groq", "together",
                "mistral", "deepseek", "openrouter", "fireworks",
                "openai_compatible_custom"
            ],
            "future": "Any OpenAI-compat (or Anthropic/Gemini wire) URL. Kernel adds no vendor crate. vLLM and Ollama are disks.",
            "not": "VllmScheduler / OllamaClient in kernel/"
        },
        "thinker": {
            "kernel_kind": "BG method emitting A",
            "bind": "OPENAI_BASE_URL=/v1 (docs/99)",
            "known": ["LangGraph", "Crew", "AutoGen", "MAF", "Talk", "script"],
            "future": "Any client that can POST /v1/chat/completions. Kernel does not import the graph type."
        },
        "resource": {
            "kernel_kind": "SP/BG resource behind admit",
            "bind": "charter + world grant / MCP bind / CONP",
            "known": ["mcp", "http_api", "webhook", "conp", "a2a", "mqtt"],
            "future": "New tool = new bind on I + typed A. Kernel is the port, not a catalog of 6000 servers."
        },
        "memory_client": {
            "kernel_kind": "WM client",
            "bind": "POST /kernel/syscall memory.* / wm.retrieve",
            "known": ["Letta", "Mem0", "LlamaIndex"],
            "future": "Their DB stays cache. /m /k stay SoT."
        }
    })
}

/// Classify a linked engine. Kernel stores a device URL, not a vendor type.
pub fn classify_device(provider: &str, endpoint: Option<&str>) -> Value {
    let p = provider.trim().to_ascii_lowercase();
    let openai_compat = !matches!(p.as_str(), "anthropic" | "gemini");
    json!({
        "provider_label": p,
        "kind": "device",
        "wire": if openai_compat { "openai_compat" } else { p.as_str() },
        "endpoint": endpoint,
        "kernel_type": "device URL",
        "honesty": "vLLM, Ollama, OpenAI, and tomorrow’s server are the same kind."
    })
}

/// Albus time-level from existing clocks. Labels only — no new runtime.
pub fn classify_level(
    horizon_param: Option<&str>,
    has_open_mission: bool,
    has_open_fabric: bool,
) -> &'static str {
    if let Some(h) = horizon_param {
        match h.trim() {
            "servo" => return "servo",
            "task" => return "task",
            "mission" => return "mission",
            "shop" => return "shop",
            _ => {}
        }
    }
    if has_open_fabric {
        "shop"
    } else if has_open_mission {
        "task"
    } else {
        "servo"
    }
}

pub fn level_for(state: &PlatformState, agent_pid: &str) -> Value {
    let horizon = crate::kernel::intelligence_spec::load_spec_doc(state, agent_pid)
        .and_then(|s| {
            s.pointer("/spec/parameters/horizon")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        });
    let mission = has_open_mission(state, agent_pid);
    let fabric = has_open_fabric(state, agent_pid);
    let level = classify_level(horizon.as_deref(), mission, fabric);
    json!({
        "level": level,
        "clocks": {
            "quantum": "servo",
            "mission": "task",
            "fabric": "shop"
        },
        "active": {
            "open_mission": mission,
            "open_fabric": fabric,
            "horizon_param": horizon,
        },
        "honesty": "Names existing clocks. Does not invent a LangGraph supervisor."
    })
}

fn has_open_mission(state: &PlatformState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return false;
    };
    let keys = es
        .folder_keys(crate::kernel::mission_journal::MISSION_FOLDER, None)
        .unwrap_or_default();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(crate::kernel::mission_journal::MISSION_FOLDER, &k) {
            let pid = v.get("agent_pid").and_then(|x| x.as_str()).unwrap_or("");
            let st = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
            if pid == agent_pid && (st == "open" || st == "waiting_hitl") {
                return true;
            }
        }
    }
    false
}

fn has_open_fabric(state: &PlatformState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return false;
    };
    let keys = es
        .folder_keys(crate::kernel::fabric_task::FABRIC_TASK_FOLDER, None)
        .unwrap_or_default();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(crate::kernel::fabric_task::FABRIC_TASK_FOLDER, &k) {
            let from = v.get("from_pid").and_then(|x| x.as_str()).unwrap_or("");
            let to = v.get("to_pid").and_then(|x| x.as_str()).unwrap_or("");
            let st = v.get("state").and_then(|x| x.as_str()).unwrap_or("");
            let terminal = matches!(
                st,
                "COMPLETED" | "FAILED" | "CANCELED" | "CANCELLED" | "REJECTED"
            );
            if !terminal && (from == agent_pid || to == agent_pid) {
                return true;
            }
        }
    }
    false
}

/// WM paging prompt injected into Talk. Any framework that hits /v1 sees this.
pub fn wm_prompt(agent_pid: &str) -> String {
    let _ = crate::kernel::aios::ensure_memory_os(agent_pid);
    let persona_len = crate::kernel::aios::core_get(agent_pid, "persona")
        .ok()
        .and_then(|v| v.get("value").and_then(|x| x.as_str()).map(|s| s.len()))
        .unwrap_or(0);
    let paging = if persona_len > 1800 {
        "Core is full — use memory.archival.insert then memory.core.set to evict, or memory.knowledge.search."
    } else {
        "World model SoT is /m (core, recall) and /k (knowledge). App RAG is cache."
    };
    format!(
        "{paging}\nSyscalls (POST /kernel/syscall, same for LangGraph/Crew/scripts): memory.core.set, memory.recall.search, memory.archival.insert, memory.knowledge.search, council.inbox, council.speak, llm.interrupt."
    )
}

/// Search this I's /k tree (knowledge SoT). With state, also licensed portal /k (not ambient).
pub fn knowledge_search(agent_pid: &str, query: &str, limit: usize) -> Result<Value, String> {
    knowledge_search_ctx(None, agent_pid, query, limit)
}

pub fn knowledge_search_ctx(
    state: Option<&PlatformState>,
    agent_pid: &str,
    query: &str,
    limit: usize,
) -> Result<Value, String> {
    let _ = crate::kernel::aios::ensure_memory_os(agent_pid)?;
    let cap = limit.max(1).min(50);
    let q = query.trim().to_lowercase();
    let mut hits = Vec::new();
    let root = nsfs::nsfs_root(agent_pid)?.join("k");
    let contain = nsfs::nsfs_root(agent_pid)?;
    walk_text(&root, &contain, &q, cap, agent_pid, "own", &mut hits);
    if let Some(st) = state {
        for portal in crate::kernel::share_portal::list_portals(st, Some(agent_pid)) {
            let from = portal.get("from_pid").and_then(|x| x.as_str()).unwrap_or("");
            let to = portal.get("to_pid").and_then(|x| x.as_str()).unwrap_or("");
            let what = portal.get("what").and_then(|x| x.as_str()).unwrap_or("");
            let peer = if to == agent_pid { from } else { continue };
            if peer.is_empty() || peer == agent_pid {
                continue;
            }
            let kish = {
                let w = what.trim().to_ascii_lowercase();
                w == "k"
                    || w == "/k"
                    || w.starts_with("/k/")
                    || w == "knowledge"
                    || w.starts_with("knowledge/")
            };
            if !kish {
                continue;
            }
            if !crate::kernel::share_portal::portal_quota_ok(&portal) {
                continue;
            }
            let portal_id = portal
                .get("portal_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let before = hits.len();
            if let Ok(peer_root) = nsfs::nsfs_root(peer) {
                walk_text(&peer_root.join("k"), &peer_root, &q, cap, peer, "portal", &mut hits);
            }
            let added: u64 = hits
                .get(before..)
                .map(|slice| slice.iter().map(|h| h.to_string().len() as u64).sum())
                .unwrap_or(0);
            if added > 0 && !portal_id.is_empty() {
                if crate::kernel::share_portal::record_portal_use(st, &portal_id, added, 1).is_err()
                {
                    hits.truncate(before);
                }
            }
        }
    }
    Ok(json!({
        "ok": true,
        "query": query,
        "hits": hits,
        "sot": "/k",
        "honesty": "App vector stores are cache. Portal /k only after a share contract."
    }))
}

/// Unified WM retrieve: recall + /k + VAC RAG-as-cache + portal pores.
pub fn wm_retrieve(
    state: Option<&PlatformState>,
    agent_pid: &str,
    query: &str,
    limit: usize,
) -> Value {
    let n = limit.max(1).min(12);
    let recall = crate::kernel::aios::recall_search(agent_pid, query, n)
        .ok()
        .and_then(|v| v.get("hits").cloned())
        .unwrap_or(json!([]));
    let knowledge = knowledge_search_ctx(state, agent_pid, query, n)
        .ok()
        .and_then(|v| v.get("hits").cloned())
        .unwrap_or(json!([]));
    let mut rag_cache = Vec::new();
    if let Some(st) = state {
        if !query.trim().is_empty() {
            if let Ok(mut kernel) = st.kernel.lock() {
                let ns = kernel
                    .get_agent(agent_pid)
                    .map(|a| a.namespace.clone())
                    .unwrap_or_else(|| format!("gateway/{agent_pid}"));
                for doc in kernel.recall_by_similarity(query, &ns, n) {
                    rag_cache.push(json!({
                        "text": doc.text,
                        "layer": "rag_cache",
                    }));
                }
            }
        }
    }
    let archival = crate::kernel::aios::archival_search(agent_pid, query, n)
        .ok()
        .and_then(|v| v.get("hits").cloned())
        .unwrap_or(json!([]));
    json!({
        "ok": true,
        "schema": "connector.wm.retrieve.v1",
        "agent_pid": agent_pid,
        "query": query,
        "recall": recall,
        "knowledge": knowledge,
        "archival": archival,
        "rag_cache": rag_cache,
        "honesty": "recall+/k/archival = WM SoT. rag_cache = VAC similarity, not truth. Fleet share = portal only."
    })
}

/// Talk/Anthropic inject string. Any thinker on /v1 gets the same WM.
pub fn wm_retrieve_prompt(
    state: Option<&PlatformState>,
    agent_pid: &str,
    query: &str,
) -> String {
    if query.trim().is_empty() {
        return String::new();
    }
    let v = wm_retrieve(state, agent_pid, query, 8);
    let mut out = String::from(
        "=== WORLD MODEL (SoT /m /k; RAG is cache; do not invent memories) ===\n",
    );
    let mut used = 0usize;
    if let Some(hits) = v["recall"].as_array() {
        for h in hits {
            let t = h.get("text").and_then(|x| x.as_str()).unwrap_or("");
            append_wm_line(&mut out, &mut used, "RECALL", t);
        }
    }
    if let Some(hits) = v["knowledge"].as_array() {
        for h in hits {
            let t = h.get("snippet").and_then(|x| x.as_str()).unwrap_or("");
            append_wm_line(&mut out, &mut used, "KNOWLEDGE", t);
        }
    }
    if let Some(hits) = v["archival"].as_array() {
        for h in hits {
            let t = h.get("text").and_then(|x| x.as_str()).unwrap_or("");
            append_wm_line(&mut out, &mut used, "ARCHIVAL", t);
        }
    }
    if let Some(hits) = v["rag_cache"].as_array() {
        for h in hits {
            let t = h.get("text").and_then(|x| x.as_str()).unwrap_or("");
            append_wm_line(&mut out, &mut used, "RAG-CACHE", t);
        }
    }
    if used == 0 {
        return String::new();
    }
    out.push_str(
        "=== END WORLD MODEL ===\nPrefer SoT (RECALL/KNOWLEDGE/ARCHIVAL) over RAG-CACHE. Persist via /kernel/syscall.\n",
    );
    out
}

/// Recall + /k only (no VAC). Gateway keeps existing RAG block intact and prepends this.
pub fn wm_sot_prompt(
    state: Option<&PlatformState>,
    agent_pid: &str,
    query: &str,
) -> String {
    if query.trim().is_empty() {
        return String::new();
    }
    let v = wm_retrieve(state, agent_pid, query, 8);
    let mut out = String::from("=== WORLD MODEL SoT (/m recall, /k, archival) ===\n");
    let mut used = 0usize;
    if let Some(hits) = v["recall"].as_array() {
        for h in hits {
            let t = h.get("text").and_then(|x| x.as_str()).unwrap_or("");
            append_wm_line(&mut out, &mut used, "RECALL", t);
        }
    }
    if let Some(hits) = v["knowledge"].as_array() {
        for h in hits {
            let t = h.get("snippet").and_then(|x| x.as_str()).unwrap_or("");
            append_wm_line(&mut out, &mut used, "KNOWLEDGE", t);
        }
    }
    if let Some(hits) = v["archival"].as_array() {
        for h in hits {
            let t = h.get("text").and_then(|x| x.as_str()).unwrap_or("");
            append_wm_line(&mut out, &mut used, "ARCHIVAL", t);
        }
    }
    if used == 0 {
        return String::new();
    }
    out.push_str("=== END WORLD MODEL SoT ===\n");
    out
}

/// Fleet = many cells in parallel. Not one orchestrator graph.
pub fn fleet_snapshot(state: &PlatformState) -> Value {
    let mut cells = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Ok(es) = state.engine_store.lock() {
        let keys = es
            .folder_keys(crate::kernel::intelligence_spec::SPEC_FOLDER, None)
            .unwrap_or_default();
        drop(es);
        for pid in keys {
            seen.insert(pid.clone());
            let inflight = crate::kernel::aios::inflight_for(&pid);
            let grants = crate::kernel::world_gateway::list_grants(state, Some(&pid)).len();
            let portals = crate::kernel::share_portal::list_portals(state, Some(&pid)).len();
            cells.push(json!({
                "I": pid,
                "mu": crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(&pid),
                "name": crate::kernel::intelligence_spec::load_spec_doc(state, &pid)
                    .and_then(|s| s.pointer("/metadata/name").and_then(|x| x.as_str()).map(|s| s.to_string())),
                "inflight_thinking": inflight,
                "grants": grants,
                "portals": portals,
                "wm": wm_ready(&pid),
            }));
        }
    }
    for pid in crate::kernel::aios::inflight_pids() {
        if seen.contains(&pid) {
            continue;
        }
        cells.push(json!({
            "I": pid,
            "mu": crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(&pid),
            "name": crate::kernel::intelligence_spec::load_spec_doc(state, &pid)
                .and_then(|s| s.pointer("/metadata/name").and_then(|x| x.as_str()).map(|s| s.to_string())),
            "inflight_thinking": crate::kernel::aios::inflight_for(&pid),
            "grants": crate::kernel::world_gateway::list_grants(state, Some(&pid)).len(),
            "portals": crate::kernel::share_portal::list_portals(state, Some(&pid)).len(),
            "wm": wm_ready(&pid),
        }));
    }
    json!({
        "ok": true,
        "schema": "connector.fleet.v1",
        "cells": cells,
        "inflight_total": crate::kernel::aios::inflight_total(),
        "per_i_cap": crate::kernel::aios::per_i_inflight_cap(),
        "honesty": "Concurrency is many I at once. Identity is μ (0xCD), not Linux PID. Per-I cap is thinking slots, not LLM-as-CPU. No shared brain."
    })
}

/// Market verbs — existing endpoints. This is how you operate the AI infra.
pub fn operate_verbs() -> Value {
    json!({
        "charter_I": "POST /api/v1/intelligence/apply",
        "link_device": "POST /api/v1/settings/llms/link",
        "talk": "POST /v1/chat/completions",
        "syscall": "POST /api/v1/kernel/syscall",
        "grant_world": "POST /api/v1/intelligence/gateway/grant",
        "kill": "POST /api/v1/agents/:pid/kill-switch",
        "compensate": "POST /api/v1/kernel/aios/operate op=compensate (revoke grant / close portal / deny tool)",
        "revoke_grant": "POST /api/v1/intelligence/gateway/grant/revoke",
        "close_portal": "POST /api/v1/intelligence/share-portals/close",
        "council_mint": "POST /api/v1/intelligence/council (human+root)",
        "council_speak": "POST /api/v1/intelligence/council/:id/speak (this I only; μ on every line; kind=speak|task|ack|done|refuse|handoff)",
        "council_floor": "GET /api/v1/intelligence/council/:id/floor",
        "council_inbox": "GET /api/v1/intelligence/council/inbox (this I's open tasks + recent floor)",
        "scim": "GET /api/v1/scim/v2/Users",
        "court": "GET /api/v1/forensics/court-readiness",
        "art9": "GET /api/v1/compliance/eu-ai-act/inventory",
        "hitl": "GET /api/v1/agents/:pid/hitl/pending",
        "acs": "GET /api/v1/runtime/acs/:pid",
        "cage": "GET /api/v1/runtime/cage/:pid",
        "infra": "GET /api/v1/kernel/aios/infra",
        "fleet": "GET /api/v1/kernel/aios/fleet",
        "absorb": "GET /api/v1/kernel/aios/absorb",
        "budget": "GET /api/v1/economy/budget-gate/:pid",
        "who_am_i": "GET /api/v1/agents/:pid/identity-envelope (kernel identity; model must not invent)",
        "evidence": "GET /api/v1/actionlog/export/otel · GET /api/v1/forensics/package",
        "honesty": "Does not wrap vLLM/LangGraph. Operator charters I, links devices, admits A, stops I."
    })
}

/// Market wants these. Frameworks skip them. Already in code — surface, don't rebuild.
pub fn buyer_surface() -> Value {
    json!({
        "honesty": "Bake-off card. Each row is a 2026 buyer ask that Crew/LangGraph/Agno skip or fake. Connector already runs it. Not a new product. Not court-green. Not Honor/GPU OS.",
        "items": [
            {
                "id": "who_am_i",
                "want": "The agent knows who it is",
                "they_ship": "A persona string; the model invents a name",
                "we_have": "Kernel who-am-I + μ (0xCD) injected on /v1. Cannot speak as another I.",
                "url": "GET /api/v1/agents/:pid/identity-envelope",
                "status": "have"
            },
            {
                "id": "isolation",
                "want": "Agents isolated by default",
                "they_ship": "One process, shared graph RAM",
                "we_have": "ACS private per I. Hosted on this computer with isolated Connector identity (not host USER). Share only via human+root portal.",
                "url": "GET /api/v1/runtime/acs/:pid · GET /api/v1/runtime/cage/:pid",
                "status": "have"
            },
            {
                "id": "world_grant",
                "want": "Governed tool/world access",
                "they_ship": "Ambient MCP / tools on the graph",
                "we_have": "Address cage: this computer, APIs, tools, IoT, robots are grants per (this I × address). Same machine ≠ host identity. MCP behind admit_tool.",
                "url": "POST /api/v1/intelligence/gateway/grant",
                "status": "have"
            },
            {
                "id": "gartner_l1_l4",
                "want": "Observe / Advise / Act-with-approval / Act-autonomous per agent",
                "they_ship": "Uniform lock-or-trust (Gartner: this fails)",
                "we_have": "Root/Cone = L3. App = L4 with kill + compensate. Per crossing, not a global switch.",
                "url": "GET /api/v1/kernel/aios/claim-readiness → gartner",
                "status": "have"
            },
            {
                "id": "kill_5min",
                "want": "Stop this agent in five minutes (Gartner P0)",
                "they_ship": "Restart the Python process",
                "we_have": "POST kill-switch interrupts this I's thought; elapsed_ms.",
                "url": "POST /api/v1/agents/:pid/kill-switch",
                "status": "have"
            },
            {
                "id": "compensate",
                "want": "L4 rollback",
                "they_ship": "They say rollback; they mean rewind the world (they don't)",
                "we_have": "Compensating: revoke grant / close portal / deny tool. WM records the line. Not world rewind.",
                "url": "POST /api/v1/kernel/aios/operate op=compensate",
                "status": "have"
            },
            {
                "id": "budget",
                "want": "Cost caps or join the 40% canceled",
                "they_ship": "A dashboard after the bill",
                "we_have": "Per-I budget gate on Talk.",
                "url": "GET /api/v1/economy/budget-gate/:pid",
                "status": "have"
            },
            {
                "id": "audit_trail",
                "want": "One trail an auditor will accept",
                "they_ship": "The framework logged it somewhere",
                "we_have": "Hash-chained DecisionTrace + actionlog OTel/JSONL. Council floor is who-said-what with μ.",
                "url": "GET /api/v1/actionlog/export/otel",
                "status": "have"
            },
            {
                "id": "court_fail_closed",
                "want": "Court / evidence posture",
                "they_ship": "A PDF policy",
                "we_have": "GET court-readiness never auto-greens. Human+counsel for CD-9.",
                "url": "GET /api/v1/forensics/court-readiness",
                "status": "have"
            },
            {
                "id": "art9",
                "want": "EU AI Act inventory (queryable, not a PDF)",
                "they_ship": "A spreadsheet in SharePoint",
                "we_have": "Living Art.9 list from classifications + GDPR subjects.",
                "url": "GET /api/v1/compliance/eu-ai-act/inventory",
                "status": "have"
            },
            {
                "id": "scim",
                "want": "SCIM for the AI runtime",
                "they_ship": "SSO for humans; agents are API keys in a gist",
                "we_have": "Thin SCIM 2.0 over user_store. OIDC remains SSO. Default install may still be dev-token.",
                "url": "GET/POST /api/v1/scim/v2/Users",
                "status": "have"
            },
            {
                "id": "sit_beneath",
                "want": "Keep LangGraph/Crew; don't rewrite",
                "they_ship": "Lock-in to their graph runtime",
                "we_have": "OPENAI_BASE_URL=/v1. Kernel never imports LangGraph.",
                "url": "POST /v1/chat/completions",
                "status": "have"
            },
            {
                "id": "memory_os",
                "want": "Memory that outlives one workflow",
                "they_ship": "RAG stuffed by the app; dies with the graph",
                "we_have": "/m/core /m/recall /k/archival syscalls + Talk inject + kernel paging.",
                "url": "POST /api/v1/kernel/syscall op=wm.retrieve",
                "status": "have"
            },
            {
                "id": "council",
                "want": "Many agents, who did what",
                "they_ship": "Crew/AutoGen chat loop in one process; invented names",
                "we_have": "Root-minted council, owner-μ tasks, Talk-injected desk.",
                "url": "GET /api/v1/intelligence/council/inbox",
                "status": "have"
            }
        ]
    })
}

fn wm_ready(agent_pid: &str) -> Value {
    let _ = crate::kernel::aios::ensure_memory_os(agent_pid);
    let persona = crate::kernel::aios::core_get(agent_pid, "persona")
        .ok()
        .and_then(|v| v.get("value").and_then(|x| x.as_str()).map(|s| !s.trim().is_empty()))
        .unwrap_or(false);
    let recall = crate::kernel::nsfs::nsfs_root(agent_pid)
        .ok()
        .map(|r| r.join("m/recall/log.jsonl").exists())
        .unwrap_or(false);
    let k = crate::kernel::nsfs::nsfs_root(agent_pid)
        .ok()
        .and_then(|r| fs::read_dir(r.join("k")).ok())
        .map(|rd| rd.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    json!({ "core": persona, "recall": recall, "k_entries": k })
}

/// One-cell operate card. Does not replace ACS; ACS embeds this.
pub fn cell_operate_slim(_state: &PlatformState, agent_pid: &str) -> Value {
    json!({
        "inflight_thinking": crate::kernel::aios::inflight_for(agent_pid),
        "wm": wm_ready(agent_pid),
        "mu": crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(agent_pid),
        "talk": "POST /v1/chat/completions",
        "syscall": "POST /api/v1/kernel/syscall",
        "who_am_i": format!("GET /api/v1/agents/{agent_pid}/identity-envelope"),
        "kill": format!("POST /api/v1/agents/{agent_pid}/kill-switch"),
        "hitl": format!("GET /api/v1/agents/{agent_pid}/hitl/pending"),
        "budget": format!("GET /api/v1/economy/budget-gate/{agent_pid}"),
        "compensate": "POST /api/v1/kernel/aios/operate op=compensate",
        "council": "GET /api/v1/intelligence/council/inbox + POST …/speak (this I; μ on every act)",
        "evidence": format!("GET /api/v1/forensics/package?agent_pid={agent_pid}"),
    })
}

pub fn cell_operate(state: &PlatformState, agent_pid: &str) -> Value {
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return json!({"ok": false, "error": "agent_pid_required"});
    }
    json!({
        "ok": true,
        "schema": "connector.infra.cell.v1",
        "agent_pid": pid,
        "acs": crate::kernel::acs::render(state, pid),
        "level": level_for(state, pid),
        "operate": cell_operate_slim(state, pid),
        "verbs": operate_verbs(),
    })
}

fn devices_on_node(state: &PlatformState) -> Value {
    let mut out = Vec::new();
    if let Some(c) = state.llm_config_snapshot() {
        let mut d = classify_device(&c.provider, c.endpoint.as_deref());
        if let Some(obj) = d.as_object_mut() {
            obj.insert("model".into(), json!(c.model));
            obj.insert("wired".into(), json!(state.llm_wired()));
            obj.insert("primary".into(), json!(true));
        }
        out.push(d);
    }
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get("settings_llms", "providers") {
            if let Some(arr) = v.as_array() {
                for p in arr {
                    let provider = p.get("provider").and_then(|x| x.as_str()).unwrap_or("");
                    if provider.is_empty() {
                        continue;
                    }
                    if out.iter().any(|d| d["provider_label"] == provider) {
                        continue;
                    }
                    let ep = p.get("endpoint").and_then(|x| x.as_str());
                    let mut d = classify_device(provider, ep);
                    if let Some(obj) = d.as_object_mut() {
                        obj.insert("model".into(), p.get("model").cloned().unwrap_or(json!(null)));
                        obj.insert("wired".into(), json!(false));
                        obj.insert("primary".into(), json!(false));
                    }
                    out.push(d);
                }
            }
        }
    }
    json!(out)
}

/// Top-level AI infra operating plane. Aggregates existing subsystems; does not replace them.
pub fn infra_plane(state: &PlatformState) -> Value {
    let mode = state
        .runtime_mode
        .read()
        .map(|m| m.as_str())
        .unwrap_or("unknown");
    let isolation = state
        .isolation_runtime
        .read()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|_| "unknown".into());
    json!({
        "ok": true,
        "schema": "connector.infra.plane.v1",
        "node": {
            "runtime_mode": mode,
            "isolation": isolation,
            "llm_wired": state.llm_wired(),
            "stub": std::env::var("CONNECTOR_LLM_STUB").ok().as_deref() == Some("1")
                || std::env::var("CONNECTOR_LLM_STUB").ok().as_deref() == Some("true"),
            "per_i_inflight_cap": crate::kernel::aios::per_i_inflight_cap(),
        },
        "devices": devices_on_node(state),
        "fleet": fleet_snapshot(state),
        "crossings": recent(24),
        "sockets": spec()["sockets"],
        "absorb": absorb_catalog(),
        "admission": crate::kernel::admission_layers::catalog(),
        "operate": operate_verbs(),
        "buyer_surface": buyer_surface(),
        "kinds": spec()["kinds"],
        "honesty": "This is the operator plane for complete AI infra on this node. vLLM/Ollama/LangGraph remain apps/devices. Connector charters I, admits A, keeps WM, stops I."
    })
}

fn append_wm_line(out: &mut String, used: &mut usize, tag: &str, text: &str) {
    if text.trim().is_empty() || *used > 3500 {
        return;
    }
    let clip: String = text.chars().take(280).collect();
    out.push_str(&format!("[{tag}] {clip}\n"));
    *used += clip.len();
}

fn walk_text(dir: &Path, contain: &Path, q: &str, limit: usize, owner: &str, layer: &str, hits: &mut Vec<Value>) {
    if hits.len() >= limit {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        if hits.len() >= limit {
            break;
        }
        let path = ent.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_text(&path, contain, q, limit, owner, layer, hits);
            continue;
        }
        let Ok(canon) = path.canonicalize() else {
            continue;
        };
        if !canon.starts_with(contain) {
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !matches!(ext, "json" | "jsonl" | "md" | "txt") {
            continue;
        }
        let Ok(body) = fs::read_to_string(&path) else {
            continue;
        };
        if q.is_empty() || body.to_lowercase().contains(q) {
            let snippet: String = body.chars().take(400).collect();
            hits.push(json!({
                "path": path.to_string_lossy(),
                "snippet": snippet,
                "owner": owner,
                "layer": layer,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_prefers_named_then_fabric_then_mission() {
        assert_eq!(classify_level(Some("mission"), false, true), "mission");
        assert_eq!(classify_level(None, false, true), "shop");
        assert_eq!(classify_level(None, true, false), "task");
        assert_eq!(classify_level(None, false, false), "servo");
    }

    #[test]
    fn spec_never_names_vendor_types_as_kernel() {
        let s = spec();
        let never = s["kernel_never_sees"].as_array().unwrap();
        assert!(never.iter().any(|v| v.as_str() == Some("LangGraph")));
        assert!(never.iter().any(|v| v.as_str() == Some("VllmScheduler")));
        assert_eq!(s["sockets"]["completion"], "POST /v1/chat/completions");
    }

    #[test]
    fn crossings_roundtrip() {
        record(
            Socket::Completion,
            "agt_ol_unit",
            "llm.complete",
            true,
            &json!({"n": 1}),
        );
        let hits = recent(8);
        assert!(hits.iter().any(|e| e["agent_pid"] == "agt_ol_unit"
            && e["socket"] == "completion"
            && e["op"] == "llm.complete"));
    }

    #[test]
    fn classify_device_treats_vllm_and_ollama_as_url() {
        let v = classify_device("vllm", Some("http://127.0.0.1:8000/v1"));
        assert_eq!(v["kind"], "device");
        assert_eq!(v["wire"], "openai_compat");
        let o = classify_device("ollama", None);
        assert_eq!(o["kernel_type"], "device URL");
    }

    #[test]
    fn absorb_catalog_future_proof() {
        let c = absorb_catalog();
        assert!(c["device"]["future"].as_str().unwrap().contains("no vendor crate"));
        assert!(c["thinker"]["bind"].as_str().unwrap().contains("/v1"));
        let v = operate_verbs();
        assert!(v["kill"].as_str().unwrap().contains("kill-switch"));
        assert!(v["talk"].as_str().unwrap().contains("/v1/chat/completions"));
        assert!(v["link_device"].as_str().unwrap().contains("llms/link"));
        assert!(v["council_speak"].as_str().unwrap().contains("council"));
        assert!(v["council_inbox"].as_str().unwrap().contains("inbox"));
        let b = buyer_surface();
        let items = b["items"].as_array().expect("buyer items");
        assert!(items.len() >= 10);
        assert!(items.iter().all(|i| i["status"] == "have"));
        assert!(items.iter().any(|i| i["id"] == "kill_5min"));
        assert!(items.iter().any(|i| i["id"] == "who_am_i"));
    }

    #[test]
    fn wm_retrieve_includes_recall_and_k() {
        let dir = std::env::temp_dir().join(format!("connector-ol-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("CONNECTOR_DATA_DIR", dir.to_string_lossy().as_ref());
        let pid = "agt_ol_k";
        nsfs::ensure_tree(pid).unwrap();
        let k = nsfs::nsfs_root(pid).unwrap().join("k/note.txt");
        fs::write(&k, "the red folder is in cabinet 3").unwrap();
        crate::kernel::aios::recall_append(pid, "user", "where is the red folder").unwrap();
        let r = knowledge_search(pid, "cabinet", 8).unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["hits"].as_array().unwrap().len(), 1);
        let wm = wm_retrieve(None, pid, "cabinet", 8);
        assert_eq!(wm["ok"], true);
        assert!(wm["knowledge"].as_array().unwrap().len() >= 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
