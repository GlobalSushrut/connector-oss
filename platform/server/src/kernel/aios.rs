//! Syscall dispatch + WM files + stop-this-I interrupt.
//! Architecture lives in `operating_layer`. This file is the syscall socket.

use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::admission_layers::{self, AdmissionLayer};
use super::agent_principal;
use super::nsfs;
use super::operating_layer::{self, Socket};
use crate::state::PlatformState;

pub const AIOS_SCHEMA: &str = "connector.aios.kernel.v1";

/// Syscalls agents may issue. New ops add here — never a raw primitive bypass.
pub const SYSCALLS: &[&str] = &[
    "llm.complete",
    "llm.interrupt",
    "memory.core.get",
    "memory.core.set",
    "memory.recall.append",
    "memory.recall.search",
    "memory.archival.insert",
    "memory.archival.search",
    "memory.knowledge.search",
    "wm.retrieve",
    "fleet.snapshot",
    "council.speak",
    "council.floor",
    "council.inbox",
    "access.check",
    "tool.invoke",
    "agent.kill_switch",
];

#[derive(Clone, Debug)]
pub struct Generation {
    pub id: String,
    pub agent_pid: String,
    pub started: Instant,
    pub interrupted: bool,
    pub partial: String,
}

struct AiosState {
    generations: HashMap<String, Generation>,
    by_pid: HashMap<String, Vec<String>>,
    syscall_log: VecDeque<Value>,
    kill_events: Vec<Value>,
}

impl AiosState {
    fn new() -> Self {
        Self {
            generations: HashMap::new(),
            by_pid: HashMap::new(),
            syscall_log: VecDeque::with_capacity(256),
            kill_events: Vec::new(),
        }
    }
}

fn state() -> &'static Mutex<AiosState> {
    static S: OnceLock<Mutex<AiosState>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(AiosState::new()))
}

pub fn ensure_memory_os(agent_pid: &str) -> Result<Value, String> {
    let snap = nsfs::ensure_tree(agent_pid)?;
    let root = nsfs::nsfs_root(agent_pid)?;
    for rel in ["m/core", "m/recall", "k/archival"] {
        fs::create_dir_all(root.join(rel)).map_err(|e| format!("aios_mkdir_{rel}: {e}"))?;
    }
    let persona = root.join("m/core/persona.json");
    if !persona.exists() {
        let body = json!({
            "schema": "connector.memory.core.v1",
            "label": "persona",
            "value": "",
            "honesty": "Core is RAM — pinned, agent-editable, small. Not RAG dump."
        });
        fs::write(&persona, serde_json::to_vec_pretty(&body).unwrap_or_default())
            .map_err(|e| format!("aios_persona: {e}"))?;
    }
    Ok(json!({
        "ok": true,
        "nsfs": snap,
        "core": root.join("m/core").to_string_lossy(),
        "recall": root.join("m/recall").to_string_lossy(),
        "archival": root.join("k/archival").to_string_lossy(),
        "map": {
            "core": "/m/core — Letta RAM (persona, human, context_partial)",
            "recall": "/m/recall — searchable conversation log",
            "archival": "/k/archival — cold facts the agent chooses to keep",
            "private": "/p — never LLM"
        }
    }))
}

fn core_path(agent_pid: &str, label: &str) -> Result<PathBuf, String> {
    ensure_memory_os(agent_pid)?;
    let safe = sanitize_label(label)?;
    Ok(nsfs::nsfs_root(agent_pid)?.join("m/core").join(format!("{safe}.json")))
}

fn recall_log(agent_pid: &str) -> Result<PathBuf, String> {
    ensure_memory_os(agent_pid)?;
    Ok(nsfs::nsfs_root(agent_pid)?.join("m/recall").join("log.jsonl"))
}

fn archival_dir(agent_pid: &str) -> Result<PathBuf, String> {
    ensure_memory_os(agent_pid)?;
    Ok(nsfs::nsfs_root(agent_pid)?.join("k/archival"))
}

fn sanitize_label(label: &str) -> Result<String, String> {
    let s = label.trim();
    if s.is_empty() || s.len() > 64 || s.contains("..") || s.contains('/') || s.contains('\\') {
        return Err("invalid_memory_label".into());
    }
    Ok(s.to_string())
}

pub fn core_get(agent_pid: &str, label: &str) -> Result<Value, String> {
    let p = core_path(agent_pid, label)?;
    if !p.exists() {
        return Ok(json!({ "ok": true, "label": label, "value": "", "exists": false }));
    }
    let raw = fs::read_to_string(&p).map_err(|e| e.to_string())?;
    let mut v: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("ok".into(), json!(true));
        obj.insert("exists".into(), json!(true));
    }
    Ok(v)
}

pub fn core_set(agent_pid: &str, label: &str, value: &str) -> Result<Value, String> {
    let p = core_path(agent_pid, label)?;
    if value.len() > 8_192 {
        return Err("core_block_too_large — keep RAM small (Letta-class)".into());
    }
    let (store, overflow) = page_value(value);
    if let Some(ov) = overflow.as_deref() {
        let _ = archival_insert(agent_pid, ov, &format!("evict_{label}"));
    }
    let body = json!({
        "schema": "connector.memory.core.v1",
        "label": label,
        "value": store,
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "paged": overflow.is_some(),
    });
    fs::write(&p, serde_json::to_vec_pretty(&body).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok(json!({
        "ok": true,
        "label": label,
        "bytes": store.len(),
        "paged_to_archival": overflow.is_some(),
    }))
}

const CORE_SOFT_CHARS: usize = 1800;
const CORE_KEEP_CHARS: usize = 1200;

fn page_value(value: &str) -> (String, Option<String>) {
    let n = value.chars().count();
    if n <= CORE_SOFT_CHARS {
        return (value.to_string(), None);
    }
    let keep: String = value.chars().skip(n.saturating_sub(CORE_KEEP_CHARS)).collect();
    let overflow: String = value.chars().take(n.saturating_sub(CORE_KEEP_CHARS)).collect();
    (keep, Some(overflow))
}

/// Kernel paging policy (U1): overflow core RAM into archival. BG may still syscall; this is WM hygiene.
pub fn page_core_if_full(agent_pid: &str) -> Value {
    let _ = ensure_memory_os(agent_pid);
    let mut paged = Vec::new();
    for label in ["persona", "human", "context_partial"] {
        let Ok(g) = core_get(agent_pid, label) else { continue };
        let Some(val) = g.get("value").and_then(|x| x.as_str()) else { continue };
        if val.chars().count() <= CORE_SOFT_CHARS {
            continue;
        }
        if core_set(agent_pid, label, val).is_ok() {
            paged.push(label);
        }
    }
    json!({ "ok": true, "paged": paged })
}

pub fn recall_append(agent_pid: &str, role: &str, text: &str) -> Result<Value, String> {
    nsfs::assert_quota(agent_pid, text.len() as u64 + 64)?;
    let p = recall_log(agent_pid)?;
    const MAX_RECALL_BYTES: u64 = 8 * 1024 * 1024;
    if p.exists() {
        if let Ok(meta) = fs::metadata(&p) {
            if meta.len() > MAX_RECALL_BYTES {
                // Rotate: keep the last half.
                if let Ok(raw) = fs::read_to_string(&p) {
                    let keep: String = raw
                        .lines()
                        .rev()
                        .take(4000)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("\n");
                    let _ = fs::write(&p, keep);
                }
            }
        }
    }
    let line = json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "role": role,
        "text": text,
    });
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .map_err(|e| e.to_string())?;
    writeln!(f, "{line}").map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true, "appended": true }))
}

pub fn recall_search(agent_pid: &str, query: &str, limit: usize) -> Result<Value, String> {
    let p = recall_log(agent_pid)?;
    let q = query.to_ascii_lowercase();
    let mut hits = Vec::new();
    if p.exists() {
        let raw = fs::read_to_string(&p).unwrap_or_default();
        for line in raw.lines().rev() {
            if line.to_ascii_lowercase().contains(&q) {
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    hits.push(v);
                }
            }
            if hits.len() >= limit.max(1).min(50) {
                break;
            }
        }
    }
    Ok(json!({ "ok": true, "hits": hits, "query": query }))
}

pub fn archival_insert(agent_pid: &str, text: &str, tag: &str) -> Result<Value, String> {
    nsfs::assert_quota(agent_pid, text.len() as u64 + 128)?;
    let dir = archival_dir(agent_pid)?;
    let id = format!(
        "{}_{}",
        chrono::Utc::now().timestamp_millis(),
        sanitize_label(if tag.is_empty() { "note" } else { tag }).unwrap_or_else(|_| "note".into())
    );
    let p = dir.join(format!("{id}.json"));
    let body = json!({
        "schema": "connector.memory.archival.v1",
        "id": id,
        "tag": tag,
        "text": text,
        "ts": chrono::Utc::now().to_rfc3339(),
    });
    fs::write(&p, serde_json::to_vec_pretty(&body).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok(json!({ "ok": true, "id": id }))
}

pub fn archival_search(agent_pid: &str, query: &str, limit: usize) -> Result<Value, String> {
    let dir = archival_dir(agent_pid)?;
    let q = query.to_ascii_lowercase();
    let mut hits = Vec::new();
    if dir.is_dir() {
        let mut files: Vec<_> = fs::read_dir(&dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        files.sort();
        files.reverse();
        for p in files {
            let raw = fs::read_to_string(&p).unwrap_or_default();
            if raw.to_ascii_lowercase().contains(&q) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    hits.push(v);
                }
            }
            if hits.len() >= limit.max(1).min(50) {
                break;
            }
        }
    }
    Ok(json!({ "ok": true, "hits": hits, "query": query }))
}

pub fn begin_generation(agent_pid: &str) -> String {
    let n = state()
        .lock()
        .map(|s| s.generations.len())
        .unwrap_or(0);
    let id = format!(
        "gen_{}_{}_{}",
        chrono::Utc::now().timestamp_millis(),
        n,
        agent_pid.chars().take(8).collect::<String>()
    );
    if let Ok(mut s) = state().lock() {
        s.generations.insert(
            id.clone(),
            Generation {
                id: id.clone(),
                agent_pid: agent_pid.to_string(),
                started: Instant::now(),
                interrupted: false,
                partial: String::new(),
            },
        );
        s.by_pid
            .entry(agent_pid.to_string())
            .or_default()
            .push(id.clone());
    }
    id
}

/// 0 = unlimited only when CONNECTOR_I_INFLIGHT=0 is explicit.
/// Default 4 concurrent generations per intelligence.
pub fn per_i_inflight_cap() -> usize {
    match std::env::var("CONNECTOR_I_INFLIGHT") {
        Ok(s) => s.parse().unwrap_or(4),
        Err(_) => 4,
    }
}

pub fn inflight_for(agent_pid: &str) -> usize {
    state()
        .lock()
        .ok()
        .map(|s| s.by_pid.get(agent_pid).map(|v| v.len()).unwrap_or(0))
        .unwrap_or(0)
}

pub fn inflight_total() -> usize {
    state()
        .lock()
        .ok()
        .map(|s| s.generations.len())
        .unwrap_or(0)
}

pub fn inflight_pids() -> Vec<String> {
    state()
        .lock()
        .ok()
        .map(|s| s.by_pid.keys().cloned().collect())
        .unwrap_or_default()
}

/// Wait up to 30s for a slot. Returns Err if still over cap (fail closed).
pub async fn wait_inflight_slot(agent_pid: &str) -> Result<(), String> {
    let cap = per_i_inflight_cap();
    if cap == 0 {
        return Ok(());
    }
    let start = Instant::now();
    while inflight_for(agent_pid) >= cap && start.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if inflight_for(agent_pid) >= cap {
        return Err(format!(
            "inflight_cap: agent={agent_pid} has {cap} concurrent generations"
        ));
    }
    Ok(())
}

pub fn append_partial(gen_id: &str, chunk: &str) {
    if let Ok(mut s) = state().lock() {
        if let Some(g) = s.generations.get_mut(gen_id) {
            g.partial.push_str(chunk);
            if g.partial.len() > 32_768 {
                let drain = g.partial.len() - 16_384;
                g.partial.drain(..drain);
            }
        }
    }
}

pub fn is_interrupted(gen_id: &str) -> bool {
    state()
        .lock()
        .ok()
        .and_then(|s| s.generations.get(gen_id).map(|g| g.interrupted))
        .unwrap_or(false)
}

pub fn interrupt_generation(agent_pid: &str, gen_id: Option<&str>) -> Value {
    let mut saved = Vec::new();
    if let Ok(mut s) = state().lock() {
        let ids: Vec<String> = if let Some(id) = gen_id {
            vec![id.to_string()]
        } else {
            s.by_pid.get(agent_pid).cloned().unwrap_or_default()
        };
        for id in ids {
            if let Some(g) = s.generations.get_mut(&id) {
                if g.agent_pid != agent_pid {
                    continue;
                }
                g.interrupted = true;
                if !g.partial.is_empty() {
                    saved.push((g.agent_pid.clone(), g.partial.clone()));
                }
            }
        }
    }
    for (pid, partial) in &saved {
        let _ = core_set(pid, "context_partial", partial);
        let _ = recall_append(pid, "system", &format!("interrupted_partial: {partial}"));
    }
    json!({
        "ok": true,
        "interrupted": true,
        "partials_saved": saved.len(),
        "honesty": "Text checkpoint on /m/core/context_partial.json — not logit snapshot. Cloud LLM APIs cannot restore mid-token weights."
    })
}

pub async fn wait_interrupted(gen_id: String) {
    loop {
        if is_interrupted(&gen_id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub enum CompleteOutcome<T> {
    Done(T),
    Interrupted,
    Denied(String),
}

/// Run an LLM complete future until it finishes or `llm.interrupt` / kill-switch fires.
/// Honesty: we stop *waiting* on this node. Cloud providers may still finish the token stream.
pub async fn with_interrupt<T>(
    agent_pid: &str,
    fut: impl std::future::Future<Output = T>,
) -> (String, CompleteOutcome<T>) {
    if let Err(e) = wait_inflight_slot(agent_pid).await {
        return (String::new(), CompleteOutcome::Denied(e));
    }
    let id = begin_generation(agent_pid);
    tokio::select! {
        biased;
        _ = wait_interrupted(id.clone()) => {
            finish_generation(&id, "", true);
            operating_layer::record(
                Socket::Completion,
                agent_pid,
                "llm.complete",
                false,
                &json!({ "generation_id": id.clone(), "interrupted": true }),
            );
            (id, CompleteOutcome::Interrupted)
        }
        v = fut => {
            finish_generation(&id, "", false);
            operating_layer::record(
                Socket::Completion,
                agent_pid,
                "llm.complete",
                true,
                &json!({ "generation_id": id.clone(), "interrupted": false }),
            );
            (id, CompleteOutcome::Done(v))
        }
    }
}

pub fn finish_generation(gen_id: &str, text: &str, interrupted: bool) {
    if interrupted && !text.is_empty() {
        if let Ok(s) = state().lock() {
            if let Some(g) = s.generations.get(gen_id) {
                let pid = g.agent_pid.clone();
                drop(s);
                let _ = core_set(&pid, "context_partial", text);
            }
        }
    }
    if let Ok(mut s) = state().lock() {
        if let Some(g) = s.generations.remove(gen_id) {
            if let Some(list) = s.by_pid.get_mut(&g.agent_pid) {
                list.retain(|x| x != gen_id);
            }
        }
    }
}

pub fn record_kill_switch(agent_pid: &str, elapsed_ms: u128, ok: bool) {
    if let Ok(mut s) = state().lock() {
        s.kill_events.push(json!({
            "agent_pid": agent_pid,
            "elapsed_ms": elapsed_ms,
            "ok": ok,
            "within_5min": elapsed_ms < 300_000,
            "ts": chrono::Utc::now().to_rfc3339(),
        }));
        if s.kill_events.len() > 64 {
            s.kill_events.remove(0);
        }
    }
}

pub fn gartner_level(layer: AdmissionLayer) -> Value {
    match layer {
        AdmissionLayer::Root | AdmissionLayer::Cone => json!({
            "gartner": "L3_act_with_approval",
            "observe": true,
            "advise": true,
            "act_with_approval": true,
            "act_autonomous": false,
            "our_layer": layer.as_str(),
        }),
        AdmissionLayer::App => json!({
            "gartner": "L4_act_autonomous",
            "observe": true,
            "advise": true,
            "act_with_approval": false,
            "act_autonomous": true,
            "requires": ["kill_switch", "circuit_breaker", "named_owner", "compensating_rollback"],
            "our_layer": "app",
            "honesty": "App Allow is L4. Kill-switch is productized. Action undo is compensating (revoke grant / close portal / disable tools) — not world-state rewind."
        }),
    }
}

fn log_syscall(agent_pid: &str, op: &str, ok: bool, detail: &Value) {
    operating_layer::record(Socket::Syscall, agent_pid, op, ok, detail);
    if let Ok(mut s) = state().lock() {
        s.syscall_log.push_back(json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "agent_pid": agent_pid,
            "op": op,
            "ok": ok,
            "detail": detail,
        }));
        while s.syscall_log.len() > 256 {
            s.syscall_log.pop_front();
        }
    }
}

/// Charter (action, target) for a syscall. `None` = no extra charter (path refuses itself).
pub fn syscall_charter(op: &str) -> Option<(&'static str, &'static str)> {
    match op {
        "memory.core.set" | "memory.recall.append" | "memory.archival.insert" => {
            Some(("memory.write", "/m"))
        }
        "memory.core.get"
        | "memory.recall.search"
        | "memory.archival.search"
        | "memory.knowledge.search"
        | "wm.retrieve" => Some(("memory.read", "/m")),
        "llm.interrupt" => Some(("llm.interrupt", "generation")),
        "fleet.snapshot" | "access.check" => Some(("access.check", "self")),
        "council.speak" => Some(("council.speak", "council")),
        "council.floor" | "council.inbox" => Some(("council.floor", "council")),
        "llm.complete" | "tool.invoke" | "agent.kill_switch" => None,
        _ => None,
    }
}

/// Charter action for a syscall. HTTP always runs this (U6). Tests call `dispatch` ungated.
pub fn syscall_contract_gate(state: &PlatformState, agent_pid: &str, op: &str) -> Result<(), String> {
    let Some((action, target)) = syscall_charter(op) else {
        return Ok(());
    };
    agent_principal::require_contract_action(state, agent_pid, action, target)
}

/// Dispatch a named syscall. `llm.complete` is admitted elsewhere (Talk path);
/// this entry records / interrupts / memory / access-check.
pub fn dispatch(agent_pid: &str, op: &str, args: &Value) -> Value {
    dispatch_with(None, agent_pid, op, args)
}

/// Same as `dispatch`, with WM search seeing licensed portal `/k` when state is present.
pub fn dispatch_with(state: Option<&PlatformState>, agent_pid: &str, op: &str, args: &Value) -> Value {
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return json!({ "ok": false, "error": "agent_pid_required" });
    }
    let result = match op {
        "memory.core.get" => {
            let label = args.get("label").and_then(|v| v.as_str()).unwrap_or("persona");
            core_get(pid, label).unwrap_or_else(|e| json!({"ok": false, "error": e}))
        }
        "memory.core.set" => {
            let label = args.get("label").and_then(|v| v.as_str()).unwrap_or("persona");
            let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("");
            core_set(pid, label, value).unwrap_or_else(|e| json!({"ok": false, "error": e}))
        }
        "memory.recall.append" => {
            let role = args.get("role").and_then(|v| v.as_str()).unwrap_or("assistant");
            let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
            recall_append(pid, role, text).unwrap_or_else(|e| json!({"ok": false, "error": e}))
        }
        "memory.recall.search" => {
            let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let n = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            recall_search(pid, q, n).unwrap_or_else(|e| json!({"ok": false, "error": e}))
        }
        "memory.archival.insert" => {
            let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let tag = args.get("tag").and_then(|v| v.as_str()).unwrap_or("note");
            archival_insert(pid, text, tag).unwrap_or_else(|e| json!({"ok": false, "error": e}))
        }
        "memory.archival.search" => {
            let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let n = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            archival_search(pid, q, n).unwrap_or_else(|e| json!({"ok": false, "error": e}))
        }
        "memory.knowledge.search" => {
            let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let n = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            operating_layer::knowledge_search_ctx(state, pid, q, n)
                .unwrap_or_else(|e| json!({"ok": false, "error": e}))
        }
        "wm.retrieve" => {
            let q = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let n = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            operating_layer::wm_retrieve(state, pid, q, n)
        }
        "fleet.snapshot" => json!({
            "ok": true,
            "inflight_total": inflight_total(),
            "per_i_cap": per_i_inflight_cap(),
            "inflight_pids": inflight_pids(),
            "hint": "GET /kernel/aios/fleet for cells + grants + portals"
        }),
        "council.floor" => match state {
            None => json!({
                "ok": false,
                "error": "state_required",
                "hint": "POST /api/v1/kernel/syscall (HTTP) or GET /intelligence/council/:id/floor"
            }),
            Some(st) => {
                let id = args.get("council_id").and_then(|v| v.as_str()).unwrap_or("");
                match crate::kernel::council::load(st, id) {
                    Some(c) if crate::kernel::council::is_member(&c, pid) => {
                        let n = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(80) as usize;
                        crate::kernel::council::floor(st, id, n)
                            .unwrap_or_else(|e| json!({"ok": false, "error": e}))
                    }
                    Some(_) => json!({"ok": false, "error": "not_a_member"}),
                    None => json!({"ok": false, "error": "council_not_found"}),
                }
            }
        },
        "council.speak" => match state {
            None => json!({
                "ok": false,
                "error": "state_required",
                "hint": "POST /api/v1/kernel/syscall — speaker is this pid, never another I"
            }),
            Some(st) => {
                let id = args.get("council_id").and_then(|v| v.as_str()).unwrap_or("");
                let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("floor");
                let kind = args.get("kind").and_then(|v| v.as_str()).unwrap_or("speak");
                let body = args.get("body").and_then(|v| v.as_str()).unwrap_or("");
                let claimed = args.get("from_mu").and_then(|v| v.as_str());
                let task_ref = args.get("task_id").and_then(|v| v.as_str());
                match crate::kernel::council::speak(st, id, pid, to, kind, body, claimed, task_ref) {
                    Ok(e) => json!({
                        "ok": true,
                        "seq": e.seq,
                        "from_I": e.from_I,
                        "from_mu": e.from_mu,
                        "from_name": e.from_name,
                        "to": e.to,
                        "kind": e.kind,
                        "task_id": e.task_id,
                        "record_hash": e.record_hash,
                        "prev_hash": e.prev_hash,
                    }),
                    Err(e) => json!({"ok": false, "error": e}),
                }
            }
        },
        "council.inbox" => match state {
            None => json!({
                "ok": false,
                "error": "state_required",
                "hint": "POST /api/v1/kernel/syscall or GET /intelligence/council/inbox"
            }),
            Some(st) => crate::kernel::council::inbox(st, pid),
        },
        "llm.interrupt" => {
            let gid = args.get("generation_id").and_then(|v| v.as_str());
            interrupt_generation(pid, gid)
        }
        "access.check" => {
            json!({
                "ok": true,
                "layers": admission_layers::catalog(),
                "gartner_by_layer": {
                    "root": gartner_level(AdmissionLayer::Root),
                    "cone": gartner_level(AdmissionLayer::Cone),
                    "app": gartner_level(AdmissionLayer::App),
                },
                "honesty": "Crossing still goes through admit_* — this syscall only names the map."
            })
        }
        "llm.complete" | "tool.invoke" => json!({
            "ok": false,
            "error": "use_existing_path",
            "hint": "llm.complete → POST /v1/chat/completions (admit_talk). tool.invoke → admit_tool. This ABI records them; it does not bypass the membrane."
        }),
        "agent.kill_switch" => json!({
            "ok": false,
            "error": "use_http",
            "hint": "POST /api/v1/agents/:pid/kill-switch"
        }),
        other => json!({ "ok": false, "error": "unknown_syscall", "op": other, "catalog": SYSCALLS }),
    };
    let ok = result.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    log_syscall(pid, op, ok, &result);
    result
}

pub fn modules() -> Value {
    json!({
        "schema": AIOS_SCHEMA,
        "modules": [
            {
                "id": "access",
                "market": "Privilege + HITL",
                "status": "have",
                "via": "admission_layers + admit_* + world grants + share portals"
            },
            {
                "id": "scheduler",
                "market": "Device/crossing queue — not LLM-as-CPU RR",
                "status": "partial",
                "via": "POST /kernel/syscall log + VAC LlmSchedulerPolicy on enqueue. Hardware multiplex. Not thought-as-cycles."
            },
            {
                "id": "context",
                "market": "Stop this I thinking (VJ), not CPU context switch",
                "status": "partial",
                "via": "interrupt complete() + /m/core/context_partial.json. Not logit snapshot. Not a fake CPU dump."
            },
            {
                "id": "memory",
                "market": "Core / recall / archival",
                "status": "have",
                "via": "NS FS /m/core /m/recall /k/archival + syscalls"
            },
            {
                "id": "storage",
                "market": "Versioned persistent knowledge",
                "status": "partial",
                "via": "VAC CID + /k archival files"
            },
            {
                "id": "tool",
                "market": "Conflict-free tools + MCP",
                "status": "partial",
                "via": "admit_tool + MCP gated"
            }
        ]
    })
}

pub fn claim_readiness() -> Value {
    let v1 = true; // Wave 0 ABI is in this module + HTTP
    json!({
        "schema": AIOS_SCHEMA,
        "claim": {
            "v1_buyer_os": v1,
            "v2_academic_aios": false,
            "device_agentic_os": false,
            "infrastructure_gpu_os": false
        },
        "ontology": {
            "cpu": "device — Linux cores/cgroups",
            "gpu": "device — accelerator; vLLM is a disk",
            "intelligence": "chartered I — Albus SP·WM·VJ·BG; Newell knowledge level",
            "llm": "that I thinking (BG/SP), not a CPU",
            "reject": "Mei et al. AIOS: LLM-as-CPU, agent-as-process"
        },
        "v1_means": "Syscall ABI, WM file hierarchy, kernel paging to archival, VJ interrupt of this I's thought, 5-min kill-switch, compensating undo, Gartner L1–L4 map. Not LLM-as-CPU.",
        "v2_still_lacks": [
            "CD-9 human+counsel sign-off — never from this JSON",
            "Honor Agentic OS / infrastructure GPU OS — out of product"
        ],
        "enterprise": {
            "scim": "GET/POST /api/v1/scim/v2/Users — thin over user_store; OIDC remains SSO",
            "court": "GET /api/v1/forensics/court-readiness — never court-green from claim JSON",
            "art9": "GET /api/v1/compliance/eu-ai-act/inventory — living classifications + GDPR subjects",
            "undo": "compensate writes WM recall; not world rewind",
            "honor_os": false,
            "gpu_os": false
        },
        "vj": {
            "on": agent_principal::intelligence_hardening_on(),
            "lab": std::env::var("CONNECTOR_PRESET").ok().as_deref() == Some("local")
                || std::env::var("CONNECTOR_LAB").ok().as_deref() == Some("1"),
            "product": "CONNECTOR_ENV=production | CONNECTOR_PRESET=production | connectorctl harden",
            "honesty": "VJ on for production-like ENV (U15). First-run without license stays lab. CONNECTOR_LAB=1 names lab."
        },
        "topology": {
            "product_sot": {
                "declared": if std::env::var("CONNECTOR_MESH_FABRIC").ok().as_deref() == Some("1") {
                    "cell_mesh_when_peers_ge_2"
                } else {
                    "single_node"
                },
                "measured_mesh_fabric": crate::services::mesh_status::measured_mesh_fabric(),
            },
            "identity": "μ 0xCD intelligence mark — not Linux PID",
            "mesh_fabric_env": std::env::var("CONNECTOR_MESH_FABRIC").ok().as_deref() == Some("1"),
            "mesh_fabric": crate::services::mesh_status::measured_mesh_fabric(),
            "honesty": "mesh_fabric is measured (env AND peers_seen≥2). Env alone is never truth."
        },
        "must_not_build": "LangGraphProcess; VllmScheduler in kernel/; Mei generation RR; LLM-as-CPU (INTELLIGENCE_MATRIX_FUNDAMENTAL.md §0)",
        "may_say": "Governed intelligence kernel (V1) — access + WM files + stop-this-I + kill on the existing membrane.",
        "must_not_say": "Mei et al. AIOS, LLM-as-CPU, 2.1× serving, logit context-switch, Honor Agentic OS, court-green.",
        "operating_layer": operating_layer::spec(),
        "modules": modules()["modules"],
        "syscalls": SYSCALLS,
        "gartner": {
            "root": gartner_level(AdmissionLayer::Root),
            "cone": gartner_level(AdmissionLayer::Cone),
            "app": gartner_level(AdmissionLayer::App)
        },
        "buyer_surface": operating_layer::buyer_surface(),
        "follow": "AIOS_OPERATING_LAYER.md · AIOS_CLAIM_PLAN.md · connectorctl iia aios"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_os_roundtrip() {
        let dir = std::env::temp_dir().join(format!("connector-aios-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("CONNECTOR_DATA_DIR", dir.to_string_lossy().as_ref());
        let pid = "agt_aios_unit";
        ensure_memory_os(pid).expect("tree");
        core_set(pid, "persona", "I am a bounded researcher").unwrap();
        let g = core_get(pid, "persona").unwrap();
        assert!(g["value"].as_str().unwrap().contains("bounded"));
        recall_append(pid, "user", "remember the red folder").unwrap();
        let hits = recall_search(pid, "red", 5).unwrap();
        assert_eq!(hits["hits"].as_array().unwrap().len(), 1);
        archival_insert(pid, "red folder is in cabinet 3", "office").unwrap();
        let a = archival_search(pid, "cabinet", 5).unwrap();
        assert_eq!(a["hits"].as_array().unwrap().len(), 1);
        let d = dispatch(pid, "memory.core.get", &json!({"label": "persona"}));
        assert_eq!(d["ok"], true);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn core_overflow_pages_to_archival() {
        let dir = std::env::temp_dir().join(format!("connector-aios-page-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("CONNECTOR_DATA_DIR", dir.to_string_lossy().as_ref());
        let pid = "agt_aios_page";
        ensure_memory_os(pid).expect("tree");
        let long = format!("overflow-token-xyz {}", "a".repeat(2000));
        let r = core_set(pid, "persona", &long).unwrap();
        assert_eq!(r["paged_to_archival"], true);
        let g = core_get(pid, "persona").unwrap();
        assert!(g["value"].as_str().unwrap().chars().count() <= CORE_KEEP_CHARS);
        let a = archival_search(pid, "overflow-token-xyz", 5).unwrap();
        assert!(!a["hits"].as_array().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn interrupt_flags_generation() {
        let pid = "agt_int";
        let id = begin_generation(pid);
        append_partial(&id, "hello ");
        let r = interrupt_generation(pid, Some(&id));
        assert_eq!(r["ok"], true);
        assert!(is_interrupted(&id));
        finish_generation(&id, "hello world", true);
    }

    #[test]
    fn unknown_syscall_fails_closed() {
        let r = dispatch("agt_x", "shell.exec", &json!({}));
        assert_eq!(r["ok"], false);
    }

    #[test]
    fn council_syscalls_need_state_and_this_i() {
        let r = dispatch("agt_x", "council.speak", &json!({"body": "hi", "council_id": "cnc_x"}));
        assert_eq!(r["ok"], false);
        assert_eq!(r["error"], "state_required");
        let f = dispatch("agt_x", "council.floor", &json!({"council_id": "cnc_x"}));
        assert_eq!(f["ok"], false);
        assert_eq!(f["error"], "state_required");
    }

    #[test]
    fn syscall_charter_maps_memory_write() {
        assert_eq!(syscall_charter("memory.core.set"), Some(("memory.write", "/m")));
        assert_eq!(syscall_charter("wm.retrieve"), Some(("memory.read", "/m")));
        assert_eq!(syscall_charter("council.speak"), Some(("council.speak", "council")));
        assert_eq!(syscall_charter("llm.complete"), None);
    }

    #[test]
    fn operating_layer_is_vendor_blind() {
        let c = claim_readiness();
        let never = c["operating_layer"]["kernel_never_sees"]
            .as_array()
            .expect("never_sees");
        let joined = never
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("LangGraph"));
        assert!(joined.contains("VllmScheduler"));
        assert_eq!(
            c["operating_layer"]["sockets"]["completion"],
            "POST /v1/chat/completions"
        );
        assert!(c["operating_layer"]["kernel_sees"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("I")));
        let items = c["buyer_surface"]["items"].as_array().expect("buyer");
        assert!(items.iter().any(|i| i["id"] == "council"));
        assert!(items.iter().all(|i| i["status"] == "have"));
    }
}
