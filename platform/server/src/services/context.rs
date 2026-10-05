//! # Context Lifecycle Service — Snapshot/Restore/Compress/Evict/Resume
//!
//! Surfaces `connector_engine::context_manager::ContextManager` as a sellable service.
//! Like Linux CRIU for AI agents — saves 40-60% on LLM costs for long-running agents.
//!
//! Routes:
//!   POST /context/{pid}/snapshot         — create CID-addressed snapshot
//!   POST /context/{pid}/restore/{cid}    — restore from snapshot
//!   POST /context/{pid}/compress         — compress with strategy
//!   POST /context/{pid}/evict            — evict to cold storage
//!   POST /context/{pid}/resume           — resume from cold storage
//!   GET  /context/{pid}/snapshots        — list available snapshots
//!   GET  /context/{pid}/pressure         — context pressure metrics

use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::context_manager::CompressionStrategy;
use serde::Deserialize;
fn now_u64() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// POST /context/{pid}/snapshot — create a CID-addressed snapshot of agent context.
pub async fn snapshot(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    // FIX BUG-029: Validate PID is not empty
    if pid.trim().is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": "agent_pid cannot be empty",
            "status": 400
        }));
    }
    let mut cm = state.context_mgr.lock().unwrap();
    // Register agent if not already tracked
    if cm.get(&pid).is_none() {
        cm.register(&pid, "session:default");
    }
    match cm.snapshot(&pid, now_u64()) {
        Ok(cid) => {
            let snap = cm.get_snapshot(&cid);
            Json(serde_json::json!({
                "ok": true,
                "agent_pid": pid,
                "snapshot_cid": cid,
                "context_tokens": snap.map(|s| s.context_tokens).unwrap_or(0),
                "step_counter": snap.map(|s| s.step_counter).unwrap_or(0),
                "created_at": now_iso(),
            }))
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// POST /context/{pid}/restore/{cid} — restore agent context from a snapshot CID.
pub async fn restore(
    State(state): State<SharedState>,
    Path((pid, cid)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    let mut cm = state.context_mgr.lock().unwrap();
    match cm.restore(&cid) {
        Ok(restored_pid) => Json(serde_json::json!({
            "ok": true,
            "agent_pid": pid,
            "snapshot_cid": cid,
            "restored_pid": restored_pid,
            "restored_at": now_iso(),
        })),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

#[derive(Deserialize)]
pub struct CompressRequest {
    #[serde(default = "default_strategy")]
    pub strategy: String,
    /// Absolute number of tokens to free.
    pub target_tokens: Option<u64>,
    /// Utilisation to compress down to. When set it wins over `target_tokens`
    /// and, unless `strategy` was given explicitly, picks the strategy too.
    pub target_utilization_pct: Option<u8>,
}
fn default_strategy() -> String {
    "truncate_oldest".into()
}

/// POST /context/{pid}/compress — compress agent context to free tokens.
///
/// Accepts either an absolute `target_tokens` or a `target_utilization_pct`
/// (what `connectorctl context compress --target-pct` sends).
pub async fn compress(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<CompressRequest>,
) -> Json<serde_json::Value> {
    let explicit_strategy = match req.strategy.as_str() {
        "keep_ends" => Some(CompressionStrategy::KeepEnds),
        "summarize" => Some(CompressionStrategy::Summarize),
        "truncate_oldest" => Some(CompressionStrategy::TruncateOldest),
        _ => None,
    };

    let mut cm = state.context_mgr.lock().unwrap();

    let before = cm.get(&pid).map(|c| (c.context_tokens, c.context_max_tokens, c.context_window.len()));
    let (before_tokens, max_tokens, before_window) = match before {
        Some(v) => v,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("No context for agent {}", pid),
                "agent_pid": pid,
            }))
        }
    };
    let before_pct = if max_tokens > 0 {
        before_tokens as f64 / max_tokens as f64 * 100.0
    } else {
        0.0
    };

    // Percentage target converts to "tokens above the target line".
    let (target, strategy) = match req.target_utilization_pct {
        Some(pct) => {
            let ceiling = (pct as f64 / 100.0 * max_tokens as f64) as u64;
            let strategy = explicit_strategy.unwrap_or(match pct {
                0..=50 => CompressionStrategy::TruncateOldest,
                51..=70 => CompressionStrategy::KeepEnds,
                _ => CompressionStrategy::Summarize,
            });
            (before_tokens.saturating_sub(ceiling), strategy)
        }
        None => (
            req.target_tokens.unwrap_or(64_000),
            explicit_strategy.unwrap_or(CompressionStrategy::TruncateOldest),
        ),
    };

    match cm.compress(&pid, target, Some(strategy)) {
        Ok(result) => {
            let after_tokens = cm.get(&pid).map(|c| c.context_tokens).unwrap_or(0);
            let after_window = cm.get(&pid).map(|c| c.context_window.len()).unwrap_or(0);
            let after_pct = if max_tokens > 0 {
                after_tokens as f64 / max_tokens as f64 * 100.0
            } else {
                0.0
            };
            Json(serde_json::json!({
                "ok": true,
                "agent_pid": pid,
                "strategy": format!("{:?}", result.strategy),
                "tokens_freed": result.tokens_freed,
                "evicted_cid_count": result.evicted_cids.len(),
                "before_pct": before_pct,
                "after_pct": after_pct,
                "target_pct": req.target_utilization_pct,
                // Window entries actually dropped — not an estimate.
                "turns_summarised": before_window.saturating_sub(after_window),
                "summary_cid": result.evicted_cids.last(),
                "evicted_cids": result.evicted_cids,
                "compressed_at": now_iso(),
            }))
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// POST /context/{pid}/evict — evict agent context to cold storage.
pub async fn evict(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let mut cm = state.context_mgr.lock().unwrap();
    if cm.get(&pid).is_none() {
        cm.register(&pid, "session:default");
    }
    match cm.evict(&pid, now_u64()) {
        Ok(cid) => Json(serde_json::json!({
            "ok": true,
            "agent_pid": pid,
            "snapshot_cid": cid,
            "evicted": true,
            "evicted_at": now_iso(),
            "note": "Agent context moved to cold storage. Use /context/{pid}/resume to restore.",
        })),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// POST /context/{pid}/resume — resume agent from cold storage.
pub async fn resume(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let mut cm = state.context_mgr.lock().unwrap();
    match cm.resume("") {
        Ok(restored_pid) => Json(serde_json::json!({
            "ok": true,
            "agent_pid": pid,
            "restored_pid": restored_pid,
            "resumed_at": now_iso(),
        })),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})),
    }
}

/// GET /context/{pid}/snapshots — list all available snapshots for an agent.
/// FIX BUG-041: Now returns actual snapshot list from engine_store
pub async fn list_snapshots(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let (total, context_tokens) = {
        let cm = state.context_mgr.lock().unwrap();
        let total = cm.snapshot_count();
        let ctx_tokens = cm.get(&pid).map(|c| c.context_tokens).unwrap_or(0);
        (total, ctx_tokens)
    };

    // FIX BUG-041: Query engine_store for snapshots belonging to this agent
    let snapshots: Vec<serde_json::Value> = {
        let es = state.engine_store.lock().unwrap();
        let snapshot_folder = format!("snapshots:{}", pid);
        let keys = es.folder_keys(&snapshot_folder, None).unwrap_or_default();
        keys.iter()
            .filter_map(|k| {
                es.folder_get(&snapshot_folder, k).ok().flatten().map(|v| {
                    serde_json::json!({
                        "cid": k,
                        "created_at": v.get("created_at"),
                        "context_tokens": v.get("context_tokens"),
                        "reason": v.get("reason"),
                    })
                })
            })
            .collect()
    };

    Json(serde_json::json!({
        "agent_pid": pid,
        "snapshot_count": snapshots.len(),
        "total_platform_snapshots": total,
        "context_tokens": context_tokens,
        "snapshots": snapshots,
    }))
}

/// GET /context/{pid}/pressure — context pressure metrics.
pub async fn pressure(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let mut cm = state.context_mgr.lock().unwrap();
    // Auto-register agent if not tracked yet (lazy registration)
    if cm.get(&pid).is_none() {
        cm.register(&pid, "session:default");
    }
    match cm.get(&pid) {
        Some(ctx) => Json(serde_json::json!({
            "agent_pid": pid,
            "current_tokens": ctx.context_tokens,
            "max_tokens": ctx.context_max_tokens,
            "pressure_pct": ctx.pressure() * 100.0,
            "window_size": ctx.context_window.len(),
            "snapshot_count": cm.snapshot_count(),
            "recommendation": if ctx.pressure() > 0.9 { "Evict immediately" } else if ctx.pressure() > 0.7 { "Consider compressing" } else { "OK" },
        })),
        None => Json(
            serde_json::json!({"agent_pid": pid, "error": "No active context. Agent not registered."}),
        ),
    }
}

// =============================================================================
// AIOS-B5: CLI-facing context management routes
// =============================================================================

/// Utilisation band used by both the per-agent and fleet views.
fn budget_status(pct: f64) -> &'static str {
    if pct >= 90.0 {
        "critical"
    } else if pct >= 70.0 {
        "warning"
    } else {
        "ok"
    }
}

/// Model the agent is actually registered with, if the kernel knows it.
fn agent_model(state: &SharedState, pid: &str) -> Option<String> {
    let k = state.kernel.lock().ok()?;
    let acb = k.get_agent(pid)?;
    acb.model
        .clone()
        .filter(|m| !m.trim().is_empty())
}

/// GET /context/:pid/budget — token budget remaining for an agent
pub async fn context_budget(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let model = agent_model(&state, &pid);
    let cm = state.context_mgr.lock().unwrap();
    let Some(ctx) = cm.get(&pid) else {
        return Json(serde_json::json!({
            "ok": false,
            "pid": pid,
            "error": "No context tracked for this agent",
            "hint": "Context is registered on first memory access or snapshot.",
        }));
    };
    let used = ctx.context_tokens;
    let limit = ctx.context_max_tokens;
    let pct = if limit > 0 { ctx.pressure() * 100.0 } else { 0.0 };
    Json(serde_json::json!({
        "ok": true,
        "pid": pid,
        "tokens_used":  used,
        "tokens_limit": limit,
        "tokens_remaining": limit.saturating_sub(used),
        "utilization_pct": pct,
        "status": budget_status(pct),
        "model": model,
        "session_id": ctx.session_id,
        "window_cids": ctx.context_window.len(),
        "reasoning_steps": ctx.reasoning_chain.len(),
        "step_counter": ctx.step_counter,
    }))
}

/// POST /context/:pid/flush — clear the working context window.
///
/// Without `purge_ephemeral` the window is snapshotted first so the flush is
/// recoverable; with it, the window is dropped outright.
pub async fn context_flush(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let purge_ephemeral = body
        .get("purge_ephemeral")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut cm = state.context_mgr.lock().unwrap();
    if cm.get(&pid).is_none() {
        return Json(serde_json::json!({
            "ok": false,
            "pid": pid,
            "error": "No context tracked for this agent",
        }));
    }

    let recovery_cid = if purge_ephemeral {
        None
    } else {
        cm.snapshot(&pid, now_u64()).ok()
    };

    let Some(ctx) = cm.get_mut(&pid) else {
        return Json(serde_json::json!({"ok": false, "pid": pid, "error": "context vanished"}));
    };
    let cids_cleared = ctx.context_window.len();
    let tokens_freed = ctx.context_tokens;
    let steps_cleared = ctx.reasoning_chain.len();
    ctx.context_window.clear();
    ctx.context_tokens = 0;
    if purge_ephemeral {
        ctx.reasoning_chain.clear();
    }

    Json(serde_json::json!({
        "ok": true,
        "pid": pid,
        "flushed": true,
        "purge_ephemeral": purge_ephemeral,
        // Real counts from the window that was cleared.
        "ephemeral_deleted": cids_cleared,
        "cids_cleared": cids_cleared,
        "tokens_freed": tokens_freed,
        "reasoning_steps_cleared": if purge_ephemeral { steps_cleared } else { 0 },
        "recovery_snapshot_cid": recovery_cid,
        "flushed_at": now_iso(),
    }))
}

/// Flatten a packet payload to searchable/previewable text.
fn payload_text(payload: &serde_json::Value) -> String {
    match payload {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => map
            .iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::String(s) => Some(format!("{}: {}", k, s)),
                serde_json::Value::Number(n) => Some(format!("{}: {}", k, n)),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

/// Fraction of query terms present in `text` (0.0..=1.0). With no query every
/// candidate scores 1.0 so recency ordering stands on its own.
fn lexical_score(text: &str, query_terms: &[String]) -> f64 {
    if query_terms.is_empty() {
        return 1.0;
    }
    let hay = text.to_ascii_lowercase();
    let hits = query_terms.iter().filter(|t| hay.contains(*t)).count();
    hits as f64 / query_terms.len() as f64
}

/// POST /context/:pid/assemble — preview what would be assembled for a query.
///
/// Walks the agent's real context window, scores each packet against the query,
/// and fills up to `budget_tokens` best-first.
pub async fn context_assemble(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let query = body
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let budget_tokens = body
        .get("budget_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(8_000);
    let query_terms: Vec<String> = query
        .to_ascii_lowercase()
        .split_whitespace()
        .filter(|t| t.len() > 2)
        .map(|t| t.to_string())
        .collect();

    let window: Vec<String> = {
        let cm = state.context_mgr.lock().unwrap();
        match cm.get(&pid) {
            Some(ctx) => ctx.context_window.clone(),
            None => {
                return Json(serde_json::json!({
                    "ok": false,
                    "pid": pid,
                    "error": "No context tracked for this agent",
                }))
            }
        }
    };

    let mut scored: Vec<(f64, u64, serde_json::Value)> = Vec::new();
    {
        let k = state.kernel.lock().unwrap();
        let packets = k.all_packets();
        for cid in &window {
            let Some(p) = packets
                .iter()
                .find(|p| p.content.payload_cid.to_string() == *cid)
            else {
                continue;
            };
            let text = payload_text(&p.content.payload);
            // ~4 chars per token, the same estimate the context manager uses.
            let tokens = (text.len() as u64 / 4).max(1);
            let score = lexical_score(&text, &query_terms);
            let preview: String = text.chars().take(160).collect();
            scored.push((
                score,
                tokens,
                serde_json::json!({
                    "cid": cid,
                    "kind": format!("{:?}", p.content.packet_type),
                    "scope": format!("{:?}", p.scope),
                    "tier": format!("{:?}", p.tier),
                    "tags": p.content.tags,
                    "score": score,
                    "tokens": tokens,
                    "preview": preview,
                }),
            ));
        }
    }

    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    let mut chunks = Vec::new();
    let mut total_tokens = 0u64;
    let mut dropped = 0usize;
    for (_, tokens, mut chunk) in scored {
        if total_tokens + tokens > budget_tokens {
            dropped += 1;
            continue;
        }
        total_tokens += tokens;
        if let Some(o) = chunk.as_object_mut() {
            o.insert("rank".into(), serde_json::json!(chunks.len() + 1));
        }
        chunks.push(chunk);
    }

    Json(serde_json::json!({
        "ok": true,
        "pid": pid,
        "query": query,
        "budget_tokens": budget_tokens,
        "total_tokens": total_tokens,
        "window_cids": window.len(),
        "dropped_over_budget": dropped,
        "chunks": chunks,
        "assembled_at": now_iso(),
    }))
}

/// GET /context/status — utilisation across every tracked agent.
pub async fn context_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let cm = state.context_mgr.lock().unwrap();
    let mut agents: Vec<serde_json::Value> = cm
        .live_contexts()
        .map(|ctx| {
            let pct = if ctx.context_max_tokens > 0 {
                ctx.pressure() * 100.0
            } else {
                0.0
            };
            serde_json::json!({
                "pid": ctx.agent_pid,
                "session_id": ctx.session_id,
                "tokens_used": ctx.context_tokens,
                "tokens_limit": ctx.context_max_tokens,
                "utilization_pct": pct,
                "status": budget_status(pct),
                "window_cids": ctx.context_window.len(),
            })
        })
        .collect();
    // Worst pressure first — that is what an operator is scanning for.
    agents.sort_by(|a, b| {
        let pa = a.get("utilization_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let pb = b.get("utilization_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
        pb.partial_cmp(&pa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let critical = agents
        .iter()
        .filter(|a| a.get("status").and_then(|v| v.as_str()) == Some("critical"))
        .count();
    let warning = agents
        .iter()
        .filter(|a| a.get("status").and_then(|v| v.as_str()) == Some("warning"))
        .count();

    Json(serde_json::json!({
        "ok": true,
        "total_agents": agents.len(),
        "critical": critical,
        "warning": warning,
        "snapshots": cm.snapshot_count(),
        "agents": agents,
        "queried_at": now_iso(),
    }))
}
