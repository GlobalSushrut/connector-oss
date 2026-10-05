use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    operator::honesty::operator_envelope,
    state::SharedState,
};

#[derive(Debug, Deserialize)]
pub struct WatchEventsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub cursor: Option<String>,
    /// Filter by agent PID (not workflow — ActionEngine indexes by agent).
    #[serde(default)]
    pub agent_pid: Option<String>,
    /// Soft filter: keep events whose target/intent/summary mention this id.
    #[serde(default)]
    pub workflow_id: Option<String>,
    /// Plane: stream (default) | tools | address | agent
    #[serde(default)]
    pub plane: Option<String>,
}

fn default_limit() -> usize {
    50
}

fn parse_cursor(cursor: &str) -> usize {
    cursor.parse().unwrap_or(0)
}

fn ts_rfc3339_from_millis(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339()
}

fn normalize_decision(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "ok" | "success" | "completed" | "approved" => "allow",
        "deny" | "denied" | "error" | "fail" | "failed" | "blocked" | "reject" | "rejected" => {
            "deny"
        }
        "skipped" | "pending" => "info",
        _ => "info",
    }
}

fn infer_workflow_id(target: &str, intent: &str) -> Option<String> {
    for candidate in [target, intent] {
        let c = candidate.trim();
        if c.starts_with("ref-") || c.starts_with("wf_") || c.contains("workflow") {
            return Some(c.to_string());
        }
        if c.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            && c.contains('-')
            && c.len() > 4
            && c.len() < 80
            && !c.contains('/')
            && !c.contains('.')
        {
            return Some(c.to_string());
        }
    }
    None
}

fn plane_name(q: &WatchEventsQuery) -> &str {
    q.plane
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("stream")
}

fn is_tool_op(op: &str) -> bool {
    let o = op.to_ascii_lowercase();
    o.contains("tooldispatch") || o.contains("tool_dispatch") || o.contains("mcp")
}

fn is_address_related(target: &str, summary: &str) -> bool {
    let blob = format!("{target} {summary}").to_ascii_lowercase();
    blob.contains("address")
        || blob.contains("dac")
        || blob.contains("tool:")
        || blob.contains("mcp:")
        || blob.contains("llm:")
        || blob.contains("memory:")
        || blob.contains("rules")
        || blob.contains("hitl")
}

/// Unified WATCH stream — AAPI actions + kernel audit, sliced by plane.
/// No synthetic health_tick (health stays on Pulse).
pub fn compute_watch_events(state: &SharedState, q: &WatchEventsQuery) -> Value {
    let plane = plane_name(q).to_ascii_lowercase();
    let offset = q.cursor.as_deref().map(parse_cursor).unwrap_or(0);
    let limit = q.limit.clamp(1, 500);
    let agent_filter = q
        .agent_pid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let wf_filter = q
        .workflow_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    let mut events: Vec<Value> = Vec::new();
    let mut sources = json!({
        "aapi_actions": false,
        "kernel_audit": false,
        "tool_approvals": false,
        "address_dac": false,
        "agent_activity": false,
        "health_tick": false
    });

    match plane.as_str() {
        "tools" => {
            sources["kernel_audit"] = json!(true);
            sources["tool_approvals"] = json!(true);
            emit_tool_audit(state, agent_filter, &mut events);
            emit_pending_tool_approvals(state, &mut events);
        }
        "address" => {
            sources["address_dac"] = json!(true);
            sources["kernel_audit"] = json!(true);
            emit_address_snapshot(state, &mut events);
            emit_address_audit(state, agent_filter, &mut events);
        }
        "agent" => {
            sources["kernel_audit"] = json!(true);
            sources["aapi_actions"] = json!(true);
            emit_aapi(state, agent_filter, &mut events);
            emit_kernel_audit(state, agent_filter, &mut events);
            // Prefer agent-scoped rows when filter set; otherwise keep all.
            if agent_filter.is_none() {
                // Still honest: empty means no records, not all-clear.
            }
        }
        _ => {
            // stream (default)
            sources["aapi_actions"] = json!(true);
            sources["kernel_audit"] = json!(true);
            emit_aapi(state, agent_filter, &mut events);
            emit_kernel_audit(state, agent_filter, &mut events);
        }
    }

    if let Some(wf) = wf_filter.as_deref() {
        events.retain(|ev| {
            ev.get("workflow_id")
                .and_then(|v| v.as_str())
                .map(|id| id.to_ascii_lowercase().contains(wf))
                .unwrap_or(false)
                || ev
                    .get("summary")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase().contains(wf))
                    .unwrap_or(false)
                || ev
                    .get("resource")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase().contains(wf))
                    .unwrap_or(false)
        });
    }

    events.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });

    let mut seen = std::collections::HashSet::new();
    events.retain(|e| {
        let id = e
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        seen.insert(id)
    });

    let total = events.len();
    let page: Vec<Value> = events.into_iter().skip(offset).take(limit).collect();
    let next_cursor = if offset + limit < total {
        Some((offset + limit).to_string())
    } else {
        None
    };

    json!({
        "schema": "operator_watch_events.v1",
        "plane": plane,
        "count": page.len(),
        "total": total,
        "next_cursor": next_cursor,
        "events": page,
        "sources": sources,
        "honesty": if total == 0 {
            "No records for this plane — empty is not all-clear."
        } else {
            "Measured kernel / AAPI / DAC rows only."
        }
    })
}

fn emit_aapi(state: &SharedState, agent_filter: Option<&str>, events: &mut Vec<Value>) {
    let aapi = state.aapi.lock().unwrap();
    for a in aapi.list_actions(agent_filter) {
        let decision = normalize_decision(&a.outcome);
        let workflow_id = infer_workflow_id(&a.target, &a.intent);
        let ts = ts_rfc3339_from_millis(a.timestamp);
        events.push(json!({
            "id": format!("action:{}:{}:{}", a.agent_pid, a.timestamp, a.action),
            "kind": "action",
            "plane": "stream",
            "timestamp": ts,
            "agent_pid": a.agent_pid,
            "intent": a.intent,
            "action": a.action,
            "target": a.target,
            "resource": a.target,
            "outcome": a.outcome,
            "decision": decision,
            "workflow_id": workflow_id,
            "summary": format!("{} → {} ({})", a.action, a.target, a.outcome),
        }));
    }
}

fn emit_kernel_audit(state: &SharedState, agent_filter: Option<&str>, events: &mut Vec<Value>) {
    let k = state.kernel.lock().unwrap();
    for e in k.audit_log().iter().rev().take(400) {
        if let Some(af) = agent_filter {
            if e.agent_pid != af {
                continue;
            }
        }
        let outcome = format!("{:?}", e.outcome);
        let decision = normalize_decision(&outcome);
        let target = e.target.clone().unwrap_or_default();
        let action = format!("{:?}", e.operation);
        let workflow_id = infer_workflow_id(&target, "");
        events.push(json!({
            "id": format!("audit:{}", e.audit_id),
            "kind": if decision == "deny" { "denied" } else { "kernel_audit" },
            "plane": "stream",
            "timestamp": ts_rfc3339_from_millis(e.timestamp),
            "agent_pid": e.agent_pid,
            "action": action,
            "target": target.clone(),
            "resource": target,
            "outcome": outcome,
            "decision": decision,
            "reason": e.reason,
            "audit_id": e.audit_id,
            "workflow_id": workflow_id,
            "summary": e.natural_language.clone().unwrap_or_else(|| {
                format!("{:?} {:?} {}", e.operation, e.outcome, e.reason.clone().unwrap_or_default())
            }),
        }));
    }
}

fn emit_tool_audit(state: &SharedState, agent_filter: Option<&str>, events: &mut Vec<Value>) {
    let k = state.kernel.lock().unwrap();
    for e in k.audit_log().iter().rev().take(400) {
        if let Some(af) = agent_filter {
            if e.agent_pid != af {
                continue;
            }
        }
        let action = format!("{:?}", e.operation);
        if !is_tool_op(&action) {
            continue;
        }
        let outcome = format!("{:?}", e.outcome);
        let decision = normalize_decision(&outcome);
        let target = e.target.clone().unwrap_or_default();
        events.push(json!({
            "id": format!("tool:{}", e.audit_id),
            "kind": "tool_dispatch",
            "plane": "tools",
            "timestamp": ts_rfc3339_from_millis(e.timestamp),
            "agent_pid": e.agent_pid,
            "action": action,
            "target": target.clone(),
            "resource": target,
            "outcome": outcome,
            "decision": decision,
            "reason": e.reason,
            "audit_id": e.audit_id,
            "summary": e.natural_language.clone().unwrap_or_else(|| {
                format!("ToolDispatch {:?} {}", e.outcome, e.reason.clone().unwrap_or_default())
            }),
        }));
    }
}

fn emit_pending_tool_approvals(state: &SharedState, events: &mut Vec<Value>) {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("pending_approvals", None).unwrap_or_default();
    for audit_id in keys {
        let Some(call) = es.folder_get("pending_approvals", &audit_id).ok().flatten() else {
            continue;
        };
        let tool = call
            .get("tool")
            .or_else(|| call.get("tool_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("tool");
        let agent = call
            .get("agent_pid")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let ts = call
            .get("created_at")
            .cloned()
            .unwrap_or_else(|| json!(chrono::Utc::now().to_rfc3339()));
        events.push(json!({
            "id": format!("pending:{audit_id}"),
            "kind": "tool_pending",
            "plane": "tools",
            "timestamp": ts,
            "agent_pid": agent,
            "action": "ToolDispatch",
            "target": tool,
            "resource": tool,
            "outcome": "pending",
            "decision": "info",
            "audit_id": audit_id,
            "summary": format!("Pending tool approval: {tool}"),
            "fix_href": "/fix",
        }));
    }
}

fn emit_address_snapshot(state: &SharedState, events: &mut Vec<Value>) {
    let addresses = crate::kernel::address_contracts::known_addresses(state.as_ref());
    let count = addresses.len();
    events.push(json!({
        "id": format!("dac:index:{}", chrono::Utc::now().timestamp_millis()),
        "kind": "address_dac_index",
        "plane": "address",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "agent_pid": "—",
        "action": "address_dac_index",
        "target": "kernel/address-dac",
        "resource": "address_dac",
        "outcome": "snapshot",
        "decision": "info",
        "summary": format!("DAC index: {count} address(es)"),
        "count": count,
        "addresses": addresses,
    }));
}

fn emit_address_audit(state: &SharedState, agent_filter: Option<&str>, events: &mut Vec<Value>) {
    let k = state.kernel.lock().unwrap();
    for e in k.audit_log().iter().rev().take(400) {
        if let Some(af) = agent_filter {
            if e.agent_pid != af {
                continue;
            }
        }
        let target = e.target.clone().unwrap_or_default();
        let summary = e.natural_language.clone().unwrap_or_default();
        if !is_address_related(&target, &summary) {
            continue;
        }
        let outcome = format!("{:?}", e.outcome);
        let decision = normalize_decision(&outcome);
        let action = format!("{:?}", e.operation);
        events.push(json!({
            "id": format!("addr:{}", e.audit_id),
            "kind": "address_audit",
            "plane": "address",
            "timestamp": ts_rfc3339_from_millis(e.timestamp),
            "agent_pid": e.agent_pid,
            "action": action,
            "target": target.clone(),
            "resource": target,
            "outcome": outcome,
            "decision": decision,
            "reason": e.reason,
            "audit_id": e.audit_id,
            "summary": if summary.is_empty() {
                format!("Address-related {:?}", e.operation)
            } else {
                summary
            },
        }));
    }
}

/// `GET /api/v1/operator/watch/events`
pub async fn get_operator_watch_events(
    State(state): State<SharedState>,
    Query(q): Query<WatchEventsQuery>,
) -> Json<Value> {
    Json(operator_envelope(compute_watch_events(&state, &q)))
}
