use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::{operator::honesty::operator_envelope, state::SharedState};

const GOVERNANCE_INBOX_SCHEMA: &str = "connector.governance_inbox.v1";

/// DG-10 — normalize every FIX/HITL row to one owner/risk/expiry/remediation shape.
/// `primary_action` / URLs / hint live on the item **and** under `remediation` so the UI
/// does not have to guess.
fn governance_item(
    id: String,
    kind: &str,
    title: String,
    severity: &str,
    timestamp: Value,
    extra: Value,
) -> Value {
    let primary = extra
        .get("primary_action")
        .cloned()
        .unwrap_or(json!("inspect"));
    let approve_url = extra.get("approve_url").cloned().unwrap_or(Value::Null);
    let deny_url = extra.get("deny_url").cloned().unwrap_or(Value::Null);
    let hint = extra.get("hint").cloned().unwrap_or(Value::Null);
    let mut obj = json!({
        "schema": GOVERNANCE_INBOX_SCHEMA,
        "id": id,
        "kind": kind,
        "title": title,
        "severity": severity,
        "risk": severity,
        "owner": extra.get("owner").cloned().unwrap_or(json!("operator")),
        "expires_at": extra.get("expires_at").cloned().unwrap_or(Value::Null),
        "timestamp": timestamp,
        "primary_action": primary.clone(),
        "approve_url": approve_url.clone(),
        "deny_url": deny_url.clone(),
        "hint": hint.clone(),
        "remediation": {
            "primary_action": primary,
            "approve_url": approve_url,
            "deny_url": deny_url,
            "hint": hint,
        },
    });
    if let (Some(dst), Some(src)) = (obj.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            if matches!(
                k.as_str(),
                "owner" | "expires_at" | "primary_action" | "approve_url" | "deny_url" | "hint"
            ) {
                continue;
            }
            dst.insert(k.clone(), v.clone());
        }
    }
    obj
}

/// Live tool calls still sitting in `pending_approvals` (what `POST /tools/approvals/:id` consumes).
/// Historical `ToolDispatch` + `Skipped` audit rows are not open work.
fn tool_approval_items(state: &SharedState) -> Vec<Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("pending_approvals", None).unwrap_or_default();
    keys.iter()
        .filter_map(|audit_id| {
            let call = es.folder_get("pending_approvals", audit_id).ok().flatten()?;
            let agent_pid = call
                .get("agent_pid")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tool = call
                .get("tool")
                .or_else(|| call.get("tool_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("tool");
            let created = call
                .get("created_at")
                .cloned()
                .unwrap_or_else(|| json!(chrono::Utc::now().to_rfc3339()));
            Some(governance_item(
                format!("approval:{audit_id}"),
                "tool_approval",
                format!("Tool approval: {tool}"),
                "medium",
                created,
                json!({
                    "owner": "operator",
                    "agent_pid": agent_pid,
                    "audit_id": audit_id,
                    "tool": tool,
                    "primary_action": "approve_tool",
                    "approve_url": format!("/api/v1/tools/approvals/{audit_id}"),
                    "hint": format!("POST /tools/approvals/{audit_id} — only listed while pending_approvals still holds this id."),
                }),
            ))
        })
        .take(100)
        .collect()
}

fn connector_agent_pids(state: &SharedState) -> std::collections::HashSet<String> {
    let k = state.kernel.lock().unwrap();
    k.agents().keys().cloned().collect()
}

fn actor_is_connector_agent(actor: &str, pids: &std::collections::HashSet<String>) -> bool {
    if actor.is_empty() {
        return false;
    }
    if pids.contains(actor) {
        return true;
    }
    for prefix in ["pid:", "agent:", "actor:"] {
        if let Some(rest) = actor.strip_prefix(prefix) {
            if pids.contains(rest) {
                return true;
            }
        }
    }
    false
}

async fn tracetramp_approval_items(state: &SharedState) -> (Vec<Value>, bool) {
    if !crate::services::tracetramp_proxy::tracetramp_management_plane_configured() {
        return (Vec::new(), false);
    }
    let base = std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
        .or_else(|_| std::env::var("TRACETRAMP_MANAGEMENT_URL"))
        .ok()
        .or_else(|| {
            crate::services::plugin_configure::overlay_string("tracetramp", "management_url")
        })
        .unwrap_or_else(|| "http://127.0.0.1:19742".into());
    let base = base.trim_end_matches('/').to_string();
    let Some(token) = std::env::var("CONNECTOR_TRACETRAMP_ADMIN_TOKEN")
        .or_else(|_| std::env::var("TRACETRAMP_ADMIN_TOKEN"))
        .ok()
        .or_else(|| crate::services::plugin_configure::overlay_string("tracetramp", "admin_token"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return (Vec::new(), false);
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (Vec::new(), true),
    };
    let url = format!("{base}/admin/approvals");
    let Ok(resp) = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
        .send()
        .await
    else {
        return (Vec::new(), true);
    };
    if !resp.status().is_success() {
        return (Vec::new(), true);
    }
    let Ok(body) = resp.json::<Value>().await else {
        return (Vec::new(), true);
    };
    let arr = body
        .get("approvals")
        .or_else(|| body.get("items"))
        .or_else(|| body.get("pending"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let pids = connector_agent_pids(state);
    let items = arr
        .into_iter()
        .filter(|a| {
            a.get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.eq_ignore_ascii_case("pending"))
                .unwrap_or(true)
        })
        .filter(|a| {
            let actor = a.get("actor_id").and_then(|x| x.as_str()).unwrap_or("");
            actor_is_connector_agent(actor, &pids)
        })
        .take(50)
        .filter_map(|a| {
            let id = a
                .get("id")
                .or_else(|| a.get("approval_id"))
                .and_then(|x| x.as_str())?
                .to_string();
            let title = a
                .get("title")
                .or_else(|| a.get("summary"))
                .or_else(|| a.get("reason"))
                .or_else(|| a.get("tool"))
                .and_then(|x| x.as_str())
                .unwrap_or("TraceTramp approval")
                .to_string();
            Some(governance_item(
                format!("tt:{id}"),
                "tracetramp_approval",
                title,
                "medium",
                a.get("created_at").cloned().unwrap_or(json!(chrono::Utc::now().to_rfc3339())),
                json!({
                    "owner": "tracetramp_reviewer",
                    "request_id": id,
                    "agent_pid": a.get("actor_id"),
                    "primary_action": "tt_approve",
                    "approve_url": format!("/api/v1/plugins/tracetramp/admin/approvals/{id}/approve"),
                    "deny_url": format!("/api/v1/plugins/tracetramp/admin/approvals/{id}/reject"),
                    "hint": "POST /plugins/tracetramp/admin/approvals/{id}/approve",
                }),
            ))
        })
        .collect();
    (items, true)
}

fn hitl_pending_items(state: &SharedState) -> Vec<Value> {
    crate::services::agents::hitl_ensure_hydrated(state);
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("iia_hitl_requests", None).unwrap_or_default();
    keys.iter()
        .filter_map(|k| es.folder_get("iia_hitl_requests", k).ok().flatten())
        .filter(|v| v.get("status").and_then(|s| s.as_str()) == Some("pending"))
        .take(100)
        .map(|v| {
            let request_id = v.get("request_id").and_then(|x| x.as_str()).unwrap_or("");
            let agent_pid = v.get("agent_pid").and_then(|x| x.as_str()).unwrap_or("");
            let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("action");
            let description = v.get("description").and_then(|x| x.as_str()).unwrap_or("");
            let kind = if action.starts_with("devguard.") {
                "devguard_approval"
            } else {
                "hitl_approval"
            };
            let expires_at = v
                .get("timeout_at")
                .and_then(|t| t.as_u64())
                .and_then(|ms| chrono::DateTime::from_timestamp_millis(ms as i64))
                .map(|d| d.to_rfc3339());
            governance_item(
                format!("hitl:{request_id}"),
                kind,
                format!("HITL: {action}"),
                "high",
                v.get("created_at")
                    .and_then(|t| t.as_u64())
                    .and_then(|ms| chrono::DateTime::from_timestamp_millis(ms as i64))
                    .map(|d| json!(d.to_rfc3339()))
                    .unwrap_or_else(|| json!(chrono::Utc::now().to_rfc3339())),
                json!({
                    "owner": if kind == "devguard_approval" { "devguard_owner" } else { "agent_owner" },
                    "expires_at": expires_at,
                    "agent_pid": agent_pid,
                    "request_id": request_id,
                    "description": description,
                    "action_digest": v.get("action_digest"),
                    "timeout_at": v.get("timeout_at"),
                    "primary_action": "approve_or_deny",
                    "approve_url": format!("/api/v1/agents/{agent_pid}/hitl/{request_id}/approve"),
                    "deny_url": format!("/api/v1/agents/{agent_pid}/hitl/{request_id}/deny"),
                    "hint": "Digest-bound approval — approve then retry the exact action once.",
                }),
            )
        })
        .collect()
}

const FIX_HONESTY: &str = "FIX is pending human decisions only: HITL rows in iia_hitl_requests with status=pending, tool calls still in pending_approvals, and TraceTramp holds whose actor_id is a live Connector agent. Historical denials belong on Watch. A TraceTramp approval_queue full of plugin demo actors is not this node's Fix inbox.";

fn sort_items_newest_first(items: &mut [Value]) {
    items.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        tb.cmp(ta)
    });
}

/// Build unified FIX inbox for operator shell.
pub async fn compute_fix_queue_async(state: &SharedState) -> Value {
    let mut items = tool_approval_items(state);
    items.extend(hitl_pending_items(state));
    let (tt_items, tt_wired) = tracetramp_approval_items(state).await;
    items.extend(tt_items);
    sort_items_newest_first(&mut items);
    json!({
        "schema": GOVERNANCE_INBOX_SCHEMA,
        "count": items.len(),
        "items": items,
        "sources": {
            "hitl_approvals": true,
            "tool_approvals": true,
            "tracetramp_approvals": tt_wired,
            "denied_operations": false,
            "workflow_fix_rules": false
        },
        "honesty": FIX_HONESTY,
    })
}

/// Sync helper for tests / non-async callers (no TT upstream fetch).
pub fn compute_fix_queue(state: &SharedState) -> Value {
    let mut items = tool_approval_items(state);
    items.extend(hitl_pending_items(state));
    sort_items_newest_first(&mut items);
    json!({
        "schema": GOVERNANCE_INBOX_SCHEMA,
        "count": items.len(),
        "items": items,
        "sources": {
            "hitl_approvals": true,
            "tool_approvals": true,
            "tracetramp_approvals": false,
            "denied_operations": false,
            "workflow_fix_rules": false
        },
        "honesty": FIX_HONESTY,
    })
}

/// `GET /api/v1/operator/fix/queue`
pub async fn get_operator_fix_queue(State(state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(compute_fix_queue_async(&state).await))
}
