use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

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

struct TtWindow {
    wired: bool,
    rows: Vec<Value>,
    table_total: Option<u64>,
}

fn tt_admin_endpoint() -> Option<(String, String)> {
    if !crate::services::tracetramp_proxy::tracetramp_management_plane_configured() {
        return None;
    }
    let base = std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
        .or_else(|_| std::env::var("TRACETRAMP_MANAGEMENT_URL"))
        .ok()
        .or_else(|| crate::services::plugin_configure::overlay_string("tracetramp", "management_url"))
        .unwrap_or_else(|| "http://127.0.0.1:19742".into());
    let token = std::env::var("CONNECTOR_TRACETRAMP_ADMIN_TOKEN")
        .or_else(|_| std::env::var("TRACETRAMP_ADMIN_TOKEN"))
        .ok()
        .or_else(|| crate::services::plugin_configure::overlay_string("tracetramp", "admin_token"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    Some((base.trim_end_matches('/').to_string(), token))
}

async fn fetch_tt_window(client: &reqwest::Client, base: &str, token: &str) -> TtWindow {
    let url = format!("{base}/admin/approvals");
    let Ok(resp) = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
        .send()
        .await
    else {
        return TtWindow { wired: true, rows: Vec::new(), table_total: None };
    };
    if !resp.status().is_success() {
        return TtWindow { wired: true, rows: Vec::new(), table_total: None };
    }
    let Ok(body) = resp.json::<Value>().await else {
        return TtWindow { wired: true, rows: Vec::new(), table_total: None };
    };
    let rows = body
        .get("approvals")
        .or_else(|| body.get("items"))
        .or_else(|| body.get("pending"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let table_total = body.get("total").and_then(|v| v.as_u64());
    TtWindow { wired: true, rows, table_total }
}

fn row_text<'a>(row: &'a Value, keys: &[&str]) -> &'a str {
    for key in keys {
        if let Some(text) = row.get(*key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
            return text;
        }
    }
    ""
}

fn pending_connector_rows(rows: &[Value], pids: &std::collections::HashSet<String>) -> Vec<Value> {
    rows.iter()
        .filter(|row| {
            row.get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.eq_ignore_ascii_case("pending"))
                .unwrap_or(true)
        })
        .filter(|row| actor_is_connector_agent(row_text(row, &["actor_id"]), pids))
        .cloned()
        .collect()
}

/// One card per actor + reason. A 50-card slice of the same reason is not a queue.
fn group_tt_rows(rows: &[Value]) -> Vec<Value> {
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for row in rows {
        let actor = row_text(row, &["actor_id", "agent_pid"]).to_string();
        let reason = row_text(row, &["reason", "title", "summary"]).to_string();
        let reason = if reason.is_empty() {
            "TraceTramp hold".to_string()
        } else {
            reason
        };
        *counts.entry((actor, reason)).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((actor, reason), count)| {
            json!({
                "actor_id": actor,
                "reason": reason,
                "count": count,
            })
        })
        .collect()
}

async fn tracetramp_approval_items(state: &SharedState) -> (Vec<Value>, TtWindow, Vec<Value>) {
    let Some((base, token)) = tt_admin_endpoint() else {
        return (Vec::new(), TtWindow { wired: false, rows: Vec::new(), table_total: None }, Vec::new());
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
    else {
        return (Vec::new(), TtWindow { wired: true, rows: Vec::new(), table_total: None }, Vec::new());
    };
    let window = fetch_tt_window(&client, &base, &token).await;
    let pids = connector_agent_pids(state);
    let matched = pending_connector_rows(&window.rows, &pids);
    let groups = group_tt_rows(&matched);
    let items = matched
        .iter()
        .filter_map(|row| {
            let id = row_text(row, &["id", "approval_id"]);
            if id.is_empty() {
                return None;
            }
            let reason = row_text(row, &["reason", "title", "summary", "tool"]);
            let title = if reason.is_empty() { "TraceTramp approval" } else { reason };
            Some(governance_item(
                format!("tt:{id}"),
                "tracetramp_approval",
                title.to_string(),
                "medium",
                row.get("created_at").cloned().unwrap_or(json!(chrono::Utc::now().to_rfc3339())),
                json!({
                    "owner": "tracetramp_reviewer",
                    "request_id": id,
                    "agent_pid": row.get("actor_id"),
                    "reason": title,
                    "primary_action": "tt_approve",
                    "approve_url": format!("/api/v1/plugins/tracetramp/admin/approvals/{id}/approve"),
                    "deny_url": format!("/api/v1/plugins/tracetramp/admin/approvals/{id}/reject"),
                    "hint": "Grouped on Fix. POST /operator/fix/tracetramp/decide walks every later window.",
                }),
            ))
        })
        .collect();
    (items, window, groups)
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

const FIX_HONESTY: &str = "Approve is PATE (iia_hitl_requests) and live tool approvals. Fix is TraceTramp holds whose actor_id is a live Connector agent. A TraceTramp approve arms the resume latch and does not run the held request. A PATE approve runs that ask. Historical denials belong on Watch.";

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
    let (tt_items, window, groups) = tracetramp_approval_items(state).await;
    let tt_shown = tt_items.len();
    let window_len = window.rows.len();
    let window_full = window_len >= 100;
    items.extend(tt_items);
    sort_items_newest_first(&mut items);
    let note = if !window.wired {
        "TraceTramp management plane is not configured.".to_string()
    } else if window_full {
        match window.table_total {
            Some(total) => format!(
                "TraceTramp returned its newest {window_len} pending rows. {tt_shown} belong to Connector agents, in {} groups. The table has {total} pending rows. A 50-card slice stayed full because the next hold filled each gap. Clear and Approve walk every later window.",
                groups.len()
            ),
            None => format!(
                "TraceTramp returned its newest {window_len} pending rows, which is its list cap. {tt_shown} belong to Connector agents, in {} groups. Older holds are behind that cap. A 50-card slice stayed full because the next hold filled each gap. Clear and Approve walk every later window.",
                groups.len()
            ),
        }
    } else {
        format!(
            "TraceTramp returned {window_len} pending rows. {tt_shown} belong to Connector agents, in {} groups.",
            groups.len()
        )
    };
    let honesty = format!("{FIX_HONESTY} {note}");
    json!({
        "schema": GOVERNANCE_INBOX_SCHEMA,
        "count": items.len(),
        "items": items,
        "sources": {
            "hitl_approvals": true,
            "tool_approvals": true,
            "tracetramp_approvals": window.wired,
            "tracetramp_pending": window.table_total.unwrap_or(tt_shown as u64),
            "tracetramp_shown": tt_shown,
            "tracetramp_window": window_len,
            "tracetramp_window_full": window_full,
            "tracetramp_groups": groups,
            "tracetramp_note": note,
            "denied_operations": false,
            "workflow_fix_rules": false
        },
        "honesty": honesty,
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

/// `POST /api/v1/operator/fix/tracetramp/decide`
///
/// `action` is `reject` (clear) or `approve` (arm the resume latch).
/// Optional `actor_id` and `reason` limit the walk to one group.
/// TraceTramp lists at most 100 newest pending rows, so this repeats until a pass
/// finds nothing left to decide, or `max` is reached.
pub async fn post_fix_tracetramp_decide(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let _ = headers;
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "approve" && action != "reject" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "action must be approve or reject",
                "honesty": "Fix clear/approve decides TraceTramp holds only. It does not decide a PATE ask.",
            })),
        )
            .into_response();
    }
    if crate::substrate::handoff_queue::handoff_backpressure_active(state.as_ref()) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "error": "handoff_backpressure",
                "honesty": "TraceTramp mutating calls are blocked while WitnessCtl handoffs are over the cap.",
            })),
        )
            .into_response();
    }
    let Some((base, token)) = tt_admin_endpoint() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "error": "tracetramp_unconfigured",
                "honesty": "TraceTramp management plane is not configured.",
            })),
        )
            .into_response();
    };
    let max = body
        .get("max")
        .and_then(|v| v.as_u64())
        .unwrap_or(500)
        .min(2000) as usize;
    let reason_filter = body.get("reason").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let actor_filter = body.get("actor_id").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": "http_client"})),
        )
            .into_response();
    };

    let mut decided = 0usize;
    let mut failed = 0usize;
    let mut latched = 0usize;
    let mut latch_failed = 0usize;
    let mut failed_ids: HashSet<String> = HashSet::new();
    let mut rounds = 0usize;
    let mut last_error = String::new();

    loop {
        if decided >= max || rounds >= 40 {
            break;
        }
        rounds += 1;
        let window = fetch_tt_window(&client, &base, &token).await;
        let pids = connector_agent_pids(&state);
        let matched = pending_connector_rows(&window.rows, &pids);
        let mut progress = false;
        for row in matched {
            if decided >= max {
                break;
            }
            let actor = row_text(&row, &["actor_id"]);
            if let Some(want) = actor_filter {
                if actor != want {
                    continue;
                }
            }
            let reason = row_text(&row, &["reason", "title", "summary"]);
            if let Some(want) = reason_filter {
                if reason != want {
                    continue;
                }
            }
            let id = row_text(&row, &["id", "approval_id"]).to_string();
            if id.is_empty() || failed_ids.contains(&id) {
                continue;
            }
            let path = if action == "approve" { "approve" } else { "reject" };
            let url = format!("{base}/admin/approvals/{id}/{path}");
            let sent = client
                .post(&url)
                .header("Authorization", format!("Bearer {token}"))
                .header("Accept", "application/json")
                .json(&json!({"approver_id": "operator"}))
                .send()
                .await;
            let ok = match sent {
                Ok(resp) if resp.status().is_success() => true,
                Ok(resp) => {
                    last_error = format!("HTTP {}", resp.status());
                    false
                }
                Err(err) => {
                    last_error = err.to_string();
                    false
                }
            };
            if !ok {
                failed += 1;
                failed_ids.insert(id);
                continue;
            }
            decided += 1;
            progress = true;
            if action == "approve" {
                let exec = format!("{base}/admin/approvals/{id}/execute");
                let latched_ok = client
                    .post(&exec)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Accept", "application/json")
                    .json(&json!({}))
                    .send()
                    .await
                    .map(|resp| resp.status().is_success())
                    .unwrap_or(false);
                if latched_ok {
                    latched += 1;
                } else {
                    latch_failed += 1;
                }
            }
        }
        if !progress {
            break;
        }
    }

    let window = fetch_tt_window(&client, &base, &token).await;
    let pids = connector_agent_pids(&state);
    let remaining = pending_connector_rows(&window.rows, &pids)
        .into_iter()
        .filter(|row| {
            if let Some(want) = actor_filter {
                if row_text(row, &["actor_id"]) != want {
                    return false;
                }
            }
            if let Some(want) = reason_filter {
                if row_text(row, &["reason", "title", "summary"]) != want {
                    return false;
                }
            }
            true
        })
        .count();

    let honesty = if action == "reject" {
        format!(
            "Cleared {decided} TraceTramp holds (rejected). Failed: {failed}. Remaining in the newest window: {remaining}. Nothing was resumed. This is not a PATE denial. {last_error}"
        )
    } else {
        format!(
            "Approved {decided} TraceTramp holds. Resume latch armed: {latched}. Latch failed: {latch_failed}. Failed before approve: {failed}. Remaining in the newest window: {remaining}. Connector did not run the held requests. This is not a PATE ask. The original caller retries with X-Approval-Resume and X-Approval-Id. {last_error}"
        )
    };
    let ok = decided > 0 || failed == 0;
    (
        StatusCode::OK,
        Json(operator_envelope(json!({
            "ok": ok,
            "action": action,
            "decided": decided,
            "failed": failed,
            "latched": latched,
            "latch_failed": latch_failed,
            "rounds": rounds,
            "remaining_in_window": remaining,
            "executed": false,
            "pate": false,
            "honesty": honesty.trim(),
        }))),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::group_tt_rows;
    use serde_json::json;

    #[test]
    fn sixty_identical_holds_are_one_group_not_fifty_cards() {
        let rows: Vec<_> = (0..60)
            .map(|i| {
                json!({
                    "id": format!("id-{i}"),
                    "actor_id": "pid:000002",
                    "reason": "Request held for human approval (default HITL policy): publish",
                    "status": "pending",
                })
            })
            .collect();
        let groups = group_tt_rows(&rows);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["count"], 60);
        assert_eq!(groups[0]["actor_id"], "pid:000002");
    }

    #[test]
    fn publish_and_delete_stay_separate_groups() {
        let rows = vec![
            json!({"id":"a","actor_id":"pid:000002","reason":"publish"}),
            json!({"id":"b","actor_id":"pid:000002","reason":"publish"}),
            json!({"id":"c","actor_id":"pid:000002","reason":"delete"}),
            json!({"id":"d","actor_id":"pid:000003","reason":"publish"}),
        ];
        let groups = group_tt_rows(&rows);
        assert_eq!(groups.len(), 3);
    }
}
