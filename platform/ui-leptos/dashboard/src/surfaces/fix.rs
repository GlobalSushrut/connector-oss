use leptos::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::cards::OpIssueCard;
use crate::components::operator::overlays::result_sheet::OpResultSheet;
use crate::components::operator::primitives::{
    OpEmptyState, OpGrid, OpSpinner, OpText, OpTextVariant,
};
use crate::request_store::{bump_reload, use_shared_requests};
use crate::ui_state::{open_agent_drawer, open_topic_drawer, DrawerTopic};

const FIX_POLL_MS: u64 = 5_000;

#[component]
pub fn FixCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let shared = use_shared_requests();
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());

    Effect::new(move |prev: Option<bool>| {
        if prev.unwrap_or(false) {
            return true;
        }
        let _ = set_interval_with_handle(
            move || bump_reload(),
            Duration::from_millis(FIX_POLL_MS),
        );
        true
    });

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10">
            <OpText text="FIX".to_string() variant=OpTextVariant::Title />
            <p class="mt-1 mb-4 text-sm text-zinc-500">
                "Pending human decisions from GET /operator/fix/queue — PATE Ask (digest-bound HITL), live tool approvals, TraceTramp when wired. Digests identify the exact action to retry after approve. Historical denials are on Watch. Auto-refresh every 5s."
            </p>
            <Suspense fallback=move || view! { <div class="flex justify-center py-12"><OpSpinner /></div> }>
                {move || Suspend::new(async move {
                    let payload = shared.fix_queue.await.ok();
                    let honesty = payload
                        .as_ref()
                        .and_then(|v| api::resource_object(v).get("honesty").and_then(|h| h.as_str()).map(str::to_string))
                        .unwrap_or_default();
                    let items = payload.as_ref().map(|v| parse_items(v)).unwrap_or_default();
                    if items.is_empty() {
                        view! {
                            <OpEmptyState
                                title="Nothing pending"
                                description="This inbox stays empty until a HITL request is pending, a tool call is still in pending_approvals, or TraceTramp has an open approval. Past denials are on Watch — they are not open work."
                            />
                            {(!honesty.is_empty()).then(|| view! {
                                <p class="mt-2 max-w-xl text-center font-mono text-[10px] text-zinc-600">{honesty.clone()}</p>
                            })}
                        }.into_any()
                    } else {
                        view! {
                            <OpGrid cols="grid-cols-1 lg:grid-cols-2">
                                {items.into_iter().map(|item| {
                                    let item_fix = item.clone();
                                    let item_deny_click = item.clone();
                                    let item_open = item.clone();
                                    let primary = primary_label(&item);
                                    let deny_label = deny_label(&item).unwrap_or_default();
                                    let digest_line = item
                                        .action_digest
                                        .as_ref()
                                        .filter(|d| !d.is_empty())
                                        .cloned();
                                    view! {
                                        <div class="space-y-1">
                                            <OpIssueCard
                                                title=item.title.clone()
                                                detail=item.detail.clone()
                                                severity=item.severity.clone()
                                                primary_label=primary
                                                secondary_label=deny_label
                                                on_fix=Arc::new(move |_| {
                                                    let item = item_fix.clone();
                                                    spawn_local(async move {
                                                        report_fix_result(
                                                            &item,
                                                            execute_decision(&item, Decision::Approve).await,
                                                            set_result_title,
                                                            set_result_summary,
                                                            set_result_open,
                                                        );
                                                    });
                                                })
                                                on_secondary=Arc::new(move |_| {
                                                    let item = item_deny_click.clone();
                                                    spawn_local(async move {
                                                        report_fix_result(
                                                            &item,
                                                            execute_decision(&item, Decision::Deny).await,
                                                            set_result_title,
                                                            set_result_summary,
                                                            set_result_open,
                                                        );
                                                    });
                                                })
                                                on_open=Arc::new(move |_| open_fix_target(&item_open))
                                            />
                                            {digest_line.map(|d| view! {
                                                <p class="px-1 font-mono text-[10px] text-amber-200/80 break-all">
                                                    {format!("action_digest={d}")}
                                                </p>
                                            })}
                                        </div>
                                    }
                                }).collect_view()}
                            </OpGrid>
                            <OpResultSheet
                                open=result_open
                                set_open=set_result_open
                                title=result_title
                                summary=result_summary
                            />
                        }.into_any()
                    }
                })}
            </Suspense>
        </div>
    }
}

fn report_fix_result(
    item: &FixItem,
    result: Result<String, String>,
    set_result_title: WriteSignal<String>,
    set_result_summary: WriteSignal<String>,
    set_result_open: WriteSignal<bool>,
) {
    match result {
        Ok(msg) => {
            set_result_title.set(item.title.clone());
            set_result_summary.set(msg);
            set_result_open.set(true);
            bump_reload();
        }
        Err(e) => {
            set_result_title.set(format!("Fix failed · {}", item.kind));
            set_result_summary.set(e);
            set_result_open.set(true);
            open_fix_target(item);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decision {
    Approve,
    Deny,
}

#[derive(Clone)]
struct FixItem {
    title: String,
    detail: String,
    kind: String,
    severity: String,
    primary_action: String,
    agent_pid: Option<String>,
    audit_id: Option<String>,
    request_id: Option<String>,
    action_digest: Option<String>,
    approve_url: Option<String>,
    deny_url: Option<String>,
}

fn primary_label(item: &FixItem) -> String {
    let a = item.primary_action.to_ascii_lowercase();
    let title = item.title.to_ascii_lowercase();
    let kind = item.kind.to_ascii_lowercase();
    if a.contains("unquarantine")
        || kind.contains("quarantine")
        || title.contains("unquarantine")
        || title.contains("quarantine")
    {
        return "Approve unquarantine → Talk 200".into();
    }
    match item.kind.as_str() {
        "tool_approval" => "Approve tool".into(),
        "tracetramp_approval" => "Approve (TT)".into(),
        "hitl_approval" | "devguard_approval" => {
            if item.action_digest.as_ref().is_some_and(|d| !d.is_empty()) {
                "Approve digest (PATE Ask)".into()
            } else {
                "Approve".into()
            }
        }
        _ => "Approve".into(),
    }
}

fn deny_label(item: &FixItem) -> Option<String> {
    if item.deny_url.as_ref().is_some_and(|u| !u.is_empty()) {
        return Some("Deny".into());
    }
    if item.kind == "tool_approval" && item.audit_id.as_ref().is_some_and(|u| !u.is_empty()) {
        return Some("Deny tool".into());
    }
    if matches!(item.kind.as_str(), "hitl_approval" | "devguard_approval")
        && item.request_id.as_ref().is_some_and(|u| !u.is_empty())
    {
        return Some("Deny".into());
    }
    None
}

fn open_fix_target(item: &FixItem) {
    if let Some(pid) = item.agent_pid.clone() {
        open_agent_drawer(pid);
    } else if item.kind == "tracetramp_approval" {
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_href("/plugins/tracetramp");
        }
    } else {
        open_topic_drawer(DrawerTopic::Monitor);
    }
}

fn strip_api_prefix(path: &str) -> String {
    path.strip_prefix("/api/v1")
        .or_else(|| path.strip_prefix("/api/v2"))
        .unwrap_or(path)
        .to_string()
}

fn still_open(value: &Value) -> Option<String> {
    let err = value
        .get("error")
        .and_then(|item| item.as_str())
        .filter(|item| !item.is_empty());
    let ok = value.get("ok").and_then(|item| item.as_bool());
    if ok == Some(false) || err.is_some() {
        return Some(err.unwrap_or("not_completed").to_string());
    }
    None
}

async fn post_fix(path: &str, body: Value) -> Result<Value, String> {
    let path = strip_api_prefix(path);
    let value = api::post_value(&path, body)
        .await
        .map_err(|e| format!("POST {path} — {}", e.message))?;
    if let Some(err) = still_open(&value) {
        return Err(format!(
            "{err}. The PATE ask is still open. Nothing was executed."
        ));
    }
    Ok(value)
}

fn decision_verb(decision: Decision) -> &'static str {
    match decision {
        Decision::Approve => "Approved",
        Decision::Deny => "Denied",
    }
}

async fn execute_decision(item: &FixItem, decision: Decision) -> Result<String, String> {
    let url = match decision {
        Decision::Approve => item.approve_url.clone().filter(|u| !u.is_empty()),
        Decision::Deny => item.deny_url.clone().filter(|u| !u.is_empty()),
    };
    let body = match (item.kind.as_str(), decision) {
        ("tool_approval", Decision::Approve) => {
            json!({ "approved_by": "operator-ui", "decision": "approve" })
        }
        ("tool_approval", Decision::Deny) => {
            json!({ "denied_by": "operator-ui", "decision": "deny" })
        }
        ("tracetramp_approval", _) => json!({ "approver_id": "operator" }),
        _ => json!({}),
    };

    if let Some(url) = url {
        let v = post_fix(&url, body).await?;
        let executed = v.get("executed").and_then(|item| item.as_bool()).unwrap_or(false);
        return Ok(format!(
            "{} the PATE ask. Executed: {executed}. It leaves the Fix queue.",
            decision_verb(decision)
        ));
    }

    match (item.kind.as_str(), decision) {
        ("tool_approval", Decision::Approve) => {
            let audit = item
                .audit_id
                .clone()
                .ok_or_else(|| "Missing audit_id for tool approval.".to_string())?;
            let path = format!("/tools/approvals/{audit}");
            let v = post_fix(
                &path,
                json!({ "approved_by": "operator-ui", "decision": "approve" }),
            )
            .await?;
            Ok(format!(
                "Approved tool via POST {path}\n{}",
                serde_json::to_string_pretty(&v).unwrap_or_default()
            ))
        }
        ("tool_approval", Decision::Deny) => {
            let audit = item
                .audit_id
                .clone()
                .ok_or_else(|| "Missing audit_id for tool deny.".to_string())?;
            let path = format!("/tools/approvals/{audit}/deny");
            let v = post_fix(
                &path,
                json!({ "denied_by": "operator-ui", "decision": "deny" }),
            )
            .await?;
            Ok(format!(
                "Denied tool via POST {path}\n{}",
                serde_json::to_string_pretty(&v).unwrap_or_default()
            ))
        }
        ("hitl_approval" | "devguard_approval", _) => {
            let pid = item
                .agent_pid
                .clone()
                .ok_or_else(|| "HITL item has no agent_pid.".to_string())?;
            let id = item
                .request_id
                .clone()
                .ok_or_else(|| "HITL item has no request_id.".to_string())?;
            let path = match decision {
                Decision::Approve => format!("/agents/{pid}/hitl/{id}/approve"),
                Decision::Deny => format!("/agents/{pid}/hitl/{id}/deny"),
            };
            let v = post_fix(&path, json!({})).await?;
            let executed = v.get("executed").and_then(|item| item.as_bool()).unwrap_or(false);
            let mut msg = format!(
                "{} the PATE ask. Executed: {executed}. It leaves the Fix queue.",
                decision_verb(decision)
            );
            let is_unq = item.primary_action.to_ascii_lowercase().contains("unquarantine")
                || item.title.to_ascii_lowercase().contains("unquarantine")
                || v.get("action").and_then(|x| x.as_str()) == Some("unquarantine");
            if decision == Decision::Approve && is_unq {
                msg.push_str(
                    "\n\nBrain/broker quarantine cleared — open Talk; resume is HTTP 200 on a new epoch.",
                );
            }
            Ok(msg)
        }
        ("tracetramp_approval", Decision::Approve) => {
            let id = item
                .request_id
                .clone()
                .ok_or_else(|| "Missing TraceTramp approval id.".to_string())?;
            let path = format!("/plugins/tracetramp/admin/approvals/{id}/approve");
            let v = post_fix(&path, json!({ "approver_id": "operator" })).await?;
            Ok(format!(
                "Approved TraceTramp item via POST {path}\n{}",
                serde_json::to_string_pretty(&v).unwrap_or_default()
            ))
        }
        (kind, _) => Err(format!(
            "No pending remediation for kind `{kind}`. This inbox is not a dump of historical denials or workflow templates."
        )),
    }
}

fn json_str<'a>(item: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(s) = item.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
            return Some(s);
        }
    }
    None
}

fn parse_items(v: &Value) -> Vec<FixItem> {
    let src = api::resource_object(v);
    let mut items: Vec<FixItem> = src
        .get("items")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let rem = item.get("remediation");
                    let severity = item
                        .get("severity")
                        .and_then(|x| x.as_str())
                        .unwrap_or("medium")
                        .to_string();
                    let kind = item
                        .get("kind")
                        .and_then(|x| x.as_str())
                        .unwrap_or("issue")
                        .to_string();
                    let hint = json_str(item, &["hint", "description", "reason"]).or_else(|| {
                        rem.and_then(|r| r.get("hint").and_then(|x| x.as_str()))
                    }).unwrap_or("pending decision");
                    let audit_id = item
                        .get("audit_id")
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                        .or_else(|| {
                            item.get("id").and_then(|x| x.as_str()).and_then(|id| {
                                id.strip_prefix("approval:").map(str::to_string)
                            })
                        });
                    let primary_action = json_str(item, &["primary_action"])
                        .or_else(|| {
                            rem.and_then(|r| r.get("primary_action").and_then(|x| x.as_str()))
                        })
                        .unwrap_or("")
                        .to_string();
                    let approve_url = json_str(item, &["approve_url"])
                        .or_else(|| {
                            rem.and_then(|r| r.get("approve_url").and_then(|x| x.as_str()))
                        })
                        .map(str::to_string);
                    let deny_url = json_str(item, &["deny_url"])
                        .or_else(|| rem.and_then(|r| r.get("deny_url").and_then(|x| x.as_str())))
                        .map(str::to_string);
                    let digest = item
                        .get("action_digest")
                        .or_else(|| item.get("digest"))
                        .and_then(|x| x.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    let digest_bit = digest
                        .as_ref()
                        .map(|d| {
                            let short = if d.len() > 16 { &d[..16] } else { d.as_str() };
                            format!(" · digest={short}…")
                        })
                        .unwrap_or_default();
                    let kind_label = match kind.as_str() {
                        "hitl_approval" => "PATE Ask / HITL",
                        "tool_approval" => "tool pending",
                        "tracetramp_approval" => "TraceTramp",
                        other => other,
                    };
                    Some(FixItem {
                        title: item
                            .get("title")
                            .and_then(|x| x.as_str())
                            .unwrap_or("Issue")
                            .to_string(),
                        detail: format!("{kind_label} · {severity} · {hint}{digest_bit}"),
                        kind,
                        severity,
                        primary_action,
                        agent_pid: item
                            .get("agent_pid")
                            .and_then(|x| x.as_str())
                            .filter(|s| !s.is_empty())
                            .map(str::to_string),
                        audit_id,
                        request_id: item
                            .get("request_id")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                        action_digest: digest,
                        approve_url,
                        deny_url,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    items.sort_by_key(|i| match i.severity.as_str() {
        "high" | "critical" => 0,
        "medium" => 1,
        _ => 2,
    });
    items
}
