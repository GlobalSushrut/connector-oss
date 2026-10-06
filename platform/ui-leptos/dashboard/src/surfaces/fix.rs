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

#[derive(Clone)]
struct DecisionReceipt {
    key: String,
    item: FixItem,
    ok: bool,
    pending: bool,
    message: String,
}

#[derive(Clone)]
struct TtGroup {
    actor: String,
    reason: String,
    count: u64,
}

#[component]
pub fn FixCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let shared = use_shared_requests();
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());
    let (result_danger, set_result_danger) = signal(false);
    let receipts = RwSignal::new(Vec::<DecisionReceipt>::new());
    let queue_items = RwSignal::new(Vec::<FixItem>::new());
    let queue_honesty = RwSignal::new(String::new());
    let queue_cap = RwSignal::new(None::<String>);
    let queue_groups = RwSignal::new(Vec::<TtGroup>::new());
    let queue_ready = RwSignal::new(false);

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
                "Two boxes from GET /operator/fix/queue. Approve is PATE (digest-bound HITL) and live tool approvals. Fix is TraceTramp holds. A decision stays on its card, success or error, until you dismiss it. Historical denials are on Watch. Auto-refresh every 5s."
            </p>
            <Suspense fallback=|| ()>
                {move || Suspend::new(async move {
                    let payload = shared.fix_queue.await.ok();
                    let honesty = payload
                        .as_ref()
                        .and_then(|v| api::resource_object(v).get("honesty").and_then(|h| h.as_str()).map(str::to_string))
                        .unwrap_or_default();
                    let items = payload.as_ref().map(|v| parse_items(v)).unwrap_or_default();
                    let groups = payload.as_ref().map(|v| parse_groups(v)).unwrap_or_default();
                    let cap_note = payload.as_ref().and_then(|v| {
                        api::resource_object(v)
                            .pointer("/sources/tracetramp_note")
                            .and_then(|n| n.as_str())
                            .map(str::to_string)
                    });
                    queue_honesty.set(honesty);
                    queue_cap.set(cap_note);
                    queue_groups.set(groups);
                    queue_items.set(items);
                    queue_ready.set(true);
                })}
            </Suspense>
            {move || {
                if !queue_ready.get() {
                    return view! { <div class="flex justify-center py-12"><OpSpinner /></div> }.into_any();
                }
                let items = queue_items.get();
                let held = receipts.get();
                let honesty = queue_honesty.get();
                let cap_note = queue_cap.get();
                let groups = queue_groups.get();
                let approve_rows = rows_for(&items, &held, true);
                let fix_rows = rows_for(&items, &held, false);
                if approve_rows.is_empty() && fix_rows.is_empty() && groups.is_empty()
                    && !held.iter().any(|row| row.item.kind == "tracetramp_group")
                {
                    return view! {
                        <OpEmptyState
                            title="Nothing pending"
                            description="Approve stays empty until a PATE ask or a live tool approval is pending. Fix stays empty until TraceTramp has an open hold for a Connector agent. Past denials are on Watch."
                        />
                        {(!honesty.is_empty()).then(|| view! {
                            <p class="mt-2 max-w-xl text-center font-mono text-[10px] text-zinc-600">{honesty}</p>
                        })}
                    }.into_any();
                }
                view! {
                    <section class="mb-8">
                        <h2 class="text-sm font-semibold tracking-wide text-zinc-100">"Approve"</h2>
                        <p class="mt-1 mb-3 text-xs text-zinc-500">
                            "PATE asks and live tool approvals. Approving a PATE ask runs that ask. It does not decide a TraceTramp hold."
                        </p>
                        {approve_rows.is_empty().then(|| view! {
                            <p class="text-sm text-zinc-500">"No PATE asks and no live tool approvals."</p>
                        })}
                        <OpGrid cols="grid-cols-1 lg:grid-cols-2">
                            {approve_rows.into_iter().map(|row| render_row(row, receipts, set_result_title, set_result_summary, set_result_open, set_result_danger)).collect_view()}
                        </OpGrid>
                    </section>
                    <section>
                        <h2 class="text-sm font-semibold tracking-wide text-zinc-100">"Fix"</h2>
                        <p class="mt-1 mb-3 text-xs text-zinc-500">
                            "One card per actor and reason, not one card per hold. Clear rejects that group, including holds behind TraceTramp's newest-100 list. Approve arms the resume latch and does not run the held request. Neither one is a PATE decision. The result stays on the card until you dismiss it."
                        </p>
                        {cap_note.map(|note| view! {
                            <p class="mb-3 font-mono text-[11px] text-amber-200/80">{note}</p>
                        })}
                        {render_fix_groups(
                            groups,
                            held.clone(),
                            receipts,
                            set_result_title,
                            set_result_summary,
                            set_result_open,
                            set_result_danger,
                        )}
                        {(!fix_rows.is_empty()).then(|| view! {
                            <OpGrid cols="grid-cols-1 lg:grid-cols-2">
                                {fix_rows.into_iter().map(|row| render_row(row, receipts, set_result_title, set_result_summary, set_result_open, set_result_danger)).collect_view()}
                            </OpGrid>
                        })}
                    </section>
                    {(!honesty.is_empty()).then(|| view! {
                        <p class="mt-4 max-w-3xl font-mono text-[10px] text-zinc-600">{honesty}</p>
                    })}
                }.into_any()
            }}
            <OpResultSheet
                open=result_open
                set_open=set_result_open
                title=result_title
                summary=result_summary
                eyebrow="Decision"
                danger=result_danger.get()
            />
        </div>
    }
}

fn is_approve_item(item: &FixItem) -> bool {
    matches!(
        item.kind.as_str(),
        "hitl_approval" | "devguard_approval" | "tool_approval"
    )
}

fn item_key(item: &FixItem) -> String {
    if let Some(id) = item.request_id.as_ref().filter(|s| !s.is_empty()) {
        return format!("{}:{id}", item.kind);
    }
    if let Some(id) = item.audit_id.as_ref().filter(|s| !s.is_empty()) {
        return format!("{}:{id}", item.kind);
    }
    format!("{}:{}", item.kind, item.title)
}

enum DecisionRow {
    Live(FixItem),
    Held(DecisionReceipt),
}

fn rows_for(items: &[FixItem], held: &[DecisionReceipt], approve_box: bool) -> Vec<DecisionRow> {
    let mut seen = Vec::new();
    let mut rows = Vec::new();
    for item in items {
        if item.kind == "tracetramp_approval" {
            continue;
        }
        if is_approve_item(item) != approve_box {
            continue;
        }
        let key = item_key(item);
        if let Some(receipt) = held.iter().find(|receipt| receipt.key == key) {
            rows.push(DecisionRow::Held(receipt.clone()));
        } else {
            rows.push(DecisionRow::Live(item.clone()));
        }
        seen.push(key);
    }
    for receipt in held {
        if seen.iter().any(|key| key == &receipt.key) {
            continue;
        }
        if receipt.item.kind == "tracetramp_group" || receipt.item.kind == "tracetramp_approval" {
            continue;
        }
        if is_approve_item(&receipt.item) != approve_box {
            continue;
        }
        rows.push(DecisionRow::Held(receipt.clone()));
    }
    rows
}

fn group_key(actor: &str, reason: &str) -> String {
    format!("ttgroup\n{actor}\n{reason}")
}

fn group_item(actor: &str, reason: &str) -> FixItem {
    FixItem {
        title: if reason.is_empty() {
            "All TraceTramp holds".into()
        } else {
            reason.to_string()
        },
        detail: actor.to_string(),
        kind: "tracetramp_group".into(),
        severity: "medium".into(),
        primary_action: String::new(),
        agent_pid: (!actor.is_empty()).then(|| actor.to_string()),
        audit_id: None,
        request_id: None,
        action_digest: None,
        approve_url: None,
        deny_url: None,
    }
}

fn render_fix_groups(
    groups: Vec<TtGroup>,
    held: Vec<DecisionReceipt>,
    receipts: RwSignal<Vec<DecisionReceipt>>,
    set_result_title: WriteSignal<String>,
    set_result_summary: WriteSignal<String>,
    set_result_open: WriteSignal<bool>,
    set_result_danger: WriteSignal<bool>,
) -> impl IntoView {
    let clear_key = group_key("*", "*");
    let clear_receipt = held.iter().find(|row| row.key == clear_key).cloned();
    let known: Vec<String> = groups
        .iter()
        .map(|group| group_key(&group.actor, &group.reason))
        .chain(std::iter::once(clear_key.clone()))
        .collect();
    let orphans: Vec<DecisionReceipt> = held
        .iter()
        .filter(|row| row.item.kind == "tracetramp_group" && !known.iter().any(|key| key == &row.key))
        .cloned()
        .collect();
    let show_clear = clear_receipt.is_none() && !groups.is_empty();
    view! {
        {clear_receipt.map(|receipt| receipt_card(receipt, receipts))}
        {orphans.into_iter().map(|receipt| receipt_card(receipt, receipts)).collect_view()}
        {show_clear.then(|| {
            view! {
                <button
                    type="button"
                    class="mb-3 rounded border border-rose-900/70 px-3 py-1.5 text-xs text-rose-200 hover:bg-rose-950/40"
                    on:click=move |_| {
                        begin_group(
                            String::new(),
                            String::new(),
                            "reject",
                            receipts,
                            set_result_title,
                            set_result_summary,
                            set_result_open,
                            set_result_danger,
                        );
                    }
                >
                    "Clear all TraceTramp holds"
                </button>
            }
        })}
        <OpGrid cols="grid-cols-1 lg:grid-cols-2">
            {groups.into_iter().map(|group| {
                let key = group_key(&group.actor, &group.reason);
                if let Some(receipt) = held.iter().find(|row| row.key == key).cloned() {
                    return receipt_card(receipt, receipts).into_any();
                }
                let actor = group.actor.clone();
                let reason = group.reason.clone();
                let actor_approve = actor.clone();
                let reason_approve = reason.clone();
                let count = group.count;
                view! {
                    <div class="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-2">
                        <p class="text-sm font-medium text-zinc-100">{reason.clone()}</p>
                        <p class="font-mono text-[10px] uppercase tracking-wide text-amber-200">
                            {format!("{count} in this window · {actor}")}
                        </p>
                        <p class="text-xs text-zinc-500">
                            "Clear rejects every pending hold in this group, including ones behind the newest 100. Approve arms each resume latch and does not run the request."
                        </p>
                        <div class="flex gap-2">
                            <button
                                type="button"
                                class="rounded border border-emerald-900/70 px-3 py-1 text-xs text-emerald-200 hover:bg-emerald-950/40"
                                on:click=move |_| {
                                    begin_group(
                                        actor_approve.clone(),
                                        reason_approve.clone(),
                                        "approve",
                                        receipts,
                                        set_result_title,
                                        set_result_summary,
                                        set_result_open,
                                        set_result_danger,
                                    );
                                }
                            >
                                "Approve group"
                            </button>
                            <button
                                type="button"
                                class="rounded border border-rose-900/70 px-3 py-1 text-xs text-rose-200 hover:bg-rose-950/40"
                                on:click=move |_| {
                                    begin_group(
                                        actor.clone(),
                                        reason.clone(),
                                        "reject",
                                        receipts,
                                        set_result_title,
                                        set_result_summary,
                                        set_result_open,
                                        set_result_danger,
                                    );
                                }
                            >
                                "Clear group"
                            </button>
                        </div>
                    </div>
                }.into_any()
            }).collect_view()}
        </OpGrid>
    }
}

fn render_row(
    row: DecisionRow,
    receipts: RwSignal<Vec<DecisionReceipt>>,
    set_result_title: WriteSignal<String>,
    set_result_summary: WriteSignal<String>,
    set_result_open: WriteSignal<bool>,
    set_result_danger: WriteSignal<bool>,
) -> impl IntoView {
    match row {
        DecisionRow::Held(receipt) => receipt_card(receipt, receipts).into_any(),
        DecisionRow::Live(item) => live_card(
            item,
            receipts,
            set_result_title,
            set_result_summary,
            set_result_open,
            set_result_danger,
        )
        .into_any(),
    }
}

fn receipt_card(receipt: DecisionReceipt, receipts: RwSignal<Vec<DecisionReceipt>>) -> impl IntoView {
    let key = receipt.key.clone();
    let border = if receipt.pending {
        "border-amber-700/70"
    } else if receipt.ok {
        "border-emerald-800/80"
    } else {
        "border-rose-800/80"
    };
    let status = if receipt.pending {
        "Waiting"
    } else if receipt.ok {
        "Success"
    } else {
        "Error"
    };
    let status_class = if receipt.pending {
        "text-amber-200"
    } else if receipt.ok {
        "text-emerald-300"
    } else {
        "text-rose-300"
    };
    let title = receipt.item.title.clone();
    let kind = receipt.item.kind.clone();
    let message = receipt.message.clone();
    let pending = receipt.pending;
    view! {
        <div class=format!("rounded-lg border {border} bg-zinc-950 p-3 space-y-2")>
            <p class="text-sm font-medium text-zinc-100">{title}</p>
            <p class=format!("font-mono text-[10px] uppercase tracking-wide {status_class}")>
                {format!("{status} · {kind}")}
            </p>
            <p class="text-sm text-zinc-300 whitespace-pre-wrap">{message}</p>
            {(!pending).then(move || {
                let key = key.clone();
                view! {
                    <button
                        type="button"
                        class="rounded border border-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-900"
                        on:click=move |_| {
                            receipts.update(|list| list.retain(|row| row.key != key));
                            bump_reload();
                        }
                    >
                        "Dismiss"
                    </button>
                }
            })}
        </div>
    }
}

fn live_card(
    item: FixItem,
    receipts: RwSignal<Vec<DecisionReceipt>>,
    set_result_title: WriteSignal<String>,
    set_result_summary: WriteSignal<String>,
    set_result_open: WriteSignal<bool>,
    set_result_danger: WriteSignal<bool>,
) -> impl IntoView {
    let item_fix = item.clone();
    let item_deny_click = item.clone();
    let item_open = item.clone();
    let primary = primary_label(&item);
    let deny = deny_label(&item).unwrap_or_default();
    let digest_line = item.action_digest.clone().filter(|d| !d.is_empty());
    view! {
        <div class="space-y-1">
            <OpIssueCard
                title=item.title.clone()
                detail=item.detail.clone()
                severity=item.severity.clone()
                primary_label=primary
                secondary_label=deny
                on_fix=Arc::new(move |_| {
                    begin_decision(
                        item_fix.clone(),
                        Decision::Approve,
                        receipts,
                        set_result_title,
                        set_result_summary,
                        set_result_open,
                        set_result_danger,
                    );
                })
                on_secondary=Arc::new(move |_| {
                    begin_decision(
                        item_deny_click.clone(),
                        Decision::Deny,
                        receipts,
                        set_result_title,
                        set_result_summary,
                        set_result_open,
                        set_result_danger,
                    );
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
}

fn waiting_message(item: &FixItem) -> &'static str {
    match item.kind.as_str() {
        "tracetramp_approval" => {
            "Waiting for TraceTramp. This card stays until that response is shown."
        }
        "hitl_approval" | "devguard_approval" => {
            "Waiting for PATE. This card stays until that response is shown."
        }
        "tool_approval" => "Waiting for the tool approval. This card stays until that response is shown.",
        _ => "Waiting for the server. This card stays until that response is shown.",
    }
}

fn begin_decision(
    item: FixItem,
    decision: Decision,
    receipts: RwSignal<Vec<DecisionReceipt>>,
    set_result_title: WriteSignal<String>,
    set_result_summary: WriteSignal<String>,
    set_result_open: WriteSignal<bool>,
    set_result_danger: WriteSignal<bool>,
) {
    let key = item_key(&item);
    let waiting = waiting_message(&item).to_string();
    receipts.update(|list| {
        list.retain(|row| row.key != key);
        list.push(DecisionReceipt {
            key: key.clone(),
            item: item.clone(),
            ok: false,
            pending: true,
            message: waiting.clone(),
        });
    });
    set_result_title.set(item.title.clone());
    set_result_summary.set(waiting);
    set_result_danger.set(false);
    set_result_open.set(true);
    spawn_local(async move {
        let result = execute_decision(&item, decision).await;
        let (ok, message) = match result {
            Ok(msg) => (
                true,
                format!("{msg}\n\nThis card stays until you dismiss it."),
            ),
            Err(err) => (
                false,
                format!("{err}\n\nThis card stays until you dismiss it."),
            ),
        };
        receipts.update(|list| {
            if let Some(row) = list.iter_mut().find(|row| row.key == key) {
                row.ok = ok;
                row.pending = false;
                row.message = message.clone();
            } else {
                list.push(DecisionReceipt {
                    key: key.clone(),
                    item: item.clone(),
                    ok,
                    pending: false,
                    message: message.clone(),
                });
            }
        });
        set_result_title.set(if ok {
            item.title.clone()
        } else {
            format!("Decision failed · {}", item.kind)
        });
        set_result_summary.set(message);
        set_result_danger.set(!ok);
        set_result_open.set(true);
    });
}

fn response_text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|item| item.as_str())
        .filter(|item| !item.is_empty())
        .or_else(|| {
            value
                .pointer(&format!("/data/{key}"))
                .and_then(|item| item.as_str())
                .filter(|item| !item.is_empty())
        })
        .unwrap_or("")
        .to_string()
}

fn begin_group(
    actor: String,
    reason: String,
    action: &'static str,
    receipts: RwSignal<Vec<DecisionReceipt>>,
    set_result_title: WriteSignal<String>,
    set_result_summary: WriteSignal<String>,
    set_result_open: WriteSignal<bool>,
    set_result_danger: WriteSignal<bool>,
) {
    let actor_key = if actor.is_empty() { "*" } else { actor.as_str() };
    let reason_key = if reason.is_empty() { "*" } else { reason.as_str() };
    let key = group_key(actor_key, reason_key);
    let item = group_item(&actor, &reason);
    let waiting = if action == "reject" {
        "Clearing TraceTramp holds. This walks every window, not only the 50 cards. The card stays until the result is shown."
    } else {
        "Approving TraceTramp holds and arming each resume latch. The held requests are not run. This is not a PATE ask. The card stays until the result is shown."
    };
    receipts.update(|list| {
        list.retain(|row| row.key != key);
        list.push(DecisionReceipt {
            key: key.clone(),
            item: item.clone(),
            ok: false,
            pending: true,
            message: waiting.to_string(),
        });
    });
    set_result_title.set(item.title.clone());
    set_result_summary.set(waiting.to_string());
    set_result_danger.set(false);
    set_result_open.set(true);
    spawn_local(async move {
        let mut body = json!({ "action": action, "max": 2000 });
        if !actor.is_empty() {
            body["actor_id"] = json!(actor);
        }
        if !reason.is_empty() {
            body["reason"] = json!(reason);
        }
        let result = async {
            let value = api::post_value_timeout("/operator/fix/tracetramp/decide", body, 120_000)
                .await
                .map_err(|err| format!("POST /operator/fix/tracetramp/decide — {}", err.message))?;
            let failed = response_text(&value, "error");
            let ok = value
                .get("ok")
                .and_then(|item| item.as_bool())
                .or_else(|| value.pointer("/data/ok").and_then(|item| item.as_bool()));
            let honesty = response_text(&value, "honesty");
            if ok == Some(false) || !failed.is_empty() {
                let detail = if honesty.is_empty() {
                    if failed.is_empty() { "The decision was not recorded.".into() } else { failed }
                } else if failed.is_empty() {
                    honesty
                } else {
                    format!("{failed}. {honesty}")
                };
                return Err(detail);
            }
            if honesty.is_empty() {
                Ok("TraceTramp recorded the decision. This is not a PATE ask.".to_string())
            } else {
                Ok(honesty)
            }
        }
        .await;
        let (ok, message) = match result {
            Ok(msg) => (true, format!("{msg}\n\nThis card stays until you dismiss it.")),
            Err(err) => (false, format!("{err}\n\nThis card stays until you dismiss it.")),
        };
        receipts.update(|list| {
            if let Some(row) = list.iter_mut().find(|row| row.key == key) {
                row.ok = ok;
                row.pending = false;
                row.message = message.clone();
            } else {
                list.push(DecisionReceipt {
                    key: key.clone(),
                    item: item.clone(),
                    ok,
                    pending: false,
                    message: message.clone(),
                });
            }
        });
        set_result_title.set(if ok { item.title } else { format!("Decision failed · {action}") });
        set_result_summary.set(message);
        set_result_danger.set(!ok);
        set_result_open.set(true);
    });
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
        let honesty = value
            .get("honesty")
            .and_then(|v| v.as_str())
            .unwrap_or("The decision was not recorded.");
        return Err(format!("{err}. {honesty}"));
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
        if item.kind == "tracetramp_approval" {
            let honesty = v
                .get("honesty")
                .and_then(|x| x.as_str())
                .unwrap_or("TraceTramp recorded the decision. This is not a PATE ask.");
            return Ok(honesty.to_string());
        }
        let executed = v.get("executed").and_then(|item| item.as_bool()).unwrap_or(false);
        let note = v
            .get("honesty")
            .or_else(|| v.get("message"))
            .and_then(|item| item.as_str())
            .unwrap_or("");
        return Ok(format!(
            "{} the PATE ask. Executed: {executed}. {note}",
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
            let note = v
                .get("honesty")
                .or_else(|| v.get("message"))
                .and_then(|item| item.as_str())
                .unwrap_or("");
            let mut msg = format!(
                "{} the PATE ask. Executed: {executed}. {note}",
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

fn parse_groups(v: &Value) -> Vec<TtGroup> {
    let src = api::resource_object(v);
    src.pointer("/sources/tracetramp_groups")
        .and_then(|groups| groups.as_array())
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| {
                    let count = group.get("count").and_then(|value| value.as_u64()).unwrap_or(0);
                    if count == 0 {
                        return None;
                    }
                    Some(TtGroup {
                        actor: group.get("actor_id").and_then(|value| value.as_str()).unwrap_or("").to_string(),
                        reason: group.get("reason").and_then(|value| value.as_str()).unwrap_or("TraceTramp hold").to_string(),
                        count,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
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
