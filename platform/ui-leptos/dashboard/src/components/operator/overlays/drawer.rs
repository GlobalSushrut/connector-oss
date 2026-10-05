use leptos::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::cards::{OpObjectTile, OpReceiptCard};
use crate::components::operator::overlays::error_hero::OpErrorHero;
use crate::components::operator::overlays::quick_actions::OpQuickActions;
use crate::components::operator::overlays::sparkline::OpSparklineGrid;
use crate::components::operator::overlays::notifications_panel::OpNotificationsPanel;
use crate::components::operator::overlays::settings_panel::OpSettingsPanel;
use crate::components::operator::overlays::topic_panels::OpTopicPanel;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpDivider, OpIconButton, OpInstitutionChip, OpScrollArea,
};
use crate::request_store::bump_reload;
use crate::ui_state::{
    close_drawer, use_developer_view, use_operator_drawer, DrawerTopic,
};

#[component]
pub fn OpDrawerHost() -> impl IntoView {
    let drawer = use_operator_drawer();

    // Escape closes drawer
    Effect::new(move |_| {
        if !drawer.topic.get().is_open() {
            return;
        }
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;
        let cb = Closure::<dyn FnMut(_)>::new(move |ev: web_sys::KeyboardEvent| {
            if ev.key() == "Escape" {
                close_drawer();
            }
        });
        if let Some(w) = web_sys::window() {
            let _ = w.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
            // leak until next open — acceptable for CSR shell
            cb.forget();
        }
    });

    view! {
        <Show when=move || drawer.topic.get().is_open()>
            <OpDrawer />
        </Show>
    }
}

#[component]
fn OpDrawer() -> impl IntoView {
    let drawer = use_operator_drawer();
    let (dev, _) = use_developer_view();
    let topic = drawer.topic;
    let tab = drawer.tab;
    let set_tab = drawer.set_tab;

    view! {
        <div class="fixed inset-0 z-[85] flex justify-end" role="dialog" aria-modal="true">
            <button
                type="button"
                class="absolute inset-0 bg-black/50 backdrop-blur-sm"
                aria-label="Close drawer"
                on:click=move |_| close_drawer()
            ></button>
            <aside class="relative flex h-full w-full max-w-md flex-col border-l border-zinc-800/80 bg-zinc-950/95 shadow-2xl backdrop-blur-xl sm:max-w-lg">
                <header class="flex shrink-0 items-center gap-2 border-b border-zinc-800/60 px-4 py-3">
                    <div class="min-w-0 flex-1">
                        <h2 class="truncate text-base font-semibold text-zinc-100">
                            {move || drawer_title(&topic.get())}
                        </h2>
                    </div>
                    <OpIconButton
                        label="Close drawer".to_string()
                        on_click=Arc::new(move |_| close_drawer())
                    >
                        <span>"×"</span>
                    </OpIconButton>
                </header>

                {move || match topic.get() {
                    DrawerTopic::Workflow(id) => view! {
                        <WorkflowDrawerBody workflow_id=id tab=tab set_tab=set_tab dev=dev />
                    }.into_any(),
                    DrawerTopic::Settings(kind) => view! {
                        <div class="min-h-0 flex-1 overflow-hidden">
                            <OpSettingsPanel kind=kind />
                        </div>
                    }.into_any(),
                    DrawerTopic::Notifications => view! {
                        <OpScrollArea class="flex-1">
                            <OpNotificationsPanel />
                        </OpScrollArea>
                    }.into_any(),
                    other if other.is_open() => view! {
                        <OpScrollArea class="flex-1">
                            <OpTopicPanel topic=other />
                        </OpScrollArea>
                    }.into_any(),
                    _ => view! { <p class="p-4 text-xs text-zinc-600">"Nothing selected."</p> }.into_any(),
                }}
            </aside>
        </div>
    }
}

fn drawer_title(t: &DrawerTopic) -> String {
    match t {
        DrawerTopic::Workflow(id) => id.clone(),
        DrawerTopic::Agent(pid) => {
            let short = if pid.len() > 14 { format!("{}…", &pid[..12]) } else { pid.clone() };
            format!("Intelligence · {short}")
        }
        DrawerTopic::Settings(k) => format!("Settings · {k}"),
        DrawerTopic::Memory => "Memory".into(),
        DrawerTopic::Trust => "Trust".into(),
        DrawerTopic::Cost => "Cost & usage".into(),
        DrawerTopic::Safety => "Safety".into(),
        DrawerTopic::Monitor => "Monitor".into(),
        DrawerTopic::Conductor => "Conductor".into(),
        DrawerTopic::Notifications => "Notifications".into(),
        DrawerTopic::Secrets => "Secrets".into(),
        DrawerTopic::Webhooks => "Webhooks".into(),
        DrawerTopic::License => "License".into(),
        DrawerTopic::Billing => "Billing".into(),
        DrawerTopic::None => "Drawer".into(),
    }
}

#[component]
fn WorkflowDrawerBody(
    workflow_id: String,
    tab: ReadSignal<String>,
    set_tab: WriteSignal<String>,
    dev: ReadSignal<bool>,
) -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let wf_id = workflow_id.clone();
    let surface = LocalResource::new(move || {
        let id = wf_id.clone();
        let _ = reload.get();
        async move { api::get_value(&format!("/workflows/{id}/surface")).await }
    });
    let dry_runs = LocalResource::new({
        let id = workflow_id.clone();
        move || {
            let id = id.clone();
            let _ = reload.get();
            async move { api::get_value(&format!("/workflows/{id}/dry-runs")).await }
        }
    });
    let report_center = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/reports/center").await }
    });
    let detail = LocalResource::new({
        let id = workflow_id.clone();
        move || {
            let id = id.clone();
            let _ = reload.get();
            async move { api::get_value(&format!("/workflows/{id}")).await }
        }
    });
    // P3.3 — builder ⇄ CLS round-trip honesty after save / re-open.
    let round_trip = LocalResource::new({
        let id = workflow_id.clone();
        move || {
            let id = id.clone();
            let _ = reload.get();
            async move { api::get_value(&format!("/workflows/{id}/builder-round-trip")).await }
        }
    });

    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let on_action_done: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        set_reload.update(|n| *n = n.wrapping_add(1));
    });

    view! {
        <OpDrawerTabs active=tab set_active=set_tab />
        <OpScrollArea class="flex-1">
            <Suspense fallback=move || view! { <OpLoadingBlock /> }>
                {move || {
                    let wf_id = workflow_id.clone();
                    let on_action_done = on_action_done.clone();
                    Suspend::new(async move {
                    let surface_res = surface.await;
                    let detail_res = detail.await;
                    let dry_res = dry_runs.await;
                    let reports_res = report_center.await;
                    let rt_res = round_trip.await;

                    match tab.get().as_str() {
                        "runs" => {
                            let runs = dry_res.ok().and_then(|v| dry_run_list(&v)).unwrap_or_default();
                            let hero = runs.first().cloned();
                            view! {
                                <div class="space-y-3 p-4">
                                    {match hero {
                                        Some((rid, when, ok)) => view! {
                                            <OpErrorHero
                                                title=if ok { format!("Last dry-run · {rid}") } else { format!("Dry-run issue · {rid}") }
                                                detail=format!("Recorded {when}")
                                            />
                                        }.into_any(),
                                        None => view! {
                                            <OpErrorHero
                                                title="No dry-runs yet".to_string()
                                                detail="Run a dry-run to populate history.".to_string()
                                            />
                                        }.into_any(),
                                    }}
                                    <OpButton
                                        label="Dry-run now".to_string()
                                        variant=OpButtonVariant::Primary
                                        loading=busy.get()
                                        on_click={
                                            let wf = wf_id.clone();
                                            Arc::new(move |_| {
                                                set_busy.set(true);
                                                let wf = wf.clone();
                                                spawn_local(async move {
                                                    match api::post_value(&format!("/workflows/{wf}/dry-run"), json!({})).await {
                                                        Ok(v) => {
                                                            set_result_title.set(wf);
                                                            set_result_summary.set(dry_run_summary(&v));
                                                            set_result_open.set(true);
                                                            bump_reload();
                                                        }
                                                        Err(e) => {
                                                            set_result_title.set(wf);
                                                            set_result_summary.set(e.message);
                                                            set_result_open.set(true);
                                                        }
                                                    }
                                                    set_busy.set(false);
                                                });
                                            })
                                        }
                                    />
                                    <div class="space-y-1">
                                        {if runs.is_empty() {
                                            view! { <p class="text-xs text-zinc-600">"No dry-run history."</p> }.into_any()
                                        } else {
                                            runs.into_iter().map(|(id, when, ok)| {
                                                view! {
                                                    <div class="flex justify-between gap-2 rounded border border-zinc-800/50 px-3 py-2 text-xs">
                                                        <span class="font-mono text-zinc-300">{id}</span>
                                                        <span class="text-zinc-500">{when}</span>
                                                        <span class=if ok { "text-emerald-400" } else { "text-amber-400" }>
                                                            {if ok { "ok" } else { "fail" }}
                                                        </span>
                                                    </div>
                                                }
                                            }).collect_view().into_any()
                                        }}
                                    </div>
                                    <crate::components::operator::overlays::result_sheet::OpResultSheet
                                        open=result_open
                                        set_open=set_result_open
                                        title=result_title
                                        summary=result_summary
                                    />
                                </div>
                            }.into_any()
                        }
                        "objects" => {
                            let surface_val = surface_res.as_ref().ok().and_then(|v| v.get("surface")).cloned().unwrap_or(Value::Null);
                            let tiles = object_tiles(&surface_val);
                            view! {
                                <div class="p-4">
                                    {if tiles.is_empty() {
                                        view! { <p class="text-xs text-zinc-600">"No objects declared on this surface."</p> }.into_any()
                                    } else {
                                        view! {
                                            <div class="grid grid-cols-2 gap-2">
                                                {tiles.into_iter().map(|(label, count)| {
                                                    view! { <OpObjectTile label=label count=count /> }
                                                }).collect_view()}
                                            </div>
                                        }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        }
                        "receipts" => {
                            let surface_val = surface_res.as_ref().ok().and_then(|v| v.get("surface")).cloned().unwrap_or(Value::Null);
                            let mut receipts = receipt_rows(&surface_val);
                            // Live dry-run history as executable receipts.
                            if let Ok(dry) = &dry_res {
                                for (id, when, ok) in dry_run_list(dry).into_iter().flatten() {
                                    receipts.push((
                                        id,
                                        if ok { "dry-run ok".into() } else { "dry-run fail".into() },
                                        when,
                                    ));
                                }
                            }
                            // Report-center stored receipts (proof/compliance/export).
                            if let Ok(rc) = &reports_res {
                                let stored = rc
                                    .pointer("/data/stored_receipts")
                                    .or_else(|| rc.get("stored_receipts"))
                                    .and_then(|x| x.as_array())
                                    .cloned()
                                    .unwrap_or_default();
                                for r in stored {
                                    let id = r
                                        .get("receipt_id")
                                        .or_else(|| r.get("id"))
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("receipt")
                                        .to_string();
                                    let summary = r
                                        .get("report_id")
                                        .or_else(|| r.get("verification_status"))
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("report receipt")
                                        .to_string();
                                    let time = r
                                        .get("stored_at")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("—")
                                        .to_string();
                                    receipts.push((id, summary, time));
                                }
                            }
                            let reports_err = reports_res.as_ref().err().cloned();
                            let dry_err = dry_res.as_ref().err().cloned();
                            let wf_for_open = wf_id.clone();
                            view! {
                                <div class="space-y-2 p-4">
                                    <div class="rounded-lg border border-indigo-500/30 bg-indigo-950/20 p-3">
                                        <p class="text-[10px] font-semibold uppercase tracking-wide text-indigo-300">"Live receipts"</p>
                                        <p class="mt-1 text-[11px] text-zinc-400">
                                            {format!(
                                                "Merged from surface.receipts + GET /workflows/{}/dry-runs + GET /reports/center",
                                                wf_for_open
                                            )}
                                        </p>
                                    </div>
                                    {reports_err.map(|e| view! { <OpApiErrorBanner error=e /> })}
                                    {dry_err.map(|e| view! { <OpApiErrorBanner error=e /> })}
                                    {if receipts.is_empty() {
                                        view! { <p class="text-xs text-zinc-600">"No receipts yet — run a dry-run or export from report center."</p> }.into_any()
                                    } else {
                                        receipts.into_iter().map(|(id, summary, time)| {
                                            let rid = id.clone();
                                            let wf = wf_for_open.clone();
                                            view! {
                                                <OpReceiptCard
                                                    receipt_id=id
                                                    summary=summary
                                                    time=time
                                                    on_click=Arc::new(move |_| {
                                                        let rid = rid.clone();
                                                        let wf = wf.clone();
                                                        spawn_local(async move {
                                                            if let Ok(v) = api::get_value(&format!("/reports/center/receipts/{rid}")).await {
                                                                set_result_title.set(format!("Receipt {rid}"));
                                                                set_result_summary.set(format!(
                                                                    "GET /reports/center/receipts/{rid}\n{}",
                                                                    serde_json::to_string_pretty(&v).unwrap_or_default()
                                                                ));
                                                                set_result_open.set(true);
                                                                return;
                                                            }
                                                            match api::get_value(&format!("/workflows/{wf}/dry-runs/{rid}")).await {
                                                                Ok(v) => {
                                                                    set_result_title.set(format!("Dry-run {rid}"));
                                                                    set_result_summary.set(format!(
                                                                        "GET /workflows/{wf}/dry-runs/{rid}\n{}",
                                                                        serde_json::to_string_pretty(&v).unwrap_or_default()
                                                                    ));
                                                                    set_result_open.set(true);
                                                                }
                                                                Err(e) => {
                                                                    set_result_title.set(format!("Receipt {rid}"));
                                                                    set_result_summary.set(format!(
                                                                        "Tried GET /reports/center/receipts/{rid} and GET /workflows/{wf}/dry-runs/{rid}\n{}",
                                                                        e.message
                                                                    ));
                                                                    set_result_open.set(true);
                                                                }
                                                            }
                                                        });
                                                    })
                                                />
                                            }
                                        }).collect_view().into_any()
                                    }}
                                    <crate::components::operator::overlays::result_sheet::OpResultSheet
                                        open=result_open
                                        set_open=set_result_open
                                        title=result_title
                                        summary=result_summary
                                    />
                                </div>
                            }.into_any()
                        }
                        _ => {
                            let surface_val = surface_res.as_ref().ok().and_then(|v| v.get("surface")).cloned().unwrap_or(Value::Null);
                            let panels = surface_val.get("panels").and_then(|p| p.as_array()).cloned().unwrap_or_default();
                            let metrics = metric_cards(&surface_val);
                            let detail_v = detail_res.ok();
                            let err = surface_res.err();
                            let state = detail_v.as_ref().map(|d| str_or(d, "state")).unwrap_or_else(|| "—".into());
                            let next = next_transitions(&state);
                            let runtime = detail_v
                                .as_ref()
                                .and_then(|d| {
                                    d.get("runtime_contract")
                                        .or_else(|| d.get("runtime"))
                                        .and_then(|x| x.as_str())
                                })
                                .unwrap_or("CLS engine + CNP dispatch")
                                .to_string();
                            let runtime_honesty = detail_v
                                .as_ref()
                                .and_then(|d| d.get("runtime_honesty").and_then(|x| x.as_str()))
                                .unwrap_or("Product ENABLE path is CLS/CNP only; dual_runtime=false.")
                                .to_string();
                            let machine = surface_val
                                .pointer("/lifecycle/state_machine")
                                .and_then(|x| x.as_str())
                                .unwrap_or("DRAFT → COMPILED → STAGED → ENABLED ⇄ PAUSED → ARCHIVED")
                                .to_string();
                            // Panels with source=workflow resolve against the nested record.
                            let mut panel_root = surface_val.clone();
                            if let Some(d) = detail_v.as_ref() {
                                let rec = workflow_record(d).clone();
                                if let Some(obj) = panel_root.as_object_mut() {
                                    obj.insert("workflow".into(), rec.clone());
                                    if let Some(map) = rec.as_object() {
                                        for (k, v) in map {
                                            obj.entry(k.clone()).or_insert(v.clone());
                                        }
                                    }
                                }
                            }
                            let on_done = on_action_done.clone();
                            view! {
                                <div class="space-y-4 p-4">
                                    {err.map(|e| view! { <OpApiErrorBanner error=e /> })}
                                    <div class="rounded-lg border border-indigo-500/30 bg-indigo-950/20 p-3">
                                        <p class="text-[10px] font-semibold uppercase tracking-wide text-indigo-300">"Live backend"</p>
                                        <p class="mt-1 text-xs text-zinc-300">
                                            {format!(
                                                "Actions call POST /workflows/{}/lifecycle and /dry-run — not mock UI.",
                                                wf_id
                                            )}
                                        </p>
                                        <p class="mt-2 font-mono text-[10px] text-zinc-500">{machine}</p>
                                        <p class="mt-1 text-[11px] text-amber-200/90">{next.to_string()}</p>
                                    </div>
                                    {detail_v.as_ref().map(|d| {
                                        let acct = surface_val
                                            .pointer("/accounting/mode")
                                            .and_then(|x| x.as_str())
                                            .or_else(|| d.get("accounting_mode").and_then(|x| x.as_str()))
                                            .unwrap_or("—")
                                            .to_string();
                                        let acct_label = if acct == "service_monitoring" {
                                            "service_monitoring (observe / seal / route)".to_string()
                                        } else if acct == "action" {
                                            "action (agents / workspace / perform)".to_string()
                                        } else {
                                            acct.clone()
                                        };
                                        view! {
                                        <dl class="space-y-1.5 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs">
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"accounting"</dt><dd class="max-w-[65%] text-right font-mono text-zinc-100" title=acct.clone()>{acct_label}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"state"</dt><dd class="font-mono text-zinc-100">{str_or(d, "state")}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"package"</dt><dd class="font-mono text-zinc-200">{str_or(d, "package_id")}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"version"</dt><dd class="font-mono text-zinc-200">{str_or(d, "version")}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"fingerprint"</dt><dd class="max-w-[60%] truncate font-mono text-zinc-200" title=str_or(d, "cls_source_fingerprint")>{str_or(d, "cls_source_fingerprint")}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"bytes"</dt><dd class="font-mono text-zinc-200">{num_or(d, "cls_source_byte_len")}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"last dry-run"</dt><dd class="font-mono text-zinc-200">{str_or(d, "last_dry_run_id")}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"runtime"</dt><dd class="max-w-[60%] text-right text-zinc-300">{runtime.clone()}</dd></div>
                                            <div class="flex justify-between gap-2"><dt class="text-zinc-500">"dual_runtime"</dt><dd class="font-mono text-zinc-200">"false"</dd></div>
                                            {match rt_res.as_ref() {
                                                Ok(rt) => {
                                                    let status = rt.get("round_trip").and_then(|x| x.as_str()).unwrap_or("planned");
                                                    let fp = rt.get("session_fingerprint").and_then(|x| x.as_bool()).unwrap_or(false);
                                                    let label = if fp || status == "partial" {
                                                        "partial — re-open OK".to_string()
                                                    } else {
                                                        format!("round_trip={status}")
                                                    };
                                                    view! {
                                                        <div class="flex justify-between gap-2">
                                                            <dt class="text-zinc-500">"builder round-trip"</dt>
                                                            <dd class="max-w-[65%] text-right font-mono text-emerald-200/90" title="GET /workflows/:id/builder-round-trip">{label}</dd>
                                                        </div>
                                                    }.into_any()
                                                }
                                                Err(_) => view! {
                                                    <div class="flex justify-between gap-2">
                                                        <dt class="text-zinc-500">"builder round-trip"</dt>
                                                        <dd class="font-mono text-zinc-500">"unavailable"</dd>
                                                    </div>
                                                }.into_any(),
                                            }}
                                            <p class="pt-1 text-[10px] text-amber-200/90">{runtime_honesty.clone()}</p>
                                            <p class="text-[10px] text-zinc-500">"Dry-run honesty: correlated fabric replay: partial|audit_tail · product_mode=cnp_correlated when ENABLE tokens exist"</p>
                                        </dl>
                                    }})}
                                    {if metrics.is_empty() {
                                        ().into_any()
                                    } else {
                                        view! { <OpSparklineGrid metrics=metrics /> }.into_any()
                                    }}
                                    <OpQuickActions
                                        workflow_id=wf_id.clone()
                                        surface=surface_val.clone()
                                        state=state.clone()
                                        on_done=on_done
                                    />
                                    <OpDivider />
                                    {if panels.is_empty() {
                                        view! { <p class="text-xs text-zinc-600">"No manifest panels."</p> }.into_any()
                                    } else {
                                        panels.into_iter().enumerate().map(|(i, panel)| {
                                            view! { <OpDrawerPanel panel=panel index=i root=panel_root.clone() /> }
                                        }).collect_view().into_any()
                                    }}
                                    <Show when=move || dev.get()>
                                        <OpDevDisclosure
                                            label="Surface JSON (developer)".to_string()
                                            raw=serde_json::to_string_pretty(&surface_val).unwrap_or_default()
                                        />
                                    </Show>
                                </div>
                            }.into_any()
                        }
                    }
                })}}
            </Suspense>
        </OpScrollArea>
    }
}

#[component]
pub fn OpDrawerTabs(
    active: ReadSignal<String>,
    set_active: WriteSignal<String>,
) -> impl IntoView {
    let tabs = [
        ("overview", "Overview"),
        ("runs", "Runs"),
        ("objects", "Objects"),
        ("receipts", "Receipts"),
    ];
    view! {
        <div class="flex shrink-0 gap-1 border-b border-zinc-800/60 px-4 py-2" role="tablist">
            {tabs.into_iter().map(|(id, label)| {
                view! {
                    <button
                        type="button"
                        role="tab"
                        aria-selected=move || (active.get() == id).to_string()
                        class=move || {
                            if active.get() == id {
                                "rounded-md bg-zinc-800 px-3 py-1 text-xs font-medium text-zinc-100"
                            } else {
                                "rounded-md px-3 py-1 text-xs font-medium text-zinc-500 hover:text-zinc-300"
                            }
                        }
                        on:click=move |_| set_active.set(id.to_string())
                    >
                        {label}
                    </button>
                }
            }).collect_view()}
        </div>
    }
}

#[component]
fn DrawerWatchEvents(workflow_id: String) -> impl IntoView {
    let wf = workflow_id.clone();
    let events = LocalResource::new(move || {
        let wf = wf.clone();
        async move {
            if wf.is_empty() {
                api::get_value_q("/operator/watch/events", &[("limit", "20")]).await
            } else {
                api::get_value_q(
                    "/operator/watch/events",
                    &[("limit", "20"), ("workflow_id", &wf)],
                )
                .await
            }
        }
    });
    view! {
        <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading events…"</p> }>
            {move || Suspend::new(async move {
                match events.await {
                    Ok(v) => {
                        let rows = crate::surfaces::watch_helpers::parse_watch_events(&v);
                        if rows.is_empty() {
                            view! {
                                <p class="text-sm text-zinc-400">
                                    "No recent events for this workflow. Full stream: WATCH."
                                </p>
                            }.into_any()
                        } else {
                            view! {
                                <ul class="space-y-1.5">
                                    {rows.into_iter().take(12).map(|r| {
                                        let line = format!("{} · {}", r.action, r.resource);
                                        view! {
                                        <li class="rounded border border-zinc-800/60 bg-zinc-950/40 px-2 py-1.5 text-[11px]">
                                            <div class="flex gap-2 font-mono text-zinc-500">
                                                <span>{r.time}</span>
                                                <span class="uppercase">{r.decision}</span>
                                            </div>
                                            <p class="truncate text-zinc-300">{line}</p>
                                        </li>
                                        }
                                    }).collect_view()}
                                </ul>
                            }.into_any()
                        }
                    }
                    Err(e) => view! {
                        <p class="text-xs text-amber-300">{e.message}</p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

#[component]
pub fn OpDrawerPanel(panel: Value, index: usize, root: Value) -> impl IntoView {
    let title = panel.get("title").and_then(|v| v.as_str()).unwrap_or("Panel").to_string();
    let ptype = panel.get("type").and_then(|v| v.as_str()).unwrap_or("kv").to_string();

    view! {
        <section class="space-y-2">
            <h4 class="text-xs font-semibold uppercase tracking-wide text-zinc-500">{title}</h4>
            {match ptype.as_str() {
                "kv" => render_kv_panel(&panel, &root).into_any(),
                "institution_chips" => render_institution_panel(&panel).into_any(),
                "summary_text" => {
                    let text = panel.get("text").and_then(|x| x.as_str())
                        .or_else(|| root.pointer("/display/summary").and_then(|x| x.as_str()))
                        .unwrap_or("—")
                        .to_string();
                    view! { <p class="text-sm text-zinc-400">{text}</p> }.into_any()
                }
                "event_list" => {
                    let wf = root
                        .get("workflow_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    view! { <DrawerWatchEvents workflow_id=wf /> }.into_any()
                }
                other => view! {
                    <p class="text-xs text-zinc-600">{format!("Panel type `{other}` (index {index})")}</p>
                }.into_any(),
            }}
        </section>
    }
}

fn render_kv_panel(panel: &Value, root: &Value) -> impl IntoView {
    let fields: Vec<(String, String)> = panel
        .get("fields")
        .and_then(|f| f.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    let label = f.get("label")?.as_str()?.to_string();
                    let path = f.get("path")?.as_str()?;
                    let resolved = resolve_path(root, path)
                        .or_else(|| resolve_path(panel, path))
                        .unwrap_or_else(|| "—".into());
                    Some((label, resolved))
                })
                .collect()
        })
        .unwrap_or_default();
    view! {
        <dl class="space-y-1.5 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
            {fields.into_iter().map(|(label, value)| {
                view! {
                    <div class="flex justify-between gap-2 text-xs">
                        <dt class="text-zinc-500">{label}</dt>
                        <dd class="font-mono text-zinc-300">{value}</dd>
                    </div>
                }
            }).collect_view()}
        </dl>
    }
}

fn resolve_path(root: &Value, path: &str) -> Option<String> {
    let pointer = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path.replace('.', "/"))
    };
    let v = root.pointer(&pointer)?;
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn render_institution_panel(panel: &Value) -> impl IntoView {
    let codes: Vec<&'static str> = panel
        .get("plugin_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|id| match id {
                    "tracetramp" => "TT",
                    "witnessctl" => "WC",
                    "devguard" => "DG",
                    _ => "??",
                })
                .collect()
        })
        .unwrap_or_default();
    view! {
        <div class="flex flex-wrap gap-1.5">
            {codes.into_iter().map(|code| {
                view! { <OpInstitutionChip code=code healthy=true installed=true /> }
            }).collect_view()}
        </div>
    }
}

fn dry_run_list(v: &Value) -> Option<Vec<(String, String, bool)>> {
    let arr = v.get("dry_runs").or_else(|| v.get("items"))?.as_array()?;
    Some(
        arr.iter()
            .filter_map(|r| {
                let id = r
                    .get("run_id")
                    .or_else(|| r.get("id"))
                    .and_then(|x| x.as_str())?
                    .to_string();
                let when = r
                    .get("recorded_at")
                    .or_else(|| r.get("created_at"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("—")
                    .to_string();
                let ok = r.get("ok").and_then(|x| x.as_bool()).unwrap_or(true);
                Some((id, when, ok))
            })
            .collect(),
    )
}

fn dry_run_summary(v: &Value) -> String {
    let honesty = v
        .get("honesty")
        .or_else(|| v.pointer("/dry_run/honesty"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("correlation")
                .or_else(|| v.pointer("/dry_run/correlation"))
                .and_then(|x| x.as_str())
                .map(|c| format!("dry-run is correlated fabric replay: {c}"))
        });
    let base = v
        .get("summary")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .or_else(|| v.get("message").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_else(|| {
            let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(true);
            if ok {
                "Dry-run completed.".into()
            } else {
                "Dry-run returned an error.".into()
            }
        });
    match honesty {
        Some(h) if !h.is_empty() => format!("{base}\n{h}"),
        _ => base,
    }
}

fn object_tiles(surface: &Value) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    if let Some(objs) = surface.get("objects").and_then(|x| x.as_object()) {
        for (k, v) in objs {
            let count = v.as_array().map(|a| a.len() as u64).or_else(|| v.as_u64());
            out.push((k.clone(), count));
        }
    }
    out
}

fn receipt_rows(surface: &Value) -> Vec<(String, String, String)> {
    surface
        .get("receipts")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some((
                        r.get("id").and_then(|x| x.as_str())?.to_string(),
                        r.get("summary").and_then(|x| x.as_str()).unwrap_or("receipt").to_string(),
                        r.get("time").and_then(|x| x.as_str()).unwrap_or("—").to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn metric_cards(surface: &Value) -> Vec<(String, String, Vec<f64>)> {
    surface
        .get("metrics")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let label = m.get("label")?.as_str()?.to_string();
                    let value = m
                        .get("value")
                        .map(|x| match x {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .unwrap_or_else(|| "—".into());
                    let spark = m
                        .get("sparkline")
                        .and_then(|x| x.as_array())
                        .map(|a| a.iter().filter_map(|n| n.as_f64()).collect())
                        .unwrap_or_default();
                    Some((label, value, spark))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Detail payloads nest fields under `workflow` — never read top-level only.
fn workflow_record<'a>(detail: &'a Value) -> &'a Value {
    detail.get("workflow").unwrap_or(detail)
}

fn str_or(v: &Value, key: &str) -> String {
    workflow_record(v)
        .get(key)
        .or_else(|| v.get(key))
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string()
}

fn num_or(v: &Value, key: &str) -> String {
    workflow_record(v)
        .get(key)
        .or_else(|| v.get(key))
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into())
}

fn next_transitions(state: &str) -> &'static str {
    match state.to_ascii_uppercase().as_str() {
        "DRAFT" => "Next: Compile → Stage → Enable (or use Activate)",
        "COMPILED" => "Next: Stage → Enable",
        "STAGED" => "Next: Enable",
        "ENABLED" => "Next: Pause or Archive · Dry-run anytime",
        "PAUSED" => "Next: Enable (resume) or Archive",
        "ARCHIVED" => "Terminal — reinstall from SETUP templates",
        _ => "Unknown state",
    }
}
