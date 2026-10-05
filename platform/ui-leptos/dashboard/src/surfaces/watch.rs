use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use serde_json::Value;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::cards::OpEventRow;
use crate::components::operator::overlays::forensics::OpForensicsPanel;
use crate::components::operator::overlays::operational_evidence::OperationalEvidencePanel;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpEmptyState, OpFilterTabs, OpLiveDot, OpSearchField, OpSpinner,
    OpText, OpTextVariant,
};
use crate::request_store::bump_reload;
use crate::surfaces::books::BooksCanvas;
use crate::surfaces::watch_helpers::{
    filter_events, is_sgke_deny, next_cursor, parse_watch_events, WatchEventVm,
};
use crate::ui_state::{open_agent_drawer, open_workflow_drawer};
use crate::utils::trigger_download_bytes;

fn initial_watch_tab() -> String {
    if let Some(w) = web_sys::window() {
        if let Ok(search) = w.location().search() {
            for part in search.trim_start_matches('?').split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "tab" && !v.is_empty() {
                        return v.to_string();
                    }
                }
            }
        }
    }
    "stream".into()
}

#[component]
pub fn WatchCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let query = use_query_map();
    let (tab, set_tab) = signal(initial_watch_tab());
    Effect::new(move |_| {
        if let Some(t) = query.get().get_str("tab").map(|s| s.to_string()) {
            if !t.is_empty() && t != tab.get_untracked() {
                set_tab.set(t);
            }
        }
    });

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10">
            <div class="mb-4">
                <OpText text="WATCH".to_string() variant=OpTextVariant::Title />
                <p class="mt-1 text-sm text-zinc-500">
                    "Machine records only. Empty is not all-clear."
                </p>
                <div class="mt-4">
                    <OpFilterTabs
                        tabs=vec![
                            ("stream", "Stream"),
                            ("tools", "Tools"),
                            ("address", "Address"),
                            ("agent", "Agent"),
                            ("fuel", "Fuel"),
                            ("trace", "Trace"),
                            ("backends", "Backends"),
                        ]
                        active=tab
                        set_active=set_tab
                    />
                </div>
            </div>
            {move || match tab.get().as_str() {
                "fuel" => view! { <BooksCanvas auth=auth embedded=true /> }.into_any(),
                "trace" => view! { <WatchTracePanel /> }.into_any(),
                "backends" => view! { <OperationalEvidencePanel /> }.into_any(),
                plane => view! { <WatchEventsPlane plane=plane.to_string() /> }.into_any(),
            }}
        </div>
    }
}

#[component]
fn WatchTracePanel() -> impl IntoView {
    let (agent_pid, set_agent_pid) = signal(String::new());
    let (tick, set_tick) = signal(0u32);
    let status = LocalResource::new(|| api::get_value("/forensics/status"));
    let agent_events = LocalResource::new(move || {
        let _ = tick.get();
        let pid = agent_pid.get();
        async move {
            if pid.trim().is_empty() {
                return Ok(Value::Null);
            }
            api::get_value(&format!(
                "/operator/watch/events?limit=40&plane=agent&agent_pid={}",
                pid.trim()
            ))
            .await
        }
    });
    view! {
        <div class="space-y-4">
            <p class="text-sm text-zinc-400">
                "GET /forensics/status — measured counts. Court-readiness is never painted green from claim JSON. Filter agent plane by pid below."
            </p>
            <div class="flex flex-wrap items-center gap-2">
                <input
                    class="w-full max-w-xs rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 font-mono text-[11px] text-zinc-200"
                    placeholder="agent_pid filter"
                    prop:value=move || agent_pid.get()
                    on:input=move |ev| {
                        use wasm_bindgen::JsCast;
                        let v = ev
                            .target()
                            .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                            .map(|el| el.value())
                            .unwrap_or_default();
                        set_agent_pid.set(v);
                        set_tick.update(|n| *n = n.wrapping_add(1));
                    }
                />
                <a
                    class="text-[11px] text-indigo-400 hover:underline"
                    href=move || {
                        let p = agent_pid.get();
                        if p.trim().is_empty() {
                            "/watch?tab=agent".into()
                        } else {
                            format!("/watch?tab=agent")
                        }
                    }
                >
                    "Open agent plane →"
                </a>
            </div>
            <Suspense fallback=move || view! { <OpSpinner /> }>
                {move || Suspend::new(async move {
                    match status.await {
                        Ok(v) => {
                            let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
                            view! {
                                <div class="space-y-3">
                                    <OpForensicsPanel />
                                    <pre class="overflow-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-400">{pretty}</pre>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <p class="text-xs text-red-300">{e.message}</p> }.into_any(),
                    }
                })}
            </Suspense>
            <Show when=move || !agent_pid.get().trim().is_empty()>
                <Suspense fallback=move || view! { <OpSpinner /> }>
                    {move || Suspend::new(async move {
                        match agent_events.await {
                            Ok(v) if !v.is_null() => {
                                let rows = parse_watch_events(&v);
                                if rows.is_empty() {
                                    view! {
                                        <p class="font-mono text-[11px] text-zinc-500">
                                            "No agent-plane events for this pid (machine empty, not invented)."
                                        </p>
                                    }.into_any()
                                } else {
                                    view! {
                                        <div class="space-y-1 rounded-lg border border-zinc-800/70 bg-zinc-950/40 p-3">
                                            <p class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                                "Agent plane · filtered"
                                            </p>
                                            {rows.into_iter().take(20).map(|ev| {
                                                view! {
                                                    <div class="grid grid-cols-[5rem_1fr_1fr] gap-2 border-b border-zinc-800/40 py-1 font-mono text-[10px] text-zinc-400">
                                                        <span>{ev.time}</span>
                                                        <span class="truncate text-zinc-300">{ev.action}</span>
                                                        <span class="truncate">{ev.resource}</span>
                                                    </div>
                                                }
                                            }).collect_view()}
                                        </div>
                                    }.into_any()
                                }
                            }
                            Ok(_) => ().into_any(),
                            Err(e) => view! { <p class="text-xs text-red-300">{e.message}</p> }.into_any(),
                        }
                    })}
                </Suspense>
            </Show>
        </div>
    }
}

#[component]
fn WatchEventsPlane(plane: String) -> impl IntoView {
    let plane_store = StoredValue::new(plane);
    let (decision, set_decision) = signal("all".to_string());
    let (search, set_search) = signal(String::new());
    let (agent_pid, set_agent_pid) = signal(String::new());
    let (tick, set_tick) = signal(0u32);
    let (paused, set_paused) = signal(false);
    let (extra_events, set_extra_events) = signal::<Vec<WatchEventVm>>(Vec::new());
    let (cursor, set_cursor) = signal::<Option<String>>(None);
    let (export_msg, set_export_msg) = signal::<Option<String>>(None);
    let (denied_json, set_denied_json) = signal::<Option<Value>>(None);
    let (honesty, set_honesty) = signal(String::new());

    Effect::new(move |_| {
        let _ = tick.get();
        spawn_local(async move {
            if let Ok(v) = api::get_value("/actionlog/denied").await {
                set_denied_json.set(Some(v));
            }
        });
    });

    Effect::new(move |_| {
        let _ = tick.get();
        if paused.get_untracked() {
            return;
        }
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(4000).await;
            if !paused.get_untracked() {
                set_tick.update(|n| *n = n.wrapping_add(1));
                bump_reload();
            }
        });
    });

    let events = LocalResource::new(move || {
        let _ = tick.get();
        let plane = plane_store.get_value();
        let pid = agent_pid.get();
        async move {
            if pid.trim().is_empty() {
                api::get_value_q(
                    "/operator/watch/events",
                    &[("limit", "100"), ("plane", plane.as_str())],
                )
                .await
            } else {
                api::get_value(&format!(
                    "/operator/watch/events?limit=100&plane={}&agent_pid={}",
                    plane,
                    pid.trim()
                ))
                .await
            }
        }
    });

    let on_export = Arc::new(move |_| {
        set_export_msg.set(Some("Exporting…".into()));
        spawn_local(async move {
            match api::get_bytes("/actionlog/export/jsonl").await {
                Ok(bytes) => {
                    let n = bytes.len();
                    trigger_download_bytes(&bytes, "actionlog.jsonl", "application/x-ndjson");
                    set_export_msg.set(Some(format!(
                        "Downloaded actionlog.jsonl ({n} bytes via GET /actionlog/export/jsonl)"
                    )));
                }
                Err(e) => set_export_msg.set(Some(format!("Export failed: {}", e.message))),
            }
        });
    });

    view! {
        <div>
            <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center gap-2 text-xs text-zinc-500">
                    <Show when=move || !paused.get()><OpLiveDot /></Show>
                    <span class="font-mono">{move || format!("plane={}", plane_store.get_value())}</span>
                </div>
                <div class="flex gap-2">
                    {move || {
                        let pause_label = if paused.get() {
                            "Resume".to_string()
                        } else {
                            "Pause".to_string()
                        };
                        view! {
                            <OpButton
                                label=pause_label
                                variant=OpButtonVariant::Secondary
                                on_click=Arc::new(move |_| set_paused.update(|p| *p = !*p))
                            />
                        }
                    }}
                    <OpButton
                        label="Export JSONL".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=on_export.clone()
                    />
                </div>
            </div>
            <Show when=move || export_msg.get().is_some()>
                <p class="mb-3 font-mono text-[11px] text-zinc-400">{move || export_msg.get().unwrap_or_default()}</p>
            </Show>
            <Show when=move || !honesty.get().is_empty()>
                <p class="mb-3 text-[11px] text-amber-200/80">{move || honesty.get()}</p>
            </Show>
            {move || {
                let denied = denied_json.get();
                let sgke_n = denied
                    .as_ref()
                    .and_then(|v| v.get("sgke_denied_count").and_then(|x| x.as_u64()))
                    .unwrap_or(0);
                if sgke_n > 0 {
                    view! {
                        <div class="mb-3 rounded-lg border border-rose-500/35 bg-rose-950/25 p-3 text-[11px] text-rose-100/90">
                            <p class="font-semibold uppercase tracking-wide text-rose-200">"Denied-by-SGKE"</p>
                            <p class="mt-1 text-zinc-300">{format!("{sgke_n} denial(s) from GET /actionlog/denied")}</p>
                        </div>
                    }.into_any()
                } else {
                    ().into_any()
                }
            }}
            <div class="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <OpFilterTabs
                    tabs=vec![("all", "All"), ("allow", "Allow"), ("deny", "Denied"), ("info", "Other")]
                    active=decision
                    set_active=set_decision
                />
                <div class="flex w-full flex-col gap-2 sm:max-w-md sm:flex-row sm:items-center">
                    <Show when=move || plane_store.get_value() == "agent" || plane_store.get_value() == "tools">
                        <input
                            class="w-full rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 font-mono text-[11px] text-zinc-200 sm:max-w-[10rem]"
                            placeholder="agent_pid"
                            prop:value=move || agent_pid.get()
                            on:input=move |ev| {
                                use wasm_bindgen::JsCast;
                                let v = ev
                                    .target()
                                    .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                                    .map(|el| el.value())
                                    .unwrap_or_default();
                                set_agent_pid.set(v);
                                set_extra_events.set(Vec::new());
                                set_tick.update(|n| *n = n.wrapping_add(1));
                            }
                        />
                    </Show>
                    <div class="w-full sm:flex-1">
                        <OpSearchField value=search set_value=set_search placeholder="Filter agent, action, resource…" />
                    </div>
                </div>
            </div>
            <div class="overflow-auto rounded-xl border border-zinc-800/60 bg-zinc-900/20">
                <div class="grid grid-cols-[5rem_4rem_1fr_1fr_1fr_4.5rem] gap-2 border-b border-zinc-800/80 px-4 py-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-600">
                    <span>"Time"</span><span>"Decision"</span><span>"Agent"</span><span>"Action"</span><span>"Resource"</span><span></span>
                </div>
                <Suspense fallback=move || view! { <div class="flex justify-center py-12"><OpSpinner /></div> }>
                    {move || Suspend::new(async move {
                        let raw = events.await.ok();
                        if let Some(ref v) = raw {
                            set_cursor.set(next_cursor(v));
                            if let Some(h) = v.get("honesty").and_then(|x| x.as_str()) {
                                set_honesty.set(h.to_string());
                            }
                        }
                        let mut rows = raw.as_ref().map(parse_watch_events).unwrap_or_default();
                        for e in extra_events.get() {
                            if !rows.iter().any(|r| r.id == e.id && !e.id.is_empty()) {
                                rows.push(e);
                            }
                        }
                        let filtered = filter_events(&rows, &decision.get(), &search.get());
                        if filtered.is_empty() {
                            view! {
                                <OpEmptyState
                                    title="No records"
                                    description="Empty is not all-clear — no measured rows for this plane yet."
                                />
                            }.into_any()
                        } else {
                            view! {
                                {filtered.into_iter().map(|r| {
                                    let wf = r.workflow_id.clone();
                                    let agent = r.agent.clone();
                                    let is_deny = r.decision == "deny";
                                    let sgke = is_sgke_deny(&r.reason, &r.error_code);
                                    let reason_line = if sgke {
                                        "Denied-by-SGKE".to_string()
                                    } else if !r.error_code.is_empty() {
                                        format!("code={}", r.error_code)
                                    } else if !r.reason.is_empty() {
                                        r.reason.clone()
                                    } else {
                                        String::new()
                                    };
                                    let reason_cls = if sgke {
                                        "px-4 pb-2 font-mono text-[10px] text-rose-300/90"
                                    } else {
                                        "px-4 pb-2 font-mono text-[10px] text-zinc-500"
                                    };
                                    let agent_open = r.agent.clone();
                                    view! {
                                        <div class="border-b border-zinc-800/40 hover:bg-zinc-900/40">
                                            <div class="grid grid-cols-[1fr_4.5rem] items-stretch">
                                                <div
                                                    class="cursor-pointer"
                                                    on:click=move |_| {
                                                        if let Some(id) = wf.clone() {
                                                            open_workflow_drawer(id);
                                                        } else if agent != "—" && !agent.is_empty() {
                                                            open_agent_drawer(agent.clone());
                                                        }
                                                    }
                                                >
                                                    <OpEventRow
                                                        time=r.time
                                                        decision=r.decision
                                                        agent=r.agent.clone()
                                                        action=r.action
                                                        resource=r.resource
                                                    />
                                                </div>
                                                <div class="flex items-center justify-end pr-3">
                                                    {if is_deny {
                                                        view! {
                                                            <button
                                                                type="button"
                                                                class="text-[10px] font-semibold uppercase text-amber-300 hover:text-amber-200"
                                                                on:click=move |ev| {
                                                                    ev.stop_propagation();
                                                                    if agent_open != "—" && !agent_open.is_empty() {
                                                                        open_agent_drawer(agent_open.clone());
                                                                    }
                                                                }
                                                            >"Open →"</button>
                                                        }.into_any()
                                                    } else {
                                                        view! { <span></span> }.into_any()
                                                    }}
                                                </div>
                                            </div>
                                            {if !reason_line.is_empty() {
                                                view! { <p class=reason_cls>{reason_line}</p> }.into_any()
                                            } else {
                                                ().into_any()
                                            }}
                                        </div>
                                    }
                                }).collect_view()}
                            }.into_any()
                        }
                    })}
                </Suspense>
            </div>
            <Show when=move || cursor.get().is_some()>
                <div class="mt-3">
                    <OpButton
                        label="Load more".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let Some(c) = cursor.get_untracked() else { return };
                            let plane = plane_store.get_value();
                            let pid = agent_pid.get_untracked();
                            spawn_local(async move {
                                let url = if pid.trim().is_empty() {
                                    format!(
                                        "/operator/watch/events?limit=100&plane={plane}&cursor={c}"
                                    )
                                } else {
                                    format!(
                                        "/operator/watch/events?limit=100&plane={plane}&cursor={c}&agent_pid={}",
                                        pid.trim()
                                    )
                                };
                                if let Ok(v) = api::get_value(&url).await {
                                    set_cursor.set(next_cursor(&v));
                                    let more = parse_watch_events(&v);
                                    set_extra_events.update(|cur| cur.extend(more));
                                }
                            });
                        })
                    />
                </div>
            </Show>
        </div>
    }
}
