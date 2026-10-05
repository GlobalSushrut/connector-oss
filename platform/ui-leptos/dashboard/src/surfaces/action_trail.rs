//! Action Trail — track and manage any agent action loop.
//!
//! Route: `/run/trail` and `/run/trail/:pid?session=`
//!
//! Stitches Workbench journal + kernel watch events + Expometer posture so the
//! operator can see what is happening and Admit / Reject / Cease without leaving.

use std::sync::Arc;

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map, use_query_map};
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::overlays::expometer::OpExpometer;
use crate::components::operator::overlays::result_sheet::OpResultSheet;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpSpinner, OpText, OpTextVariant,
};
use crate::iia_api;
use crate::surfaces::watch_helpers::{parse_watch_events, WatchEventVm};

#[derive(Clone, Debug)]
struct TrailStep {
    id: String,
    when: String,
    kind: String,
    title: String,
    detail: String,
    tone: &'static str, // ok | warn | bad | info
    source: &'static str, // journal | watch
}

#[component]
pub fn ActionTrailCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let params = use_params_map();
    let query = use_query_map();
    let navigate = use_navigate();

    let initial_pid = params
        .with_untracked(|p| p.get("pid").unwrap_or_default())
        .trim()
        .to_string();
    let initial_sid = query
        .with_untracked(|q| q.get("session").unwrap_or_default())
        .trim()
        .to_string();
    let initial_focus = {
        let f = query
            .with_untracked(|q| q.get("focus").unwrap_or_default())
            .trim()
            .to_ascii_lowercase();
        match f.as_str() {
            "orders" | "order" => "orders",
            "evidence" | "proof" | "chart" => "evidence",
            "standing" | "identity" | "charter" => "standing",
            "hitl" => "hitl",
            "activity" | "watch" => "activity",
            _ => "all",
        }
        .to_string()
    };

    let (pid, set_pid) = signal(initial_pid);
    let (session_id, set_session_id) = signal(initial_sid);
    let (focus, set_focus) = signal(initial_focus);
    let (agents, set_agents) = signal(Vec::<(String, String)>::new());
    let (sessions, set_sessions) = signal(Vec::<(String, String)>::new());
    let (steps, set_steps) = signal(Vec::<TrailStep>::new());
    let (pending, set_pending) = signal(Vec::<Value>::new());
    let (phase, set_phase) = signal(String::new());
    let (dal_run, set_dal_run) = signal(String::new());
    let (dal_snap, set_dal_snap) = signal(Option::<Value>::None);
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal(String::new());
    let (tick, set_tick) = signal(0u32);
    let (refuse_open, set_refuse_open) = signal(false);
    let (refuse_title, set_refuse_title) = signal(String::new());
    let (refuse_summary, set_refuse_summary) = signal(String::new());

    // Load agent roster once.
    Effect::new(move |_| {
        spawn_local(async move {
            match iia_api::list_agents().await {
                Ok(v) => {
                    let list = v
                        .get("agents")
                        .or_else(|| v.get("items"))
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let mut rows: Vec<(String, String)> = list
                        .iter()
                        .filter_map(|a| {
                            let id = a
                                .get("pid")
                                .or_else(|| a.get("agent_pid"))
                                .or_else(|| a.get("id"))
                                .and_then(|x| x.as_str())?
                                .to_string();
                            let name = a
                                .get("name")
                                .and_then(|x| x.as_str())
                                .unwrap_or(id.as_str())
                                .to_string();
                            Some((id, name))
                        })
                        .collect();
                    rows.sort_by(|a, b| a.1.to_ascii_lowercase().cmp(&b.1.to_ascii_lowercase()));
                    if pid.get_untracked().is_empty() {
                        if let Some((id, _)) = rows
                            .iter()
                            .find(|(id, name)| {
                                name.eq_ignore_ascii_case("BankOps")
                                    || id.to_ascii_lowercase().contains("bankops")
                            })
                            .cloned()
                            .or_else(|| rows.first().cloned())
                        {
                            set_pid.set(id);
                        }
                    }
                    set_agents.set(rows);
                }
                Err(e) => set_err.set(e.message),
            }
        });
    });

    // Poll trail while an agent is selected.
    Effect::new(move |_| {
        let _ = tick.get();
        let p = pid.get();
        if p.is_empty() {
            return;
        }
        let want_sid = session_id.get();
        spawn_local(async move {
            // Sessions list
            if let Ok(list) = iia_api::workbench_list_sessions(&p).await {
                let rows: Vec<(String, String)> = list
                    .get("sessions")
                    .and_then(|s| s.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| {
                                let sid = s.get("session_id").and_then(|x| x.as_str())?;
                                let title = s
                                    .get("title")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or(sid)
                                    .to_string();
                                Some((sid.to_string(), title))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                set_sessions.set(rows.clone());
                if want_sid.is_empty() {
                    if let Some((sid, _)) = rows.first() {
                        set_session_id.set(sid.clone());
                    }
                }
            }

            let sid = {
                let cur = session_id.get_untracked();
                if cur.is_empty() {
                    return;
                }
                cur
            };

            let mut trail: Vec<TrailStep> = Vec::new();
            let mut pending_orders = Vec::new();
            let mut phase_s = String::new();
            let mut dal_id = String::new();

            match iia_api::workbench_get_session(&p, &sid).await {
                Ok(doc) => {
                    let sess = doc.get("session").unwrap_or(&doc);
                    phase_s = sess
                        .get("phase")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    if let Some(v) = doc.get("vitals") {
                        dal_id = v
                            .get("dal_run_id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        if phase_s.is_empty() {
                            phase_s = v
                                .get("phase")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .to_string();
                        }
                    }
                    pending_orders = doc
                        .get("pending_orders")
                        .or_else(|| sess.get("pending_orders"))
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let events = doc
                        .get("events")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                    for ev in events {
                        trail.push(journal_step(&ev));
                    }
                    set_err.set(String::new());
                }
                Err(e) => set_err.set(e.message),
            }

            // Kernel / AAPI plane for this agent.
            if let Ok(wv) = api::get_value_q(
                "/operator/watch/events",
                &[
                    ("limit", "60"),
                    ("plane", "agent"),
                    ("agent_pid", p.as_str()),
                ],
            )
            .await
            {
                for w in parse_watch_events(&wv) {
                    trail.push(watch_step(&w));
                }
            }

            // Activity slice (admit ledger / operations).
            if let Ok(act) = iia_api::agent_activity(&p).await {
                if let Some(arr) = act.get("activity").and_then(|x| x.as_array()) {
                    for a in arr.iter().take(40) {
                        trail.push(activity_step(a));
                    }
                }
            }

            trail.sort_by(|a, b| b.when.cmp(&a.when));
            // Dedup by id+title when possible
            let mut seen = std::collections::HashSet::new();
            trail.retain(|s| {
                let key = format!("{}|{}|{}", s.source, s.id, s.title);
                seen.insert(key)
            });
            trail.truncate(120);

            set_phase.set(phase_s);
            set_dal_run.set(dal_id.clone());
            set_pending.set(pending_orders);
            set_steps.set(trail);

            if !dal_id.is_empty() {
                match api::get_value(&format!("/dal/{dal_id}")).await {
                    Ok(v) => set_dal_snap.set(Some(v)),
                    Err(_) => set_dal_snap.set(None),
                }
            } else {
                set_dal_snap.set(None);
            }
        });
    });

    // Auto-refresh
    Effect::new(move |prev: Option<bool>| {
        if prev.unwrap_or(false) {
            return true;
        }
        let _ = set_interval_with_handle(
            move || set_tick.update(|t| *t = t.wrapping_add(1)),
            std::time::Duration::from_millis(3_000),
        );
        true
    });

    let sync_url = {
        let navigate = navigate.clone();
        Arc::new(move || {
            let p = pid.get_untracked();
            let s = session_id.get_untracked();
            let f = focus.get_untracked();
            if p.is_empty() {
                navigate(&format!("/run/trail?focus={f}"), Default::default());
            } else if s.is_empty() {
                navigate(&format!("/run/trail/{p}?focus={f}"), Default::default());
            } else {
                navigate(
                    &format!("/run/trail/{p}?session={s}&focus={f}"),
                    Default::default(),
                );
            }
        })
    };

    let admit_pending = {
        Arc::new(move |_| {
            let p = pid.get_untracked();
            let sid = session_id.get_untracked();
            let ids: Vec<String> = pending
                .get_untracked()
                .iter()
                .filter_map(|o| {
                    o.get("order_id")
                        .or_else(|| o.get("event_id"))
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                })
                .collect();
            if p.is_empty() || sid.is_empty() || ids.is_empty() || busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            spawn_local(async move {
                match iia_api::workbench_admit(&p, &sid, &ids).await {
                    Ok(doc) => {
                        if let Some(detail) = api::body_failure_detail(&doc) {
                            set_refuse_title.set("Admit refused".into());
                            set_refuse_summary.set(detail.clone());
                            set_refuse_open.set(true);
                            set_err.set(detail);
                        }
                    }
                    Err(e) => {
                        set_refuse_title.set("Admit refused".into());
                        set_refuse_summary.set(e.message.clone());
                        set_refuse_open.set(true);
                        set_err.set(e.message);
                    }
                }
                set_busy.set(false);
                set_tick.update(|t| *t = t.wrapping_add(1));
            });
        })
    };

    let reject_pending = {
        Arc::new(move |_| {
            let p = pid.get_untracked();
            let sid = session_id.get_untracked();
            let ids: Vec<String> = pending
                .get_untracked()
                .iter()
                .filter_map(|o| {
                    o.get("order_id")
                        .or_else(|| o.get("event_id"))
                        .and_then(|x| x.as_str())
                        .map(str::to_string)
                })
                .collect();
            if p.is_empty() || sid.is_empty() || busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            spawn_local(async move {
                let _ = iia_api::workbench_cancel_orders(&p, &sid, &ids).await;
                set_busy.set(false);
                set_tick.update(|t| *t = t.wrapping_add(1));
            });
        })
    };

    let cease_agent = {
        Arc::new(move |_| {
            if !web_sys::window()
                .and_then(|w| {
                    w.confirm_with_message(
                        "SpendCease this agent generation? Fence + void ctx_tok + reap. Cancel tax may remain.",
                    )
                    .ok()
                })
                .unwrap_or(false)
            {
                return;
            }
            let p = pid.get_untracked();
            if p.is_empty() || busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            spawn_local(async move {
                match iia_api::agent_cease(&p).await {
                    Ok(v) => {
                        if let Some(e) = api::body_error(&v) {
                            set_err.set(format!("cease failed: {e}"));
                        } else {
                            set_err.set("Cease ok — admits dead for this generation".into());
                        }
                    }
                    Err(e) => set_err.set(format!("cease failed: {e}")),
                }
                set_busy.set(false);
                set_tick.update(|t| *t = t.wrapping_add(1));
            });
        })
    };

    view! {
        <div class="w-full">
            <OpResultSheet
                open=refuse_open
                set_open=set_refuse_open
                title=refuse_title
                summary=refuse_summary
                eyebrow="Admit refused"
                danger=true
            />

            <div class="shrink-0 border-b border-cyan-900/40 bg-gradient-to-b from-cyan-950/40 to-transparent px-4 py-4 sm:px-6">
                <div class="flex flex-wrap items-start justify-between gap-3">
                    <div>
                        <p class="text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-400/90">
                            "Dedicated page · not Workbench sidebar"
                        </p>
                        <OpText text="ACTION TRAIL".to_string() variant=OpTextVariant::Title />
                        <p class="mt-1 text-sm text-zinc-400">
                            "Full loop timeline: Talk → proposal → Admit → PATE → ToolDispatch. Filter Orders / Evidence / Standing. Manage Admit · Reject · Cease here."
                        </p>
                        <p class="mt-1 font-mono text-[11px] text-cyan-200/80">
                            {move || {
                                let p = pid.get();
                                let f = focus.get();
                                if p.is_empty() {
                                    format!("/run/trail?focus={f}")
                                } else {
                                    format!("/run/trail/{p}?focus={f}")
                                }
                            }}
                        </p>
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <OpButton
                            label="Refresh".to_string()
                            variant=OpButtonVariant::Ghost
                            on_click=Arc::new(move |_| set_tick.update(|t| *t = t.wrapping_add(1)))
                        />
                        <OpButton
                            label="Open Workbench".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| {
                                let p = pid.get_untracked();
                                let s = session_id.get_untracked();
                                let href = if p.is_empty() {
                                    "/run/workbench".into()
                                } else if s.is_empty() {
                                    format!("/run/workbench/{p}")
                                } else {
                                    format!("/run/workbench/{p}?session={s}")
                                };
                                if let Some(w) = web_sys::window() {
                                    let _ = w.location().set_href(&href);
                                }
                            })
                        />
                        <a class="inline-flex items-center rounded-md px-3 py-1.5 text-xs text-indigo-400 hover:underline" href="/watch?tab=stream">
                            "Raw Watch →"
                        </a>
                    </div>
                </div>

                <div class="mt-4 flex flex-wrap gap-1">
                    {[
                        ("all", "All"),
                        ("orders", "Orders"),
                        ("evidence", "Evidence"),
                        ("standing", "Standing"),
                        ("hitl", "HITL"),
                        ("activity", "Activity"),
                    ]
                        .into_iter()
                        .map(|(id, label)| {
                            let sync_url = sync_url.clone();
                            view! {
                                <button
                                    type="button"
                                    class=move || {
                                        if focus.get() == id {
                                            "rounded border border-cyan-600/70 bg-cyan-950/50 px-2.5 py-1 text-[11px] font-medium text-cyan-100"
                                        } else {
                                            "rounded border border-zinc-700 px-2.5 py-1 text-[11px] text-zinc-400 hover:text-zinc-200"
                                        }
                                    }
                                    on:click=move |_| {
                                        set_focus.set(id.to_string());
                                        sync_url();
                                    }
                                >{label}</button>
                            }
                        })
                        .collect_view()}
                </div>

                <div class="mt-4 flex flex-col gap-2 sm:flex-row sm:items-end">
                    <label class="flex flex-1 flex-col gap-1 text-[10px] uppercase tracking-wide text-zinc-500">
                        "Agent"
                        <select
                            class="rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
                            prop:value=move || pid.get()
                            on:change={
                                let sync_url = sync_url.clone();
                                move |ev| {
                                let v = event_target_value(&ev);
                                set_pid.set(v);
                                set_session_id.set(String::new());
                                sync_url();
                                set_tick.update(|t| *t = t.wrapping_add(1));
                            }}
                        >
                            <option value="">"Select agent…"</option>
                            {move || agents.get().into_iter().map(|(id, name)| {
                                let id2 = id.clone();
                                view! { <option value=id>{format!("{name} ({id2})")}</option> }
                            }).collect_view()}
                        </select>
                    </label>
                    <label class="flex flex-1 flex-col gap-1 text-[10px] uppercase tracking-wide text-zinc-500">
                        "Workbench session"
                        <select
                            class="rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-100"
                            prop:value=move || session_id.get()
                            on:change={
                                let sync_url = sync_url.clone();
                                move |ev| {
                                set_session_id.set(event_target_value(&ev));
                                sync_url();
                                set_tick.update(|t| *t = t.wrapping_add(1));
                            }}
                        >
                            <option value="">"Select session…"</option>
                            {move || sessions.get().into_iter().map(|(sid, title)| {
                                let sid2 = sid.clone();
                                view! { <option value=sid>{format!("{title} · {sid2}")}</option> }
                            }).collect_view()}
                        </select>
                    </label>
                </div>
            </div>

            <div class="px-4 py-4 sm:px-6 pb-12 space-y-4">
                <Show when=move || !err.get().is_empty()>
                    <div class="rounded-lg border border-rose-900/40 bg-rose-950/30 px-3 py-2 text-[12px] text-rose-200">
                        {move || err.get()}
                    </div>
                </Show>

                <Show when=move || !pid.get().is_empty()>
                    <div class="grid gap-3 lg:grid-cols-3">
                        <div class="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2 space-y-1 lg:col-span-1">
                            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Loop now"</p>
                            <p class="text-sm text-zinc-100">
                                {move || {
                                    let p = phase.get();
                                    if p.is_empty() { "—".into() } else { format!("phase · {p}") }
                                }}
                            </p>
                            <p class="text-[11px] text-zinc-400">
                                {move || {
                                    let n = pending.get().len();
                                    if n == 0 {
                                        "no pending proposals".into()
                                    } else {
                                        format!("{n} proposal(s) awaiting Admit")
                                    }
                                }}
                            </p>
                            <p class="text-[10px] text-zinc-500 truncate" title=move || dal_run.get()>
                                {move || {
                                    let d = dal_run.get();
                                    if d.is_empty() { "DAL run · —".into() } else { format!("DAL · {d}") }
                                }}
                            </p>
                            {move || dal_snap.get().map(|v| {
                                let phase = v.pointer("/run/phase")
                                    .or_else(|| v.get("phase"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("—");
                                let stop = v.pointer("/run/stop_reason")
                                    .or_else(|| v.get("stop_reason"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("");
                                view! {
                                    <p class="text-[10px] text-zinc-400">
                                        {if stop.is_empty() {
                                            format!("DAL snapshot · {phase}")
                                        } else {
                                            format!("DAL · {phase} · stop={stop}")
                                        }}
                                    </p>
                                }
                            })}
                        </div>
                        <div class="lg:col-span-2">
                            {move || {
                                let p = pid.get();
                                if p.is_empty() {
                                    ().into_any()
                                } else {
                                    view! { <OpExpometer pid=p reload=tick /> }.into_any()
                                }
                            }}
                        </div>
                    </div>
                </Show>

                <Show when=move || !pending.get().is_empty()>
                    <div class="rounded-lg border border-amber-900/40 bg-amber-950/20 px-3 py-3 space-y-2">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <p class="text-[11px] font-semibold uppercase tracking-wide text-amber-200">
                                "Manage pending loop"
                            </p>
                            <div class="flex flex-wrap gap-2">
                                <OpButton
                                    label="Admit all pending".to_string()
                                    variant=OpButtonVariant::Primary
                                    on_click=admit_pending.clone()
                                />
                                <OpButton
                                    label="Reject all".to_string()
                                    variant=OpButtonVariant::Ghost
                                    on_click=reject_pending.clone()
                                />
                                <OpButton
                                    label="Cease generation".to_string()
                                    variant=OpButtonVariant::Secondary
                                    on_click=cease_agent.clone()
                                />
                            </div>
                        </div>
                        <ul class="space-y-1">
                            {move || pending.get().into_iter().map(|o| {
                                let name = o.get("tool_name")
                                    .or_else(|| o.pointer("/openai_call/function/name"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("tool")
                                    .to_string();
                                let oid = o.get("order_id")
                                    .or_else(|| o.get("event_id"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("—")
                                    .to_string();
                                view! {
                                    <li class="flex flex-wrap items-center gap-2 text-[12px] text-zinc-200">
                                        <span class="rounded border border-amber-800/50 px-1.5 py-0.5 text-[10px] text-amber-100">"pending"</span>
                                        <span class="font-medium">{name}</span>
                                        <span class="font-mono text-[10px] text-zinc-500">{oid}</span>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    </div>
                </Show>

                <section class="space-y-2">
                    <div class="flex items-center justify-between gap-2">
                        <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                            {move || format!("Trail · focus={} · journal · watch · activity", focus.get())}
                        </p>
                        <Show when=move || busy.get()>
                            <OpSpinner />
                        </Show>
                    </div>
                    <Show when=move || steps.get().is_empty() && !pid.get().is_empty()>
                        <p class="text-sm text-zinc-500">"No steps yet — run a Workbench turn or Admit to start the trail."</p>
                    </Show>
                    <Show when=move || pid.get().is_empty()>
                        <p class="text-sm text-zinc-500">"Pick an agent to follow its action loop."</p>
                    </Show>
                    <ul class="space-y-1.5">
                        {move || {
                            let f = focus.get();
                            let filtered: Vec<_> = steps
                                .get()
                                .into_iter()
                                .filter(|s| step_matches_focus(s, &f))
                                .collect();
                            if filtered.is_empty() && !steps.get().is_empty() {
                                return view! {
                                    <li class="text-sm text-zinc-500">
                                        {format!("No steps in focus “{f}”. Switch to All or another tab.")}
                                    </li>
                                }.into_any();
                            }
                            filtered.into_iter().map(|s| {
                            let tone = match s.tone {
                                "ok" => "border-emerald-900/40 bg-emerald-950/15",
                                "warn" => "border-amber-900/40 bg-amber-950/15",
                                "bad" => "border-rose-900/40 bg-rose-950/20",
                                _ => "border-zinc-800 bg-zinc-950/40",
                            };
                            let badge = match s.tone {
                                "ok" => "text-emerald-300",
                                "warn" => "text-amber-300",
                                "bad" => "text-rose-300",
                                _ => "text-zinc-400",
                            };
                            let detail = s.detail.clone();
                            let has_detail = !detail.is_empty();
                            view! {
                                <li class=format!("rounded-lg border px-3 py-2 {tone}")>
                                    <div class="flex flex-wrap items-center gap-2">
                                        <span class=format!("text-[10px] uppercase tracking-wide {badge}")>{s.kind.clone()}</span>
                                        <span class="text-[10px] text-zinc-500">{s.source}</span>
                                        <span class="ml-auto text-[10px] text-zinc-500">{s.when.clone()}</span>
                                    </div>
                                    <p class="mt-0.5 text-[13px] text-zinc-100">{s.title}</p>
                                    {has_detail.then(|| view! {
                                        <p class="mt-0.5 text-[11px] text-zinc-400 whitespace-pre-wrap">{detail.clone()}</p>
                                    })}
                                </li>
                            }
                        }).collect_view().into_any()
                        }}
                    </ul>
                </section>
            </div>
        </div>
    }
}

fn step_matches_focus(s: &TrailStep, focus: &str) -> bool {
    match focus {
        "all" | "" => true,
        "orders" => {
            s.kind == "order"
                || s.title.to_ascii_lowercase().contains("proposal")
                || s.detail.to_ascii_lowercase().contains("pending")
        }
        "evidence" => {
            matches!(s.kind.as_str(), "tool" | "admission")
                || s.title.to_ascii_lowercase().contains("tooldispatch")
                || s.title.to_ascii_lowercase().contains("admit")
                || s.title.to_ascii_lowercase().contains("pate")
                || s.detail.to_ascii_lowercase().contains("policy_denied")
                || s.detail.to_ascii_lowercase().contains("block")
                || s.kind.contains("pate")
                || s.title.contains("effect_intent")
        }
        "standing" => {
            s.kind == "system"
                || s.title.to_ascii_lowercase().contains("charter")
                || s.title.to_ascii_lowercase().contains("identity")
        }
        "hitl" => s.kind == "hitl" || s.title.to_ascii_lowercase().contains("hitl"),
        "activity" => s.source == "activity" || s.source == "watch",
        _ => true,
    }
}

fn journal_step(ev: &Value) -> TrailStep {
    let kind = ev
        .get("kind")
        .or_else(|| ev.get("type"))
        .and_then(|x| x.as_str())
        .unwrap_or("event")
        .to_string();
    let id = ev
        .get("event_id")
        .or_else(|| ev.get("id"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let when = ev
        .get("ts")
        .or_else(|| ev.get("timestamp"))
        .or_else(|| ev.get("created_at"))
        .map(|x| match x {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => "—".into(),
        })
        .unwrap_or_else(|| "—".into());
    let (title, detail, tone) = match kind.as_str() {
        "order" => {
            let name = ev
                .pointer("/payload/tool_name")
                .and_then(|x| x.as_str())
                .unwrap_or("tool");
            let st = ev
                .pointer("/payload/status")
                .and_then(|x| x.as_str())
                .unwrap_or("pending");
            (
                format!("Proposal · {name}"),
                format!("status={st}"),
                if st == "pending" { "warn" } else { "info" },
            )
        }
        "tool" => {
            let name = ev
                .pointer("/payload/tool_name")
                .and_then(|x| x.as_str())
                .unwrap_or("tool");
            let ok = ev
                .pointer("/payload/ok")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let err = ev
                .pointer("/payload/error")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            (
                format!("ToolDispatch · {name}"),
                if ok {
                    "ok".into()
                } else {
                    err.to_string()
                },
                if ok { "ok" } else { "bad" },
            )
        }
        "admission" => {
            let body = ev
                .get("content")
                .or_else(|| ev.pointer("/payload/summary"))
                .and_then(|x| x.as_str())
                .unwrap_or("admission");
            let bad = body.to_ascii_lowercase().contains("block")
                || body.to_ascii_lowercase().contains("refus");
            (
                "Admit / PATE".into(),
                body.to_string(),
                if bad { "bad" } else { "ok" },
            )
        }
        "user" | "assistant" | "system" | "hitl" => {
            let content = ev
                .get("content")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let short = if content.len() > 160 {
                format!("{}…", &content[..160])
            } else {
                content
            };
            let tone = if kind == "hitl" {
                "warn"
            } else if short.to_ascii_lowercase().contains("cease")
                || short.to_ascii_lowercase().contains("refus")
                || short.to_ascii_lowercase().contains("blocked")
            {
                "bad"
            } else {
                "info"
            };
            (kind.clone(), short, tone)
        }
        _ => (
            kind.clone(),
            ev.get("content")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            "info",
        ),
    };
    TrailStep {
        id,
        when,
        kind,
        title,
        detail,
        tone,
        source: "journal",
    }
}

fn watch_step(w: &WatchEventVm) -> TrailStep {
    let tone = match w.decision {
        "allow" => "ok",
        "deny" => "bad",
        _ => "info",
    };
    let mut detail = w.summary.clone();
    if !w.reason.is_empty() {
        if !detail.is_empty() {
            detail.push_str(" · ");
        }
        detail.push_str(&w.reason);
    }
    if !w.error_code.is_empty() {
        if !detail.is_empty() {
            detail.push_str(" · ");
        }
        detail.push_str(&w.error_code);
    }
    TrailStep {
        id: w.id.clone(),
        when: w.time.clone(),
        kind: w.kind.clone(),
        title: format!("{} · {}", w.action, w.resource),
        detail,
        tone,
        source: "watch",
    }
}

fn activity_step(a: &Value) -> TrailStep {
    let op = a
        .get("operation")
        .or_else(|| a.get("action"))
        .and_then(|x| x.as_str())
        .unwrap_or("activity")
        .to_string();
    let outcome = a
        .get("outcome")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let reason = a
        .get("reason")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let when = a
        .get("timestamp")
        .map(|x| match x {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => "—".into(),
        })
        .unwrap_or_else(|| "—".into());
    let tone = match outcome.to_ascii_lowercase().as_str() {
        "ok" | "allow" | "success" | "allowed" => "ok",
        "deny" | "denied" | "error" | "fail" | "failed" | "blocked" => "bad",
        _ => "info",
    };
    TrailStep {
        id: a
            .get("audit_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        when,
        kind: "activity".into(),
        title: format!("{op} · {outcome}"),
        detail: reason,
        tone,
        source: "activity",
    }
}

fn event_target_value(ev: &web_sys::Event) -> String {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
        .map(|el| el.value())
        .unwrap_or_default()
}
