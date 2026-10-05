//! Operations Theater — Workbench orchestrator floor for one intelligence.
//!
//! Route: /run/workbench and /run/workbench/:pid
//! Center is not chat: session journal via Workbench APIs (turn / admit / cancel).

use std::sync::Arc;

use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map, use_query_map};
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::overlays::acs::OpAcsStrip;
use crate::components::operator::overlays::intelligence_pack::OpIntelligencePackStrip;
use crate::components::operator::overlays::confirm::OpConfirm;
use crate::components::operator::overlays::gateway_form::OpGatewayGrantForm;
use crate::components::operator::overlays::agent_data_workspace::AgentDataWorkspace;
use crate::components::operator::overlays::workbench_consult::{
    OpWorkbenchConsult, WorkbenchConsultLayout,
};
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpSpinner, OpText, OpTextVariant,
};
use crate::iia_api;
use crate::request_store::{bump_reload, use_shared_requests};
use crate::ui_state::{
    focus_workbench_session, open_agent_drawer, open_create_agent,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum RailPanel {
    Orders,
    Hitl,
    Mission,
    Context,
    Evidence,
    Capabilities,
    Standing,
    Gateway,
    Data,
    DevGuard,
    TraceTramp,
    WitnessCtl,
}

impl RailPanel {
    fn from_query(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "orders" | "order" => Self::Orders,
            "hitl" => Self::Hitl,
            "evidence" | "proof" | "chart" => Self::Evidence,
            "mission" => Self::Mission,
            "context" => Self::Context,
            "standing" | "identity" | "charter" => Self::Standing,
            "caps" | "capabilities" => Self::Capabilities,
            "gateway" | "grants" => Self::Gateway,
            "data" | "library" | "files" => Self::Data,
            "devguard" => Self::DevGuard,
            "tracetramp" | "trace" => Self::TraceTramp,
            "witness" | "witnessctl" => Self::WitnessCtl,
            _ => Self::Data,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Orders => "Orders",
            Self::Hitl => "HITL",
            Self::Mission => "Mission",
            Self::Context => "Context",
            Self::Evidence => "Evidence",
            Self::Capabilities => "Caps",
            Self::Standing => "Standing",
            Self::Gateway => "Gateway",
            Self::Data => "Data",
            Self::DevGuard => "DevGuard",
            Self::TraceTramp => "TraceTramp",
            Self::WitnessCtl => "WitnessCtl",
        }
    }

    fn query_key(self) -> &'static str {
        match self {
            Self::Orders => "orders",
            Self::Hitl => "hitl",
            Self::Mission => "mission",
            Self::Context => "context",
            Self::Evidence => "evidence",
            Self::Capabilities => "caps",
            Self::Standing => "standing",
            Self::Gateway => "gateway",
            Self::Data => "data",
            Self::DevGuard => "devguard",
            Self::TraceTramp => "tracetramp",
            Self::WitnessCtl => "witness",
        }
    }
}

fn scroll_operator_rail_into_view() {
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if let Some(el) = doc.get_element_by_id("wb-operator-rail") {
            el.scroll_into_view_with_bool(true);
        }
    }
}

#[component]
pub fn AgentWorkbenchTheater(#[prop(optional)] auth: Option<ReadSignal<AuthState>>) -> impl IntoView {
    let _ = auth;
    let params = use_params_map();
    let pid = Memo::new(move |_| {
        params
            .with(|p| p.get("pid").map(|s| s.to_string()))
            .unwrap_or_default()
    });

    view! {
        <Show
            when=move || !pid.get().is_empty()
            fallback=move || view! { <WorkbenchPicker /> }
        >
            {move || {
                let p = pid.get();
                view! { <TheaterFloor pid=p /> }
            }}
        </Show>
    }
}

#[component]
fn WorkbenchPicker() -> impl IntoView {
    let shared = use_shared_requests();
    let navigate = use_navigate();
    view! {
        <div class="flex h-full min-h-0 flex-col">
            <div class="shrink-0 border-b border-zinc-800/60 px-4 py-4 sm:px-6">
                <OpText text="Workbench".to_string() variant=OpTextVariant::Title />
                <p class="mt-1 text-sm text-zinc-500">
                    "Operations theater for one intelligence — consult, admit orders, chart receipts. Pick an agent."
                </p>
            </div>
            <div class="flex-1 overflow-auto px-4 py-4 sm:px-6">
                <Suspense fallback=move || view! { <div class="flex justify-center py-12"><OpSpinner /></div> }>
                    {move || Suspend::new({
                        let nav = navigate.clone();
                        async move {
                            let agents = shared.agents.await.ok().map(|v| agent_rows(&v)).unwrap_or_default();
                            if agents.is_empty() {
                                view! {
                                    <div class="rounded-xl border border-zinc-800/80 bg-zinc-950/50 p-8 text-center space-y-3">
                                        <p class="text-sm text-zinc-400">"No agents yet. Create one to open Workbench."</p>
                                        <OpButton
                                            label="+ New agent".to_string()
                                            variant=OpButtonVariant::Primary
                                            on_click=Arc::new(move |_| open_create_agent())
                                        />
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                                        {agents.into_iter().map(|(name, pid)| {
                                            let nav = nav.clone();
                                            let pid_go = pid.clone();
                                            view! {
                                                <button
                                                    type="button"
                                                    class="rounded-xl border border-zinc-800/80 bg-zinc-950/60 px-4 py-3 text-left hover:border-zinc-600"
                                                    on:click=move |_| {
                                                        nav(&format!("/run/workbench/{pid_go}"), Default::default());
                                                    }
                                                >
                                                    <p class="text-sm font-medium text-zinc-100">{name}</p>
                                                    <p class="mt-0.5 font-mono text-[10px] text-zinc-500">{pid}</p>
                                                </button>
                                            }
                                        }).collect_view()}
                                    </div>
                                }.into_any()
                            }
                        }
                    })}
                </Suspense>
            </div>
        </div>
    }
}

#[component]
fn TheaterFloor(pid: String) -> impl IntoView {
    let navigate = use_navigate();
    let query = use_query_map();
    let pid_sv = StoredValue::new(pid.clone());
    let (rail, set_rail) = signal({
        query.with_untracked(|q| RailPanel::from_query(&q.get("rail").unwrap_or_default()))
    });
    let (rail_notice, set_rail_notice) = signal(String::new());
    let (session_id, set_session_id) = signal({
        query.with_untracked(|q| q.get("session").unwrap_or_default())
    });
    let (sessions, set_sessions) = signal(Vec::<Value>::new());
    let (events, set_events) = signal(Vec::<Value>::new());
    let (pending, set_pending) = signal(Vec::<Value>::new());
    let (phase, set_phase) = signal(String::new());
    let (projection, set_projection) = signal(String::new());
    let (vitals, set_vitals) = signal(Value::Null);
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal(String::new());
    let (who, set_who) = signal(String::new());
    let (reload, set_reload) = signal(0u32);
    let (consult_tick, set_consult_tick) = signal(0u32);
    let (kill_open, set_kill_open) = signal(false);

    let apply_doc = move |doc: &Value| {
        let sess = doc.get("session").unwrap_or(doc);
        if let Some(sid) = sess.get("session_id").and_then(|x| x.as_str()) {
            set_session_id.set(sid.to_string());
            focus_workbench_session(&pid_sv.get_value(), sid);
        }
        if let Some(p) = sess.get("phase").and_then(|x| x.as_str()) {
            set_phase.set(p.to_string());
        }
        if let Some(o) = sess
            .get("last_projection_outcome")
            .and_then(|x| x.as_str())
        {
            set_projection.set(o.to_string());
        } else {
            set_projection.set(String::new());
        }
        let evs = doc
            .get("events")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        set_events.set(evs);
        let pend = doc
            .get("pending_orders")
            .or_else(|| sess.get("pending_orders"))
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        set_pending.set(pend);
        if let Some(v) = doc.get("vitals").cloned() {
            set_vitals.set(v);
        }
    };

    let sync_session_url = {
        let navigate = navigate.clone();
        Arc::new(move |sid: String| {
            let pid = pid_sv.get_value();
            if sid.is_empty() {
                return;
            }
            let rail_q = rail.get_untracked().query_key();
            navigate(
                &format!("/run/workbench/{pid}?session={sid}&rail={rail_q}"),
                Default::default(),
            );
        })
    };

    let open_rail = {
        Arc::new(move |name: String| {
            let panel = RailPanel::from_query(&name);
            set_rail.set(panel);
            set_rail_notice.set(format!("Opened {} rail — see the operator panel", panel.label()));
            spawn_local(async move {
                gloo_timers::future::TimeoutFuture::new(30).await;
                scroll_operator_rail_into_view();
            });
        })
    };

    Effect::new({
        let sync_session_url = sync_session_url.clone();
        move |_| {
        let _ = reload.get();
        let pid = pid_sv.get_value();
        let sync_session_url = sync_session_url.clone();
        spawn_local(async move {
            if let Ok(v) = iia_api::runtime_self(&pid).await {
                if let Some(w) = v
                    .pointer("/self/who_am_i_authoritative")
                    .or_else(|| v.pointer("/data/self/who_am_i_authoritative"))
                    .or_else(|| v.get("who_am_i_authoritative"))
                    .and_then(|x| x.as_str())
                {
                    set_who.set(w.to_string());
                }
            }
            match iia_api::workbench_list_sessions(&pid).await {
                Ok(list) => {
                    let rows = list
                        .get("sessions")
                        .and_then(|s| s.as_array())
                        .cloned()
                        .unwrap_or_default();
                    set_sessions.set(rows.clone());
                    let current = session_id.get_untracked();
                    let from_url = query.with_untracked(|q| q.get("session").unwrap_or_default());
                    let pick = if !from_url.is_empty()
                        && rows.iter().any(|s| {
                            s.get("session_id").and_then(|x| x.as_str()) == Some(from_url.as_str())
                        }) {
                        from_url
                    } else if !current.is_empty()
                        && rows.iter().any(|s| {
                            s.get("session_id").and_then(|x| x.as_str()) == Some(current.as_str())
                        }) {
                        current.clone()
                    } else {
                        rows.first()
                            .and_then(|s| s.get("session_id"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string()
                    };
                    if pick.is_empty() {
                        match iia_api::workbench_create_session(
                            &pid,
                            "Workbench",
                            "Consult and admit orders",
                        )
                        .await
                        {
                            Ok(doc) => {
                                set_err.set(String::new());
                                apply_doc(&doc);
                                if let Some(sid) = doc
                                    .pointer("/session/session_id")
                                    .or_else(|| doc.get("session_id"))
                                    .and_then(|x| x.as_str())
                                {
                                    sync_session_url(sid.to_string());
                                }
                                if let Ok(list2) = iia_api::workbench_list_sessions(&pid).await {
                                    set_sessions.set(
                                        list2
                                            .get("sessions")
                                            .and_then(|s| s.as_array())
                                            .cloned()
                                            .unwrap_or_default(),
                                    );
                                }
                                set_consult_tick.update(|n| *n = n.wrapping_add(1));
                            }
                            Err(e) => set_err.set(e.message),
                        }
                    } else {
                        let sid_changed = pick != current;
                        match iia_api::workbench_get_session(&pid, &pick).await {
                            Ok(doc) => {
                                set_err.set(String::new());
                                apply_doc(&doc);
                                sync_session_url(pick.clone());
                                if sid_changed {
                                    set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                }
                            }
                            Err(e) => set_err.set(e.message),
                        }
                    }
                }
                Err(e) => set_err.set(e.message),
            }
        });
        }
    });

    let admit_all = {
        Arc::new(move |_| {
            let pid = pid_sv.get_value();
            let sid = session_id.get_untracked();
            let v = vitals.get_untracked();
            let missing = v
                .pointer("/identity_stack/missing")
                .and_then(|x| x.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let enforced = v
                .pointer("/identity_stack/enforced")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            if enforced && missing > 0 {
                set_err.set(format!(
                    "identity_stack_incomplete — {missing} pillar(s) missing; Admit refused"
                ));
                return;
            }
            let ids: Vec<String> = pending
                .get_untracked()
                .iter()
                .filter_map(|o| o.get("order_id").and_then(|x| x.as_str()).map(str::to_string))
                .collect();
            if sid.is_empty() || ids.is_empty() || busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            set_err.set(String::new());
            spawn_local(async move {
                match iia_api::workbench_admit(&pid, &sid, &ids).await {
                    Ok(doc) => {
                        if doc.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                            set_err.set(
                                doc.get("error")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("admit_failed")
                                    .to_string(),
                            );
                        }
                        apply_doc(&doc);
                    }
                    Err(e) => set_err.set(e.message),
                }
                set_busy.set(false);
            });
        })
    };

    let cancel_all = {
        Arc::new(move |_| {
            let pid = pid_sv.get_value();
            let sid = session_id.get_untracked();
            if sid.is_empty() || busy.get_untracked() {
                return;
            }
            set_busy.set(true);
            spawn_local(async move {
                match iia_api::workbench_cancel_orders(&pid, &sid, &[]).await {
                    Ok(doc) => apply_doc(&doc),
                    Err(e) => set_err.set(e.message),
                }
                set_busy.set(false);
            });
        })
    };

    view! {
        <div class="flex h-full min-h-0 flex-col">
            // Duty strip
            <div class="shrink-0 border-b border-zinc-800/60 bg-zinc-950/80 px-3 py-2 sm:px-4">
                <div class="flex flex-wrap items-center gap-2 text-[11px]">
                    <span class="font-semibold uppercase tracking-wide text-zinc-400">"Workbench"</span>
                    <span class="font-mono text-zinc-500">{move || pid_sv.get_value()}</span>
                    <Show when=move || !who.get().is_empty()>
                        <span class="rounded bg-zinc-800/80 px-1.5 py-0.5 text-zinc-200">{move || who.get()}</span>
                    </Show>
                    <Show when=move || !phase.get().is_empty()>
                        <span class="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-300">
                            {move || format!("phase:{}", phase.get())}
                        </span>
                    </Show>
                    <Show when=move || !projection.get().is_empty()>
                        <span class="rounded border border-emerald-800/60 bg-emerald-950/40 px-1.5 py-0.5 text-emerald-200">
                            {move || format!("projection:{}", projection.get())}
                        </span>
                    </Show>
                    <Show when=move || !pending.get().is_empty()>
                        <span class="rounded border border-amber-800/60 bg-amber-950/30 px-1.5 py-0.5 text-amber-100">
                            {move || format!("orders:{}", pending.get().len())}
                        </span>
                    </Show>
                    {move || {
                        let v = vitals.get();
                        if v.is_null() {
                            return ().into_any();
                        }
                        let lab = v.get("lab_mode").and_then(|x| x.as_bool()).unwrap_or(true);
                        let hitl = v.get("hitl_pending_count").and_then(|x| x.as_u64()).unwrap_or(0);
                        let held = v.get("held_order_count").and_then(|x| x.as_u64()).unwrap_or(0);
                        let tools = v
                            .pointer("/capabilities/mcp_tool_count")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0);
                        let miss = v
                            .pointer("/identity_stack/missing")
                            .and_then(|x| x.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        let bind = v
                            .pointer("/binding/bind_tok")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let bind_short = if bind.len() > 16 {
                            format!("{}…", &bind[..16])
                        } else {
                            bind.to_string()
                        };
                        view! {
                            <span class="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-300">
                                {if lab { "hmac_lab" } else { "prod_candidate" }}
                            </span>
                            <span class="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-400">
                                {format!("hitl:{hitl}")}
                            </span>
                            <Show when=move || held != 0>
                                <span class="rounded border border-rose-800/60 bg-rose-950/30 px-1.5 py-0.5 text-rose-100">
                                    {format!("held:{held}")}
                                </span>
                            </Show>
                            <span class="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-400">
                                {format!("tools:{tools}")}
                            </span>
                            <span class="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-400">
                                {format!("stack_miss:{miss}")}
                            </span>
                            <span class="font-mono text-zinc-500">{bind_short}</span>
                        }.into_any()
                    }}
                    <button
                        type="button"
                        class="ml-auto text-zinc-500 hover:text-zinc-200"
                        on:click=move |_| set_reload.update(|n| *n = n.wrapping_add(1))
                    >"Refresh"</button>
                    <button
                        type="button"
                        class="text-zinc-500 hover:text-zinc-200"
                        on:click=move |_| navigate("/run", Default::default())
                    >"← RUN"</button>
                    <a
                        class="text-indigo-400 hover:underline"
                        href=move || {
                            let p = pid_sv.get_value();
                            let s = session_id.get();
                            if p.is_empty() {
                                "/run/trail".into()
                            } else if s.is_empty() {
                                format!("/run/trail/{p}")
                            } else {
                                format!("/run/trail/{p}?session={s}")
                            }
                        }
                    >"Action Trail"</a>
                    <a class="text-indigo-400 hover:underline" href="/setup/uplink">"Bring your agent"</a>
                </div>
                <div class="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-zinc-400">
                    {move || {
                        let v = vitals.get();
                        if v.is_null() { return ().into_any(); }
                        let mid = v.pointer("/mission/mission_id").and_then(|x| x.as_str()).unwrap_or("");
                        let dphase = v
                            .pointer("/dal/phase")
                            .map(|x| match x {
                                Value::String(s) => s.clone(),
                                other => other.to_string().trim_matches('"').to_string(),
                            })
                            .unwrap_or_else(|| "—".into());
                        let press = v.pointer("/context/pressure_pct").map(|x| x.to_string()).unwrap_or_else(|| "—".into());
                        let bud = if v.pointer("/budget/configured").and_then(|x| x.as_bool()).unwrap_or(false) {
                            format!("budget:{}", v.pointer("/budget/remaining").map(|x| x.to_string()).unwrap_or_else(|| "?".into()))
                        } else {
                            "budget:unset".into()
                        };
                        let pid = pid_sv.get_value();
                        view! {
                            <span class="rounded border border-zinc-800 px-1.5 py-0.5">
                                {if mid.is_empty() { "mission:—".into() } else { format!("mission:{mid}") }}
                            </span>
                            <span class="rounded border border-zinc-800 px-1.5 py-0.5">{format!("dal:{dphase}")}</span>
                            <span class="rounded border border-zinc-800 px-1.5 py-0.5">{format!("ctx:{press}%")}</span>
                            <span class="rounded border border-zinc-800 px-1.5 py-0.5">{bud}</span>
                            <a class="text-indigo-400 hover:underline" href=format!("/run/workbench/{pid}?rail=data")>"Data workspace →"</a>
                        }.into_any()
                    }}
                    <OpButton
                        label="Quarantine".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click={
                            Arc::new(move |_| {
                                let pid = pid_sv.get_value();
                                spawn_local(async move {
                                    match iia_api::agent_quarantine(&pid, "workbench duty strip").await {
                                        Ok(_) => set_err.set("quarantine ok — approve on FIX".into()),
                                        Err(e) => set_err.set(e.message),
                                    }
                                });
                            })
                        }
                    />
                    <OpButton
                        label="Kill".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| set_kill_open.set(true))
                    />
                </div>
                <OpConfirm
                    open=kill_open
                    set_open=set_kill_open
                    title="Kill this intelligence?".to_string()
                    message="Kill switch is irreversible from Workbench. Confirm only if you intend to stop this principal.".to_string()
                    confirm_label="Kill"
                    on_confirm={
                        let pid = pid_sv.get_value();
                        move || {
                            let pid = pid.clone();
                            spawn_local(async move {
                                match iia_api::agent_kill_switch(&pid).await {
                                    Ok(_) => set_err.set("kill switch requested".into()),
                                    Err(e) => set_err.set(e.message),
                                }
                            });
                        }
                    }
                />
                <div class="mt-2">
                    <OpAcsStrip pid=pid_sv.get_value() />
                    <OpIntelligencePackStrip pid=pid_sv.get_value() />
                </div>
            </div>

            <div class="flex min-h-0 flex-1 flex-col lg:flex-row">
                // Sessions + agents
                <aside class="hidden w-56 shrink-0 overflow-auto border-r border-zinc-800/60 p-3 lg:block">
                    <p class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Sessions"</p>
                    <div class="mb-2">
                        <OpButton
                            label="+ Session".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click={
                                let pid = pid_sv.get_value();
                                Arc::new(move |_| {
                                    let pid = pid.clone();
                                    spawn_local(async move {
                                        match iia_api::workbench_create_session(
                                            &pid,
                                            "Workbench",
                                            "Consult and admit orders",
                                        )
                                        .await
                                        {
                                            Ok(doc) => {
                                                apply_doc(&doc);
                                                set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                            }
                                            Err(e) => set_err.set(e.message),
                                        }
                                        set_reload.update(|n| *n = n.wrapping_add(1));
                                    });
                                })
                            }
                        />
                    </div>
                    {move || {
                        let rows = sessions.get();
                        let needs: Vec<_> = rows.iter().filter(|s| {
                            matches!(
                                s.get("phase").and_then(|x| x.as_str()),
                                Some("await_admit" | "hitl_wait" | "acting")
                            )
                        }).cloned().collect();
                        let idle: Vec<_> = rows.iter().filter(|s| {
                            !matches!(
                                s.get("phase").and_then(|x| x.as_str()),
                                Some("await_admit" | "hitl_wait" | "acting")
                            )
                        }).cloned().collect();
                        let render_row = |s: Value| {
                            let sid = s.get("session_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let title = s.get("title").and_then(|x| x.as_str()).unwrap_or("session").to_string();
                            let ph = s.get("phase").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let pending_n = s
                                .get("pending_order_ids")
                                .and_then(|x| x.as_array())
                                .map(|a| a.len() as u64)
                                .or_else(|| s.get("pending_order_count").and_then(|x| x.as_u64()))
                                .unwrap_or(0);
                            let sid_click = sid.clone();
                            let active = session_id.get() == sid;
                            let sid_short = sid.chars().take(10).collect::<String>();
                            let sync_session_url = sync_session_url.clone();
                            view! {
                                <li>
                                    <button
                                        type="button"
                                        class={
                                            let needs = matches!(ph.as_str(), "await_admit" | "hitl_wait" | "acting");
                                            if active && needs {
                                                "wb-session--needs-you w-full rounded border border-indigo-700/50 px-2 py-1.5 text-left ring-1 ring-indigo-600/40"
                                            } else if active {
                                                "w-full rounded border border-indigo-700/50 bg-indigo-950/30 px-2 py-1.5 text-left"
                                            } else if needs {
                                                "wb-session--needs-you w-full rounded border px-2 py-1.5 text-left"
                                            } else {
                                                "w-full rounded border border-zinc-800/60 px-2 py-1.5 text-left hover:bg-zinc-900/50"
                                            }
                                        }
                                        on:click=move |_| {
                                            set_session_id.set(sid_click.clone());
                                            focus_workbench_session(&pid_sv.get_value(), &sid_click);
                                            sync_session_url(sid_click.clone());
                                            set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                        }
                                    >
                                        <p class="truncate text-[11px] text-zinc-200">{title}</p>
                                        {if pending_n > 0 || matches!(ph.as_str(), "await_admit" | "hitl_wait") {
                                            view! {
                                                <span class="wb-session__badge">
                                                    {if pending_n > 0 {
                                                        format!("{pending_n} awaiting admit")
                                                    } else {
                                                        "needs review".into()
                                                    }}
                                                </span>
                                            }.into_any()
                                        } else {
                                            ().into_any()
                                        }}
                                        <p class="font-mono text-[9px] text-zinc-500">
                                            {format!("{ph} · {sid_short}")}
                                        </p>
                                    </button>
                                </li>
                            }
                        };
                        view! {
                            <div class="mb-4 space-y-3">
                                <div>
                                    <p class="mb-1 text-[10px] font-semibold text-amber-200/90">
                                        {format!("Needs you · {}", needs.len())}
                                    </p>
                                    <ul class="space-y-1">
                                        {if needs.is_empty() {
                                            view! { <li class="text-[10px] text-zinc-600">"(none)"</li> }.into_any()
                                        } else {
                                            needs.into_iter().map(render_row).collect_view().into_any()
                                        }}
                                    </ul>
                                </div>
                                <div>
                                    <p class="mb-1 text-[10px] font-semibold text-zinc-500">
                                        {format!("Idle · {}", idle.len())}
                                    </p>
                                    <ul class="space-y-1">
                                        {idle.into_iter().map(render_row).collect_view()}
                                    </ul>
                                </div>
                            </div>
                        }.into_any()
                    }}
                    <p class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Agents"</p>
                    <BenchList active=pid_sv.get_value() />
                    <div class="mt-3">
                        <OpButton
                            label="+ New agent".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| open_create_agent())
                        />
                    </div>
                    <div class="mt-4">
                        <p class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Agent tree"</p>
                        <ProgenyMini pid=pid_sv.get_value() vitals=vitals />
                    </div>
                </aside>

                // Persistent journal + agent chat
                <main class="flex min-w-0 flex-1 flex-col">
                    <Show when=move || !err.get().is_empty()>
                        <p class="border-b border-rose-900/40 bg-rose-950/30 px-3 py-2 text-xs text-rose-200">{move || err.get()}</p>
                    </Show>
                    <div class="min-h-0 flex-1 overflow-hidden p-3">
                        {move || {
                            let sid = session_id.get();
                            view! {
                                <OpWorkbenchConsult
                                    pid=pid_sv.get_value()
                                    layout=WorkbenchConsultLayout::Full
                                    show_open_theater=false
                                    show_llm_connect=true
                                    session_id_prop=sid
                                    reload_tick=consult_tick
                                    on_open_rail=Callback::new({
                                        let open_rail = open_rail.clone();
                                        move |name: String| open_rail(name)
                                    })
                                />
                            }.into_any()
                        }}
                    </div>
                </main>

                // Operator rail
                <aside
                    id="wb-operator-rail"
                    class="w-full max-h-[42vh] shrink-0 overflow-auto border-t border-zinc-800/60 p-3 lg:max-h-none lg:w-80 lg:border-l lg:border-t-0 scroll-mt-4"
                >
                    <Show when=move || !rail_notice.get().is_empty()>
                        <div class="mb-2 rounded border border-indigo-800/50 bg-indigo-950/40 px-2 py-1.5 text-[11px] text-indigo-100">
                            {move || rail_notice.get()}
                            <button
                                type="button"
                                class="ml-2 text-[10px] text-indigo-300 hover:underline"
                                on:click=move |_| set_rail_notice.set(String::new())
                            >"dismiss"</button>
                        </div>
                    </Show>
                    <div class="mb-2 flex flex-wrap gap-1">
                        <RailChip label="Orders" id=RailPanel::Orders rail set_rail />
                        <RailChip label="HITL" id=RailPanel::Hitl rail set_rail />
                        <RailChip label="Mission" id=RailPanel::Mission rail set_rail />
                        <RailChip label="Context" id=RailPanel::Context rail set_rail />
                        <RailChip label="Evidence" id=RailPanel::Evidence rail set_rail />
                        <RailChip label="Caps" id=RailPanel::Capabilities rail set_rail />
                        <RailChip label="Standing" id=RailPanel::Standing rail set_rail />
                        <RailChip label="Gateway" id=RailPanel::Gateway rail set_rail />
                        <RailChip label="Workspace" id=RailPanel::Data rail set_rail />
                        <RailChip label="DevGuard" id=RailPanel::DevGuard rail set_rail />
                        <RailChip label="TraceTramp" id=RailPanel::TraceTramp rail set_rail />
                        <RailChip label="WitnessCtl" id=RailPanel::WitnessCtl rail set_rail />
                    </div>
                    {move || match rail.get() {
                        RailPanel::Orders => view! {
                            <div class="space-y-3">
                                <div class="rounded-lg border border-zinc-800/70 bg-zinc-900/40 p-2">
                                    <p class="text-[10px] text-zinc-500">"Pending orders"</p>
                                    <p class="text-lg font-semibold tabular-nums text-zinc-100">
                                        {move || pending.get().len()}
                                    </p>
                                    <div class="mt-2 flex flex-wrap gap-1">
                                        <OpButton
                                            label="Admit all".to_string()
                                            variant=OpButtonVariant::Primary
                                            on_click=admit_all.clone()
                                        />
                                        <OpButton
                                            label="Cancel".to_string()
                                            variant=OpButtonVariant::Ghost
                                            on_click=cancel_all.clone()
                                        />
                                    </div>
                                </div>
                                <OrdersPanel
                                    pid=pid_sv.get_value()
                                    session_id=session_id
                                    pending=pending
                                    vitals=vitals
                                    set_busy=set_busy
                                    set_err=set_err
                                    apply_reload=set_reload
                                    set_consult_tick=set_consult_tick
                                />
                                <HitlResumePanel
                                    pid=pid_sv.get_value()
                                    session_id=session_id
                                    vitals=vitals
                                    set_reload=set_reload
                                    set_consult_tick=set_consult_tick
                                />
                                <LifecycleMini pid=pid_sv.get_value() />
                            </div>
                        }.into_any(),
                        RailPanel::Hitl => view! {
                            <div class="space-y-3">
                                <HitlResumePanel
                                    pid=pid_sv.get_value()
                                    session_id=session_id
                                    vitals=vitals
                                    set_reload=set_reload
                                    set_consult_tick=set_consult_tick
                                />
                                <HitlRail
                                    pid=pid_sv.get_value()
                                    session_id=session_id
                                    vitals=vitals
                                    set_reload=set_reload
                                    set_consult_tick=set_consult_tick
                                />
                            </div>
                        }.into_any(),
                        RailPanel::Mission => view! {
                            <MissionRail vitals=vitals />
                        }.into_any(),
                        RailPanel::Context => view! {
                            <ContextRail pid=pid_sv.get_value() vitals=vitals />
                        }.into_any(),
                        RailPanel::Evidence => view! {
                            <div class="space-y-3">
                                <ChartPanel events=events pid=pid_sv.get_value() />
                                <RoundsPanel events=events />
                            </div>
                        }.into_any(),
                        RailPanel::Capabilities => view! {
                            <CapabilitiesRail pid=pid_sv.get_value() vitals=vitals />
                        }.into_any(),
                        RailPanel::Standing => view! {
                            <div class="space-y-3">
                                <IdentityRail vitals=vitals />
                                <StandingPanel pid=pid_sv.get_value() />
                            </div>
                        }.into_any(),
                        RailPanel::Data => view! {
                            <AgentDataWorkspace pid=pid_sv.get_value() />
                        }.into_any(),
                        RailPanel::Gateway => view! {
                            <div class="space-y-2">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"World gateway"</p>
                                <p class="text-[11px] text-zinc-400">
                                    "Grant this agent one address. Demo already has hosted Isolate / Govern / Prove tools. Extra grants are Cone Ask unless you justify App Allow."
                                </p>
                                <OpGatewayGrantForm agent_pid=pid_sv.get_value() />
                            </div>
                        }.into_any(),
                        RailPanel::DevGuard => view! {
                            <DevGuardRail />
                        }.into_any(),
                        RailPanel::TraceTramp => view! {
                            <TraceTrampRail />
                        }.into_any(),
                        RailPanel::WitnessCtl => view! {
                            <WitnessCtlRail vitals=vitals />
                        }.into_any(),
                    }}
                    <div class="mt-3">
                        <OpButton
                            label="Open drawer workbench".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| open_agent_drawer(pid_sv.get_value()))
                        />
                    </div>
                </aside>
            </div>
        </div>
    }
}

#[component]
fn RailChip(
    label: &'static str,
    id: RailPanel,
    rail: ReadSignal<RailPanel>,
    set_rail: WriteSignal<RailPanel>,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class=move || {
                if rail.get() == id {
                    "rounded border border-indigo-700/60 bg-indigo-950/40 px-2 py-0.5 text-[10px] text-indigo-100"
                } else {
                    "rounded border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-400 hover:bg-zinc-800/60"
                }
            }
            on:click=move |_| {
                set_rail.set(id);
                scroll_operator_rail_into_view();
            }
        >{label}</button>
    }
}

#[component]
fn HitlResumePanel(
    pid: String,
    session_id: ReadSignal<String>,
    vitals: ReadSignal<Value>,
    set_reload: WriteSignal<u32>,
    set_consult_tick: WriteSignal<u32>,
) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (flash, set_flash) = signal(String::new());
    view! {
        <Show when=move || {
            vitals
                .get()
                .get("held_order_count")
                .and_then(|x| x.as_u64())
                .unwrap_or(0)
                != 0
        }>
            <div class="space-y-2 rounded-lg border border-rose-900/40 bg-rose-950/20 p-2">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-rose-200">"HITL held orders"</p>
                <p class="text-[11px] text-zinc-400">
                    "PATE Ask paused effects. Approve on FIX first, then Resume re-queues for Admit. Deny cancels without ToolDispatch."
                </p>
                <div class="flex flex-wrap gap-1">
                    <OpButton
                        label="Resume after FIX approve".to_string()
                        variant=OpButtonVariant::Primary
                        on_click={
                            Arc::new(move |_| {
                                let pid = pid_sv.get_value();
                                let sid = session_id.get_untracked();
                                let rid = vitals
                                    .get_untracked()
                                    .get("hitl_request_id")
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                spawn_local(async move {
                                    match iia_api::workbench_hitl_resume(
                                        &pid,
                                        &sid,
                                        rid.as_deref(),
                                    )
                                    .await
                                    {
                                        Ok(doc) => {
                                            if doc.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                                                let msg = doc
                                                    .get("error")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("resume_failed");
                                                let hint = doc
                                                    .get("hint")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("");
                                                set_flash.set(format!("{msg} — {hint}"));
                                            } else {
                                                set_flash.set("Resumed — Admit pending orders".into());
                                            }
                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                            set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                        }
                                        Err(e) => set_flash.set(e.message),
                                    }
                                });
                            })
                        }
                    />
                    <OpButton
                        label="Deny".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click={
                            Arc::new(move |_| {
                                let pid = pid_sv.get_value();
                                let sid = session_id.get_untracked();
                                let rid = vitals
                                    .get_untracked()
                                    .get("hitl_request_id")
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                spawn_local(async move {
                                    match iia_api::workbench_hitl_deny(
                                        &pid,
                                        &sid,
                                        "operator denied",
                                        rid.as_deref(),
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            set_flash.set("Held orders denied".into());
                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                            set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                        }
                                        Err(e) => set_flash.set(e.message),
                                    }
                                });
                            })
                        }
                    />
                    <a class="inline-flex items-center text-[10px] text-indigo-400 hover:underline" href="/fix">
                        "Open FIX →"
                    </a>
                </div>
                <Show when=move || !flash.get().is_empty()>
                    <p class="text-[10px] text-amber-100/90">{move || flash.get()}</p>
                </Show>
            </div>
        </Show>
    }
}

#[component]
fn CapabilitiesRail(pid: String, vitals: ReadSignal<Value>) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (registry, set_registry) = signal(Value::Null);
    let (authz, set_authz) = signal(Value::Null);
    Effect::new(move |_| {
        let pid = pid_sv.get_value();
        spawn_local(async move {
            if let Ok(v) = iia_api::operator_capabilities().await {
                set_registry.set(api::resource_object(&v).clone());
            }
            if let Ok(v) = iia_api::capabilities(&pid).await {
                set_authz.set(api::resource_object(&v).clone());
            }
        });
    });
    view! {
        <div class="space-y-2 text-[11px]">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Capabilities (truth)"</p>
            <p class="rounded border border-indigo-900/40 bg-indigo-950/20 p-2 text-indigo-100/90">
                "Capability ≠ authority. Installed institutions enable panels; grants/charter still gate effects."
            </p>
            {move || {
                let institutions = registry
                    .get()
                    .get("institutions")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                if institutions.is_empty() {
                    return view! {
                        <p class="text-zinc-500">"Loading operator capability registry…"</p>
                    }.into_any();
                }
                view! {
                    <ul class="space-y-2">
                        {institutions.into_iter().map(|inst| {
                            let id = inst.get("institution_id").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                            let label = inst.get("label").and_then(|x| x.as_str()).unwrap_or(&id).to_string();
                            let installed = inst.get("installed").and_then(|x| x.as_bool()).unwrap_or(false);
                            let caps = inst.get("capabilities").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                            view! {
                                <li class="rounded border border-zinc-800/70 bg-zinc-900/40 p-2">
                                    <div class="flex items-center justify-between gap-2">
                                        <span class="font-medium text-zinc-200">{label}</span>
                                        <span class=if installed {
                                            "rounded border border-emerald-800/50 px-1 text-[9px] text-emerald-200"
                                        } else {
                                            "rounded border border-zinc-700 px-1 text-[9px] text-zinc-500"
                                        }>
                                            {if installed { "installed" } else { "not installed" }}
                                        </span>
                                    </div>
                                    <p class="font-mono text-[9px] text-zinc-500">{id}</p>
                                    <Show when=move || installed>
                                        <ul class="mt-1 max-h-24 space-y-0.5 overflow-auto">
                                            {caps.clone().into_iter().take(8).map(|c| {
                                                let cid = c.get("id").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                                let avail = c.get("available").and_then(|x| x.as_bool()).unwrap_or(false);
                                                view! {
                                                    <li class="font-mono text-[10px] text-zinc-400">
                                                        {format!("{cid} · {}", if avail { "available" } else { "unavailable" })}
                                                    </li>
                                                }
                                            }).collect_view()}
                                        </ul>
                                    </Show>
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                }.into_any()
            }}
            {move || {
                let v = vitals.get();
                let tools = v
                    .pointer("/capabilities/mcp_tools")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                let unsupported = v
                    .pointer("/capabilities/unsupported_here")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                view! {
                    <div class="rounded border border-zinc-800/70 bg-zinc-900/40 p-2">
                        <p class="text-zinc-500">"MCP tools (order targets)"</p>
                        <ul class="mt-1 max-h-28 space-y-0.5 overflow-auto">
                            {if tools.is_empty() {
                                view! { <li class="text-zinc-600">"(none registered — proposals will not mint)"</li> }.into_any()
                            } else {
                                tools.into_iter().map(|x| {
                                    let s = x.as_str().unwrap_or("?").to_string();
                                    view! { <li class="font-mono text-emerald-200/90">{s}</li> }
                                }).collect_view().into_any()
                            }}
                        </ul>
                    </div>
                    <div class="rounded border border-amber-900/40 bg-amber-950/15 p-2">
                        <p class="text-amber-200/90">"Unsupported here (honest)"</p>
                        <ul class="mt-1 space-y-0.5">
                            {unsupported.into_iter().map(|x| {
                                let s = x.as_str().unwrap_or("?").to_string();
                                view! { <li class="font-mono text-amber-100/70">{s}</li> }
                            }).collect_view()}
                        </ul>
                    </div>
                }.into_any()
            }}
            {move || {
                let a = authz.get();
                if a.is_null() {
                    return ().into_any();
                }
                let pretty = serde_json::to_string_pretty(&a).unwrap_or_default();
                let short = if pretty.len() > 480 {
                    format!("{}…", &pretty[..480])
                } else {
                    pretty
                };
                view! {
                    <div class="rounded border border-zinc-800/70 bg-zinc-900/40 p-2">
                        <p class="text-zinc-500">"Principal authority snapshot (grants ≠ capability)"</p>
                        <pre class="mt-1 max-h-32 overflow-auto font-mono text-[9px] text-zinc-400">{short}</pre>
                        <a class="mt-1 inline-block text-indigo-400 hover:underline" href=format!("/agents/{}/charter", pid_sv.get_value())>
                            "Charter / grants →"
                        </a>
                    </div>
                }.into_any()
            }}
        </div>
    }
}

#[component]
fn DevGuardRail() -> impl IntoView {
    view! {
        <div class="space-y-2 text-[11px]">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"DevGuard"</p>
            <p class="text-zinc-400">
                "In-process on this node. Stamp a repo cage, then any agent in that folder follows DevGuard. Demo is not DevGuard. The seeded RUN workflow is ENABLED (catalog) — not a busy worker. Empty cage is idle, not broken."
            </p>
            <div class="rounded border border-emerald-900/40 bg-emerald-950/15 p-2 space-y-1">
                <a class="block text-indigo-400 hover:underline" href="/plugins/devguard">
                    "DevGuard console →"
                </a>
                <a class="block text-indigo-400 hover:underline" href="/run">
                    "Seeded workflow on RUN →"
                </a>
                <p class="text-[10px] text-zinc-500">
                    "Paste a GitHub URL or org/repo. Git manages the files. KERNEL_ENFORCE may be off on this hosted trial."
                </p>
            </div>
        </div>
    }
}

#[component]
fn WitnessCtlRail(vitals: ReadSignal<Value>) -> impl IntoView {
    view! {
        <div class="space-y-2 text-[11px]">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"WitnessCtl"</p>
            <p class="text-zinc-400">
                "Sidecar on this node. Console link — Demo Admit does not ingest WitnessCtl sessions. Prove writes playground_demo_receipts (issuer HMAC, not court-grade)."
            </p>
            {move || {
                let rec = vitals
                    .get()
                    .get("demo_receipts")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                let n = rec.len();
                view! {
                    <p class="text-zinc-300">{format!("Demo receipts on this node: {n}")}</p>
                }
            }}
            <div class="rounded border border-sky-900/40 bg-sky-950/15 p-2 space-y-1">
                <a class="block text-indigo-400 hover:underline" href="/plugins/witnessctl">
                    "WitnessCtl console →"
                </a>
                <a class="block text-indigo-400 hover:underline" href="/run/workbench">
                    "Prove on Demo →"
                </a>
            </div>
        </div>
    }
}

#[component]
fn TraceTrampRail() -> impl IntoView {
    view! {
        <div class="space-y-2 text-[11px]">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"TraceTramp"</p>
            <p class="text-zinc-400">
                "Sidecar on this node. Console link — Talk uses the platform LLM router and does not hop TraceTramp :9741. Green means the management plane (:9742) is reachable. Empty graph is expected on this trial. Demo is not TraceTramp."
            </p>
            <div class="rounded border border-amber-900/40 bg-amber-950/15 p-2 space-y-1">
                <a class="block text-indigo-400 hover:underline" href="/plugins/tracetramp">
                    "TraceTramp console →"
                </a>
                <p class="text-[10px] text-zinc-500">
                    "Playground management plane is :9742 on the node. Do not reconfigure to lab :19742."
                </p>
            </div>
        </div>
    }
}

#[component]
fn BenchList(active: String) -> impl IntoView {
    let shared = use_shared_requests();
    let navigate = use_navigate();
    let active_sv = StoredValue::new(active);
    view! {
        <Suspense fallback=move || view! { <OpSpinner /> }>
            {move || Suspend::new({
                let nav = navigate.clone();
                async move {
                    let agents = shared.agents.await.ok().map(|v| agent_rows(&v)).unwrap_or_default();
                    view! {
                        <ul class="space-y-1">
                            {agents.into_iter().map(|(name, pid)| {
                                let nav = nav.clone();
                                let pid_go = pid.clone();
                                let is_active = pid == active_sv.get_value();
                                view! {
                                    <li>
                                        <button
                                            type="button"
                                            class=if is_active {
                                                "w-full rounded-md bg-zinc-800/80 px-2 py-1.5 text-left text-xs text-zinc-100"
                                            } else {
                                                "w-full rounded-md px-2 py-1.5 text-left text-xs text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"
                                            }
                                            on:click=move |_| {
                                                nav(&format!("/run/workbench/{pid_go}"), Default::default());
                                            }
                                        >
                                            <span class="block truncate font-medium">{name}</span>
                                            <span class="block truncate font-mono text-[9px] text-zinc-500">{pid}</span>
                                        </button>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }
            })}
        </Suspense>
    }
}

#[component]
fn OrdersPanel(
    pid: String,
    session_id: ReadSignal<String>,
    pending: ReadSignal<Vec<Value>>,
    vitals: ReadSignal<Value>,
    set_busy: WriteSignal<bool>,
    set_err: WriteSignal<String>,
    apply_reload: WriteSignal<u32>,
    set_consult_tick: WriteSignal<u32>,
) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let identity_blocked = Signal::derive(move || {
        let v = vitals.get();
        let missing = v
            .pointer("/identity_stack/missing")
            .and_then(|x| x.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let enforced = v
            .pointer("/identity_stack/enforced")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        enforced && missing > 0
    });
    view! {
        <div class="space-y-2">
            <p class="text-xs text-zinc-500">
                "Orders are tool proposals. Admit on the legal rail — Ring-1 never auto-dispatches from Consult."
            </p>
            <Show when=move || identity_blocked.get()>
                <div class="wb-admit-block">
                    <p>"Admit blocked — identity stack incomplete."</p>
                    <p class="mt-1 text-[10px] text-rose-100/80">
                        {move || {
                            vitals
                                .get()
                                .pointer("/identity_stack/missing")
                                .and_then(|x| x.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
                                .unwrap_or_default()
                        }}
                    </p>
                    <a class="mt-1 inline-block text-indigo-300 hover:underline" href=format!("/agents/{}/charter", pid_sv.get_value())>
                        "Open Charter / Access →"
                    </a>
                </div>
            </Show>
            <Show when=move || pending.get().is_empty()>
                <p class="text-sm text-zinc-500">"No pending orders."</p>
            </Show>
            {move || pending.get().into_iter().map(|o| {
                let oid = o.get("order_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let name = o.get("tool_name").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                let args = o.get("arguments").cloned().unwrap_or(Value::Null);
                let pretty = serde_json::to_string_pretty(&args).unwrap_or_default();
                let oid_admit = oid.clone();
                let oid_cancel = oid.clone();
                let blocked = identity_blocked.get();
                view! {
                    <div class="rounded-lg border border-amber-900/40 bg-amber-950/15 p-3">
                        <p class="text-sm font-medium text-amber-100">{name}</p>
                        <p class="font-mono text-[9px] text-zinc-500">{oid.clone()}</p>
                        <pre class="mt-1 max-h-32 overflow-auto font-mono text-[10px] text-zinc-400">{pretty}</pre>
                        <div class="mt-2 flex flex-wrap gap-1">
                            <button
                                type="button"
                                class="rounded border border-indigo-700/50 bg-indigo-950/40 px-2 py-1 text-[10px] text-indigo-100 disabled:opacity-40"
                                disabled=blocked
                                title=if blocked {
                                    "identity_stack_incomplete — mint pillars on SETUP/Access before Admit"
                                } else {
                                    "Admit = identity → DAL → PATE → ToolDispatch"
                                }
                                on:click=move |_| {
                                    if identity_blocked.get_untracked() {
                                        set_err.set("identity_stack_incomplete — Admit refused".into());
                                        return;
                                    }
                                    let pid = pid_sv.get_value();
                                    let sid = session_id.get_untracked();
                                    let id = oid_admit.clone();
                                    if sid.is_empty() || id.is_empty() {
                                        return;
                                    }
                                    set_busy.set(true);
                                    spawn_local(async move {
                                        match iia_api::workbench_admit(&pid, &sid, &[id]).await {
                                            Ok(doc) => {
                                                if doc.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                                                    set_err.set(
                                                        doc.get("error")
                                                            .and_then(|x| x.as_str())
                                                            .unwrap_or("admit_failed")
                                                            .to_string(),
                                                    );
                                                }
                                                apply_reload.update(|n| *n = n.wrapping_add(1));
                                                set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                            }
                                            Err(e) => set_err.set(e.message),
                                        }
                                        set_busy.set(false);
                                    });
                                }
                            >"Admit"</button>
                            <OpButton
                                label="Reject".to_string()
                                variant=OpButtonVariant::Ghost
                                on_click={
                                    Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        let sid = session_id.get_untracked();
                                        let id = oid_cancel.clone();
                                        if sid.is_empty() || id.is_empty() {
                                            return;
                                        }
                                        set_busy.set(true);
                                        spawn_local(async move {
                                            match iia_api::workbench_cancel_orders(&pid, &sid, &[id]).await {
                                                Ok(_) => {
                                                    apply_reload.update(|n| *n = n.wrapping_add(1));
                                                    set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                                }
                                                Err(e) => set_err.set(e.message),
                                            }
                                            set_busy.set(false);
                                        });
                                    })
                                }
                            />
                        </div>
                    </div>
                }
            }).collect_view()}
        </div>
    }
}

#[component]
fn MissionRail(vitals: ReadSignal<Value>) -> impl IntoView {
    let (steps_text, set_steps_text) = signal(String::new());
    Effect::new(move |_| {
        let v = vitals.get();
        let mid = v
            .pointer("/mission/mission_id")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let Some(mid) = mid else {
            set_steps_text.set(String::new());
            return;
        };
        spawn_local(async move {
            match iia_api::get_mission(&mid).await {
                Ok(doc) => {
                    let steps = doc
                        .get("steps")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if steps.is_empty() {
                        set_steps_text.set("(no steps yet)".into());
                    } else {
                        let lines: Vec<String> = steps
                            .into_iter()
                            .take(12)
                            .map(|s| {
                                let kind = s.get("kind").and_then(|x| x.as_str()).unwrap_or("step");
                                let status =
                                    s.get("status").and_then(|x| x.as_str()).unwrap_or("?");
                                let label = s
                                    .get("label")
                                    .or_else(|| s.get("content"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("");
                                format!("{kind}:{status} {label}")
                            })
                            .collect();
                        set_steps_text.set(lines.join("\n"));
                    }
                }
                Err(e) => set_steps_text.set(e.message),
            }
        });
    });
    view! {
        <div class="space-y-2 text-[11px]">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Mission / DAL"</p>
            <p class="text-zinc-400">"Status from Workbench vitals — advanced control stays on mission/DAL APIs."</p>
            {move || {
                let v = vitals.get();
                let mission = v.get("mission").cloned().unwrap_or(Value::Null);
                let dal = v.get("dal").cloned().unwrap_or(Value::Null);
                let mid = mission.get("mission_id").and_then(|x| x.as_str()).unwrap_or("(none)");
                let phase = dal.get("phase").map(|x| x.to_string()).unwrap_or_else(|| "—".into());
                let run = v.get("dal_run_id").and_then(|x| x.as_str()).unwrap_or("(none)");
                let link = mission.get("link").and_then(|x| x.as_str()).unwrap_or("/missions").to_string();
                view! {
                    <div class="rounded border border-zinc-800/70 bg-zinc-900/40 p-2 space-y-1">
                        <p class="text-zinc-500">"mission_id"</p>
                        <p class="font-mono text-zinc-200">{mid.to_string()}</p>
                        <p class="text-zinc-500">"dal_run_id"</p>
                        <p class="font-mono text-zinc-200">{run.to_string()}</p>
                        <p class="text-zinc-500">"dal_phase"</p>
                        <p class="font-mono text-zinc-200">{phase}</p>
                        <a class="inline-block text-indigo-400 hover:underline" href=link>"Mission deep link →"</a>
                    </div>
                }.into_any()
            }}
            <Show when=move || !steps_text.get().is_empty()>
                <div class="rounded border border-zinc-800/70 bg-zinc-900/40 p-2">
                    <p class="text-zinc-500">"Recent steps"</p>
                    <pre class="mt-1 max-h-40 overflow-auto font-mono text-[9px] text-zinc-400">{move || steps_text.get()}</pre>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn ContextRail(pid: String, vitals: ReadSignal<Value>) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (live, set_live) = signal(String::new());
    view! {
        <div class="space-y-2 text-[11px]">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Context / budget"</p>
            {move || {
                let v = vitals.get();
                let ctx = v.get("context").cloned().unwrap_or(Value::Null);
                let bud = v.get("budget").cloned().unwrap_or(Value::Null);
                let press = ctx.get("pressure_pct").map(|x| x.to_string()).unwrap_or_else(|| "—".into());
                let tracked = ctx.get("tracked").and_then(|x| x.as_bool()).unwrap_or(false);
                let configured = bud.get("configured").and_then(|x| x.as_bool()).unwrap_or(false);
                let rem = bud.get("remaining").map(|x| x.to_string()).unwrap_or_else(|| "—".into());
                let pid = pid_sv.get_value();
                view! {
                    <div class="rounded border border-zinc-800/70 bg-zinc-900/40 p-2 space-y-1">
                        <p class="text-zinc-500">{if tracked { "pressure_pct (vitals)" } else { "context not tracked yet" }}</p>
                        <p class="font-mono text-zinc-200">{press}</p>
                        <p class="text-zinc-500">{if configured { "budget remaining" } else { "budget gate not configured" }}</p>
                        <p class="font-mono text-zinc-200">{rem}</p>
                        <a class="block text-indigo-400 hover:underline" href=format!("/run/workbench/{pid}?rail=data")>"Open data workspace →"</a>
                    </div>
                }.into_any()
            }}
            <OpButton
                label="Refresh live pressure".to_string()
                variant=OpButtonVariant::Secondary
                on_click={
                    Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            match iia_api::context_pressure(&pid).await {
                                Ok(v) => {
                                    let pct = v.get("pressure_pct").map(|x| x.to_string()).unwrap_or_default();
                                    let rec = v.get("recommendation").and_then(|x| x.as_str()).unwrap_or("");
                                    set_live.set(format!("{pct}% · {rec}"));
                                }
                                Err(e) => set_live.set(e.message),
                            }
                        });
                    })
                }
            />
            <Show when=move || !live.get().is_empty()>
                <p class="text-zinc-300">{move || live.get()}</p>
            </Show>
        </div>
    }
}

#[component]
fn IdentityRail(vitals: ReadSignal<Value>) -> impl IntoView {
    view! {
        <div class="space-y-2 text-[11px]">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Identity stack"</p>
            {move || {
                let v = vitals.get();
                let missing = v
                    .pointer("/identity_stack/missing")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                let complete = v
                    .pointer("/identity_stack/complete")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let enforced = v
                    .pointer("/identity_stack/enforced")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let who = v.get("who").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let purpose = v.get("purpose").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let charter = v
                    .pointer("/links/charter")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                view! {
                    <div class="rounded border border-zinc-800/70 bg-zinc-900/40 p-2 space-y-1">
                        <p class="text-zinc-200">{if who.is_empty() { "(unnamed)".into() } else { who }}</p>
                        {if purpose.is_empty() {
                            ().into_any()
                        } else {
                            view! { <p class="text-zinc-400">{purpose}</p> }.into_any()
                        }}
                        <p class="text-zinc-500">{format!("complete:{complete} · enforce:{enforced}")}</p>
                        {if charter.is_empty() {
                            ().into_any()
                        } else {
                            view! {
                                <a class="block text-indigo-400 hover:underline" href=charter>
                                    "Charter →"
                                </a>
                            }.into_any()
                        }}
                        {if missing.is_empty() {
                            ().into_any()
                        } else if enforced {
                            view! {
                                <div class="rounded border border-rose-900/40 bg-rose-950/20 p-1.5">
                                    <p class="text-rose-200">"Missing pillars — Admit will refuse"</p>
                                    <ul class="mt-1">
                                        {missing.into_iter().map(|m| {
                                            let s = m.as_str().unwrap_or("?").to_string();
                                            view! { <li class="font-mono text-rose-100/80">{s}</li> }
                                        }).collect_view()}
                                    </ul>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="rounded border border-zinc-800/70 bg-zinc-900/40 p-1.5">
                                    <p class="text-zinc-400">"Missing pillars listed for operators. Enforce is off on this trial — Admit still runs."</p>
                                    <ul class="mt-1">
                                        {missing.into_iter().map(|m| {
                                            let s = m.as_str().unwrap_or("?").to_string();
                                            view! { <li class="font-mono text-zinc-500">{s}</li> }
                                        }).collect_view()}
                                    </ul>
                                </div>
                            }.into_any()
                        }}
                    </div>
                }.into_any()
            }}
        </div>
    }
}

#[component]
fn ProgenyMini(pid: String, vitals: ReadSignal<Value>) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (tree, set_tree) = signal(Value::Null);
    Effect::new(move |_| {
        let pid = pid_sv.get_value();
        spawn_local(async move {
            if let Ok(v) = iia_api::agent_progeny(&pid).await {
                set_tree.set(v);
            }
        });
    });
    view! {
        <div class="text-[10px] text-zinc-400">
            {move || {
                let n = vitals
                    .get()
                    .pointer("/progeny/direct_children")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                format!("direct children (vitals): {n}")
            }}
            {move || {
                let t = tree.get();
                let root = t.get("subtree").cloned().unwrap_or(Value::Null);
                if root.is_null() {
                    return view! { <p class="mt-1 text-zinc-600">"(no progeny)"</p> }.into_any();
                }
                let root_name = root
                    .get("agent_name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("principal")
                    .to_string();
                let root_pid = root
                    .get("agent_pid")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let children = root
                    .get("children")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                view! {
                    <ul class="mt-1 space-y-0.5 font-mono text-zinc-300">
                        <li class="truncate">{format!("● {root_name} · {root_pid}")}</li>
                        {children.into_iter().map(|c| {
                            let name = c.get("agent_name").and_then(|x| x.as_str()).unwrap_or("child").to_string();
                            let cpid = c.get("agent_pid").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let grands = c.get("children").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                            view! {
                                <li class="truncate pl-3">
                                    {if grands > 0 {
                                        format!("└ {name} · {cpid} (+{grands})")
                                    } else {
                                        format!("└ {name} · {cpid}")
                                    }}
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                }.into_any()
            }}
        </div>
    }
}

#[component]
fn ChartPanel(events: ReadSignal<Vec<Value>>, pid: String) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (flash, set_flash) = signal(String::new());
    view! {
        <div class="space-y-3">
            <p class="text-xs text-zinc-500">
                "Chart = Workbench session admissions plus playground_demo_receipts (Prove). WitnessCtl ingest is a separate sidecar — not this list. HMAC here is not court-grade."
            </p>
            <div class="flex flex-wrap gap-2">
                <OpButton
                    label="Load SOAS grade".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            match iia_api::soas_report(&pid).await {
                                Ok(v) => {
                                    let g = v.get("overall_grade").and_then(|x| x.as_str()).unwrap_or("?");
                                    set_flash.set(format!("SOAS overall_grade={g} (honest — not court unless CD green)"));
                                }
                                Err(e) => set_flash.set(e.message),
                            }
                        });
                    })
                />
                <OpButton
                    label="Open Evidence drawer".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        open_agent_drawer(pid_sv.get_value());
                    })
                />
                <a
                    class="inline-flex items-center rounded px-2 py-1 text-[11px] text-indigo-400 hover:underline"
                    href=format!("/run/workbench/{}?rail=evidence", pid_sv.get_value())
                >
                    "Evidence rail →"
                </a>
            </div>
            <Show when=move || !flash.get().is_empty()>
                <p class="text-xs text-zinc-300">{move || flash.get()}</p>
            </Show>
            <ul class="space-y-1">
                {move || events.get().into_iter().filter(|e| {
                    matches!(e.get("kind").and_then(|x| x.as_str()), Some("tool" | "admission" | "hitl" | "order"))
                }).map(|ev| {
                    let kind = ev.get("kind").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                    let tool = ev
                        .pointer("/payload/tool_name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let ok = ev.pointer("/payload/ok").and_then(|x| x.as_bool());
                    let err = ev
                        .pointer("/payload/error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let status = ev
                        .pointer("/payload/status")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let content = ev.get("content").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let digest = ev
                        .pointer("/payload/action_digest")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let has_digest = !digest.is_empty();
                    let line = if !err.is_empty() {
                        if tool.is_empty() {
                            format!("{kind} · {err}")
                        } else {
                            format!("{kind} · {tool} · {err}")
                        }
                    } else if !tool.is_empty() {
                        let st = status
                            .is_empty()
                            .then(|| ok.map(|b| if b { "ok" } else { "error" }).unwrap_or("—"))
                            .unwrap_or(status.as_str());
                        format!("{kind} · {tool} · {st}")
                    } else if !content.is_empty() {
                        format!("{kind} · {content}")
                    } else {
                        kind.clone()
                    };
                    let bad = ok == Some(false)
                        || (!err.is_empty())
                        || content.to_ascii_lowercase().contains("block")
                        || content.to_ascii_lowercase().contains("denied");
                    let row_cls = if bad {
                        "rounded border border-rose-900/50 bg-rose-950/20 px-2 py-1.5 font-mono text-[11px] text-rose-100"
                    } else {
                        "rounded border border-zinc-800 px-2 py-1.5 font-mono text-[11px] text-zinc-300"
                    };
                    let pid = pid_sv.get_value();
                    view! {
                        <li class=row_cls>
                            {line}
                            {if has_digest {
                                view! { <p class="mt-0.5 truncate text-[9px] text-zinc-500">{format!("digest:{digest}")}</p> }.into_any()
                            } else {
                                ().into_any()
                            }}
                            {if bad {
                                view! {
                                    <a
                                        class="mt-1 inline-block text-[10px] text-indigo-400 hover:underline"
                                        href=format!("/run/trail/{pid}")
                                    >"Open Action Trail →"</a>
                                }.into_any()
                            } else {
                                ().into_any()
                            }}
                        </li>
                    }
                }).collect_view()}
            </ul>
        </div>
    }
}

#[component]
fn StandingPanel(pid: String) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (text, set_text) = signal(String::new());
    Effect::new(move |_| {
        let pid = pid_sv.get_value();
        spawn_local(async move {
            let mut parts = Vec::new();
            if let Ok(c) = iia_api::agent_contract(&pid).await {
                parts.push(format!(
                    "contract:\n{}",
                    serde_json::to_string_pretty(&api::resource_object(&c)).unwrap_or_default()
                ));
            }
            if let Ok(s) = iia_api::agent_setup(&pid).await {
                parts.push(format!(
                    "setup:\n{}",
                    serde_json::to_string_pretty(&api::resource_object(&s)).unwrap_or_default()
                ));
            }
            set_text.set(if parts.is_empty() {
                "No standing charter loaded.".into()
            } else {
                parts.join("\n\n")
            });
        });
    });
    let pid_link = pid_sv.get_value();
    view! {
        <div class="space-y-2">
            <p class="text-xs text-zinc-500">
                "Standing = identity/charter posture. Mission, budget, context stay on their control planes — deep links only."
            </p>
            <div class="flex flex-col gap-1 rounded border border-zinc-800/70 bg-zinc-900/40 p-2 text-[11px]">
                <a class="text-indigo-400 hover:underline" href=format!("/agents/{pid_link}/charter")>
                    "Charter Studio →"
                </a>
                <a class="text-indigo-400 hover:underline" href=format!("/run/workbench/{pid_link}?rail=data")>
                    "Data workspace →"
                </a>
                <a class="text-indigo-400 hover:underline" href="/fix">
                    "FIX / HITL queue →"
                </a>
                <a class="text-indigo-400 hover:underline" href=format!("/run/workbench/{pid_link}?rail=evidence")>
                    "Evidence rail →"
                </a>
                <a class="text-indigo-400 hover:underline" href="/operator/capabilities">
                    "Operator capabilities →"
                </a>
            </div>
            <pre class="max-h-[22rem] overflow-auto rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 font-mono text-[10px] text-zinc-400">
                {move || text.get()}
            </pre>
        </div>
    }
}

#[component]
fn RoundsPanel(events: ReadSignal<Vec<Value>>) -> impl IntoView {
    view! {
        <div class="space-y-2">
            <p class="text-xs text-zinc-500">"Rounds = system / HITL / lane events in this session."</p>
            {move || {
                let rows: Vec<_> = events.get().into_iter().filter(|e| {
                    matches!(e.get("kind").and_then(|x| x.as_str()), Some("system" | "hitl" | "admission"))
                }).collect();
                if rows.is_empty() {
                    view! { <p class="text-sm text-zinc-500">"No round events yet."</p> }.into_any()
                } else {
                    view! {
                        <ul class="space-y-1">
                            {rows.into_iter().map(|ev| {
                                let kind = ev.get("kind").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                let content = ev.get("content").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                view! {
                                    <li class="rounded border border-zinc-800 px-2 py-1.5 text-xs text-zinc-300">
                                        <span class="font-mono text-[10px] uppercase text-zinc-500">{kind}</span>
                                        <p class="mt-0.5">{content}</p>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[component]
fn LifecycleMini(pid: String) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (flash, set_flash) = signal(String::new());
    view! {
        <div class="rounded-lg border border-zinc-800/70 p-2 space-y-2">
            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Lifecycle"</p>
            <div class="flex flex-wrap gap-1">
                <OpButton
                    label="Quarantine".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            match iia_api::agent_quarantine(&pid, "workbench legal rail").await {
                                Ok(_) => {
                                    set_flash.set("quarantine ok — approve HITL on FIX".into());
                                    bump_reload();
                                }
                                Err(e) => set_flash.set(e.message),
                            }
                        });
                    })
                />
                <a class="inline-flex items-center rounded px-2 py-1 text-[11px] text-indigo-400 hover:underline" href="/fix">
                    "FIX"
                </a>
            </div>
            <Show when=move || !flash.get().is_empty()>
                <p class="text-[10px] text-zinc-400">{move || flash.get()}</p>
            </Show>
        </div>
    }
}

#[component]
fn HitlRail(
    pid: String,
    session_id: ReadSignal<String>,
    vitals: ReadSignal<Value>,
    set_reload: WriteSignal<u32>,
    set_consult_tick: WriteSignal<u32>,
) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (flash, set_flash) = signal(String::new());
    view! {
        <div class="rounded-lg border border-zinc-800/70 p-2 space-y-2">
            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Pending HITL"</p>
            <p class="text-[10px] text-zinc-500">
                "Approve on FIX, then Workbench resume re-queues held Ask orders for Admit."
            </p>
            {move || {
                let items = vitals
                    .get()
                    .get("hitl_pending")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                if items.is_empty() {
                    view! { <p class="text-[10px] text-zinc-500">"None"</p> }.into_any()
                } else {
                    view! {
                        <ul class="space-y-1">
                            {items.into_iter().map(|h| {
                                let rid = h.get("request_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let action = h.get("action").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                let rid_c = rid.clone();
                                view! {
                                    <li class="rounded border border-rose-900/40 bg-rose-950/20 px-2 py-1 text-[10px]">
                                        <p class="text-rose-100">{action}</p>
                                        <button
                                            type="button"
                                            class="mt-1 text-indigo-400 hover:underline"
                                            on:click=move |_| {
                                                let pid = pid_sv.get_value();
                                                let sid = session_id.get_untracked();
                                                let rid = rid_c.clone();
                                                spawn_local(async move {
                                                    match iia_api::hitl_approve(&pid, &rid).await {
                                                        Ok(_) => {
                                                            let _ = iia_api::workbench_hitl_resume(
                                                                &pid,
                                                                &sid,
                                                                Some(&rid),
                                                            )
                                                            .await;
                                                            set_flash.set(format!(
                                                                "approved+resumed {rid} — Admit held orders"
                                                            ));
                                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                                            set_consult_tick.update(|n| *n = n.wrapping_add(1));
                                                        }
                                                        Err(e) => set_flash.set(e.message),
                                                    }
                                                });
                                            }
                                        >"Approve → Resume"</button>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }
            }}
            <Show when=move || !flash.get().is_empty()>
                <p class="text-[10px] text-zinc-400">{move || flash.get()}</p>
            </Show>
            <a class="text-[10px] text-indigo-400 hover:underline" href="/fix">"Open FIX →"</a>
        </div>
    }
}

fn agent_rows(v: &Value) -> Vec<(String, String)> {
    let src = api::resource_object(v);
    let arr = src
        .get("agents")
        .or_else(|| src.get("items"))
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    arr.into_iter()
        .filter_map(|a| {
            let pid = a
                .get("pid")
                .or_else(|| a.get("agent_pid"))
                .and_then(|x| x.as_str())?
                .to_string();
            let name = a
                .get("name")
                .or_else(|| a.get("display_name"))
                .and_then(|x| x.as_str())
                .unwrap_or(pid.as_str())
                .to_string();
            Some((name, pid))
        })
        .collect()
}
