//! Industry-standard agent execution thread (Cursor / OpenAI Work / Claude loop).
//!
//! Human-facing core:
//!   - Scrollable agent thread (not a `<pre>` dump)
//!   - Role bubbles: You · Agent · System
//!   - Inline **order cards** with Admit / Reject (HITL in-chat)
//!   - Tool receipt cards after Connector ToolDispatch
//!   - Sticky composer + starter chips
//!   - Status strip: Running · Waiting review · Idle
//!
//! Backend stays Connector Workbench: turn never dispatches; Admit = DAL/PATE/tools.

use std::sync::Arc;

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::overlays::expometer::OpExpometer;
use crate::components::operator::overlays::llm_connect::OpLlmQuickConnect;
use crate::components::operator::overlays::result_sheet::OpResultSheet;
use crate::components::operator::primitives::{OpButton, OpButtonVariant};
use crate::deployment::use_deployment_mode;
use crate::iia_api;
use crate::ui_state::{
    focus_workbench_session, open_agent_workbench_session, stash_tool_proposals,
};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkbenchConsultLayout {
    /// Drawer Talk tab — compact height.
    #[default]
    Compact,
    /// Theater center pane — fills available height.
    Full,
}

/// Shared agent thread for drawer Talk and Operations Theater Consult.
#[component]
pub fn OpWorkbenchConsult(
    #[prop(into)] pid: String,
    #[prop(optional)] layout: WorkbenchConsultLayout,
    #[prop(optional)] show_open_theater: Option<bool>,
    #[prop(optional)] show_llm_connect: Option<bool>,
    /// When set, load this session instead of ensure/latest.
    #[prop(optional)]
    session_id_prop: String,
    #[prop(optional)] reload_tick: Option<ReadSignal<u32>>,
    /// Theater can jump the operator rail when a journal card is clicked.
    #[prop(optional)]
    on_open_rail: Option<Callback<String>>,
) -> impl IntoView {
    let layout = layout;
    let show_open = show_open_theater.unwrap_or(true);
    let show_llm = show_llm_connect.unwrap_or(true);
    let mode = use_deployment_mode();
    let fixed_sid = session_id_prop;
    let pid_sv = StoredValue::new(pid);
    let fixed_sid_sv = StoredValue::new(fixed_sid);
    let open_rail_cb = on_open_rail;
    let (session_id, set_session_id) = signal(String::new());
    // Journal "Open … trail" links always leave Workbench for the Action Trail page
    // (side-rail switching felt like "same page" — operators need a real URL).
    let go_rail = Arc::new(move |rail: String| {
        let p = pid_sv.get_value();
        let s = session_id.get_untracked();
        let focus = match rail.as_str() {
            "orders" | "order" => "orders",
            "evidence" | "proof" | "chart" => "evidence",
            "standing" | "identity" | "charter" => "standing",
            "hitl" => "hitl",
            _ => "all",
        };
        let href = if p.is_empty() {
            format!("/run/trail?focus={focus}")
        } else if s.is_empty() {
            format!("/run/trail/{p}?focus={focus}")
        } else {
            format!("/run/trail/{p}?session={s}&focus={focus}")
        };
        // Prefer callback only as an extra hint; still navigate so the URL changes.
        if let Some(cb) = open_rail_cb {
            cb.run(rail);
        }
        if let Some(w) = web_sys::window() {
            let _ = w.location().set_href(&href);
        }
    });
    let (events, set_events) = signal(Vec::<Value>::new());
    let (pending, set_pending) = signal(Vec::<Value>::new());
    let (phase, set_phase) = signal(String::new());
    let (projection, set_projection) = signal(String::new());
    let (agent_name, set_agent_name) = signal(String::new());
    let (lab_mode, set_lab_mode) = signal(true);
    let (hitl_n, set_hitl_n) = signal(0u64);
    let (stack_miss, set_stack_miss) = signal(0usize);
    let (stack_enforced, set_stack_enforced) = signal(false);
    let (stack_missing_names, set_stack_missing_names) = signal(String::new());
    let (held_n, set_held_n) = signal(0usize);
    let (hitl_request_id, set_hitl_request_id) = signal(Option::<String>::None);
    let (caps_summary, set_caps_summary) = signal(String::new());
    let (input, set_input) = signal(String::new());
    let (model, set_model) = signal("default".to_string());
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal(String::new());
    let (last_failed, set_last_failed) = signal(String::new());
    let (reload, set_reload) = signal(0u32);
    let (burn_chip, set_burn_chip) = signal(String::new());
    let (ceased, set_ceased) = signal(false);
    let (refuse_open, set_refuse_open) = signal(false);
    let (refuse_title, set_refuse_title) = signal(String::new());
    let (refuse_summary, set_refuse_summary) = signal(String::new());

    let refresh_burn = move || {
        let pid = pid_sv.get_value();
        spawn_local(async move {
            match iia_api::spend_burn(&pid).await {
                Ok(v) => {
                    set_burn_chip.set(iia_api::format_burn_chip(&v));
                    let has_cease = v
                        .get("latest_cease")
                        .map(|x| !x.is_null())
                        .unwrap_or(false);
                    set_ceased.set(has_cease);
                }
                Err(_) => {}
            }
        });
    };

    Effect::new(move |_| {
        let _ = busy.get();
        let _ = reload.get();
        refresh_burn();
    });

    let apply_doc = move |doc: &Value| {
        let sess = doc.get("session").unwrap_or(doc);
        if let Some(sid) = sess.get("session_id").and_then(|x| x.as_str()) {
            set_session_id.set(sid.to_string());
            focus_workbench_session(&pid_sv.get_value(), sid);
        }
        if let Some(p) = sess.get("phase").and_then(|x| x.as_str()) {
            set_phase.set(p.to_string());
        }
        set_projection.set(
            sess.get("last_projection_outcome")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        );
        set_events.set(
            doc.get("events")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default(),
        );
        let pend = doc
            .get("pending_orders")
            .or_else(|| sess.get("pending_orders"))
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        set_pending.set(pend.clone());
        let calls: Vec<Value> = pend
            .iter()
            .filter_map(|o| o.get("openai_call").cloned())
            .collect();
        if !calls.is_empty() {
            stash_tool_proposals(&pid_sv.get_value(), &calls);
        }
        if let Some(v) = doc.get("vitals") {
            set_agent_name.set(
                v.get("who")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            );
            set_lab_mode.set(v.get("lab_mode").and_then(|x| x.as_bool()).unwrap_or(true));
            set_hitl_n.set(
                v.get("hitl_pending_count")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
            );
            set_stack_miss.set(
                v.pointer("/identity_stack/missing")
                    .and_then(|x| x.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0),
            );
            set_stack_enforced.set(
                v.pointer("/identity_stack/enforced")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
            );
            set_stack_missing_names.set(
                v.pointer("/identity_stack/missing")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default(),
            );
            set_held_n.set(
                v.get("held_order_count")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as usize,
            );
            set_hitl_request_id.set(
                v.get("hitl_request_id")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
            );
            let tools = v
                .pointer("/capabilities/mcp_tool_count")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            let inst = v
                .pointer("/capabilities/institutions_installed")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            set_caps_summary.set(format!("caps:{inst} · tools:{tools}"));
        }
    };

    Effect::new(move |_| {
        let _ = reload.get();
        if let Some(tick) = reload_tick {
            let _ = tick.get();
        }
        // Never clobber an in-flight turn with a mid-consult snapshot (orphaned user msgs).
        if busy.get() {
            return;
        }
        let pid = pid_sv.get_value();
        let want = fixed_sid_sv.get_value();
        spawn_local(async move {
            if busy.get_untracked() {
                return;
            }
            if let Ok(st) = api::get_value_timeout("/settings/llms/status", 5_000).await {
                let src = api::resource_object(&st);
                if let Some(m) = src
                    .get("model")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                {
                    set_model.set(m.to_string());
                }
            }
            if busy.get_untracked() {
                return;
            }
            let result = if !want.is_empty() {
                iia_api::workbench_get_session(&pid, &want)
                    .await
                    .map(|doc| (want, doc))
            } else {
                iia_api::workbench_ensure_session(&pid).await
            };
            if busy.get_untracked() {
                return;
            }
            match result {
                Ok((_sid, doc)) => {
                    set_err.set(String::new());
                    apply_doc(&doc);
                }
                Err(e) => set_err.set(e.message),
            }
        });
    });

    let send = Arc::new(move |text: String| {
        if text.trim().is_empty() || busy.get_untracked() {
            return;
        }
        let pid = pid_sv.get_value();
        let sid = session_id.get_untracked();
        if sid.is_empty() {
            set_err.set("No workbench session.".into());
            return;
        }
        let model = model.get_untracked();
        let outbound = text.clone();
        set_busy.set(true);
        set_err.set(String::new());
        set_last_failed.set(String::new());
        set_input.set(String::new());
        spawn_local(async move {
            match iia_api::workbench_turn(&pid, &sid, &outbound, &model).await {
                Ok(doc) => {
                    if doc.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        set_err.set(
                            doc.get("error")
                                .and_then(|x| x.as_str())
                                .unwrap_or("turn_failed")
                                .to_string(),
                        );
                        set_last_failed.set(outbound);
                    }
                    apply_doc(&doc);
                }
                Err(e) => {
                    set_err.set(e.message);
                    set_last_failed.set(outbound);
                    // Refresh so phase leaves "consulting" after timeout/wedge.
                    set_reload.update(|n| *n = n.wrapping_add(1));
                }
            }
            set_busy.set(false);
        });
    });

    let run_demo = Arc::new(move |verb: &'static str| {
        if busy.get_untracked() {
            return;
        }
        let pid = pid_sv.get_value();
        let sid = session_id.get_untracked();
        if sid.is_empty() {
            set_err.set("No workbench session.".into());
            return;
        }
        set_busy.set(true);
        set_err.set(String::new());
        spawn_local(async move {
            match iia_api::workbench_demo(&pid, &sid, verb).await {
                Ok(doc) => {
                    if doc.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        set_err.set(
                            doc.get("error")
                                .and_then(|x| x.as_str())
                                .unwrap_or("demo_failed")
                                .to_string(),
                        );
                    }
                    apply_doc(&doc);
                }
                Err(e) => set_err.set(e.message),
            }
            set_busy.set(false);
        });
    });

    let admit_ids = Arc::new(move |ids: Vec<String>| {
        let pid = pid_sv.get_value();
        let sid = session_id.get_untracked();
        if sid.is_empty() || ids.is_empty() || busy.get_untracked() {
            return;
        }
        // Client pre-check only when the node actually enforces the stack.
        if stack_enforced.get_untracked() && stack_miss.get_untracked() != 0 {
            let pillars = stack_missing_names.get_untracked();
            let detail = if pillars.is_empty() {
                format!(
                    "{} identity pillar(s) missing. Mint character / memory / address RULES+HITL on Charter or Access, then retry Admit.",
                    stack_miss.get_untracked()
                )
            } else {
                format!(
                    "Missing: {pillars}. Mint those on Charter / Access, then retry Admit."
                )
            };
            set_err.set(format!("Admit refused — identity incomplete — {detail}"));
            set_refuse_title.set("Admit refused — identity incomplete".into());
            set_refuse_summary.set(detail);
            set_refuse_open.set(true);
            return;
        }
        set_busy.set(true);
        set_err.set(String::new());
        spawn_local(async move {
            match iia_api::workbench_admit(&pid, &sid, &ids).await {
                Ok(doc) => {
                    if let Some(detail) = api::body_failure_detail(&doc) {
                        let missing = doc
                            .get("missing")
                            .and_then(|x| x.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .filter(|s| !s.is_empty());
                        let summary = match missing {
                            Some(m) => format!("{detail}\n\nMissing pillars: {m}"),
                            None => detail.clone(),
                        };
                        set_err.set(detail);
                        set_refuse_title.set("Admit refused".into());
                        set_refuse_summary.set(summary);
                        set_refuse_open.set(true);
                    }
                    apply_doc(&doc);
                }
                Err(e) => {
                    set_err.set(e.message.clone());
                    set_refuse_title.set("Admit refused".into());
                    set_refuse_summary.set(e.message);
                    set_refuse_open.set(true);
                }
            }
            set_busy.set(false);
        });
    });

    let cancel_ids = Arc::new(move |ids: Vec<String>| {
        let pid = pid_sv.get_value();
        let sid = session_id.get_untracked();
        if sid.is_empty() || busy.get_untracked() {
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            match iia_api::workbench_cancel_orders(&pid, &sid, &ids).await {
                Ok(doc) => apply_doc(&doc),
                Err(e) => set_err.set(e.message),
            }
            set_busy.set(false);
        });
    });

    let thread_h = match layout {
        WorkbenchConsultLayout::Compact => "max-h-64 min-h-[12rem]",
        WorkbenchConsultLayout::Full => "flex-1 min-h-0",
    };
    let shell = match layout {
        WorkbenchConsultLayout::Compact => "flex flex-col gap-3",
        WorkbenchConsultLayout::Full => "flex h-full min-h-0 flex-col gap-0",
    };

    view! {
        <div class=shell>
            <OpResultSheet
                open=refuse_open
                set_open=set_refuse_open
                title=refuse_title
                summary=refuse_summary
                eyebrow="Admit refused"
                danger=true
            />
            // Status strip — Cursor Agents Window / Devin “Waiting for review”
            <div class="wb-agent-status shrink-0">
                <StatusPill
                    label=Signal::derive(move || {
                        let p = phase.get();
                        if busy.get() {
                            if p == "acting" {
                                "Executing".into()
                            } else {
                                "Consulting".into()
                            }
                        } else if p == "consulting" {
                            "Consulting".into()
                        } else if p == "await_admit" || !pending.get().is_empty() {
                            "Waiting for review".into()
                        } else if p == "hitl_wait" {
                            "Blocked · HITL".into()
                        } else if p == "acting" {
                            "Executing".into()
                        } else {
                            "Idle".into()
                        }
                    })
                    tone=Signal::derive(move || {
                        let p = phase.get();
                        if busy.get() || p == "acting" || p == "consulting" {
                            "run"
                        } else if p == "await_admit" || !pending.get().is_empty() {
                            "wait"
                        } else if p == "hitl_wait" {
                            "block"
                        } else {
                            "idle"
                        }
                    })
                />
                <Show when=move || !agent_name.get().is_empty()>
                    <span class="wb-agent-status__meta">{move || agent_name.get()}</span>
                </Show>
                <Show when=move || !projection.get().is_empty()>
                    <span class="wb-agent-status__chip wb-agent-status__chip--ok">
                        {move || format!("projection · {}", projection.get())}
                    </span>
                </Show>
                <Show when=move || !burn_chip.get().is_empty()>
                    <span
                        class="wb-agent-status__chip"
                        title="SpendCease admit ledger — not the provider invoice; cancel tax may remain"
                    >
                        {move || burn_chip.get()}
                    </span>
                </Show>
                <Show when=move || ceased.get()>
                    <span
                        class="wb-agent-status__chip wb-agent-status__chip--warn"
                        title="Generation fenced — further admits refuse until new generation"
                    >
                        "ceased"
                    </span>
                </Show>
                <span class="wb-agent-status__chip">
                    {move || if lab_mode.get() { "hmac_lab" } else { "prod_candidate" }}
                </span>
                <Show when=move || hitl_n.get() != 0>
                    <span class="wb-agent-status__chip wb-agent-status__chip--warn">
                        {move || format!("HITL · {}", hitl_n.get())}
                    </span>
                </Show>
                <Show when=move || stack_miss.get() != 0>
                    <span class="wb-agent-status__chip wb-agent-status__chip--warn">
                        {move || format!("stack · {} missing", stack_miss.get())}
                    </span>
                </Show>
                <Show when=move || held_n.get() != 0>
                    <span class="wb-agent-status__chip wb-agent-status__chip--warn">
                        {move || format!("held · {}", held_n.get())}
                    </span>
                </Show>
                <Show when=move || !caps_summary.get().is_empty()>
                    <span class="wb-agent-status__chip">{move || caps_summary.get()}</span>
                </Show>
                {show_open.then(|| view! {
                    <button
                        type="button"
                        class="ml-auto text-[11px] text-indigo-400 hover:underline"
                        on:click=move |_| {
                            open_agent_workbench_session(
                                pid_sv.get_value(),
                                Some(session_id.get_untracked()),
                            )
                        }
                    >"Full theater →"</button>
                })}
            </div>

            <div class="shrink-0 px-0">
                <OpExpometer pid=pid_sv.get_value() reload=reload />
            </div>
            <div class="shrink-0 flex flex-wrap gap-2 px-0 text-[11px]">
                <a
                    class="text-indigo-400 hover:underline"
                    href=move || {
                        let p = pid_sv.get_value();
                        let s = session_id.get();
                        if s.is_empty() {
                            format!("/run/trail/{p}")
                        } else {
                            format!("/run/trail/{p}?session={s}")
                        }
                    }
                >
                    "Action Trail →"
                </a>
            </div>

            {show_llm.then(|| view! { <div class="shrink-0 px-0"><OpLlmQuickConnect /></div> })}

            <Show when=move || mode.get().is_playground()>
                <div class="shrink-0 rounded-lg border border-cyan-900/40 bg-cyan-950/20 px-3 py-2">
                    <p class="text-[11px] font-semibold text-cyan-100">
                        "Demo verbs — no LLM key"
                    </p>
                    <p class="mt-0.5 text-[10px] leading-snug text-zinc-400">
                        "BankOps: Score wire → Hold funds → Decide (Admit each). Ledger to inspect. Isolate / Prove still work. Cease (Control) fences the generation — CONTINUE must refuse. Institutions on this node are not this agent."
                    </p>
                    <p class="mt-1 flex flex-wrap gap-x-2 gap-y-0.5 text-[10px]">
                        <a class="text-indigo-400 hover:underline" href="/plugins/devguard">"DevGuard"</a>
                        <a class="text-indigo-400 hover:underline" href="/plugins/tracetramp">"TraceTramp"</a>
                        <a class="text-indigo-400 hover:underline" href="/plugins/witnessctl">"WitnessCtl"</a>
                    </p>
                </div>
            </Show>

            { {
                let send_retry = send.clone();
                move || {
                let e = err.get();
                if e.is_empty() {
                    return ().into_any();
                }
                let failed = last_failed.get();
                let send = send_retry.clone();
                view! {
                    <div class="shrink-0 space-y-2 rounded-lg border border-rose-900/40 bg-rose-950/30 px-3 py-2">
                        <p class="text-[12px] text-rose-200">{e.clone()}</p>
                        <Show when=move || {
                            let el = e.to_ascii_lowercase();
                            el.contains("api key") || el.contains("authentication") || el.contains("invalid")
                        }>
                            <p class="text-[11px] text-rose-100/90">
                                "Linked LLM rejected the key. Re-paste a valid key in LLM connect above — Isolate/Govern/Stop/Prove and who/job/refuse chips need no vendor; free-text Talk does."
                            </p>
                        </Show>
                        {if failed.is_empty() {
                            ().into_any()
                        } else {
                            let send = send.clone();
                            let failed2 = failed.clone();
                            view! {
                                <OpButton
                                    label="Retry last message".to_string()
                                    variant=OpButtonVariant::Secondary
                                    on_click={
                                        Arc::new(move |_| {
                                            set_input.set(failed2.clone());
                                            send(failed2.clone());
                                        })
                                    }
                                />
                            }.into_any()
                        }}
                    </div>
                }.into_any()
            }} }

            <Show when=move || stack_enforced.get() && stack_miss.get() != 0>
                <div class="wb-admit-block shrink-0">
                    <p>"Admit blocked while identity pillars are missing (enforced on this node)."</p>
                    <p class="mt-1 text-[10px] text-rose-100/80">
                        {move || {
                            let names = stack_missing_names.get();
                            if names.is_empty() {
                                format!("{} missing — mint on SETUP / Charter before effects.", stack_miss.get())
                            } else {
                                format!("Missing: {names}")
                            }
                        }}
                    </p>
                    <a class="mt-1 inline-block text-indigo-300 hover:underline" href=format!("/agents/{}/charter", pid_sv.get_value())>
                        "Open Charter / Access →"
                    </a>
                </div>
            </Show>

            <Show when=move || held_n.get() != 0>
                <div class="shrink-0 space-y-2 rounded-lg border border-rose-900/40 bg-rose-950/20 px-3 py-2">
                    <p class="text-[11px] text-rose-100">
                        "HITL held orders — Approve on FIX first, then Resume re-queues for Admit. Deny cancels without ToolDispatch."
                    </p>
                    <div class="flex flex-wrap gap-1">
                        <OpButton
                            label="Resume after FIX approve".to_string()
                            variant=OpButtonVariant::Primary
                            on_click={
                                Arc::new(move |_| {
                                    let pid = pid_sv.get_value();
                                    let sid = session_id.get_untracked();
                                    let rid = hitl_request_id.get_untracked();
                                    if sid.is_empty() || busy.get_untracked() {
                                        return;
                                    }
                                    set_busy.set(true);
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
                                                    set_err.set(format!("{msg} — {hint}"));
                                                }
                                                apply_doc(&doc);
                                            }
                                            Err(e) => set_err.set(e.message),
                                        }
                                        set_busy.set(false);
                                        set_reload.update(|n| *n = n.wrapping_add(1));
                                    });
                                })
                            }
                        />
                        <a class="inline-flex items-center text-[11px] text-indigo-400 hover:underline" href="/fix">
                            "Open FIX →"
                        </a>
                        <OpButton
                            label="Deny held".to_string()
                            variant=OpButtonVariant::Ghost
                            on_click={
                                Arc::new(move |_| {
                                    let pid = pid_sv.get_value();
                                    let sid = session_id.get_untracked();
                                    let rid = hitl_request_id.get_untracked();
                                    if sid.is_empty() || busy.get_untracked() {
                                        return;
                                    }
                                    set_busy.set(true);
                                    spawn_local(async move {
                                        match iia_api::workbench_hitl_deny(
                                            &pid,
                                            &sid,
                                            "operator denied",
                                            rid.as_deref(),
                                        )
                                        .await
                                        {
                                            Ok(doc) => apply_doc(&doc),
                                            Err(e) => set_err.set(e.message),
                                        }
                                        set_busy.set(false);
                                        set_reload.update(|n| *n = n.wrapping_add(1));
                                    });
                                })
                            }
                        />
                    </div>
                </div>
            </Show>

            // Agent thread
            <div class=format!("wb-agent-thread {thread_h} overflow-y-auto")>
                <Show when=move || events.get().is_empty()>
                    <div class="wb-agent-empty">
                        <p class="wb-agent-empty__title">"Start the agent"</p>
                        <p class="wb-agent-empty__body">
                            "Same loop as Cursor / OpenAI Work: you instruct, the agent proposes, you admit effects. Connector never auto-runs tools."
                        </p>
                    </div>
                </Show>
                { {
                    let admit_ids = admit_ids.clone();
                    let cancel_ids = cancel_ids.clone();
                    let go_rail = go_rail.clone();
                    move || {
                    let admit = admit_ids.clone();
                    let cancel = cancel_ids.clone();
                    let go_rail = go_rail.clone();
                    events.get().into_iter().map(|ev| {
                        let kind = ev.get("kind").and_then(|x| x.as_str()).unwrap_or("system").to_string();
                        match kind.as_str() {
                            "user" => {
                                let content = ev.get("content").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                view! {
                                    <div class="wb-msg wb-msg--user">
                                        <div class="wb-msg__role">"You"</div>
                                        <div class="wb-msg__bubble">{content}</div>
                                    </div>
                                }.into_any()
                            }
                            "assistant" => {
                                let content = ev.get("content").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let outcome = ev
                                    .pointer("/payload/projection_outcome")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let has_outcome = !outcome.is_empty();
                                let kernel = ev
                                    .pointer("/payload/mutations")
                                    .and_then(|x| x.as_array())
                                    .map(|a| {
                                        a.iter().any(|m| {
                                            m.as_str().is_some_and(|s| {
                                                s.contains("kernel") || s.contains("vendor_llm_bypassed")
                                            })
                                        })
                                    })
                                    .unwrap_or(false);
                                let aipsprt_id = ev
                                    .pointer("/payload/aipsprt/passport_id")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let aipsprt_role = ev
                                    .pointer("/payload/aipsprt/provenance_role")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let aipsprt_digest = ev
                                    .pointer("/payload/aipsprt/payload/digest")
                                    .or_else(|| ev.pointer("/payload/aipsprt/digest_hex"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let has_aipsprt = !aipsprt_id.is_empty();
                                let aipsprt_badge = if aipsprt_role.is_empty() {
                                    "aipsprt".to_string()
                                } else {
                                    format!("aipsprt · {aipsprt_role}")
                                };
                                let aipsprt_title = {
                                    let dig = if aipsprt_digest.len() > 16 {
                                        format!("{}…", &aipsprt_digest[..16])
                                    } else {
                                        aipsprt_digest.clone()
                                    };
                                    format!("{aipsprt_id} · digest {dig}")
                                };
                                view! {
                                    <div class="wb-msg wb-msg--agent">
                                        <div class="wb-msg__role">
                                            "Agent"
                                            <Show when=move || has_outcome>
                                                <span class="wb-msg__badge">{outcome.clone()}</span>
                                            </Show>
                                            <Show when=move || kernel>
                                                <span class="wb-msg__badge" title="Answered from Connector kernel — not the linked LLM vendor">
                                                    "kernel"
                                                </span>
                                            </Show>
                                            <Show when=move || has_aipsprt>
                                                <span class="wb-msg__badge" title=aipsprt_title.clone()>
                                                    {aipsprt_badge.clone()}
                                                </span>
                                            </Show>
                                        </div>
                                        <div class="wb-msg__bubble">{content}</div>
                                    </div>
                                }.into_any()
                            }
                            "order" => {
                                let oid = ev.get("event_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let name = ev
                                    .pointer("/payload/tool_name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("tool")
                                    .to_string();
                                let status = ev
                                    .pointer("/payload/status")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("pending")
                                    .to_string();
                                let args = ev
                                    .pointer("/payload/arguments")
                                    .cloned()
                                    .unwrap_or(Value::Null);
                                let args_s = serde_json::to_string_pretty(&args).unwrap_or_default();
                                let args_short = if args_s.len() > 280 {
                                    format!("{}…", &args_s[..280])
                                } else {
                                    args_s
                                };
                                let show_actions = status == "pending";
                                let oid_a = oid.clone();
                                let oid_c = oid.clone();
                                let admit = admit.clone();
                                let cancel = cancel.clone();
                                view! {
                                    <div class="wb-tool-card">
                                        <div class="wb-tool-card__head">
                                            <span class="wb-tool-card__kind">"Tool proposal"</span>
                                            <span class="wb-tool-card__name">{name}</span>
                                            <span class=format!("wb-tool-card__status wb-tool-card__status--{status}")>{status.clone()}</span>
                                        </div>
                                        <pre class="wb-tool-card__args">{args_short}</pre>
                                        <Show when=move || show_actions>
                                            <div class="wb-tool-card__actions">
                                                <button
                                                    type="button"
                                                    class="wb-tool-card__btn wb-tool-card__btn--admit"
                                                    disabled=move || busy.get()
                                                    title="Admit = identity → DAL → PATE → ToolDispatch. Refusal shows a reason popup."
                                                    on:click={
                                                        let admit = admit.clone();
                                                        let oid = oid_a.clone();
                                                        move |_| admit(vec![oid.clone()])
                                                    }
                                                >"Admit"</button>
                                                <button
                                                    type="button"
                                                    class="wb-tool-card__btn"
                                                    disabled=move || busy.get()
                                                    on:click={
                                                        let cancel = cancel.clone();
                                                        let oid = oid_c.clone();
                                                        move |_| cancel(vec![oid.clone()])
                                                    }
                                                >"Reject"</button>
                                            </div>
                                        </Show>
                                        <p class="wb-tool-card__hint">
                                            "HITL — OpenAI needsApproval / Cursor review. Admit = PATE → ToolDispatch."
                                        </p>
                                        {
                                            let go = go_rail.clone();
                                            view! {
                                            <button
                                                type="button"
                                                class="mt-1 text-[10px] text-indigo-400 hover:underline"
                                                on:click=move |_| go("orders".into())
                                            >"Open Orders trail →"</button>
                                        }}
                                    </div>
                                }.into_any()
                            }
                            "tool" => {
                                let name = ev
                                    .pointer("/payload/tool_name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("tool")
                                    .to_string();
                                let ok = ev.pointer("/payload/ok").and_then(|x| x.as_bool()).unwrap_or(false);
                                let digest = ev
                                    .pointer("/payload/action_digest")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let err = ev
                                    .pointer("/payload/error")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let result = ev.pointer("/payload/result").cloned().unwrap_or(Value::Null);
                                let preview = if ok {
                                    let s = serde_json::to_string_pretty(&result).unwrap_or_default();
                                    if s.len() > 400 { format!("{}…", &s[..400]) } else { s }
                                } else {
                                    err
                                };
                                let has_digest = !digest.is_empty();
                                view! {
                                    <div class=if ok { "wb-tool-card wb-tool-card--done" } else { "wb-tool-card wb-tool-card--fail" }>
                                        <div class="wb-tool-card__head">
                                            <span class="wb-tool-card__kind">"Executed"</span>
                                            <span class="wb-tool-card__name">{name}</span>
                                            <span class=if ok {
                                                "wb-tool-card__status wb-tool-card__status--ok"
                                            } else {
                                                "wb-tool-card__status wb-tool-card__status--fail"
                                            }>{if ok { "ok" } else { "error" }}</span>
                                        </div>
                                        <Show when=move || has_digest>
                                            <p class="wb-tool-card__digest font-mono">{digest.clone()}</p>
                                        </Show>
                                        <pre class="wb-tool-card__args">{preview}</pre>
                                        {
                                            let go = go_rail.clone();
                                            view! {
                                            <button
                                                type="button"
                                                class="mt-1 text-[10px] text-indigo-400 hover:underline"
                                                on:click=move |_| go("evidence".into())
                                            >"Open Evidence trail →"</button>
                                        }}
                                    </div>
                                }.into_any()
                            }
                            "admission" => {
                                let content = ev.get("content").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                view! {
                                    <div class="wb-msg wb-msg--system">
                                        <div class="wb-msg__role">"Admission"</div>
                                        <div class="wb-msg__bubble wb-msg__bubble--mono">{content}</div>
                                        {
                                            let go = go_rail.clone();
                                            view! {
                                            <button
                                                type="button"
                                                class="mt-1 text-[10px] text-indigo-400 hover:underline"
                                                on:click=move |_| go("evidence".into())
                                            >"Open Evidence trail →"</button>
                                        }}
                                    </div>
                                }.into_any()
                            }
                            "hitl" | "system" => {
                                let content = ev.get("content").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let label = if kind == "hitl" { "HITL" } else { "System" };
                                let rail = if kind == "hitl" {
                                    "hitl"
                                } else if content.contains("pate_")
                                    || content.contains("effect_intent")
                                    || content.contains("admit")
                                {
                                    "evidence"
                                } else {
                                    "standing"
                                };
                                let rail_label = match rail {
                                    "hitl" => "Open HITL trail →",
                                    "evidence" => "Open Evidence trail →",
                                    _ => "Open Standing trail →",
                                };
                                view! {
                                    <div class="wb-msg wb-msg--system">
                                        <div class="wb-msg__role">{label}</div>
                                        <div class="wb-msg__bubble">{content}</div>
                                        {
                                            let go = go_rail.clone();
                                            let rail = rail.to_string();
                                            view! {
                                            <button
                                                type="button"
                                                class="mt-1 text-[10px] text-indigo-400 hover:underline"
                                                on:click=move |_| go(rail.clone())
                                            >{rail_label}</button>
                                        }}
                                    </div>
                                }.into_any()
                            }
                            _ => {
                                let content = ev.get("content").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                view! {
                                    <div class="wb-msg wb-msg--system">
                                        <div class="wb-msg__role">{kind}</div>
                                        <div class="wb-msg__bubble">{content}</div>
                                    </div>
                                }.into_any()
                            }
                        }
                    }).collect_view()
                    }
                }}
            </div>

            // Batch review bar when multiple pending (Cursor / OpenAI interruptions array)
            <Show when=move || pending.get().get(1).is_some()>
                <div class="wb-review-bar shrink-0">
                    <span class="text-[12px] text-amber-100">
                        {move || format!("{} proposals awaiting review", pending.get().len())}
                    </span>
                    <button
                        type="button"
                        class="wb-tool-card__btn wb-tool-card__btn--admit"
                        disabled=move || busy.get()
                        on:click={
                            let admit = admit_ids.clone();
                            move |_| {
                                let ids: Vec<String> = pending
                                    .get_untracked()
                                    .iter()
                                    .filter_map(|o| o.get("order_id").and_then(|x| x.as_str()).map(str::to_string))
                                    .collect();
                                admit(ids);
                            }
                        }
                    >"Admit all"</button>
                    <button
                        type="button"
                        class="wb-tool-card__btn"
                        disabled=move || busy.get()
                        on:click={
                            let cancel = cancel_ids.clone();
                            move |_| cancel(vec![])
                        }
                    >"Reject all"</button>
                </div>
            </Show>

            // Sticky composer — industry standard
            <div class="wb-composer shrink-0">
                <div class="wb-composer__chips">
                    <Show when=move || mode.get().is_playground()>
                        <div class="wb-composer__chips">
                            {[
                                ("score", "Score wire"),
                                ("hold", "Hold funds"),
                                ("decide", "Decide"),
                                ("ledger", "Ledger"),
                                ("isolate", "Isolate"),
                                ("prove", "Prove"),
                                ("stop", "Stop"),
                            ]
                                .into_iter()
                                .map(|(verb, label)| {
                                    let run = run_demo.clone();
                                    view! {
                                        <button
                                            type="button"
                                            class="wb-composer__chip wb-composer__chip--verb"
                                            disabled=move || busy.get()
                                            on:click=move |_| run(verb)
                                        >{label}</button>
                                    }
                                })
                                .collect_view()}
                        </div>
                    </Show>
                    {[
                        "Score the $47,500 Cayman wire",
                        "Hold the wire pending review",
                        "Decline the held wire with rationale",
                        "Show the ledger balances",
                        "Who are you?",
                    ]
                        .into_iter()
                        .map(|q| {
                            let q = q.to_string();
                            let label = q.clone();
                            view! {
                                <button
                                    type="button"
                                    class="wb-composer__chip"
                                    disabled=move || busy.get()
                                    on:click=move |_| set_input.set(q.clone())
                                >{label}</button>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="wb-composer__row">
                    <textarea
                        class="wb-composer__input"
                        rows=if matches!(layout, WorkbenchConsultLayout::Full) { 3 } else { 2 }
                        placeholder="Message the agent… tools become reviewable proposals (never auto-run)."
                        prop:value=move || input.get()
                        prop:disabled=move || busy.get()
                        on:input=move |ev| set_input.set(event_target_value(&ev))
                        on:keydown={
                            let send = send.clone();
                            move |ev: web_sys::KeyboardEvent| {
                                if ev.key() == "Enter" && (ev.meta_key() || ev.ctrl_key()) {
                                    ev.prevent_default();
                                    send(input.get_untracked());
                                }
                            }
                        }
                    />
                    <OpButton
                        label="Send".to_string()
                        variant=OpButtonVariant::Primary
                        on_click={
                            let send = send.clone();
                            Arc::new(move |_| {
                                if !busy.get_untracked() {
                                    send(input.get_untracked());
                                }
                            })
                        }
                    />
                    <Show when=move || busy.get()>
                        <OpButton
                            label="Cease".to_string()
                            variant=OpButtonVariant::Ghost
                            on_click=Arc::new(move |_| {
                                if !web_sys::window()
                                    .and_then(|w| {
                                        w.confirm_with_message(
                                            "SpendCease this generation? Fence + void ctx_tok + reap. Cancel tax may remain.",
                                        )
                                        .ok()
                                    })
                                    .unwrap_or(false)
                                {
                                    return;
                                }
                                let pid = pid_sv.get_value();
                                set_busy.set(true);
                                spawn_local(async move {
                                    match iia_api::agent_cease(&pid).await {
                                        Ok(v) => {
                                            if let Some(e) = api::body_error(&v) {
                                                set_err.set(format!("cease failed: {e}"));
                                            } else {
                                                set_ceased.set(true);
                                                set_err.set(
                                                    "ceased — generation fenced; admits dead".into(),
                                                );
                                            }
                                        }
                                        Err(e) => set_err.set(format!("cease failed: {e}")),
                                    }
                                    set_busy.set(false);
                                    set_reload.update(|n| *n += 1);
                                });
                            })
                        />
                    </Show>
                </div>
                <div class="wb-composer__footer">
                    <span>"⌘/Ctrl+Enter to send · Isolate/Govern/Stop/Prove enqueue real Admit orders · Ring-1 until Admit"</span>
                    <button
                        type="button"
                        class="hover:text-zinc-300"
                        on:click=move |_| set_reload.update(|n| *n = n.wrapping_add(1))
                    >"Refresh"</button>
                </div>
            </div>
        </div>
    }
}

#[component]
fn StatusPill(label: Signal<String>, tone: Signal<&'static str>) -> impl IntoView {
    view! {
        <span class=move || {
            match tone.get() {
                "run" => "wb-status-pill wb-status-pill--run",
                "wait" => "wb-status-pill wb-status-pill--wait",
                "block" => "wb-status-pill wb-status-pill--block",
                _ => "wb-status-pill",
            }
        }>
            <span class="wb-status-pill__dot"></span>
            {move || label.get()}
        </span>
    }
}
