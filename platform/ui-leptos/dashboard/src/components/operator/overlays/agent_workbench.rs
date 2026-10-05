//! Agent workbench — Control · Talk · Identity · Charter tabs (Phase E0 shell).

use std::sync::Arc;

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::Value;
use wasm_bindgen::JsCast;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpLoadingBlock};
use crate::components::operator::overlays::acs::OpAcsStrip;
use crate::components::operator::overlays::court_checklist::OpCourtDefensiblePanel;
use crate::components::operator::overlays::intelligence_pack::OpIntelligencePackStrip;
use crate::components::operator::overlays::power_world::OpPowerWorldEditor;
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpText, OpTextVariant};
use crate::components::ui::{DownloadButton, PdfViewer};
use crate::iia_api;
use crate::components::operator::overlays::llm_connect::OpLlmQuickConnect;
use crate::components::operator::overlays::workbench_consult::OpWorkbenchConsult;
use crate::components::operator::overlays::expometer::OpExpometer;
use crate::deployment::use_deployment_mode;
use crate::ui_state::{
    open_topic_drawer, stash_tool_proposals, use_operator_drawer, use_tool_proposals, DrawerTopic,
};
use crate::utils::trigger_download_bytes;

#[derive(Clone, Copy, PartialEq, Eq)]
enum AgentTab {
    Action,
    Control,
    Talk,
    Identity,
    Charter,
    Manage,
    Evidence,
    Data,
}

/// Full agent drawer workbench (Action · Talk · Identity · Charter · Manage).
#[component]
pub fn OpAgentWorkbench(pid: String) -> impl IntoView {
    let drawer = use_operator_drawer();
    let initial = match drawer.tab.get_untracked().as_str() {
        "control" | "overview" | "view" => AgentTab::Control,
        "charter" => AgentTab::Charter,
        "evidence" => AgentTab::Evidence,
        "data" | "library" | "files" => AgentTab::Data,
        "manage" => AgentTab::Manage,
        "identity" => AgentTab::Identity,
        "talk" => AgentTab::Talk,
        _ => AgentTab::Action,
    };
    let (tab, set_tab) = signal(initial);
    let pid_store = StoredValue::new(pid);

    view! {
        <div class="space-y-3 p-4">
            <OpText text=format!("Intelligence {}", pid_store.get_value()) variant=OpTextVariant::Title />
            <p class="text-[11px] text-zinc-500">
                "Action: identity gate → Talk proposals → DAL/PATE → ToolDispatch. Talk does not auto-dispatch."
            </p>
            <OpAcsStrip pid=pid_store.get_value() />
            <OpIntelligencePackStrip pid=pid_store.get_value() />
            <div class="flex flex-wrap gap-1 border-b border-zinc-800/80 pb-2">
                <TabChip label="Action" id=AgentTab::Action tab set_tab />
                <TabChip label="Control" id=AgentTab::Control tab set_tab />
                <TabChip label="Talk" id=AgentTab::Talk tab set_tab />
                <TabChip label="Identity" id=AgentTab::Identity tab set_tab />
                <TabChip label="Charter" id=AgentTab::Charter tab set_tab />
                <TabChip label="Manage" id=AgentTab::Manage tab set_tab />
                <TabChip label="Evidence" id=AgentTab::Evidence tab set_tab />
                <TabChip label="Data" id=AgentTab::Data tab set_tab />
            </div>
            {move || {
                let pid = pid_store.get_value();
                match tab.get() {
                    AgentTab::Action => view! { <ActionTab pid=pid /> }.into_any(),
                    AgentTab::Control => view! { <ControlTab pid=pid /> }.into_any(),
                    AgentTab::Talk => view! { <TalkTab pid=pid /> }.into_any(),
                    AgentTab::Identity => view! { <IdentityTab pid=pid /> }.into_any(),
                    AgentTab::Charter => view! { <CharterTab pid=pid /> }.into_any(),
                    AgentTab::Manage => view! { <ManageTab pid=pid /> }.into_any(),
                    AgentTab::Evidence => view! { <EvidenceTab pid=pid /> }.into_any(),
                    AgentTab::Data => view! { <crate::components::operator::overlays::agent_data_workspace::AgentDataWorkspace pid=pid /> }.into_any(),
                }
            }}
        </div>
    }
}

#[component]
fn TabChip(
    label: &'static str,
    id: AgentTab,
    tab: ReadSignal<AgentTab>,
    set_tab: WriteSignal<AgentTab>,
) -> impl IntoView {
    view! {
        <button
            type="button"
            class=move || {
                if tab.get() == id {
                    "rounded px-2.5 py-1 text-[11px] font-medium bg-zinc-100 text-zinc-900"
                } else {
                    "rounded px-2.5 py-1 text-[11px] font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60"
                }
            }
            on:click=move |_| set_tab.set(id)
        >
            {label}
        </button>
    }
}

#[component]
fn AuditPdfStrip(agent_pid: String) -> impl IntoView {
    view! {
        <div class="rounded-lg border border-violet-800/50 bg-violet-950/25 px-3 py-2 space-y-2">
            <p class="text-[10px] uppercase tracking-wide text-violet-300/90">
                "Audit PDFs — UTC-stamped node workpapers (not CPA attestation)"
            </p>
            <div class="flex flex-wrap gap-2">
                <DownloadButton
                    path=format!("/agents/{agent_pid}/audit/pdf")
                    filename=format!("connector-agent-isolation-{agent_pid}.pdf")
                    mime="application/pdf".to_string()
                    success_toast="Downloaded agent isolation PDF".to_string()
                >
                    "Agent isolation PDF"
                </DownloadButton>
                <DownloadButton
                    path="/compliance/brief/pdf".to_string()
                    filename="connector-compliance-brief.pdf".to_string()
                    mime="application/pdf".to_string()
                    success_toast="Downloaded system brief PDF".to_string()
                >
                    "System brief PDF"
                </DownloadButton>
                <DownloadButton
                    path="/compliance/report/pdf".to_string()
                    filename="connector-compliance-report.pdf".to_string()
                    mime="application/pdf".to_string()
                    success_toast="Downloaded system report PDF".to_string()
                >
                    "System report PDF"
                </DownloadButton>
            </div>
        </div>
    }
}

#[component]
fn ControlTab(pid: String) -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (flash, set_flash) = signal(String::new());
    let (reload, set_reload) = signal(0u32);
    let pid_sv = StoredValue::new(pid.clone());
    let pid_r = pid.clone();
    let recorder = LocalResource::new(move || {
        let pid = pid_r.clone();
        let _ = reload.get();
        async move {
            let crumbs = iia_api::runtime_self(&pid).await.ok();
            let matrix = iia_api::runtime_matrix(&pid).await.ok();
            let activity = iia_api::agent_activity(&pid).await;
            let traces = iia_api::agent_traces(&pid).await;
            let cage = iia_api::agent_cage_runtime(&pid).await;
            let lab = api::get_value("/runtime/lab-mode").await.ok();
            (crumbs, matrix, activity, traces, cage, lab)
        }
    });
    let run = move |action: &'static str| {
        set_busy.set(true);
        let pid = pid_sv.get_value();
        spawn_local(async move {
            let r = iia_api::agent_lifecycle(&pid, action).await;
            set_flash.set(match r {
                Ok(v) => {
                    if let Some(e) = api::body_error(&v) {
                        format!("{action} failed: {e}")
                    } else {
                        format!("{action} ok")
                    }
                }
                Err(e) => format!("{action} failed: {e}"),
            });
            set_busy.set(false);
            set_reload.update(|n| *n += 1);
        });
    };
    view! {
        <div class="space-y-3">
            <OpExpometer pid=pid.clone() reload=reload />
            <AuditPdfStrip agent_pid=pid.clone() />
            <div class="flex flex-wrap gap-2">
                <OpButton
                    label="Start".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| run("start"))
                />
                <OpButton
                    label="Pause".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| run("pause"))
                />
                <OpButton
                    label="Cease (SpendCease)".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        if !web_sys::window()
                            .and_then(|w| {
                                w.confirm_with_message(
                                    "SpendCease: fence this generation, void ctx_tok, reap workers, abort in-flight LLM? (Model desire is irrelevant — admit paths die. Cancel tax may remain on the provider.)",
                                )
                                .ok()
                            })
                            .unwrap_or(false)
                        {
                            return;
                        }
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::agent_cease(&pid).await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("cease failed: {e}")
                                    } else {
                                        let tax = v
                                            .pointer("/spend_cease/cancel_tax_usd_est")
                                            .and_then(|x| x.as_f64())
                                            .map(|t| format!(" · cancel_tax_est ${t:.4}"))
                                            .unwrap_or_default();
                                        let rid = v
                                            .pointer("/spend_cease/receipt_id")
                                            .or_else(|| v.pointer("/spend_cease/cease_id"))
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("ok");
                                        format!("cease ok — {rid}{tax} — admits dead for this generation")
                                    }
                                }
                                Err(e) => format!("cease failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Resume".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| run("resume"))
                />
                <OpButton
                    label="Freeze".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        if !web_sys::window()
                            .and_then(|w| {
                                w.confirm_with_message(
                                    "Freeze agent (persist snapshot)? Use Thaw to restore.",
                                )
                                .ok()
                            })
                            .unwrap_or(false)
                        {
                            return;
                        }
                        run("freeze");
                    })
                />
                <OpButton
                    label="Thaw".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| run("thaw"))
                />
                <OpButton
                    label="Activate".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::activate(&pid).await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("activate failed: {e}")
                                    } else {
                                        "activate ok — Talk/setup gate cleared if charter complete"
                                            .into()
                                    }
                                }
                                Err(e) => format!("activate failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Signal Suspend".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::agent_signal(
                                &pid,
                                "Suspend",
                                "operator Control tab",
                            )
                            .await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("signal failed: {e}")
                                    } else {
                                        "signal Suspend ok".into()
                                    }
                                }
                                Err(e) => format!("signal failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Interrupt Talk (AIOS)".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::aios_operate(
                                "interrupt",
                                &pid,
                                serde_json::json!({}),
                            )
                            .await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("interrupt failed: {e}")
                                    } else {
                                        "AIOS interrupt ok — in-flight Talk cut".into()
                                    }
                                }
                                Err(e) => format!("interrupt failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Compress context".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::context_compress(&pid).await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("compress failed: {e}")
                                    } else {
                                        "context compress ok".into()
                                    }
                                }
                                Err(e) => format!("compress failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Quarantine (brain)".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        if !web_sys::window()
                            .and_then(|w| {
                                w.confirm_with_message(
                                    "Quarantine this agent brain/broker? Talk will return 499 until Fix HITL approve.",
                                )
                                .ok()
                            })
                            .unwrap_or(false)
                        {
                            return;
                        }
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::agent_quarantine(
                                &pid,
                                "operator Control tab — agent brain / broker quarantine",
                            )
                            .await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("quarantine failed: {e}")
                                    } else {
                                        let hitl = v
                                            .get("quarantine_hitl_id")
                                            .or_else(|| v.pointer("/data/quarantine_hitl_id"))
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("");
                                        if hitl.is_empty() {
                                            "quarantine ok — open Fix and Approve unquarantine (Talk stays 499)".into()
                                        } else {
                                            format!(
                                                "quarantine ok — HITL {hitl}; Approve on Fix/Manage (not direct Unquarantine)"
                                            )
                                        }
                                    }
                                }
                                Err(e) => format!("quarantine failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Approve unquarantine HITL".to_string()
                    variant=OpButtonVariant::Primary
                    on_click=Arc::new(move |_| {
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::approve_unquarantine_hitl(&pid, "").await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("HITL approve failed: {e}")
                                    } else {
                                        "HITL approved — Talk resumes on new broker epoch (HTTP 200)".into()
                                    }
                                }
                                Err(e) => format!("HITL approve failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Force unquarantine (admin)".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        if !web_sys::window()
                            .and_then(|w| {
                                w.confirm_with_message(
                                    "Admin force unquarantine? Prefer Fix HITL Approve when available.",
                                )
                                .ok()
                            })
                            .unwrap_or(false)
                        {
                            return;
                        }
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::agent_unquarantine_force(&pid).await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("force unquarantine failed: {e}")
                                    } else {
                                        "force unquarantine ok — Talk 200 new epoch".into()
                                    }
                                }
                                Err(e) => format!("force unquarantine failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Kill".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        if !web_sys::window()
                            .and_then(|w| {
                                w.confirm_with_message("Kill this agent process?")
                                    .ok()
                            })
                            .unwrap_or(false)
                        {
                            return;
                        }
                        run("kill");
                    })
                />
                <OpButton
                    label="Kill-switch".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        if !web_sys::window()
                            .and_then(|w| {
                                w.confirm_with_message(
                                    "Kill-switch: interrupt in-flight Talk then kill?",
                                )
                                .ok()
                            })
                            .unwrap_or(false)
                        {
                            return;
                        }
                        set_busy.set(true);
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let r = iia_api::agent_kill_switch(&pid).await;
                            set_flash.set(match r {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        format!("kill-switch failed: {e}")
                                    } else {
                                        "kill-switch ok — Talk interrupted then killed".into()
                                    }
                                }
                                Err(e) => format!("kill-switch failed: {e}"),
                            });
                            set_busy.set(false);
                            set_reload.update(|n| *n += 1);
                        });
                    })
                />
                <OpButton
                    label="Refresh recorder".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| set_reload.update(|n| *n += 1))
                />
            </div>
            <p class="text-[10px] text-zinc-500">
                "Brain quarantine ≠ TraceTramp traffic quarantine. Unquarantine requires Fix HITL Approve (or admin Force). Cease fences the generation (SpendCease); Kill-switch interrupts Talk then kills. Pause may also trigger Cease server-side."
            </p>
            <p class="text-xs text-zinc-400">{move || flash.get()}</p>
            <Show when=move || busy.get()>
                <p class="text-[11px] text-zinc-500">"Working…"</p>
            </Show>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading activity…".to_string() /> }>
                {move || Suspend::new(async move {
                    let (crumbs, matrix, activity_r, traces_r, cage_r, lab) = recorder.await;
                    let crumb_line = format_intelligence_crumbs(crumbs.as_ref(), matrix.as_ref());
                    let lab_on = lab
                        .as_ref()
                        .and_then(|v| v.get("lab_mode").and_then(|x| x.as_bool()))
                        .unwrap_or(false);
                    let activity_raw = match &activity_r {
                        Ok(v) => serde_json::to_string_pretty(v).unwrap_or_default(),
                        Err(e) => format!("activity unavailable: {e}"),
                    };
                    let traces_raw = match &traces_r {
                        Ok(v) => serde_json::to_string_pretty(v).unwrap_or_default(),
                        Err(e) => format!("traces unavailable: {e}"),
                    };
                    let trace_strip = match &traces_r {
                        Ok(v) => format_trace_strip(v),
                        Err(_) => Vec::new(),
                    };
                    let cage_raw = match &cage_r {
                        Ok(v) => serde_json::to_string_pretty(v).unwrap_or_default(),
                        Err(e) => format!("cage-runtime unavailable: {e}"),
                    };
                    view! {
                        <div class="space-y-2">
                            <Show when=move || lab_on>
                                <div class="rounded border border-amber-700/70 bg-amber-950/80 px-2 py-1.5 text-[11px] text-amber-100">
                                    <span class="font-semibold tracking-wide">"LAB MODE"</span>
                                    " — intelligence hardening off on this node. Use shell banner → Enable intelligence hardening."
                                </div>
                            </Show>
                            <div class="rounded border border-zinc-800/60 bg-zinc-900/40 px-2 py-1.5">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                    "Intelligence crumbs"
                                </p>
                                <p class="mt-0.5 font-mono text-[10px] text-zinc-300">{crumb_line}</p>
                            </div>
                            <div class="flex flex-wrap gap-2 items-center">
                                <a
                                    class="rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-300 hover:border-violet-600 hover:text-zinc-100"
                                    href="/plugins/tracetramp"
                                >
                                    "Open TraceTramp"
                                </a>
                                <DownloadButton
                                    path=format!("/agents/{}/audit/pdf", pid_sv.get_value())
                                    filename=format!(
                                        "connector-agent-isolation-{}.pdf",
                                        pid_sv.get_value()
                                    )
                                    mime="application/pdf".to_string()
                                >
                                    "Agent isolation PDF"
                                </DownloadButton>
                                <DownloadButton
                                    path="/compliance/brief/pdf".to_string()
                                    filename="connector-compliance-brief.pdf".to_string()
                                    mime="application/pdf".to_string()
                                >
                                    "System brief PDF"
                                </DownloadButton>
                            </div>
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-cyan-500/90">
                                "Cage / runtime (≠ audit)"
                            </p>
                            <pre class="max-h-40 overflow-y-auto whitespace-pre-wrap rounded border border-cyan-900/40 bg-cyan-950/20 p-2 text-[10px] font-mono text-cyan-100/80">{cage_raw}</pre>
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                "WATCH · agent activity (kernel audit)"
                            </p>
                            <pre class="max-h-36 overflow-y-auto whitespace-pre-wrap rounded border border-zinc-800/50 p-2 text-[10px] font-mono text-zinc-400">{activity_raw}</pre>
                            <div class="flex items-center justify-between gap-2">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-violet-400/90">
                                    "TraceTramp · AI actions strip"
                                </p>
                                <span class="text-[10px] text-zinc-600">"GET /agents/:pid/traces"</span>
                            </div>
                            {
                                let strip = trace_strip.clone();
                                (!strip.is_empty()).then(|| view! {
                                    <ul class="space-y-1 rounded border border-violet-900/40 bg-violet-950/20 p-2">
                                        {strip.into_iter().map(|line| {
                                            view! {
                                                <li class="font-mono text-[10px] text-violet-100/85">{line}</li>
                                            }
                                        }).collect_view()}
                                    </ul>
                                })
                            }
                            <pre class="max-h-36 overflow-y-auto whitespace-pre-wrap rounded border border-zinc-800/50 p-2 text-[10px] font-mono text-zinc-400">{traces_raw}</pre>
                        </div>
                    }.into_any()
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn IdentityTab(pid: String) -> impl IntoView {
    let pid_r = pid.clone();
    let pid_stack = pid.clone();
    let resource = LocalResource::new(move || {
        let pid = pid_r.clone();
        async move { iia_api::identity_envelope(&pid).await }
    });
    let stack = LocalResource::new(move || {
        let pid = pid_stack.clone();
        async move {
            api::get_value(&format!(
                "/kernel/identity-stack?agent_pid={pid}&op=tool.dispatch"
            ))
            .await
        }
    });
    view! {
        <div class="space-y-3">
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading identity stack…".to_string() /> }>
                {move || Suspend::new(async move {
                    match stack.await {
                        Ok(v) => {
                            let src = api::resource_object(&v);
                            let miss: Vec<String> = src
                                .get("missing")
                                .and_then(|m| m.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_str().map(str::to_string))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let address = src
                                .get("address")
                                .and_then(|x| x.as_str())
                                .unwrap_or("—")
                                .to_string();
                            let enforced = src
                                .get("enforced")
                                .or_else(|| src.get("identity_stack_enforced"))
                                .and_then(|x| x.as_bool());
                            view! {
                                <section class="rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-3 space-y-2">
                                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                        "Identity stack · tool.dispatch"
                                    </p>
                                    <p class="font-mono text-[11px] text-zinc-400">{format!("address={address}")}</p>
                                    <p class="text-[11px] text-zinc-500">
                                        {match enforced {
                                            Some(true) => "Enforced on this node.",
                                            Some(false) => "Not enforced (playground / soft).",
                                            None => "Enforcement flag unavailable.",
                                        }}
                                    </p>
                                    {if miss.is_empty() {
                                        view! {
                                            <p class="text-xs text-emerald-300/90">"No missing pillars for this inspect."</p>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <div class="rounded border border-amber-800/50 bg-amber-950/30 px-2.5 py-2">
                                                <p class="text-xs text-amber-100">
                                                    {format!("Missing: {}", miss.join(", "))}
                                                </p>
                                                <p class="mt-1 text-[11px] text-amber-200/80">
                                                    "Augmented tools stay denied until character, last memory, address graph, RULES, and HITL exist — or a digest-bound HITL approves one action."
                                                </p>
                                                <a class="mt-2 inline-block text-[11px] text-indigo-400 hover:underline" href="/setup/access">
                                                    "Mint DAC RULES + HITL →"
                                                </a>
                                            </div>
                                        }.into_any()
                                    }}
                                    <details>
                                        <summary class="cursor-pointer text-[10px] text-zinc-500">"Raw GET /kernel/identity-stack"</summary>
                                        <pre class="mt-1 max-h-40 overflow-auto font-mono text-[10px] text-zinc-500">
                                            {serde_json::to_string_pretty(&v).unwrap_or_default()}
                                        </pre>
                                    </details>
                                </section>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading identity envelope…".to_string() /> }>
                {move || Suspend::new(async move {
                    match resource.await {
                        Ok(v) => {
                            let who = extract_who(&v);
                            let principal = pointer_str(&v, &[
                                "/data/envelope/base/principal/principal_id",
                                "/envelope/base/principal/principal_id",
                                "/data/principal/principal_id",
                                "/principal/principal_id",
                            ]).unwrap_or_else(|| "—".into());
                            view! {
                                <div class="space-y-3">
                                    <section class="rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-3">
                                        <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                            "Who am I (kernel)"
                                        </p>
                                        <pre class="mt-2 whitespace-pre-wrap text-[11px] leading-relaxed text-zinc-200 font-mono">{who}</pre>
                                    </section>
                                    <p class="text-xs font-mono text-zinc-400">{principal}</p>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
#[allow(dead_code)]
fn LlmReadyHint() -> impl IntoView {
    let status = LocalResource::new(|| api::get_value_timeout("/settings/llms/status", 5_000));
    view! {
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                match status.await {
                    Ok(v) => {
                        let wired = v.get("router_wired").and_then(|x| x.as_bool()).unwrap_or(false);
                        let stub = v.get("stub_mode").and_then(|x| x.as_bool()).unwrap_or(false);
                        if wired {
                            let prov = v.get("provider").and_then(|x| x.as_str()).unwrap_or("llm");
                            let modl = v.get("model").and_then(|x| x.as_str()).unwrap_or("");
                            view! {
                                <p class="rounded border border-emerald-800/40 bg-emerald-950/20 px-2 py-1 text-[11px] text-emerald-100/90">
                                    {format!("Talk router wired · {prov} {modl}")}
                                </p>
                            }.into_any()
                        } else {
                            view! {
                                <button
                                    type="button"
                                    class="w-full rounded border border-amber-800/50 bg-amber-950/30 px-2.5 py-1.5 text-left text-[11px] text-amber-100/90 hover:border-amber-600"
                                    on:click=move |_| open_topic_drawer(DrawerTopic::Settings("llm".into()))
                                >
                                    {if stub {
                                        "Stub mode — connect an LLM key to Talk for real completions."
                                    } else {
                                        "No LLM linked — open Settings → LLM routing to paste a vault key."
                                    }}
                                </button>
                            }.into_any()
                        }
                    }
                    Err(_) => ().into_any(),
                }
            })}
        </Suspense>
    }
}

#[component]
fn GapBanner(code: &'static str, text: &'static str) -> impl IntoView {
    view! {
        <div class="rounded border border-amber-800/50 bg-amber-950/30 px-2.5 py-1.5 text-[11px] text-amber-100/90">
            <span class="font-mono text-amber-300/90">{code}</span>
            " — "
            {text}
        </div>
    }
}

#[component]
fn CharterTab(pid: String) -> impl IntoView {
    // S1 purpose / identity
    let (name, set_name) = signal(String::new());
    let (acume, set_acume) = signal(String::new());
    let (purpose, set_purpose) = signal(String::new());
    // S2 contract cage
    let (cap_text, set_cap_text) = signal(String::new());
    let (denied_text, set_denied_text) = signal(String::new());
    let (fs_read, set_fs_read) = signal(String::new());
    let (fs_write, set_fs_write) = signal(String::new());
    let (net_allow, set_net_allow) = signal(String::new());
    let (net_default, set_net_default) = signal("deny".to_string());
    let (receipt_req, set_receipt_req) = signal("true".to_string());
    // S3–S5
    let (hitl, set_hitl) = signal("none".to_string());
    let (forensic, set_forensic) = signal("off".to_string());
    let (mem_types, set_mem_types) = signal(
        "working,episodic,semantic,procedural,reflective,social,prospective".to_string(),
    );
    // S6 grants — one path; readable_by CSV (includes self)
    let (grant_path, set_grant_path) = signal(String::new());
    let (grant_readers, set_grant_readers) = signal(String::new());
    let (flash, set_flash) = signal(String::new());
    let pid_sv = StoredValue::new(pid.clone());

    let pid_load = pid.clone();
    let resource = LocalResource::new(move || {
        let pid = pid_load.clone();
        async move {
            let c = iia_api::agent_contract(&pid).await;
            let s = iia_api::agent_setup(&pid).await;
            (c, s)
        }
    });

    let studio_href = format!("/agents/{}/charter", pid);
    view! {
        <div class="space-y-3">
            <GapBanner
                code="charter_studio"
                text="Drawer edits S1–S6 + Activate. Full stage rail (S9 institutions, S10–S11 review) is on Charter Studio."
            />
            <a
                class="inline-block rounded border border-zinc-700/80 px-2.5 py-1 text-[11px] text-zinc-200 hover:bg-zinc-800/60"
                href=studio_href
            >
                "Open Charter Studio →"
            </a>
            <OpPowerWorldEditor pid=pid.clone() />
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading charter…".to_string() /> }>
                {move || Suspend::new(async move {
                    let (contract_r, setup_r) = resource.await;
                    if let Ok(ref c) = contract_r {
                        let contract = c.get("contract")
                            .or_else(|| c.pointer("/data/contract"))
                            .unwrap_or(c);
                        if cap_text.get_untracked().is_empty() {
                            set_cap_text.set(join_str_array(contract.get("capabilities")));
                            set_denied_text.set(join_str_array(contract.get("denied_operations")));
                            set_purpose.set(join_str_array(contract.get("purpose")));
                            set_fs_read.set(join_str_array(contract.get("filesystem_read")));
                            set_fs_write.set(join_str_array(contract.get("filesystem_write")));
                            set_net_allow.set(join_str_array(contract.get("network_allow")));
                            if let Some(nd) = contract.get("network_default").and_then(|v| v.as_str()) {
                                set_net_default.set(nd.to_string());
                            }
                            if let Some(rr) = contract.get("receipt_required").and_then(|v| v.as_bool()) {
                                set_receipt_req.set(if rr { "true" } else { "false" }.into());
                            }
                        }
                    }
                    if let Ok(ref s) = setup_r {
                        let setup = s.get("setup").or_else(|| s.pointer("/data/setup")).unwrap_or(s);
                        if name.get_untracked().is_empty() {
                            if let Some(n) = setup.get("name").and_then(|v| v.as_str()) {
                                set_name.set(n.to_string());
                            }
                            if let Some(a) = setup.get("acume").and_then(|v| v.as_str()) {
                                set_acume.set(a.to_string());
                            }
                            if let Some(h) = setup.get("hitl_policy").and_then(|v| v.as_str()) {
                                set_hitl.set(h.to_string());
                            }
                            if let Some(f) = setup.get("forensic_profile").and_then(|v| v.as_str()) {
                                set_forensic.set(f.to_string());
                            }
                            if let Some(mt) = setup.pointer("/memory_profile/enabled_types") {
                                set_mem_types.set(join_str_array(Some(mt)));
                            }
                            if let Some(spaces) = setup.get("common_spaces").and_then(|v| v.as_array()) {
                                if let Some(g0) = spaces.first() {
                                    if let Some(p) = g0.get("path").and_then(|x| x.as_str()) {
                                        set_grant_path.set(p.to_string());
                                    }
                                    set_grant_readers.set(join_str_array(g0.get("readable_by")));
                                }
                            }
                        }
                    }
                    view! {
                        <div class="space-y-4">
                            <section class="space-y-2">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"S1 · Purpose"</p>
                                <Field label="Display name" value=name on_input=set_name />
                                <Field label="Acume (role identity)" value=acume on_input=set_acume />
                                <Field label="Purpose tags (comma)" value=purpose on_input=set_purpose />
                            </section>
                            <section class="space-y-2">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"S2 · Contract cage"</p>
                                <Field label="Capabilities" value=cap_text on_input=set_cap_text />
                                <Field label="Denied operations" value=denied_text on_input=set_denied_text />
                                <Field label="Filesystem read (globs)" value=fs_read on_input=set_fs_read />
                                <Field label="Filesystem write (globs)" value=fs_write on_input=set_fs_write />
                                <Field label="Network allow" value=net_allow on_input=set_net_allow />
                                <SelectField label="Network default" value=net_default on_change=set_net_default
                                    options=&["deny", "allow"] />
                                <SelectField label="Receipt required" value=receipt_req on_change=set_receipt_req
                                    options=&["true", "false"] />
                            </section>
                            <section class="space-y-2">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"S3–S5 · HITL · Forensic · Memory"</p>
                                <SelectField label="HITL policy" value=hitl on_change=set_hitl
                                    options=&["none", "egress", "tool", "export", "all_material"] />
                                <SelectField label="Forensic profile" value=forensic on_change=set_forensic
                                    options=&["off", "standard", "soc2", "hipaa", "court"] />
                                <Field label="Memory types (comma)" value=mem_types on_input=set_mem_types />
                            </section>
                            <section class="space-y-2">
                                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"S6 · Grants"</p>
                                <Field label="Common space path" value=grant_path on_input=set_grant_path />
                                <Field label="Readable by (pids, comma)" value=grant_readers on_input=set_grant_readers />
                            </section>
                            <div class="flex flex-wrap gap-2">
                                <OpButton label="Save contract".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        let body = serde_json::json!({
                                            "purpose": split_csv(&purpose.get()),
                                            "capabilities": split_csv(&cap_text.get()),
                                            "denied_operations": split_csv(&denied_text.get()),
                                            "filesystem_read": split_csv(&fs_read.get()),
                                            "filesystem_write": split_csv(&fs_write.get()),
                                            "network_allow": split_csv(&net_allow.get()),
                                            "network_default": net_default.get(),
                                            "receipt_required": receipt_req.get() == "true",
                                        });
                                        spawn_local(async move {
                                            match iia_api::patch_contract(&pid, body).await {
                                                Ok(v) => {
                                                    let nr = v.get("needs_reactivate").and_then(|x| x.as_bool()).unwrap_or(false);
                                                    set_flash.set(format!("contract saved (needs_reactivate={nr})"));
                                                }
                                                Err(e) => set_flash.set(format!("contract error: {e}")),
                                            }
                                        });
                                    }) />
                                <OpButton label="Save setup".to_string() variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        let mut readers = split_csv(&grant_readers.get());
                                        if !readers.iter().any(|r| r == &pid) {
                                            readers.push(pid.clone());
                                        }
                                        let path = grant_path.get();
                                        let common_spaces = if path.trim().is_empty() {
                                            serde_json::json!([])
                                        } else {
                                            serde_json::json!([{
                                                "grant_id": format!("ng_ui_{}", &pid[..pid.len().min(8)]),
                                                "path": path,
                                                "readable_by": readers,
                                                "writable_by": [pid.clone()],
                                            }])
                                        };
                                        let body = serde_json::json!({
                                            "name": name.get(),
                                            "acume": acume.get(),
                                            "hitl_policy": hitl.get(),
                                            "forensic_profile": forensic.get(),
                                            "setup_complete": true,
                                            "memory_profile": {
                                                "default_memory_type": "working",
                                                "quota_tier": "standard",
                                                "enabled_types": split_csv(&mem_types.get()),
                                            },
                                            "common_spaces": common_spaces,
                                        });
                                        spawn_local(async move {
                                            match iia_api::post_setup(&pid, body).await {
                                                Ok(_) => set_flash.set("setup saved".into()),
                                                Err(e) => set_flash.set(format!("setup error: {e}")),
                                            }
                                        });
                                    }) />
                                <OpButton label="Activate".to_string() variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        spawn_local(async move {
                                            match iia_api::activate(&pid).await {
                                                Ok(v) => {
                                                    let hint = v.pointer("/activation/witnessctl_session_hint")
                                                        .or_else(|| v.pointer("/data/activation/witnessctl_session_hint"))
                                                        .and_then(|x| x.as_str())
                                                        .unwrap_or("");
                                                    set_flash.set(format!("activated {hint}"));
                                                }
                                                Err(e) => set_flash.set(format!("activate error: {e}")),
                                            }
                                        });
                                    }) />
                            </div>
                            <p class="text-xs text-zinc-300">{move || flash.get()}</p>
                        </div>
                    }.into_any()
                })}
            </Suspense>
        </div>
    }
}

fn format_chat_thread_log(thread: &serde_json::Value) -> String {
    thread
        .get("turns")
        .or_else(|| thread.pointer("/thread/turns"))
        .and_then(|t| t.as_array())
        .map(|turns| {
            turns
                .iter()
                .filter_map(|t| {
                    let role = t.get("role")?.as_str()?;
                    let content = t.get("content")?.as_str()?;
                    let label = if role.eq_ignore_ascii_case("user") {
                        "you"
                    } else if role.eq_ignore_ascii_case("assistant") {
                        "agent"
                    } else {
                        role
                    };
                    Some(format!("{label}: {content}"))
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

#[component]
fn ActionTab(pid: String) -> impl IntoView {
    let proposals = use_tool_proposals();
    let (goal, set_goal) = signal(String::new());
    let (run_id, set_run_id) = signal(String::new());
    let (log, set_log) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (stack_json, set_stack_json) = signal(String::new());
    let (missing, set_missing) = signal(String::new());
    let (verdict, set_verdict) = signal(String::new());
    let (calls_edit, set_calls_edit) = signal(String::new());
    let pid_sv = StoredValue::new(pid);

    // Prefill from Talk proposals bus when this agent matches.
    Effect::new(move |_| {
        let pid = pid_sv.get_value();
        let bus_pid = proposals.agent_pid.get();
        let raw = proposals.proposals_json.get();
        if !raw.is_empty() && (bus_pid.is_empty() || bus_pid == pid) {
            set_calls_edit.set(raw);
        }
    });

    Effect::new(move |_| {
        let pid = pid_sv.get_value();
        spawn_local(async move {
            let q = format!("/kernel/identity-stack?agent_pid={pid}&op=tool.dispatch");
            match api::get_value(&q).await {
                Ok(v) => {
                    let src = api::resource_object(&v);
                    let miss = src
                        .get("missing")
                        .and_then(|m| m.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    set_missing.set(miss);
                    set_stack_json.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                }
                Err(e) => set_stack_json.set(e.message),
            }
        });
    });

    view! {
        <div class="space-y-3">
            <div class="rounded-lg border border-zinc-800/70 bg-zinc-900/40 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Identity stack (tool.dispatch)"</p>
                <Show when=move || !missing.get().is_empty()>
                    <p class="mt-1 text-xs text-amber-200">
                        {move || format!("Missing: {} — mint in SETUP / Access before tools run.", missing.get())}
                    </p>
                    <a class="mt-1 inline-block text-[11px] text-indigo-400 hover:underline" href="/setup/access">"Open SETUP → Access"</a>
                </Show>
                <Show when=move || missing.get().is_empty()>
                    <p class="mt-1 text-xs text-emerald-300/90">"No missing pillars reported for this inspect (empty missing[])."</p>
                </Show>
                <details class="mt-2">
                    <summary class="cursor-pointer text-[10px] text-zinc-500">"Raw inspect"</summary>
                    <pre class="mt-1 max-h-40 overflow-auto font-mono text-[10px] text-zinc-500">{move || stack_json.get()}</pre>
                </details>
            </div>
            <p class="text-[11px] text-zinc-400">
                "Talk never auto-dispatches. Paste or load tool_calls here → DAL turn → PATE Allow/Ask/Block. Ask → FIX."
            </p>
            <label class="block text-xs text-zinc-400">
                "Goal"
                <input
                    class="mt-1 w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200"
                    prop:value=move || goal.get()
                    on:input=move |ev| set_goal.set(event_target_value(&ev))
                    placeholder="What should this agent attempt?"
                />
            </label>
            <label class="block text-xs text-zinc-400">
                "tool_calls JSON (proposals only)"
                <textarea
                    class="mt-1 min-h-[100px] w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-[11px] text-zinc-200"
                    prop:value=move || calls_edit.get()
                    on:input=move |ev| set_calls_edit.set(event_target_value(&ev))
                    placeholder="[{\"id\":\"call_1\",\"function\":{\"name\":\"…\",\"arguments\":\"{}\"}}]"
                />
            </label>
            <Show when=move || !verdict.get().is_empty()>
                <p class="rounded border border-indigo-800/40 bg-indigo-950/30 px-2 py-1.5 text-[11px] text-indigo-100">
                    {move || verdict.get()}
                </p>
            </Show>
            <div class="flex flex-wrap gap-2">
                <OpButton
                    label="Start DAL run".to_string()
                    variant=OpButtonVariant::Primary
                    loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        let g = goal.get_untracked().trim().to_string();
                        if g.is_empty() {
                            set_log.set("Goal required.".into());
                            return;
                        }
                        if !missing.get_untracked().is_empty() {
                            set_log.set(format!(
                                "Identity stack incomplete ({}) — tools will be refused until mint or digest HITL.",
                                missing.get_untracked()
                            ));
                        }
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value(
                                "/dal/start",
                                serde_json::json!({ "agent_vid": pid, "goal": g }),
                            )
                            .await
                            {
                                Ok(v) => {
                                    let rid = v
                                        .pointer("/run/run_id")
                                        .or_else(|| v.pointer("/data/run/run_id"))
                                        .or_else(|| v.get("run").and_then(|r| r.get("run_id")))
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    set_run_id.set(rid.clone());
                                    set_log.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                                    set_verdict.set(if rid.is_empty() {
                                        "DAL start returned no run_id".into()
                                    } else {
                                        format!("Run started · {rid}")
                                    });
                                }
                                Err(e) => {
                                    set_log.set(e.message.clone());
                                    set_verdict.set(e.message);
                                }
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <OpButton
                    label="Admit turn (PATE)".to_string()
                    variant=OpButtonVariant::Secondary
                    loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let rid = run_id.get_untracked();
                        if rid.is_empty() {
                            set_log.set("Start a DAL run first.".into());
                            return;
                        }
                        let raw = calls_edit.get_untracked();
                        let calls: Value = if raw.trim().is_empty() {
                            serde_json::json!([])
                        } else {
                            match serde_json::from_str(&raw) {
                                Ok(v) => v,
                                Err(e) => {
                                    set_log.set(format!("tool_calls JSON invalid: {e}"));
                                    return;
                                }
                            }
                        };
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value(
                                &format!("/dal/{rid}/turn"),
                                serde_json::json!({ "tool_calls": calls }),
                            )
                            .await
                            {
                                Ok(v) => {
                                    set_log.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                                    set_verdict.set(summarize_dal_turn(&v));
                                }
                                Err(e) => {
                                    set_log.set(e.message.clone());
                                    set_verdict.set(e.message);
                                }
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <a class="inline-flex items-center text-[11px] text-indigo-400 hover:underline" href="/fix">"FIX (HITL Ask)"</a>
                <a class="inline-flex items-center text-[11px] text-indigo-400 hover:underline" href="/watch?tab=tools">"WATCH Tools"</a>
            </div>
            <Show when=move || !run_id.get().is_empty()>
                <p class="font-mono text-[11px] text-zinc-400">{move || format!("run_id={}", run_id.get())}</p>
            </Show>
            <pre class="max-h-64 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-[10px] text-zinc-400 whitespace-pre-wrap">{move || log.get()}</pre>
        </div>
    }
}

fn summarize_dal_turn(v: &Value) -> String {
    let src = api::resource_object(v);
    let receipts = src
        .pointer("/run/receipts")
        .or_else(|| src.get("receipts"))
        .or_else(|| src.pointer("/data/receipts"))
        .and_then(|x| x.as_array());
    if let Some(arr) = receipts {
        if arr.is_empty() {
            return "Turn ok · no receipts (empty proposals or all inhibited)".into();
        }
        let mut parts = Vec::new();
        for r in arr {
            let name = r
                .get("tool_name")
                .and_then(|x| x.as_str())
                .unwrap_or("tool");
            let ok = r.get("ok").and_then(|x| x.as_bool());
            let err = r.get("error").and_then(|x| x.as_str()).unwrap_or("");
            let digest = r
                .get("action_digest")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let verdict = match ok {
                Some(true) => "Allow/executed".to_string(),
                Some(false) if err.to_ascii_lowercase().contains("ask")
                    || err.to_ascii_lowercase().contains("hitl") =>
                {
                    format!("AskHitl → FIX · digest={digest}")
                }
                Some(false) => format!("Block/deny · {err}"),
                None => "outcome unknown".into(),
            };
            parts.push(format!("{name}: {verdict}"));
        }
        return parts.join(" · ");
    }
    if src.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return src
            .get("message")
            .or_else(|| src.get("error"))
            .and_then(|x| x.as_str())
            .unwrap_or("turn failed")
            .to_string();
    }
    "Turn response recorded (see JSON)".into()
}

fn extract_tool_calls(v: &Value) -> Vec<Value> {
    let paths = [
        "/choices/0/message/tool_calls",
        "/data/choices/0/message/tool_calls",
        "/message/tool_calls",
        "/tool_calls",
    ];
    for p in paths {
        if let Some(arr) = v.pointer(p).and_then(|x| x.as_array()) {
            if !arr.is_empty() {
                return arr.clone();
            }
        }
    }
    Vec::new()
}

#[component]
fn TalkTab(pid: String) -> impl IntoView {
    let pid_sv = StoredValue::new(pid.clone());
    let session_from_url = web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|search| {
            for part in search.trim_start_matches('?').split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    if k == "session" && !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
            None
        })
        .unwrap_or_default();
    let url_sv = StoredValue::new(session_from_url);
    view! {
        {move || {
            let pid = pid_sv.get_value();
            let focused = crate::ui_state::workbench_session_for(&pid).unwrap_or_default();
            let from_url = url_sv.get_value();
            let session_id_prop = if !from_url.is_empty() {
                from_url
            } else {
                focused
            };
            // Re-read bus so theater session switches refresh drawer Talk.
            if let Some(bus) = crate::ui_state::use_workbench_focus() {
                let _ = bus.session_id.get();
                let _ = bus.agent_pid.get();
            }
            view! {
                <OpWorkbenchConsult pid=pid session_id_prop=session_id_prop />
            }.into_any()
        }}
    }
}

#[component]
fn ManageTab(pid: String) -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (action, set_action) = signal("review".to_string());
    let (desc, set_desc) = signal(String::new());
    let (grantee, set_grantee) = signal(String::new());
    let (grant_ns, set_grant_ns) = signal(String::new());
    let (grant_perms, set_grant_perms) = signal("read".to_string());
    let (grant_why, set_grant_why) = signal(String::new());
    let (grant_root, set_grant_root) = signal(String::new());
    let (task_to, set_task_to) = signal(String::new());
    let (task_msg, set_task_msg) = signal(String::new());
    let (flash, set_flash) = signal(String::new());
    let pid_sv = StoredValue::new(pid.clone());

    let pid_load = pid.clone();
    let resource = LocalResource::new(move || {
        let pid = pid_load.clone();
        let _ = reload.get();
        async move {
            let pending = iia_api::hitl_pending(&pid).await;
            let caps = iia_api::capabilities(&pid).await.ok();
            let grants = iia_api::list_grants(&pid).await.ok();
            let knot = iia_api::knot_summary(&pid).await.ok();
            (pending, caps, grants, knot)
        }
    });

    view! {
        <div class="space-y-3">
            <p class="text-[11px] text-zinc-400">
                "Manage — HITL, clearance/trust, policy check, inter-intelligence grants (DI-4), knot peek."
            </p>
            <div class="space-y-2 rounded border border-zinc-800/60 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                    "Governance (mounted agent APIs)"
                </p>
                <div class="flex flex-wrap gap-2">
                    <OpButton
                        label="Clearance → protected".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::agent_set_clearance(&pid, "protected").await {
                                    Ok(v) => {
                                        if let Some(e) = api::body_error(&v) {
                                            set_flash.set(e);
                                        } else {
                                            set_flash.set("clearance → protected".into());
                                        }
                                    }
                                    Err(e) => set_flash.set(format!("clearance failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Trust → medium".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::agent_set_trust(&pid, "medium").await {
                                    Ok(v) => {
                                        if let Some(e) = api::body_error(&v) {
                                            set_flash.set(e);
                                        } else {
                                            set_flash.set("trust override → medium".into());
                                        }
                                    }
                                    Err(e) => set_flash.set(format!("trust failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Reflect".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::agent_reflect(&pid).await {
                                    Ok(v) => {
                                        if let Some(e) = api::body_error(&v) {
                                            set_flash.set(e);
                                        } else {
                                            set_flash.set(format!(
                                                "reflect: {}",
                                                serde_json::to_string(&v).unwrap_or_default()
                                                    .chars()
                                                    .take(120)
                                                    .collect::<String>()
                                            ));
                                        }
                                    }
                                    Err(e) => set_flash.set(format!("reflect failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Policy check (dry-run)".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::agent_policy_check(
                                    &pid,
                                    serde_json::json!({
                                        "action": "tool.invoke",
                                        "resource": "default",
                                    }),
                                )
                                .await
                                {
                                    Ok(v) => {
                                        set_flash.set(format!(
                                            "policy: {}",
                                            serde_json::to_string(&v).unwrap_or_default()
                                                .chars()
                                                .take(160)
                                                .collect::<String>()
                                        ));
                                    }
                                    Err(e) => set_flash.set(format!("policy check failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Residency".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::agent_residency(&pid).await {
                                    Ok(v) => {
                                        set_flash.set(format!(
                                            "residency: {}",
                                            serde_json::to_string(&v).unwrap_or_default()
                                                .chars()
                                                .take(160)
                                                .collect::<String>()
                                        ));
                                    }
                                    Err(e) => set_flash.set(format!("residency failed: {e}")),
                                }
                            });
                        })
                    />
                </div>
                <p class="text-[10px] text-zinc-500">
                    "Clearance/trust need admin. Full freeze/migrate/economy stay on Console when rare."
                </p>
            </div>
            <div class="space-y-2 rounded border border-zinc-800/60 p-3">
                <Field label="HITL action" value=action on_input=set_action />
                <Field label="Description" value=desc on_input=set_desc />
                <OpButton
                    label="Create HITL".to_string()
                    variant=OpButtonVariant::Primary
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        let action = action.get();
                        let desc = desc.get();
                        spawn_local(async move {
                            match iia_api::hitl_create(&pid, &action, &desc).await {
                                Ok(v) => {
                                    let id = v.get("request_id").and_then(|x| x.as_str()).unwrap_or("?");
                                    set_flash.set(format!("HITL created: {id}"));
                                    set_reload.update(|n| *n += 1);
                                }
                                Err(e) => set_flash.set(format!("HITL create failed: {e}")),
                            }
                        });
                    })
                />
            </div>
            <div class="space-y-2 rounded border border-zinc-800/60 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                    "Sharing contract → portal (human + root)"
                </p>
                <p class="text-[11px] text-zinc-500">
                    "Agents are isolated. A shared portal is minted only after you justify what, where, and how much."
                </p>
                <Field label="Grantee agent pid" value=grantee on_input=set_grantee />
                <Field label="What (namespace / NS FS path)" value=grant_ns on_input=set_grant_ns />
                <Field label="Permissions (csv)" value=grant_perms on_input=set_grant_perms />
                <Field label="Justification (what, where, how much, why)" value=grant_why on_input=set_grant_why />
                <Field label="Kernel root passcode" value=grant_root on_input=set_grant_root />
                <div class="flex flex-wrap gap-2">
                    <OpButton
                        label="Grant".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let grantor = pid_sv.get_value();
                            let grantee = grantee.get();
                            let ns = grant_ns.get();
                            let perms_raw = grant_perms.get();
                            let why = grant_why.get();
                            let root = grant_root.get();
                            if grantee.trim().is_empty() || ns.trim().is_empty() {
                                set_flash.set("grantee + namespace required".into());
                                return;
                            }
                            if why.trim().len() < 16 {
                                set_flash.set("Justification required (what, where, how much — min 16 chars). Isolated by default.".into());
                                return;
                            }
                            spawn_local(async move {
                                let perms: Vec<&str> = perms_raw
                                    .split([',', ' ', ':'])
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                let perms = if perms.is_empty() { vec!["read"] } else { perms };
                                match iia_api::grant_access(&grantor, &grantee, &ns, &perms, &why, &root).await {
                                    Ok(v) => {
                                        let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                                        set_flash.set(if ok {
                                            format!(
                                                "portal {} · {grantee} → {ns}",
                                                v.get("portal_id").and_then(|x| x.as_str()).unwrap_or("ok")
                                            )
                                        } else {
                                            format!("grant failed: {}", v)
                                        });
                                        set_reload.update(|n| *n += 1);
                                    }
                                    Err(e) => set_flash.set(format!("grant failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Revoke".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let revoker = pid_sv.get_value();
                            let target = grantee.get();
                            let ns = grant_ns.get();
                            if target.trim().is_empty() || ns.trim().is_empty() {
                                set_flash.set("grantee + namespace required".into());
                                return;
                            }
                            spawn_local(async move {
                                match iia_api::revoke_access(&revoker, &target, &ns).await {
                                    Ok(v) => {
                                        let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                                        set_flash.set(if ok {
                                            format!("revoked {target} ← {ns}")
                                        } else {
                                            format!("revoke failed: {}", v)
                                        });
                                        set_reload.update(|n| *n += 1);
                                    }
                                    Err(e) => set_flash.set(format!("revoke failed: {e}")),
                                }
                            });
                        })
                    />
                </div>
            </div>
            <div class="space-y-2 rounded border border-zinc-800/60 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                    "Dispatch task (charter + grant)"
                </p>
                <Field label="To agent pid" value=task_to on_input=set_task_to />
                <Field label="Message" value=task_msg on_input=set_task_msg />
                <OpButton
                    label="Dispatch".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        let from = pid_sv.get_value();
                        let to = task_to.get();
                        let msg = task_msg.get();
                        let ns = grant_ns.get();
                        if to.trim().is_empty() || msg.trim().is_empty() {
                            set_flash.set("to pid + message required".into());
                            return;
                        }
                        spawn_local(async move {
                            match iia_api::dispatch_task(&from, &to, &ns, &msg).await {
                                Ok(v) => {
                                    let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                                    let tid = v
                                        .get("task_id")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("?");
                                    set_flash.set(if ok {
                                        format!("task queued: {tid}")
                                    } else {
                                        format!("dispatch failed: {}", v)
                                    });
                                    set_reload.update(|n| *n += 1);
                                }
                                Err(e) => set_flash.set(format!("dispatch failed: {e}")),
                            }
                        });
                    })
                />
            </div>
            <p class="text-xs text-zinc-300">{move || flash.get()}</p>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading manage…".to_string() /> }>
                {move || Suspend::new(async move {
                    let (pending_r, caps, grants, knot) = resource.await;
                    let pending_list = pending_r
                        .as_ref()
                        .ok()
                        .and_then(|v| v.get("pending").and_then(|p| p.as_array()).cloned())
                        .unwrap_or_default();
                    let pid_for_btns = pid_sv.get_value();
                    view! {
                        <div class="space-y-2">
                            <p class="text-[10px] uppercase text-zinc-500">
                                {format!("Pending HITL ({})", pending_list.len())}
                            </p>
                            {if pending_list.is_empty() {
                                view! { <p class="text-xs text-zinc-500">"No pending requests."</p> }.into_any()
                            } else {
                                pending_list.into_iter().map(|row| {
                                    let id = row.get("request_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                    let action = row.get("action").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                    let description = row.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                    let pid_a = pid_for_btns.clone();
                                    let pid_d = pid_for_btns.clone();
                                    let id_a = id.clone();
                                    let id_d = id.clone();
                                    view! {
                                        <div class="rounded border border-zinc-800/50 bg-zinc-900/40 p-2 text-xs">
                                            <p class="font-mono text-zinc-300">{id}</p>
                                            <p class="text-zinc-400">{format!("{action} — {description}")}</p>
                                            <div class="mt-2 flex gap-2">
                                                <OpButton
                                                    label="Approve".to_string()
                                                    variant=OpButtonVariant::Secondary
                                                    on_click=Arc::new(move |_| {
                                                        let pid = pid_a.clone();
                                                        let id = id_a.clone();
                                                        spawn_local(async move {
                                                            match iia_api::hitl_approve(&pid, &id).await {
                                                                Ok(v) => {
                                                                    if let Some(e) = api::body_error(&v) {
                                                                        set_flash.set(e);
                                                                    } else {
                                                                        let action = v
                                                                            .get("action")
                                                                            .and_then(|x| x.as_str())
                                                                            .unwrap_or("");
                                                                        set_flash.set(if action == "unquarantine" {
                                                                            "approved — Talk resumes HTTP 200 on new broker epoch".into()
                                                                        } else {
                                                                            format!("approved ({action})")
                                                                        });
                                                                        set_reload.update(|n| *n += 1);
                                                                    }
                                                                }
                                                                Err(e) => set_flash.set(format!("approve failed: {e}")),
                                                            }
                                                        });
                                                    })
                                                />
                                                <OpButton
                                                    label="Deny".to_string()
                                                    variant=OpButtonVariant::Ghost
                                                    on_click=Arc::new(move |_| {
                                                        let pid = pid_d.clone();
                                                        let id = id_d.clone();
                                                        spawn_local(async move {
                                                            match iia_api::hitl_deny(&pid, &id).await {
                                                                Ok(v) => {
                                                                    if let Some(e) = api::body_error(&v) {
                                                                        set_flash.set(e);
                                                                    } else {
                                                                        set_flash.set("denied".into());
                                                                        set_reload.update(|n| *n += 1);
                                                                    }
                                                                }
                                                                Err(e) => set_flash.set(format!("deny failed: {e}")),
                                                            }
                                                        });
                                                    })
                                                />
                                            </div>
                                        </div>
                                    }
                                }).collect_view().into_any()
                            }}
                            {caps.map(|c| {
                                let raw = serde_json::to_string_pretty(&c).unwrap_or_else(|_| "{}".into());
                                view! {
                                    <details class="mt-2">
                                        <summary class="cursor-pointer text-[10px] uppercase text-zinc-500">"Capabilities"</summary>
                                        <pre class="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-400">{raw}</pre>
                                    </details>
                                }.into_any()
                            })}
                            {grants.map(|g| {
                                let raw = serde_json::to_string_pretty(&g).unwrap_or_else(|_| "{}".into());
                                view! {
                                    <details class="mt-2" open=true>
                                        <summary class="cursor-pointer text-[10px] uppercase text-zinc-500">"Grants (Isolation)"</summary>
                                        <pre class="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-400">{raw}</pre>
                                    </details>
                                }.into_any()
                            })}
                            {knot.map(|k| {
                                let raw = serde_json::to_string_pretty(&k).unwrap_or_else(|_| "{}".into());
                                view! {
                                    <details class="mt-2">
                                        <summary class="cursor-pointer text-[10px] uppercase text-zinc-500">"Knot summary"</summary>
                                        <pre class="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-400">{raw}</pre>
                                    </details>
                                }.into_any()
                            })}
                            {pending_r.err().map(|e| view! { <OpApiErrorBanner error=e /> }.into_any())}
                        </div>
                    }.into_any()
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn EvidenceTab(pid: String) -> impl IntoView {
    let (flash, set_flash) = signal(String::new());
    let (reload, set_reload) = signal(0u32);
    let (join_session, set_join_session) = signal(String::new());
    let (court_json, set_court_json) = signal::<Option<String>>(None);
    let (iso_pdf, set_iso_pdf) = signal::<Option<Vec<u8>>>(None);
    let (iso_pdf_loading, set_iso_pdf_loading) = signal(false);
    let pid_sv = StoredValue::new(pid.clone());
    let pid_r = pid.clone();
    let resource = LocalResource::new(move || {
        let pid = pid_r.clone();
        let _ = reload.get();
        let typed_sid = join_session.get_untracked();
        async move {
            let cc = iia_api::compliance_contract(&pid).await;
            let fu = iia_api::forensic_universal(&pid).await.ok();
            let tt = iia_api::tt_policies_for_agent(&pid).await.ok();
            let wc = iia_api::wc_list_sessions().await.ok();
            let isolation = iia_api::agent_isolation_audit(&pid).await.ok();
            let from_cc = cc.as_ref().ok().and_then(extract_wc_session_hint);
            let session_hint = if !typed_sid.trim().is_empty() {
                Some(typed_sid)
            } else {
                from_cc.or_else(|| Some(format!("wc:agent:{pid}")))
            };
            let join = match session_hint.as_deref() {
                Some(sid) => iia_api::wc_iia_join(sid).await.ok(),
                None => None,
            };
            (cc, fu, tt, wc, session_hint, join, isolation)
        }
    });
    view! {
        <div class="space-y-3">
            <GapBanner
                code="evidence_console"
                text="Compliance · WC iia-join · forensic · TT bind. Deep admin consoles remain at /plugins/witnessctl and /plugins/tracetramp."
            />
            <div class="rounded-lg border border-amber-800/40 bg-amber-950/20 px-3 py-2 space-y-2">
                <p class="text-[10px] uppercase tracking-wide text-amber-200/70">
                    "SOAS — Standard Operation Agentic Standard"
                </p>
                <p class="text-[11px] text-zinc-400">
                    "Honest readiness grade (playground_demo on Fly — never greenwashed to military court)."
                </p>
                <div class="flex flex-wrap gap-2">
                    <OpButton
                        label="Load SOAS report".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::soas_report(&pid).await {
                                    Ok(v) => {
                                        let grade = v
                                            .get("overall_grade")
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("?");
                                        set_flash.set(format!("SOAS overall_grade={grade}"));
                                        set_court_json.set(Some(
                                            serde_json::to_string_pretty(&v).unwrap_or_default(),
                                        ));
                                    }
                                    Err(e) => set_flash.set(format!("SOAS failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Download SOAS PDF".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::soas_report_pdf(&pid).await {
                                    Ok(bytes) => {
                                        let n = bytes.len();
                                        set_flash.set(format!("SOAS PDF downloaded ({n} bytes)"));
                                        #[cfg(target_arch = "wasm32")]
                                        {
                                            use wasm_bindgen::JsCast;
                                            let uint8 = js_sys::Uint8Array::new_with_length(n as u32);
                                            uint8.copy_from(&bytes);
                                            let blob_parts = js_sys::Array::new();
                                            blob_parts.push(&uint8.buffer());
                                            if let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence(&blob_parts) {
                                                if let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) {
                                                    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
                                                        if let Ok(a) = doc.create_element("a") {
                                                            let a: web_sys::HtmlAnchorElement = a.unchecked_into();
                                                            a.set_href(&url);
                                                            a.set_download(&format!("soas-{pid}.pdf"));
                                                            a.click();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => set_flash.set(format!("SOAS PDF failed: {e}")),
                                }
                            });
                        })
                    />
                </div>
            </div>
            <div class="rounded-lg border border-sky-800/40 bg-sky-950/20 px-3 py-2 space-y-2">
                <p class="text-[10px] uppercase tracking-wide text-sky-200/70">
                    "AACR — Augmented Agentic Compliance Record"
                </p>
                <p class="text-[11px] text-zinc-400">
                    "Kernel digest chain for agentic evidence (probabilistic identity · zero-trust). Not CPA — court-adoptable after CD gates."
                </p>
                <div class="flex flex-wrap gap-2">
                    <OpButton
                        label="Mint AACR".to_string()
                        variant=OpButtonVariant::Primary
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::aacr_mint(&pid).await {
                                    Ok(v) => {
                                        let grade = v
                                            .get("overall_grade")
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("?");
                                        let tier = v
                                            .get("signing_tier")
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("?");
                                        set_flash.set(format!(
                                            "AACR minted · grade={grade} · tier={tier}"
                                        ));
                                        set_court_json.set(Some(
                                            serde_json::to_string_pretty(&v).unwrap_or_default(),
                                        ));
                                    }
                                    Err(e) => set_flash.set(format!("AACR mint failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Load AACR report".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::aacr_report(&pid, "all").await {
                                    Ok(v) => {
                                        set_flash.set("AACR report loaded".into());
                                        set_court_json.set(Some(
                                            serde_json::to_string_pretty(&v).unwrap_or_default(),
                                        ));
                                    }
                                    Err(e) => set_flash.set(format!("AACR report failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Download AACR PDF".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::aacr_report_pdf(&pid).await {
                                    Ok(bytes) => {
                                        let n = bytes.len();
                                        set_flash.set(format!("AACR PDF ({n} bytes)"));
                                        #[cfg(target_arch = "wasm32")]
                                        {
                                            use wasm_bindgen::JsCast;
                                            let uint8 = js_sys::Uint8Array::new_with_length(n as u32);
                                            uint8.copy_from(&bytes);
                                            let blob_parts = js_sys::Array::new();
                                            blob_parts.push(&uint8.buffer());
                                            if let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence(&blob_parts) {
                                                if let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) {
                                                    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
                                                        if let Ok(a) = doc.create_element("a") {
                                                            let a: web_sys::HtmlAnchorElement = a.unchecked_into();
                                                            a.set_href(&url);
                                                            a.set_download(&format!("aacr-{pid}.pdf"));
                                                            a.click();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => set_flash.set(format!("AACR PDF failed: {e}")),
                                }
                            });
                        })
                    />
                </div>
            </div>
            <OpCourtDefensiblePanel pid=pid.clone() />
            <div class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 px-3 py-2 space-y-2">
                <p class="text-[10px] uppercase tracking-wide text-zinc-500">
                    "Audit receipt chain"
                </p>
                <div class="flex flex-wrap gap-2">
                    <OpButton
                        label="List receipts".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::agent_audit_receipts(&pid).await {
                                    Ok(v) => {
                                        let n = v
                                            .get("receipts")
                                            .or_else(|| v.get("items"))
                                            .and_then(|x| x.as_array())
                                            .map(|a| a.len())
                                            .unwrap_or(0);
                                        set_flash.set(format!("receipts listed · {n} rows"));
                                        set_court_json.set(Some(
                                            serde_json::to_string_pretty(&v).unwrap_or_default(),
                                        ));
                                    }
                                    Err(e) => set_flash.set(format!("receipts failed: {e}")),
                                }
                            });
                        })
                    />
                    <OpButton
                        label="Verify chain".to_string()
                        variant=OpButtonVariant::Primary
                        on_click=Arc::new(move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::agent_audit_receipts_verify(&pid).await {
                                    Ok(v) => {
                                        if let Some(e) = api::body_error(&v) {
                                            set_flash.set(e);
                                        } else {
                                            set_flash.set("receipt chain verify ok".into());
                                        }
                                        set_court_json.set(Some(
                                            serde_json::to_string_pretty(&v).unwrap_or_default(),
                                        ));
                                    }
                                    Err(e) => set_flash.set(format!("verify failed: {e}")),
                                }
                            });
                        })
                    />
                </div>
            </div>
            <Suspense fallback=move || view! { <p class="text-[11px] text-zinc-600">"Loading isolation plane…"</p> }>
                {move || Suspend::new(async move {
                    let (_, _, _, _, _, _, isolation) = resource.await;
                    let strip = isolation.as_ref().map(format_governance_strip).unwrap_or_else(|| {
                        "Isolation audit unavailable — download PDF/JSON after agent is registered.".into()
                    });
                    let iso_raw = isolation
                        .as_ref()
                        .and_then(|v| serde_json::to_string_pretty(v).ok())
                        .unwrap_or_default();
                    view! {
                        <div class="rounded-lg border border-cyan-900/40 bg-cyan-950/20 px-3 py-2 space-y-2">
                            <p class="text-[10px] uppercase tracking-wide text-cyan-400/90">
                                "LLM governance · live (200 / 409 / 499)"
                            </p>
                            <p class="font-mono text-[10px] text-cyan-100/90">{strip}</p>
                            <div class="flex flex-wrap gap-2">
                                <DownloadButton
                                    path=format!("/agents/{}/audit/pdf", pid_sv.get_value())
                                    filename=format!(
                                        "connector-agent-isolation-{}.pdf",
                                        pid_sv.get_value()
                                    )
                                    mime="application/pdf".to_string()
                                    success_toast="Downloaded per-agent isolation audit PDF".to_string()
                                >
                                    "Agent isolation PDF"
                                </DownloadButton>
                                <OpButton
                                    label="Preview isolation PDF".to_string()
                                    variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        set_iso_pdf_loading.set(true);
                                        spawn_local(async move {
                                            match api::get_bytes(&format!(
                                                "/agents/{pid}/audit/pdf"
                                            ))
                                            .await
                                            {
                                                Ok(bytes) => {
                                                    set_iso_pdf.set(Some(bytes));
                                                    set_flash.set("Isolation PDF loaded in viewer".into());
                                                }
                                                Err(e) => {
                                                    set_flash.set(format!("PDF preview failed: {e}"));
                                                }
                                            }
                                            set_iso_pdf_loading.set(false);
                                        });
                                    })
                                />
                                <OpButton
                                    label="Download isolation JSON".to_string()
                                    variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        spawn_local(async move {
                                            match iia_api::agent_isolation_audit(&pid).await {
                                                Ok(v) => {
                                                    match serde_json::to_vec_pretty(&v) {
                                                        Ok(bytes) => {
                                                            let fname = format!(
                                                                "connector-agent-isolation-{pid}.json"
                                                            );
                                                            trigger_download_bytes(
                                                                &bytes,
                                                                &fname,
                                                                "application/json",
                                                            );
                                                            set_flash.set(format!(
                                                                "Saved {fname} ({} bytes)",
                                                                bytes.len()
                                                            ));
                                                        }
                                                        Err(e) => set_flash.set(format!("JSON encode: {e}")),
                                                    }
                                                }
                                                Err(e) => set_flash.set(format!("Isolation JSON failed: {e}")),
                                            }
                                        });
                                    })
                                />
                            </div>
                            <PdfViewer
                                bytes=iso_pdf
                                filename=Signal::derive(move || {
                                    format!(
                                        "connector-agent-isolation-{}.pdf",
                                        pid_sv.get_value()
                                    )
                                })
                                is_loading=iso_pdf_loading
                                empty_hint="Click Preview isolation PDF to view FS/net/VM/broker proofs here.".to_string()
                                empty_title="Isolation PDF".to_string()
                                height_class="min-h-[360px]".to_string()
                            />
                            {(!iso_raw.is_empty()).then(|| view! {
                                <details class="mt-1">
                                    <summary class="cursor-pointer text-[10px] uppercase text-zinc-500">
                                        "Isolation packet preview"
                                    </summary>
                                    <pre class="mt-1 max-h-40 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-400">{iso_raw.clone()}</pre>
                                </details>
                            })}
                        </div>
                    }.into_any()
                })}
            </Suspense>
            <div class="flex flex-wrap gap-2 items-center rounded-lg border border-zinc-800/60 bg-zinc-900/30 px-3 py-2">
                <p class="mr-auto text-[10px] uppercase tracking-wide text-zinc-500">
                    "System brief/report (fleet workpapers)"
                </p>
                <DownloadButton
                    path="/compliance/brief/pdf".to_string()
                    filename="connector-compliance-brief.pdf".to_string()
                    mime="application/pdf".to_string()
                    success_toast="Downloaded timestamped compliance brief PDF".to_string()
                >
                    "System brief PDF"
                </DownloadButton>
                <DownloadButton
                    path="/compliance/report/pdf".to_string()
                    filename="connector-compliance-report.pdf".to_string()
                    mime="application/pdf".to_string()
                    success_toast="Downloaded timestamped compliance report PDF".to_string()
                >
                    "System report PDF"
                </DownloadButton>
            </div>
            <div class="flex flex-wrap gap-2 items-end">
                <OpButton
                    label="Bind TT monitor policy".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            let name = format!("agent-bind-{}", &pid[..pid.len().min(12)]);
                            match iia_api::tt_bind_agent_policy(&pid, "default", &name).await {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        set_flash.set(e);
                                    } else {
                                        set_flash.set("TT policy bound (monitor)".into());
                                        set_reload.update(|n| *n += 1);
                                    }
                                }
                                Err(e) => set_flash.set(format!("TT bind failed: {e}")),
                            }
                        });
                    })
                />
                <OpButton
                    label="Download forensic package".to_string()
                    variant=OpButtonVariant::Primary
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        set_flash.set("Building forensic package…".into());
                        spawn_local(async move {
                            match iia_api::forensic_package(&pid).await {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        set_flash.set(format!("Package failed: {e}"));
                                        return;
                                    }
                                    match serde_json::to_vec_pretty(&v) {
                                        Ok(bytes) => {
                                            let n = bytes.len();
                                            let fname = format!("forensic-package-{pid}.json");
                                            trigger_download_bytes(
                                                &bytes,
                                                &fname,
                                                "application/json",
                                            );
                                            set_flash.set(format!(
                                                "Downloaded {fname} ({n} bytes · GET /forensics/package)"
                                            ));
                                        }
                                        Err(e) => set_flash.set(format!("Serialize failed: {e}")),
                                    }
                                }
                                Err(e) => set_flash.set(format!("Package failed: {e}")),
                            }
                        });
                    })
                />
                <OpButton
                    label="Court readiness".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        set_flash.set("Checking court readiness…".into());
                        spawn_local(async move {
                            match iia_api::court_readiness(&pid).await {
                                Ok(v) => {
                                    let ready = v
                                        .get("live_court_e2e_ready")
                                        .and_then(|x| x.as_bool())
                                        .unwrap_or(false);
                                    let missing = v
                                        .get("missing")
                                        .and_then(|m| m.as_array())
                                        .map(|a| {
                                            a.iter()
                                                .filter_map(|x| x.as_str())
                                                .collect::<Vec<_>>()
                                                .join(", ")
                                        })
                                        .unwrap_or_default();
                                    set_court_json.set(Some(
                                        serde_json::to_string_pretty(&v).unwrap_or_default(),
                                    ));
                                    set_flash.set(if ready {
                                        "Court readiness: LIVE checklist green (ops soak still separate)".into()
                                    } else {
                                        format!("Court readiness: not ready — {missing}")
                                    });
                                }
                                Err(e) => set_flash.set(format!("Court readiness failed: {e}")),
                            }
                        });
                    })
                />
                <label class="block text-[10px] uppercase text-zinc-500">
                    "WC session id"
                    <input
                        class="mt-1 w-56 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-100 font-mono"
                        prop:value=move || join_session.get()
                        on:input=move |ev| set_join_session.set(event_target_value(&ev))
                        placeholder="uuid or wc:agent:…"
                    />
                </label>
                <OpButton
                    label="Load iia-join".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        if join_session.get().trim().is_empty() {
                            set_flash.set("Enter a WC session id first".into());
                            return;
                        }
                        set_flash.set("Loading iia-join…".into());
                        set_reload.update(|n| *n += 1);
                    })
                />
                <a
                    class="rounded px-2.5 py-1 text-[11px] text-zinc-300 underline hover:text-zinc-100"
                    href="/plugins/witnessctl"
                >
                    "Open WitnessCtl"
                </a>
                <a
                    class="rounded px-2.5 py-1 text-[11px] text-zinc-300 underline hover:text-zinc-100"
                    href="/plugins/tracetramp"
                >
                    "Open TraceTramp"
                </a>
            </div>
            <p class="text-xs text-zinc-300">{move || flash.get()}</p>
            <Show when=move || court_json.get().is_some()>
                <section class="rounded border border-zinc-800/60 bg-zinc-900/30 p-2">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                        "Court readiness checklist"
                    </p>
                    <pre class="mt-1 max-h-48 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-300">
                        {move || court_json.get().unwrap_or_default()}
                    </pre>
                </section>
            </Show>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading evidence…".to_string() /> }>
                {move || Suspend::new(async move {
                    let (cc_r, fu, tt, wc, session_hint, join, _isolation) = resource.await;
                    match cc_r {
                        Ok(v) => {
                            let mismatch = v.get("witnessctl_framework_mismatch").cloned();
                            let alignment = v.get("witnessctl_alignment").cloned();
                            let raw = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into());
                            let fu_raw = fu
                                .as_ref()
                                .map(|f| serde_json::to_string_pretty(f).unwrap_or_default())
                                .unwrap_or_else(|| "(unavailable)".into());
                            let tt_count = tt
                                .as_ref()
                                .and_then(|t| t.get("count").and_then(|c| c.as_u64()))
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "—".into());
                            let tt_raw = tt
                                .as_ref()
                                .map(|t| serde_json::to_string_pretty(t).unwrap_or_default())
                                .unwrap_or_else(|| "(TT proxy unavailable)".into());
                            let wc_raw = wc
                                .as_ref()
                                .map(|w| serde_json::to_string_pretty(w).unwrap_or_default())
                                .unwrap_or_else(|| "(WC proxy unavailable — set MANAGEMENT_URL)".into());
                            let join_raw = join
                                .as_ref()
                                .map(|j| serde_json::to_string_pretty(j).unwrap_or_default())
                                .unwrap_or_else(|| "(no iia-join yet — activate with WC or enter session id)".into());
                            let hint_label = session_hint.clone().unwrap_or_else(|| "—".into());
                            if join_session.get_untracked().is_empty() {
                                if let Some(sid) = extract_wc_session_hint(&v) {
                                    set_join_session.set(sid);
                                }
                            }
                            view! {
                                <div class="space-y-3">
                                    {mismatch.map(|m| {
                                        let s = serde_json::to_string_pretty(&m).unwrap_or_default();
                                        view! {
                                            <div class="rounded border border-rose-800/50 bg-rose-950/30 p-2 text-[11px] text-rose-100">
                                                <p class="font-semibold">"WC framework mismatch / pending"</p>
                                                <pre class="mt-1 whitespace-pre-wrap font-mono text-[10px]">{s}</pre>
                                            </div>
                                        }.into_any()
                                    })}
                                    {alignment.map(|a| {
                                        let status = a.get("status").and_then(|x| x.as_str()).unwrap_or("?");
                                        let frameworks = a.get("frameworks")
                                            .and_then(|f| f.as_array())
                                            .map(|arr| arr.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
                                            .unwrap_or_default();
                                        view! {
                                            <p class="text-xs text-zinc-300">
                                                {format!("WC alignment: {status} · frameworks [{frameworks}]")}
                                            </p>
                                        }.into_any()
                                    })}
                                    <section class="rounded border border-zinc-800/60 bg-zinc-900/30 p-2">
                                        <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                            {format!("WC iia-join · {hint_label}")}
                                        </p>
                                        <pre class="mt-1 max-h-40 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-300">{join_raw}</pre>
                                    </section>
                                    <p class="text-[10px] uppercase text-zinc-500">
                                        {format!("TT policies for agent ({tt_count})")}
                                    </p>
                                    <pre class="max-h-28 overflow-y-auto whitespace-pre-wrap rounded border border-zinc-800/50 p-2 text-[10px] font-mono text-zinc-400">{tt_raw}</pre>
                                    <details>
                                        <summary class="cursor-pointer text-[10px] uppercase text-zinc-500">"Compliance contract"</summary>
                                        <pre class="mt-1 max-h-48 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-300">{raw}</pre>
                                    </details>
                                    <details>
                                        <summary class="cursor-pointer text-[10px] uppercase text-zinc-500">"Forensic universals"</summary>
                                        <pre class="mt-1 max-h-48 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-300">{fu_raw}</pre>
                                    </details>
                                    <details>
                                        <summary class="cursor-pointer text-[10px] uppercase text-zinc-500">"WC sessions (proxy)"</summary>
                                        <pre class="mt-1 max-h-40 overflow-y-auto whitespace-pre-wrap text-[10px] font-mono text-zinc-400">{wc_raw}</pre>
                                    </details>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

fn format_governance_strip(v: &Value) -> String {
    let broker = v
        .pointer("/isolation_proofs/4/broker_unbypassable")
        .and_then(|x| x.as_bool())
        .or_else(|| {
            v.pointer("/sandbox_unbypassable/llm_broker_unbypassable")
                .and_then(|x| x.as_bool())
        })
        .unwrap_or(false);
    let tokenize = v
        .pointer("/isolation_proofs/4/tokenization/enforced")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let gate = v
        .get("sandbox_gate_ok")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let tier = v
        .pointer("/isolation/tier")
        .and_then(|x| x.as_str())
        .unwrap_or("—");
    let gen = v
        .pointer("/isolation_proofs/4/generation")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let q = v
        .pointer("/isolation_proofs/4/brain_quarantined")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    format!(
        "tier={tier} · broker_unbypassable={} · tokenize={} · sandbox_gate={} · gen={gen} · quarantined={} · HTTP 200/409/499",
        if broker { "yes" } else { "no" },
        if tokenize { "yes" } else { "no" },
        if gate { "ok" } else { "FAIL" },
        if q { "yes" } else { "no" },
    )
}

fn extract_wc_session_hint(v: &Value) -> Option<String> {
    for path in [
        "/witnessctl_session_id",
        "/data/witnessctl_session_id",
        "/contract/witnessctl_session_id",
        "/witnessctl_alignment/session_id",
        "/data/witnessctl_alignment/session_id",
    ] {
        if let Some(s) = v.pointer(path).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Control crumbs: principal · continuity · intelligence mark (not OS PID theatre).
fn format_trace_strip(v: &Value) -> Vec<String> {
    let arr = v
        .get("traces")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();
    arr.into_iter()
        .take(8)
        .map(|t| {
            let id = t
                .get("trace_id")
                .or_else(|| t.get("audit_id"))
                .and_then(|x| x.as_str())
                .unwrap_or("—");
            let op = t
                .get("operation")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let outcome = t
                .get("outcome")
                .and_then(|x| x.as_str())
                .unwrap_or("?");
            let target = t
                .get("target")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let ms = t
                .get("duration_ms")
                .and_then(|x| x.as_u64())
                .map(|n| format!("{n}ms"))
                .unwrap_or_else(|| "—".into());
            if target.is_empty() {
                format!("{id} · {op} → {outcome} ({ms})")
            } else {
                format!("{id} · {op} → {outcome} · {target} ({ms})")
            }
        })
        .collect()
}

fn format_intelligence_crumbs(self_v: Option<&Value>, matrix: Option<&Value>) -> String {
    let principal = self_v
        .and_then(|v| {
            pointer_str(
                v,
                &[
                    "/principal_id",
                    "/self/principal/principal_id",
                    "/self/principal_id",
                    "/identity_envelope/principal/principal_id",
                    "/identity_envelope/principal_id",
                ],
            )
        })
        .or_else(|| {
            matrix.and_then(|v| {
                pointer_str(v, &["/matrix/principal_id", "/principal_id"])
            })
        })
        .unwrap_or_else(|| "principal:?".into());
    let quantum = self_v
        .and_then(|v| {
            pointer_str(
                v,
                &[
                    "/self/quantum_id",
                    "/self/active_quantum_id",
                    "/quantum_id",
                    "/identity_envelope/quantum_id",
                    "/identity_envelope/active_quantum_id",
                ],
            )
        })
        .unwrap_or_else(|| "quantum:—".into());
    let continuity = self_v
        .and_then(|v| {
            pointer_str(
                v,
                &[
                    "/continuity_state",
                    "/self/continuity/state",
                    "/self/continuity_state",
                ],
            )
        })
        .or_else(|| {
            matrix.and_then(|v| {
                pointer_str(v, &["/matrix/continuity_state", "/continuity_state"])
            })
        })
        .unwrap_or_else(|| "continuity:?".into());
    let mark = self_v
        .and_then(|v| pointer_str(v, &["/intelligence_mark"]))
        .or_else(|| {
            matrix.and_then(|v| {
                pointer_str(v, &["/matrix/intelligence_mark", "/intelligence_mark"])
            })
        })
        .unwrap_or_else(|| "mark:—".into());
    let short = |s: &str| {
        if s.len() > 28 {
            format!("{}…", &s[..24])
        } else {
            s.to_string()
        }
    };
    format!(
        "{} · {} · {} · {}",
        short(&principal),
        short(&quantum),
        continuity,
        mark
    )
}

#[component]
fn Field(
    label: &'static str,
    value: ReadSignal<String>,
    on_input: WriteSignal<String>,
) -> impl IntoView {
    view! {
        <label class="block text-[10px] uppercase text-zinc-500">
            {label}
            <input
                class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100 font-mono"
                prop:value=move || value.get()
                on:input=move |ev| on_input.set(event_target_value(&ev))
            />
        </label>
    }
}

#[component]
fn SelectField(
    label: &'static str,
    value: ReadSignal<String>,
    on_change: WriteSignal<String>,
    options: &'static [&'static str],
) -> impl IntoView {
    view! {
        <label class="block text-[10px] uppercase text-zinc-500">
            {label}
            <select
                class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100"
                prop:value=move || value.get()
                on:change=move |ev| on_change.set(event_target_value(&ev))
            >
                {options.iter().map(|o| {
                    let o = *o;
                    view! { <option value=o>{o}</option> }
                }).collect_view()}
            </select>
        </label>
    }
}

fn extract_who(v: &Value) -> String {
    pointer_str(v, &[
        "/data/who_am_i_authoritative",
        "/who_am_i_authoritative",
        "/data/envelope/who_am_i_authoritative",
        "/envelope/who_am_i_authoritative",
        "/data/envelope/base/who_am_i_authoritative",
    ])
    .unwrap_or_else(|| {
        v.get("data")
            .cloned()
            .unwrap_or_else(|| v.clone())
            .to_string()
    })
}

fn pointer_str(v: &Value, paths: &[&str]) -> Option<String> {
    for p in paths {
        if let Some(s) = v.pointer(p).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn join_str_array(v: Option<&Value>) -> String {
    v.and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn event_target_value(ev: &web_sys::Event) -> String {
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.value())
        .or_else(|| {
            ev.target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlTextAreaElement>().ok())
                .map(|el| el.value())
        })
        .or_else(|| {
            ev.target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
                .map(|el| el.value())
        })
        .unwrap_or_default()
}
