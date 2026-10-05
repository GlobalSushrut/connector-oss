use leptos::prelude::*;
use serde_json::Value;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::auth::AuthState;
use crate::api;
use crate::components::operator::cards::{OpAgentCard, OpCardAccent, OpEventRow, OpWorkflowCard};
use crate::components::operator::overlays::confirm::OpConfirm;
use crate::components::operator::journey_choice::AgentJourney;
use crate::components::operator::overlays::llm_connect::OpLlmQuickConnect;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpEmptyState, OpFilterTabs, OpGrid, OpLiveDot, OpSearchField,
    OpSpinner, OpText, OpTextVariant, OpViewMode, OpViewToggle,
};
use crate::components::ui::DownloadButton;
use crate::deployment::use_deployment_mode;
use crate::request_store::{bump_reload, use_shared_requests};
use crate::surfaces::watch_helpers::parse_watch_events;
use crate::ui_state::{
    open_agent_view, open_agent_workbench, open_create_agent, open_create_workflow,
    open_workflow_drawer,
};

#[component]
pub fn RunCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let shared = use_shared_requests();
    let mode = use_deployment_mode();
    let (filter, set_filter) = signal("all".to_string());
    let (search, set_search) = signal(String::new());
    let (view_mode, set_view_mode) = signal(OpViewMode::Grid);
    let (tick, set_tick) = signal(0u32);

    // Poll watch strip every 4s
    Effect::new(move |_| {
        let _ = tick.get();
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(4000).await;
            set_tick.update(|n| *n = n.wrapping_add(1));
            bump_reload();
        });
    });

    view! {
        <div class="w-full">
            <div class="shrink-0 border-b border-zinc-800/60 px-4 py-4 sm:px-6">
                <div class="flex flex-wrap items-start justify-between gap-3">
                    <div>
                        <OpText text="RUN".to_string() variant=OpTextVariant::Title />
                        <p class="mt-1 text-sm text-zinc-500">
                            {move || if mode.get().is_playground() {
                                "Your Demo agent is in the box below. Isolate / Govern / Stop / Prove need no LLM key. Paste a provider key only for free-text Talk."
                            } else {
                                "Demo is already on this node. Click it and start talking. Connect an LLM when you want free-text answers."
                            }}
                        </p>
                        <RunFuelChip />
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <OpButton
                            label="Bring your agent".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| {
                                if let Some(w) = web_sys::window() {
                                    let _ = w.location().set_href("/setup/uplink");
                                }
                            })
                        />
                        <OpButton
                            label="Advanced workspace".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| {
                                if let Some(w) = web_sys::window() {
                                    let _ = w.location().set_href("/run/workbench?rail=data");
                                }
                            })
                        />
                        <OpButton
                            label="Action Trail".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| {
                                if let Some(w) = web_sys::window() {
                                    let _ = w.location().set_href("/run/trail");
                                }
                            })
                        />
                        <OpButton
                            label="+ New agent".to_string()
                            variant=OpButtonVariant::Primary
                            on_click=Arc::new(move |_| open_create_agent())
                        />
                        <OpButton
                            label="+ New workflow".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| open_create_workflow())
                        />
                        <a class="inline-flex items-center rounded-md px-3 py-1.5 text-xs text-indigo-400 hover:underline" href="/dev">"DEV"</a>
                    </div>
                </div>
                <section class="mt-3 max-w-3xl rounded-xl border border-zinc-800 bg-zinc-950/40 p-3">
                    <p class="text-[11px] font-semibold uppercase tracking-wider text-zinc-300">"Bring your agent"</p>
                    <p class="mt-1 text-xs leading-relaxed text-zinc-400">
                        "Any agent uses the same wires. It calls this node as an MCP client, or this node reads its MCP server, A2A card, or OpenAI-compatible chat URL. A product with none of those addresses stays unconnected."
                    </p>
                    <div class="mt-3">
                        <AgentJourney />
                    </div>
                </section>
                <Show when=move || !mode.get().is_playground()>
                    <div class="mt-3 max-w-3xl rounded-xl border border-indigo-900/40 bg-indigo-950/20 px-3 py-2.5">
                        <p class="text-[11px] font-semibold uppercase tracking-wider text-indigo-200">
                            "Click Demo and start talking"
                        </p>
                        <p class="mt-1 text-xs leading-relaxed text-zinc-400">
                            "Demo explains Connector from its Knowledge collection: what it is, how a turn is admitted, and what you can do next. Connect a provider key, then ask."
                        </p>
                    </div>
                </Show>
                <Show when=move || mode.get().is_playground()>
                    <div class="mt-3 max-w-3xl rounded-xl border border-cyan-900/40 bg-cyan-950/20 px-3 py-2.5">
                        <p class="text-[11px] font-semibold uppercase tracking-wider text-cyan-200">
                            "Try Demo — no LLM key"
                        </p>
                        <p class="mt-1 text-xs leading-relaxed text-zinc-400">
                            "Open the Demo agent → Isolate, Govern, Stop, or Prove. Those enqueue real Workbench orders. Admit runs identity → PATE → ToolDispatch. Stop kills the loop and is not undo. DevGuard / TraceTramp / WitnessCtl are institutions on this node — they are not this agent."
                        </p>
                    </div>
                </Show>
                <div class="mt-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <OpFilterTabs
                        tabs=vec![
                            ("all", "All"),
                            ("running", "Running"),
                            ("attention", "Needs you"),
                            ("idle", "Idle"),
                        ]
                        active=filter
                        set_active=set_filter
                    />
                    <div class="flex w-full flex-col gap-2 sm:flex-row sm:items-center lg:w-auto">
                        <div class="w-full sm:max-w-xs">
                            <OpSearchField value=search set_value=set_search placeholder="Filter workflows…" />
                        </div>
                        <OpViewToggle mode=view_mode set_mode=set_view_mode />
                    </div>
                </div>
            </div>

            <div class="px-4 py-4 sm:px-6 pb-10">
                <ActiveAgentsPanel />
                <Suspense fallback=move || view! { <div class="flex justify-center py-12"><OpSpinner /></div> }>
                    {move || Suspend::new(async move {
                        let list = shared.workflows.await.ok().map(|v| workflow_items(&v)).unwrap_or_default();
                        let f = filter.get();
                        let q = search.get().to_ascii_lowercase();
                        let mut filtered: Vec<_> = list.into_iter().filter(|w| {
                            let bucket = match w.accent {
                                OpCardAccent::Running => "running",
                                OpCardAccent::Attention => "attention",
                                _ => "idle",
                            };
                            let filter_ok = f == "all" || f == bucket;
                            let search_ok = q.is_empty()
                                || w.id.to_ascii_lowercase().contains(&q)
                                || w.title.to_ascii_lowercase().contains(&q)
                                || w.subtitle.to_ascii_lowercase().contains(&q);
                            filter_ok && search_ok
                        }).collect();
                        // Attention first
                        filtered.sort_by_key(|w| match w.accent {
                            OpCardAccent::Attention => 0,
                            OpCardAccent::Running => 1,
                            _ => 2,
                        });

                        if filtered.is_empty() {
                            view! {
                                <OpEmptyState
                                    title="Start from the DevGuard workflow above"
                                    description="Generate or link a repo, cage it, attach agents. Or + New workflow to write a custom one. TraceTramp and WitnessCtl stay on this node."
                                >
                                    <div class="flex flex-wrap justify-center gap-2">
                                        <button type="button" class="inline-flex items-center rounded-lg border border-zinc-700 px-3 py-2 text-sm font-semibold text-zinc-100 hover:bg-zinc-800"
                                            on:click=move |_| open_create_workflow()>
                                            "+ New workflow"
                                        </button>
                                    </div>
                                </OpEmptyState>
                            }.into_any()
                        } else if view_mode.get() == OpViewMode::List {
                            view! {
                                <div class="overflow-hidden rounded-xl border border-zinc-800/60">
                                    <div class="grid grid-cols-[1fr_6rem_7rem_1fr_5rem] gap-2 border-b border-zinc-800/80 px-4 py-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-600">
                                        <span>"Workflow"</span><span>"State"</span><span>"Accounting"</span><span>"Package"</span><span></span>
                                    </div>
                                    {filtered.into_iter().map(|w| {
                                        let open_id = w.id.clone();
                                        let acct = if w.accounting_mode == "service_monitoring" {
                                            "service"
                                        } else if w.accounting_mode.is_empty() {
                                            "—"
                                        } else {
                                            "action"
                                        };
                                        view! {
                                            <button
                                                type="button"
                                                class="grid w-full grid-cols-[1fr_6rem_7rem_1fr_5rem] gap-2 border-b border-zinc-800/40 px-4 py-2.5 text-left text-xs hover:bg-zinc-900/50"
                                                on:click=move |_| open_workflow_drawer(open_id.clone())
                                            >
                                                <span class="truncate font-medium text-zinc-100">{w.title}</span>
                                                <span class="text-zinc-400">{w.state}</span>
                                                <span class="font-mono text-[10px] uppercase text-zinc-500">{acct}</span>
                                                <span class="truncate font-mono text-zinc-500">{w.subtitle}</span>
                                                <span class="text-indigo-400">"Open →"</span>
                                            </button>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <OpGrid>
                                    {filtered.into_iter().map(|w| {
                                        let id = w.id.clone();
                                        let open_id = id.clone();
                                        view! {
                                            <OpWorkflowCard
                                                workflow_id=id
                                                title=w.title
                                                subtitle=w.subtitle
                                                state=w.state
                                                accent=w.accent
                                                accounting_mode=w.accounting_mode
                                                on_open=Arc::new(move |_| open_workflow_drawer(open_id.clone()))
                                            />
                                        }
                                    }).collect_view()}
                                </OpGrid>
                            }.into_any()
                        }
                    })}
                </Suspense>
            </div>

            <div class="shrink-0 border-t border-zinc-800/60 bg-zinc-950/50">
                <div class="flex items-center justify-between px-4 py-2">
                    <div class="flex items-center gap-2">
                        <OpLiveDot />
                        <OpText text="Live event stream".to_string() variant=OpTextVariant::Caption />
                    </div>
                    <a href="/watch" class="text-xs text-indigo-400 hover:underline">"Open full stream →"</a>
                </div>
                <Suspense fallback=move || view! { <p class="px-4 pb-3 text-xs text-zinc-600">"Loading events…"</p> }>
                    {move || Suspend::new(async move {
                        let _ = tick.get();
                        let events = shared.watch_events.await.ok()
                            .map(|v| parse_watch_events(&v))
                            .unwrap_or_default();
                        let strip: Vec<_> = events.into_iter().take(8).collect();
                        if strip.is_empty() {
                            view! { <p class="px-4 pb-3 text-xs text-zinc-600">"No events yet."</p> }.into_any()
                        } else {
                            view! {
                                <div class="max-h-40 overflow-auto pb-2">
                                    {strip.into_iter().map(|e| {
                                        let wf = e.workflow_id.clone();
                                        view! {
                                            <div
                                                class=if wf.is_some() { "cursor-pointer" } else { "" }
                                                on:click=move |_| {
                                                    if let Some(id) = wf.clone() {
                                                        open_workflow_drawer(id);
                                                    }
                                                }
                                            >
                                                <OpEventRow
                                                    time=e.time
                                                    decision=e.decision
                                                    agent=e.agent
                                                    action=e.action
                                                    resource=e.resource
                                                />
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }
                    })}
                </Suspense>
            </div>
        </div>
    }
}

#[component]
fn ActiveAgentsPanel() -> impl IntoView {
    let shared = use_shared_requests();
    let llm = LocalResource::new(|| api::get_value_timeout("/settings/llms/status", 5_000));
    let (confirm_open, set_confirm_open) = signal(false);
    let (pending_delete, set_pending_delete) = signal(None::<(String, String)>);
    let (delete_err, set_delete_err) = signal(String::new());

    view! {
        <section class="mb-8 rounded-2xl border border-zinc-800/80 bg-zinc-950/50 p-4 sm:p-5">
            <div class="flex flex-wrap items-end justify-between gap-2">
                <div>
                    <h2 class="text-sm font-semibold uppercase tracking-wider text-zinc-300">"Your agents"</h2>
                    <p class="mt-0.5 text-xs text-zinc-500">
                        "Every agent in this session. Run opens Workbench. View opens the drawer. Delete removes it."
                    </p>
                </div>
                <button
                    type="button"
                    class="text-xs text-indigo-400 hover:underline"
                    on:click=move |_| bump_reload()
                >"Refresh"</button>
            </div>
            {move || {
                let err = delete_err.get();
                (!err.is_empty()).then(|| view! {
                    <p class="mt-2 text-xs text-red-300">{err}</p>
                })
            }}
            <OpConfirm
                open=confirm_open
                set_open=set_confirm_open
                title="Delete this agent?".to_string()
                message="This removes the agent from this session. You can create another after it is gone.".to_string()
                confirm_label="Delete"
                on_confirm={
                    let set_pending_delete = set_pending_delete;
                    let set_delete_err = set_delete_err;
                    move || {
                        let Some((pid, _)) = pending_delete.get_untracked() else { return };
                        set_delete_err.set(String::new());
                        spawn_local(async move {
                            match crate::iia_api::delete_agent(&pid).await {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        set_delete_err.set(e);
                                    } else if v.get("terminated") == Some(&serde_json::json!(false)) {
                                        set_delete_err.set("Agent was not terminated.".into());
                                    } else {
                                        set_pending_delete.set(None);
                                        bump_reload();
                                    }
                                }
                                Err(e) => set_delete_err.set(e.message),
                            }
                        });
                    }
                }
            />
            <Suspense fallback=move || view! { <div class="flex justify-center py-6"><OpSpinner /></div> }>
                {move || Suspend::new(async move {
                    let proven = llm.await.ok().map(|v| {
                        let src = api::resource_object(&v);
                        src.get("proven").and_then(|x| x.as_bool()).unwrap_or(false)
                    }).unwrap_or(false);
                    let llm_prompt = if proven {
                        view! { <></> }.into_any()
                    } else {
                        view! {
                            <div class="rounded-xl border border-amber-800/50 bg-amber-950/20 p-3">
                                <p class="mb-2 text-xs font-medium text-amber-100">
                                    "Talk is live only after a provider key pings. Isolate / Govern / Stop / Prove need no key."
                                </p>
                                <OpLlmQuickConnect />
                            </div>
                        }.into_any()
                    };
                    let mut agents = shared.agents.await.ok().map(|v| agent_cards(&v)).unwrap_or_default();
                    agents.sort_by_key(|agent| if agent.is_demo { 0 } else { 1 });
                    if agents.is_empty() {
                        view! {
                            <div class="space-y-3">
                                {llm_prompt}
                                <OpEmptyState
                                    title="No active agent yet"
                                    description="Demo is created when this node starts. Refresh agents. On a playground session, open Isolate / Govern / Stop / Prove, then Admit."
                                >
                                    <div class="flex flex-wrap justify-center gap-2">
                                        <button type="button" class="inline-flex items-center rounded-lg border border-zinc-700 px-3 py-2 text-sm font-semibold text-zinc-100 hover:bg-zinc-800"
                                            on:click=move |_| bump_reload()>
                                            "Refresh agents"
                                        </button>
                                        <button type="button" class="inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white hover:bg-indigo-500"
                                            on:click=move |_| open_create_agent()>
                                            "+ New agent"
                                        </button>
                                    </div>
                                </OpEmptyState>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-3">
                                {llm_prompt}
                                <OpGrid>
                                    {agents.into_iter().map(|a| {
                                        let pid = a.pid.clone();
                                        let talk_pid = pid.clone();
                                        let view_pid = pid.clone();
                                        let del_pid = pid.clone();
                                        let pdf_pid = pid.clone();
                                        let del_name = a.name.clone();
                                        let is_demo = a.is_demo;
                                        let primary = if is_demo { "Start talking".to_string() } else { "Run".to_string() };
                                        view! {
                                            <div class="space-y-2">
                                                <OpAgentCard
                                                    name=a.name
                                                    pid=pid
                                                    state=a.state
                                                    primary_label=primary
                                                    on_open=Arc::new(move |_| {
                                                        if is_demo {
                                                            if let Some(w) = web_sys::window() {
                                                                let _ = w.location().set_href(&format!("/run/workbench/{}?rail=data", talk_pid));
                                                            }
                                                        } else {
                                                            open_agent_workbench(talk_pid.clone());
                                                        }
                                                    })
                                                    on_view=Arc::new(move |_| open_agent_view(view_pid.clone()))
                                                    on_delete=Arc::new(move |_| {
                                                        set_pending_delete.set(Some((del_pid.clone(), del_name.clone())));
                                                        set_delete_err.set(String::new());
                                                        set_confirm_open.set(true);
                                                    })
                                                />
                                                <DownloadButton
                                                    path=format!("/agents/{pdf_pid}/audit/pdf")
                                                    filename=format!("connector-agent-isolation-{pdf_pid}.pdf")
                                                    mime="application/pdf".to_string()
                                                    success_toast="Downloaded agent isolation PDF".to_string()
                                                    variant=crate::components::ui::ButtonVariant::Outline
                                                >
                                                    "Download agent PDF"
                                                </DownloadButton>
                                            </div>
                                        }
                                    }).collect_view()}
                                </OpGrid>
                            </div>
                        }.into_any()
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn RunFuelChip() -> impl IntoView {
    let fuel = LocalResource::new(|| async {
        let status = api::get_value_timeout("/settings/llms/status", 5_000).await.ok();
        let costs = api::get_value("/books/costs").await.ok();
        (status, costs)
    });
    view! {
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                let (status, costs) = fuel.await;
                let wired = status
                    .as_ref()
                    .and_then(|v| {
                        let src = api::resource_object(v);
                        src.get("router_wired").and_then(|x| x.as_bool())
                    })
                    .unwrap_or(false);
                let has_usage = costs
                    .as_ref()
                    .and_then(|v| {
                        let src = api::resource_object(v);
                        src.pointer("/data/has_usage_data")
                            .or_else(|| src.get("has_usage_data"))
                            .and_then(|x| x.as_bool())
                    })
                    .unwrap_or(false);
                let tokens = costs.as_ref().and_then(|v| {
                    let src = api::resource_object(v);
                    src.pointer("/data/total_tokens")
                        .or_else(|| src.get("total_tokens"))
                        .and_then(|x| x.as_u64())
                });
                if !wired {
                    view! {
                        <a href="/setup" class="mt-2 inline-flex text-[11px] text-amber-300/90 hover:underline">
                            "No live LLM — connect in SETUP · fuel stays unavailable (not $0)"
                        </a>
                    }.into_any()
                } else if has_usage {
                    let label = tokens
                        .map(|n| format!("Fuel · {n} tokens (measured)"))
                        .unwrap_or_else(|| "Fuel · usage recorded".into());
                    view! {
                        <a href="/watch?tab=fuel" class="mt-2 inline-flex font-mono text-[11px] text-emerald-300/90 hover:underline">
                            {label}
                        </a>
                    }.into_any()
                } else {
                    view! {
                        <a href="/watch?tab=fuel" class="mt-2 inline-flex text-[11px] text-zinc-500 hover:underline">
                            "LLM wired · no usage events yet — WATCH Fuel"
                        </a>
                    }.into_any()
                }
            })}
        </Suspense>
    }
}

struct AgentVm {
    pid: String,
    name: String,
    state: String,
    is_demo: bool,
}

fn agent_cards(v: &Value) -> Vec<AgentVm> {
    let root = api::resource_object(v);
    let arr = root
        .get("agents")
        .or_else(|| root.get("items"))
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();
    arr.into_iter()
        .filter_map(|item| {
            let pid = item
                .get("pid")
                .or_else(|| item.get("agent_pid"))
                .or_else(|| item.get("id"))
                .and_then(|x| x.as_str())?
                .to_string();
            if pid.is_empty() || pid == "?" {
                return None;
            }
            let mut name = item
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                name = "Demo".into();
            }
            let tags = item.get("tags").and_then(|t| t.as_array()).cloned().unwrap_or_default();
            let is_demo = tags.iter().any(|t| t.as_str() == Some("demo") || t.as_str() == Some("connector-guide"))
                || name.eq_ignore_ascii_case("demo");
            if is_demo && !name.to_ascii_lowercase().contains("demo") {
                name = format!("{name} (demo)");
            }
            let state = item
                .get("status")
                .or_else(|| item.get("state"))
                .and_then(|x| x.as_str())
                .unwrap_or("active")
                .to_string();
            Some(AgentVm { pid, name, state, is_demo })
        })
        .collect()
}

struct WorkflowVm {
    id: String,
    title: String,
    subtitle: String,
    state: String,
    accent: OpCardAccent,
    accounting_mode: String,
}

fn workflow_items(v: &Value) -> Vec<WorkflowVm> {
    let arr = v
        .get("workflows")
        .or_else(|| v.get("data"))
        .and_then(|d| d.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default();

    arr.into_iter()
        .filter_map(|item| {
            let id = item
                .get("workflow_id")
                .or_else(|| item.get("id"))
                .and_then(|x| x.as_str())?
                .to_string();
            let state = item
                .get("state")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            let accent = match state.to_ascii_uppercase().as_str() {
                "ENABLED" | "ACTIVE" | "RUNNING" => OpCardAccent::Running,
                "PAUSED" | "ATTENTION" | "BLOCKED" | "ERROR" => OpCardAccent::Attention,
                _ => OpCardAccent::Idle,
            };
            let accounting_mode = item
                .get("accounting_mode")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some(WorkflowVm {
                title: item
                    .get("title")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&id)
                    .to_string(),
                subtitle: item
                    .get("subtitle")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("package_id").and_then(|x| x.as_str()))
                    .unwrap_or("workflow")
                    .to_string(),
                id,
                state,
                accent,
                accounting_mode,
            })
        })
        .collect()
}
