use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::components::operator::primitives::OpSearchField;
use crate::request_store::use_shared_requests;
use crate::ui_state::{
    open_create_agent, open_create_workflow, open_topic_drawer, open_workflow_drawer,
    use_search_overlay, DrawerTopic, SearchOverlay,
};
use serde_json::Value;

#[derive(Clone)]
struct PaletteItem {
    label: String,
    hint: String,
    action: PaletteAction,
}

#[derive(Clone)]
enum PaletteAction {
    Navigate(&'static str),
    OpenWorkflow(String),
    Topic(DrawerTopic),
    CreateWorkflow,
    CreateAgent,
}

fn static_items() -> Vec<PaletteItem> {
    vec![
        PaletteItem { label: "RUN — agents · ENABLED workflows · Action".into(), hint: "/run".into(), action: PaletteAction::Navigate("/run") },
        PaletteItem { label: "Workbench — consult · admit · chart".into(), hint: "/run/workbench".into(), action: PaletteAction::Navigate("/run/workbench") },
        PaletteItem { label: "WATCH — Stream · Tools · Address · Agent · Fuel · Trace".into(), hint: "/watch".into(), action: PaletteAction::Navigate("/watch") },
        PaletteItem { label: "FIX — HITL / PATE Ask".into(), hint: "/fix".into(), action: PaletteAction::Navigate("/fix") },
        PaletteItem { label: "SETUP — LLM · DAC · institutions".into(), hint: "/setup".into(), action: PaletteAction::Navigate("/setup") },
        PaletteItem { label: "DEV — packages · author · CLS · SDK".into(), hint: "/dev".into(), action: PaletteAction::Navigate("/dev") },
        PaletteItem { label: "DEV · SDK".into(), hint: "/dev?tab=sdk".into(), action: PaletteAction::Navigate("/dev?tab=sdk") },
        PaletteItem { label: "DEV · Packages (.cpkg)".into(), hint: "/dev?tab=packages".into(), action: PaletteAction::Navigate("/dev?tab=packages") },
        PaletteItem { label: "DEV · Author".into(), hint: "/dev?tab=author".into(), action: PaletteAction::Navigate("/dev?tab=author") },
        PaletteItem { label: "SETUP · Uplink".into(), hint: "/setup/uplink".into(), action: PaletteAction::Navigate("/setup/uplink") },
        PaletteItem { label: "SETUP · Access (DAC)".into(), hint: "/setup/access".into(), action: PaletteAction::Navigate("/setup/access") },
        PaletteItem { label: "WATCH · Fuel".into(), hint: "/watch?tab=fuel".into(), action: PaletteAction::Navigate("/watch?tab=fuel") },
        PaletteItem { label: "WATCH · Tools".into(), hint: "/watch?tab=tools".into(), action: PaletteAction::Navigate("/watch?tab=tools") },
        PaletteItem { label: "New workflow (templates)".into(), hint: "action".into(), action: PaletteAction::CreateWorkflow },
        PaletteItem { label: "Create intelligence".into(), hint: "5-min apply".into(), action: PaletteAction::CreateAgent },
        PaletteItem { label: "Create intelligence (full page)".into(), hint: "/agents/create".into(), action: PaletteAction::Navigate("/agents/create") },
        PaletteItem { label: "Settings · node".into(), hint: "topic".into(), action: PaletteAction::Topic(DrawerTopic::Settings("node".into())) },
        PaletteItem { label: "Network & proxy".into(), hint: "domains · edge".into(), action: PaletteAction::Topic(DrawerTopic::Settings("network".into())) },
        PaletteItem { label: "LLM routing".into(), hint: "settings".into(), action: PaletteAction::Topic(DrawerTopic::Settings("llm".into())) },
        PaletteItem { label: "Notifications".into(), hint: "inbox".into(), action: PaletteAction::Topic(DrawerTopic::Notifications) },
        PaletteItem { label: "Memory".into(), hint: "topic".into(), action: PaletteAction::Topic(DrawerTopic::Memory) },
        PaletteItem { label: "Trust".into(), hint: "topic".into(), action: PaletteAction::Topic(DrawerTopic::Trust) },
        PaletteItem { label: "Cost & usage".into(), hint: "topic".into(), action: PaletteAction::Topic(DrawerTopic::Cost) },
        PaletteItem { label: "Safety".into(), hint: "topic".into(), action: PaletteAction::Topic(DrawerTopic::Safety) },
        PaletteItem { label: "License".into(), hint: "topic".into(), action: PaletteAction::Topic(DrawerTopic::License) },
        PaletteItem { label: "Secrets".into(), hint: "topic".into(), action: PaletteAction::Topic(DrawerTopic::Secrets) },
        PaletteItem { label: "Component gallery".into(), hint: "dev".into(), action: PaletteAction::Navigate("/dev/components") },
        PaletteItem { label: "Console (DEV tab)".into(), hint: "/dev?tab=console".into(), action: PaletteAction::Navigate("/dev?tab=console") },
        PaletteItem { label: "TraceTramp".into(), hint: "plugin · SETUP".into(), action: PaletteAction::Navigate("/plugins/tracetramp") },
        PaletteItem { label: "WitnessCtl".into(), hint: "plugin · SETUP".into(), action: PaletteAction::Navigate("/plugins/witnessctl") },
        PaletteItem { label: "DevGuard".into(), hint: "plugin · SETUP".into(), action: PaletteAction::Navigate("/plugins/devguard") },
    ]
}

#[component]
pub fn OpPaletteHost() -> impl IntoView {
    let overlay = use_search_overlay();
    view! {
        <Show when=move || overlay.open.get()>
            <OpPalette overlay=overlay />
        </Show>
    }
}

#[component]
pub fn OpPalette(overlay: SearchOverlay) -> impl IntoView {
    let (query, set_query) = signal(String::new());
    let (selected, set_selected) = signal(0usize);
    let (wf_items, set_wf_items) = signal(Vec::<PaletteItem>::new());
    let set_open = overlay.set_open;
    let shared = use_shared_requests();
    let navigate = use_navigate();

    // Load workflow ids into palette
    Effect::new(move |_| {
        if !overlay.open.get() {
            return;
        }
        spawn_local(async move {
            if let Ok(v) = shared.workflows.await {
                set_wf_items.set(workflow_palette_items(&v));
            }
        });
    });

    let run_action: Arc<dyn Fn(PaletteAction) + Send + Sync> = {
        let navigate = navigate.clone();
        Arc::new(move |action: PaletteAction| {
            set_open.set(false);
            match action {
                PaletteAction::Navigate(path) => navigate(path, Default::default()),
                PaletteAction::OpenWorkflow(id) => open_workflow_drawer(id),
                PaletteAction::Topic(t) => open_topic_drawer(t),
                PaletteAction::CreateWorkflow => open_create_workflow(),
                PaletteAction::CreateAgent => open_create_agent(),
            }
        })
    };
    let run_action_keys = run_action.clone();
    let run_action_list = run_action;

    view! {
        <div class="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[12vh]" role="dialog" aria-modal="true" aria-label="Command palette">
            <button
                type="button"
                class="absolute inset-0 bg-black/60 backdrop-blur-sm"
                aria-label="Close palette"
                on:click=move |_| set_open.set(false)
            ></button>
            <div
                class="relative w-full max-w-lg overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl"
                on:keydown=move |ev| {
                    let key = ev.key();
                    let items = filtered_items(&query.get(), &wf_items.get());
                    if key == "Escape" {
                        set_open.set(false);
                    } else if key == "ArrowDown" {
                        ev.prevent_default();
                        let n = items.len().saturating_sub(1);
                        set_selected.update(|i| *i = (*i + 1).min(n));
                    } else if key == "ArrowUp" {
                        ev.prevent_default();
                        set_selected.update(|i| *i = i.saturating_sub(1));
                    } else if key == "Enter" {
                        ev.prevent_default();
                        if let Some(item) = items.get(selected.get()) {
                            run_action_keys(item.action.clone());
                        }
                    }
                }
            >
                <div class="border-b border-zinc-800/60 p-3">
                    <OpSearchField value=query set_value=set_query placeholder="Search modes, workflows, topics…" />
                </div>
                <ul class="max-h-80 overflow-auto py-2" role="listbox">
                    {move || {
                        let run_action = run_action_list.clone();
                        let items = filtered_items(&query.get(), &wf_items.get());
                        let sel = selected.get();
                        if items.is_empty() {
                            return view! {
                                <li class="px-4 py-6 text-center text-xs text-zinc-600">"No matches"</li>
                            }.into_any();
                        }
                        items.into_iter().enumerate().map(|(idx, item)| {
                            let action = item.action.clone();
                            let label = item.label.clone();
                            let hint = item.hint.clone();
                            let active = idx == sel;
                            let run_action = run_action.clone();
                            view! {
                                <li role="option" aria-selected=active.to_string()>
                                    <button
                                        type="button"
                                        class=if active {
                                            "flex w-full items-center justify-between gap-3 bg-zinc-900 px-4 py-2.5 text-left text-sm text-zinc-100"
                                        } else {
                                            "flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left text-sm text-zinc-200 hover:bg-zinc-900"
                                        }
                                        on:click=move |_| run_action(action.clone())
                                    >
                                        <span>{label}</span>
                                        <span class="text-xs font-mono text-zinc-600">{hint}</span>
                                    </button>
                                </li>
                            }
                        }).collect_view().into_any()
                    }}
                </ul>
                <div class="border-t border-zinc-800/60 px-4 py-2 text-[10px] text-zinc-600">
                    "↑↓ navigate · Enter open · Esc close"
                </div>
            </div>
        </div>
    }
}

fn filtered_items(q: &str, workflows: &[PaletteItem]) -> Vec<PaletteItem> {
    let q = q.trim().to_ascii_lowercase();
    let mut all = static_items();
    all.extend(workflows.iter().cloned());
    if q.is_empty() {
        return all;
    }
    all.into_iter()
        .filter(|item| {
            item.label.to_ascii_lowercase().contains(&q)
                || item.hint.to_ascii_lowercase().contains(&q)
        })
        .collect()
}

fn workflow_palette_items(v: &Value) -> Vec<PaletteItem> {
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
            Some(PaletteItem {
                label: format!("Workflow · {id}"),
                hint: "drawer".into(),
                action: PaletteAction::OpenWorkflow(id),
            })
        })
        .take(40)
        .collect()
}

#[component]
pub fn OpPaletteItem(label: String, hint: String, href: String) -> impl IntoView {
    view! {
        <a href=href class="flex items-center justify-between gap-3 rounded-lg px-3 py-2 text-sm hover:bg-zinc-900">
            <span>{label}</span>
            <span class="text-xs text-zinc-600">{hint}</span>
        </a>
    }
}
