//! Quick create — name + class + optional LLM, then POST /intelligence/apply.

use leptos::prelude::*;
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::components::operator::overlays::llm_connect::OpLlmQuickConnect;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpSelect, OpSwitch, OpTextField,
};
use crate::iia_api;
use crate::request_store::bump_reload;
use crate::ui_state::{open_agent_workbench, use_create_modal, CreateModalKind};

#[component]
pub fn OpCreateAgentHost() -> impl IntoView {
    let modal = use_create_modal();
    view! {
        <Show when=move || modal.kind.get() == CreateModalKind::Agent>
            <OpCreateAgentModal />
        </Show>
    }
}

#[component]
fn OpCreateAgentModal() -> impl IntoView {
    let modal = use_create_modal();
    let (name, set_name) = signal(String::new());
    let (purpose, set_purpose) = signal(String::new());
    let (class, set_class) = signal("app".to_string());
    let (knowledge, set_knowledge) = signal(String::new());
    let (skill_cap, set_skill_cap) = signal(String::new());
    let (skill_kind, set_skill_kind) = signal("tool".to_string());
    let (portal_entity, set_portal_entity) = signal(String::new());
    let (portal_type, set_portal_type) = signal("http_api".to_string());
    let (harden, set_harden) = signal(true);
    let (more, set_more) = signal(false);
    let (busy, set_busy) = signal(false);
    let (error, set_error) = signal(String::new());
    let (existing_pid, set_existing_pid) = signal(String::new());

    let close = move || modal.set_kind.set(CreateModalKind::None);

    Effect::new(move |_| {
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;
        let cb = Closure::<dyn FnMut(_)>::new(move |ev: web_sys::KeyboardEvent| {
            if ev.key() == "Escape" {
                modal.set_kind.set(CreateModalKind::None);
            }
        });
        if let Some(w) = web_sys::window() {
            let _ = w.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
            cb.forget();
        }
    });

    let apply = {
        let modal = modal;
        Arc::new(move |_| {
            let n = name.get_untracked().trim().to_string();
            if n.is_empty() {
                set_error.set("Give it a name.".into());
                return;
            }
            let mut purpose_s = purpose.get_untracked().trim().to_string();
            if purpose_s.is_empty() {
                purpose_s = knowledge.get_untracked().trim().to_string();
            }
            if purpose_s.is_empty() {
                set_error.set("Name the job this agent is for — purpose is required.".into());
                return;
            }
            set_busy.set(true);
            set_error.set(String::new());
            set_existing_pid.set(String::new());
            let class_s = class.get_untracked();
            let mut skills = vec![];
            let cap = skill_cap.get_untracked().trim().to_string();
            if !cap.is_empty() {
                skills.push(json!({
                    "id": "primary",
                    "kind": skill_kind.get_untracked(),
                    "capability": cap,
                    "risk": "tool",
                    "requires_hitl": true,
                }));
            }
            let mut knowledge_arr = vec![];
            let k = knowledge.get_untracked().trim().to_string();
            if !k.is_empty() {
                knowledge_arr.push(json!({ "title": "primary", "content": k }));
            }
            let instructions = if k.is_empty() {
                purpose_s.clone()
            } else {
                format!("{purpose_s}\n\n{k}")
            };
            let mut portals = vec![];
            let ent = portal_entity.get_untracked().trim().to_string();
            if !ent.is_empty() {
                portals.push(json!({
                    "id": "primary",
                    "type": portal_type.get_untracked(),
                    "entity_id": ent,
                }));
            }
            spawn_local(async move {
                let model = match crate::api::get_value_timeout("/settings/llms/status", 5_000).await {
                    Ok(st) => {
                        let src = crate::api::resource_object(&st);
                        src.get("model")
                            .and_then(|x| x.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                    }
                    Err(_) => None,
                };
                let body = json!({
                    "apiVersion": "connector.ai/v1",
                    "kind": "Intelligence",
                    "metadata": { "name": n },
                    "spec": {
                        "purpose": purpose_s,
                        "class": class_s,
                        "parameters": {
                            "model": model,
                            "namespace": "default",
                            "role": "reader",
                            "instructions": instructions,
                        },
                        "skills": skills,
                        "knowledge": knowledge_arr,
                        "portals": portals,
                        "harden": harden.get_untracked(),
                        "activate": true,
                    }
                });
                match iia_api::intelligence_apply(body).await {
                    Ok(v) => {
                        let existing = v
                            .get("existing_pid")
                            .or_else(|| v.pointer("/detail/existing_pid"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let cap = v.get("code").and_then(|x| x.as_str())
                            == Some("PLAYGROUND_AGENT_CAP")
                            || v.pointer("/detail/code").and_then(|x| x.as_str())
                                == Some("PLAYGROUND_AGENT_CAP");
                        if cap || v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                            let err = v
                                .get("error")
                                .or_else(|| v.pointer("/detail/error"))
                                .or_else(|| v.get("hint"))
                                .and_then(|x| {
                                    if x.is_string() {
                                        x.as_str().map(|s| s.to_string())
                                    } else {
                                        Some(x.to_string())
                                    }
                                })
                                .unwrap_or_else(|| "Could not create the agent.".into());
                            set_existing_pid.set(existing);
                            set_error.set(err);
                            set_busy.set(false);
                            return;
                        }
                        let pid = v
                            .get("pid")
                            .or_else(|| v.get("agent_pid"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        bump_reload();
                        modal.set_kind.set(CreateModalKind::None);
                        if !pid.is_empty() {
                            open_agent_workbench(pid);
                        }
                    }
                    Err(e) => {
                        set_error.set(e.message);
                    }
                }
                set_busy.set(false);
            });
        })
    };

    view! {
        <div class="fixed inset-0 z-[95] flex items-center justify-center p-3 sm:p-4" role="dialog" aria-modal="true" aria-label="Create agent">
            <button type="button" class="absolute inset-0 z-0 bg-black/65 backdrop-blur-sm" aria-label="Close" on:click=move |_| close()></button>
            <div
                class="relative z-10 flex max-h-[92vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl"
                on:click=move |ev| ev.stop_propagation()
                on:mousedown=move |ev| ev.stop_propagation()
            >
                <div class="flex shrink-0 items-start justify-between gap-3 border-b border-zinc-800/80 px-5 py-4">
                    <div>
                        <h2 class="text-base font-semibold text-zinc-100">"Create an agent"</h2>
                        <p class="mt-0.5 text-[12px] text-zinc-400">
                            "Name it and name the job. This trial seeds one Demo (max 1). A second create is refused — open Demo instead."
                        </p>
                    </div>
                    <button type="button" class="text-zinc-500 hover:text-zinc-200" on:click=move |_| close()>"×"</button>
                </div>
                <div class="min-h-0 flex-1 overflow-y-auto px-5 py-4 space-y-4">
                    <Show when=move || !error.get().is_empty()>
                        <p class="rounded-md border border-red-900/40 bg-red-950/30 px-3 py-2 text-xs text-red-300">{move || error.get()}</p>
                    </Show>

                    <OpLlmQuickConnect />

                    <OpTextField label="Name".to_string() value=name set_value=set_name placeholder="research-helper" />
                    <label class="flex flex-col gap-1.5">
                        <span class="text-xs font-medium text-zinc-400">"What should it do?"</span>
                        <textarea
                            class="min-h-[56px] rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:ring-1 focus:ring-indigo-500/50"
                            placeholder="Guard src/ writes. Review PRs. Record who did what."
                            prop:value=move || purpose.get()
                            on:input=move |ev| set_purpose.set(event_target_value(&ev))
                        ></textarea>
                    </label>

                    <div>
                        <p class="mb-1.5 text-xs font-medium text-zinc-400">"Type"</p>
                        <div class="grid grid-cols-2 gap-1.5">
                            {CLASS_CARDS.iter().map(|(slug, title, hint)| {
                                let slug_owned = (*slug).to_string();
                                let selected = {
                                    let s = slug_owned.clone();
                                    move || class.get() == s
                                };
                                let slug_click = slug_owned.clone();
                                view! {
                                    <button
                                        type="button"
                                        class=move || if selected() {
                                            "rounded-lg border border-emerald-500/50 bg-emerald-500/10 px-2.5 py-2 text-left"
                                        } else {
                                            "rounded-lg border border-zinc-800/60 bg-zinc-900/40 px-2.5 py-2 text-left hover:border-zinc-700"
                                        }
                                        on:click=move |_| set_class.set(slug_click.clone())
                                    >
                                        <p class="text-[13px] font-semibold text-zinc-100">{*title}</p>
                                        <p class="mt-0.5 text-[10px] text-zinc-500">{*hint}</p>
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                    </div>

                    <button
                        type="button"
                        class="text-[11px] text-zinc-500 hover:text-zinc-300"
                        on:click=move |_| set_more.update(|v| *v = !*v)
                    >
                        {move || if more.get() { "Hide extra options" } else { "More options — knowledge, tools, world portal" }}
                    </button>
                    <Show when=move || more.get()>
                        <div class="space-y-3 rounded-lg border border-zinc-800/70 p-3">
                            <label class="flex flex-col gap-1.5">
                                <span class="text-xs font-medium text-zinc-400">"Knowledge (optional)"</span>
                                <textarea
                                    class="min-h-[72px] rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2 text-sm text-zinc-200"
                                    placeholder="Paste notes or a one-liner the agent should remember"
                                    prop:value=move || knowledge.get()
                                    on:input=move |ev| set_knowledge.set(event_target_value(&ev))
                                ></textarea>
                            </label>
                            <div class="grid grid-cols-2 gap-2">
                                <OpSelect
                                    label="Skill kind"
                                    value=skill_kind
                                    set_value=set_skill_kind
                                    options=vec![
                                        ("tool".into(), "tool".into()),
                                        ("conp".into(), "conp".into()),
                                        ("mcp".into(), "mcp".into()),
                                        ("http".into(), "http".into()),
                                    ]
                                />
                                <OpTextField label="Capability".to_string() value=skill_cap set_value=set_skill_cap placeholder="web_search" />
                            </div>
                            <div class="grid grid-cols-2 gap-2">
                                <OpSelect
                                    label="Portal"
                                    value=portal_type
                                    set_value=set_portal_type
                                    options=vec![
                                        ("http_api".into(), "http_api".into()),
                                        ("browser".into(), "browser".into()),
                                        ("machine".into(), "machine".into()),
                                        ("device".into(), "device".into()),
                                        ("mcp".into(), "mcp".into()),
                                    ]
                                />
                                <OpTextField label="Entity / URL".to_string() value=portal_entity set_value=set_portal_entity placeholder="https://…" />
                            </div>
                            <OpSwitch
                                checked=harden
                                set_checked=set_harden
                                label="Harden membrane (recommended)".to_string()
                            />
                        </div>
                    </Show>
                </div>
                <div class="flex shrink-0 flex-col gap-2 border-t border-zinc-800/80 px-5 py-3">
                    <Show when=move || !error.get().is_empty()>
                        <p class="text-xs text-red-300">{move || error.get()}</p>
                    </Show>
                    <Show when=move || !existing_pid.get().is_empty()>
                        <OpButton
                            label="Open Demo Workbench".to_string()
                            variant=OpButtonVariant::Primary
                            on_click=Arc::new(move |_| {
                                let pid = existing_pid.get_untracked();
                                if !pid.is_empty() {
                                    modal.set_kind.set(CreateModalKind::None);
                                    open_agent_workbench(pid);
                                }
                            })
                        />
                    </Show>
                    <div class="flex items-center justify-between gap-2">
                        <a href="/agents/create" class="text-[11px] text-zinc-500 hover:text-zinc-300" on:click=move |_| close()>
                            "Step-by-step wizard"
                        </a>
                        <div class="flex gap-2">
                            <OpButton label="Cancel".to_string() variant=OpButtonVariant::Ghost on_click=Arc::new(move |_| close()) />
                            <button
                                type="button"
                                class="inline-flex h-9 items-center justify-center rounded-lg bg-indigo-600 px-4 text-sm font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
                                disabled=move || busy.get()
                                on:click=move |ev| {
                                    ev.stop_propagation();
                                    apply(ev);
                                }
                            >{move || if busy.get() { "Creating…" } else { "Create agent" }}</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

const CLASS_CARDS: &[(&str, &str, &str)] = &[
    ("app", "App", "Chat, docs, tools"),
    ("service", "Service", "APIs & backends"),
    ("robotics", "Robotics", "Machines / CONP"),
    ("iot", "IoT", "Devices & sensors"),
    ("cybernetic", "Security", "High HITL ops"),
    ("custom", "Custom", "You set bounds"),
];
