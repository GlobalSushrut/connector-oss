//! Create-intelligence wizard — `/agents/create`.
//!
//! Handheld path for POST `/intelligence/apply` (parameters → class →
//! skills/knowledge → world/harden → review). The operator modal is the
//! fast path; this page is the full-screen tour.

use leptos::prelude::*;
use leptos_router::components::A;
use serde::{Deserialize, Serialize};
use serde_json::json;
use wasm_bindgen_futures::spawn_local;

use crate::auth::AuthState;
use crate::components::layout::Header;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};
use crate::iia_api;
use crate::ui_state::{open_agent_workbench, open_create_agent};

const WIZARD_ID: &str = "create-intelligence-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateAgentState {
    name: String,
    namespace: String,
    purpose: String,
    class: String,
    role: String,
    model: String,
    knowledge: String,
    skill_kind: String,
    skill_cap: String,
    portal_type: String,
    portal_entity: String,
    harden: bool,
    token_budget: u64,
}

impl Default for CreateAgentState {
    fn default() -> Self {
        Self {
            name: String::new(),
            namespace: "default".into(),
            purpose: String::new(),
            class: "app".into(),
            role: "writer".into(),
            model: "gpt-4o-mini".into(),
            knowledge: String::new(),
            skill_kind: "tool".into(),
            skill_cap: String::new(),
            portal_type: "http_api".into(),
            portal_entity: String::new(),
            harden: true,
            token_budget: 16_000,
        }
    }
}

#[component]
pub fn CreateAgentWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("Create intelligence");

    let steps = vec![
        WizardStep::new("identity", "Identity")
            .with_subtitle("Name, namespace, and a specific purpose. A blank or general-purpose purpose is not a valid build. Connecting a tool does not admit an effect."),
        WizardStep::new("class", "Classification")
            .with_subtitle("Agentic class seeds default cage capabilities. Skills and portals still bound the real work."),
        WizardStep::new("knowledge", "Model + knowledge")
            .with_subtitle("LLM id plus 1 line or a long ops document. Keys live in Settings → LLM routing, not the cage."),
        WizardStep::new("world", "Skills + world")
            .with_subtitle("Bounded skill (not markdown) and optional portal. Harden = HITL≥tool, forensic≥standard, network deny."),
        WizardStep::new("review", "Review + apply")
            .with_subtitle("Finish POSTs /api/v1/intelligence/apply and lands you in Charter.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<CreateAgentState>(WIZARD_ID);
    let (created_pid, set_created_pid) = signal::<Option<String>>(None);
    let (err, set_err) = signal::<Option<String>>(None);
    let (existing_pid, set_existing_pid) = signal(String::new());

    let on_finish = Callback::new(move |()| {
        if created_pid.get().is_some() {
            return;
        }
        let s = state.get();
        if s.name.trim().is_empty() {
            set_err.set(Some("Name is required".into()));
            return;
        }
        if s.purpose.trim().is_empty() {
            set_err.set(Some("Purpose is required".into()));
            return;
        }
        spawn_local(async move {
            let mut skills = vec![];
            let cap = s.skill_cap.trim();
            if !cap.is_empty() {
                skills.push(json!({
                    "id": "primary",
                    "kind": s.skill_kind,
                    "capability": cap,
                    "risk": "tool",
                    "requires_hitl": true,
                }));
            }
            let mut knowledge_arr = vec![];
            if !s.knowledge.trim().is_empty() {
                knowledge_arr.push(json!({
                    "title": "primary",
                    "content": s.knowledge.trim(),
                }));
            }
            let mut portals = vec![];
            if !s.portal_entity.trim().is_empty() {
                portals.push(json!({
                    "id": "primary",
                    "type": s.portal_type,
                    "entity_id": s.portal_entity.trim(),
                }));
            }
            let body = json!({
                "apiVersion": "connector.ai/v1",
                "kind": "Intelligence",
                "metadata": { "name": s.name.trim() },
                "spec": {
                    "purpose": s.purpose.trim(),
                    "class": s.class,
                    "parameters": {
                        "model": s.model,
                        "namespace": s.namespace,
                        "role": s.role,
                        "token_budget": s.token_budget,
                    },
                    "skills": skills,
                    "knowledge": knowledge_arr,
                    "portals": portals,
                    "harden": s.harden,
                    "activate": true,
                }
            });
            match iia_api::intelligence_apply(body).await {
                Ok(v) => {
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        let cap = v.get("code").and_then(|x| x.as_str())
                            == Some("PLAYGROUND_AGENT_CAP")
                            || v.pointer("/detail/code").and_then(|x| x.as_str())
                                == Some("PLAYGROUND_AGENT_CAP");
                        let existing = v
                            .get("existing_pid")
                            .or_else(|| v.pointer("/detail/existing_pid"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let msg = v
                            .get("error")
                            .or_else(|| v.get("hint"))
                            .or_else(|| v.get("stage"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("apply_failed");
                        if cap {
                            set_existing_pid.set(existing);
                            set_err.set(Some(format!(
                                "This trial allows one agent. Open the Demo already in this session. {msg}"
                            )));
                        } else {
                            set_err.set(Some(format!("Apply failed: {msg}")));
                        }
                        return;
                    }
                    let pid = v
                        .get("pid")
                        .or_else(|| v.get("agent_pid"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    set_created_pid.set(Some(pid.clone()));
                    if let Some(win) = web_sys::window() {
                        let href = if pid.is_empty() {
                            "/agents".into()
                        } else {
                            format!("/agents/{pid}/charter")
                        };
                        let _ = win.location().set_href(&href);
                    }
                }
                Err(e) => set_err.set(Some(e.message)),
            }
        });
    });

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! { <IdentityStep state=state set_state=set_state /> }.into_any(),
            1 => view! { <ClassStep state=state set_state=set_state /> }.into_any(),
            2 => view! { <KnowledgeStep state=state set_state=set_state /> }.into_any(),
            3 => view! { <WorldStep state=state set_state=set_state /> }.into_any(),
            4 => view! { <ReviewStep state=state err=err existing_pid=existing_pid /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    view! {
        <div class="page-wrapper">
            <Header title="Create an agent" auth=auth />
            <div class="page-content max-w-3xl">
                <p class="mb-4 text-sm text-zinc-400">
                    "Need it faster? "
                    <button
                        type="button"
                        class="underline text-zinc-200"
                        on:click=move |_| open_create_agent()
                    >"Quick create"</button>
                    " — name + type, then Talk. This page is the full walkthrough."
                </p>
                <div class="mb-4">
                    <crate::components::operator::overlays::llm_connect::OpLlmQuickConnect />
                </div>
                <WizardShell
                    controller=controller
                    steps=steps
                    step_view=step_view
                    on_finish=on_finish
                    on_cancel=Callback::new(|()| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href("/setup");
                        }
                    })
                />
            </div>
        </div>
    }
}

const CLASSES: &[(&str, &str, &str)] = &[
    ("app", "App", "Software / product tasks — Talk + tools + memory"),
    ("robotics", "Robotics", "Machines & actuators — CONP + signal"),
    ("iot", "IoT", "Devices & sensors — CONP device.*"),
    ("cybernetic", "Cybernetic", "Security ops — high HITL expected"),
    ("service", "Service", "API / backend agent — network + tools"),
    ("custom", "Custom", "You define skills, portals, and rules"),
];

#[component]
fn IdentityStep(
    state: ReadSignal<CreateAgentState>,
    set_state: WriteSignal<CreateAgentState>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Name"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500/60"
                    placeholder="warehouse-picker"
                    prop:value=move || state.get().name
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.name = v);
                    }
                />
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Purpose (required)"</span>
                <textarea
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500/60 min-h-[4.5rem]"
                    placeholder="Pick and place in aisle B"
                    prop:value=move || state.get().purpose
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.purpose = v);
                    }
                ></textarea>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Namespace"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    placeholder="default"
                    prop:value=move || state.get().namespace
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.namespace = v);
                    }
                />
            </label>
        </div>
    }
}

#[component]
fn ClassStep(
    state: ReadSignal<CreateAgentState>,
    set_state: WriteSignal<CreateAgentState>,
) -> impl IntoView {
    view! {
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {CLASSES.iter().map(|(slug, title, hint)| {
                let slug_owned = slug.to_string();
                let selected = {
                    let s = slug_owned.clone();
                    Memo::new(move |_| state.get().class == s)
                };
                let slug_click = slug_owned.clone();
                view! {
                    <button
                        type="button"
                        class=move || if selected.get() {
                            "rounded-lg border border-indigo-500/50 bg-indigo-500/10 px-3 py-2 text-left"
                        } else {
                            "rounded-lg border border-zinc-800/60 bg-zinc-900/40 px-3 py-2 text-left hover:border-zinc-700/80"
                        }
                        on:click=move |_| {
                            let v = slug_click.clone();
                            set_state.update(|s| s.class = v);
                        }
                    >
                        <p class="text-sm font-semibold text-zinc-100">{*title}</p>
                        <p class="mt-0.5 text-[11px] text-zinc-500">{*hint}</p>
                    </button>
                }
            }).collect::<Vec<_>>()}
        </div>
    }
}

#[component]
fn KnowledgeStep(
    state: ReadSignal<CreateAgentState>,
    set_state: WriteSignal<CreateAgentState>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Model"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    placeholder="gpt-4o-mini"
                    prop:value=move || state.get().model
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.model = v);
                    }
                />
            </label>
            <p class="text-[11px] text-zinc-500">
                "Provider keys: "
                <A href="/setup" attr:class="text-indigo-400">"Setup → LLM routing"</A>
                " (vault, not cage)."
            </p>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Knowledge (1 line or long doc)"</span>
                <textarea
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500/60 min-h-[8rem]"
                    placeholder="Never exceed 2m/s in aisle B. Bay doors require human approval."
                    prop:value=move || state.get().knowledge
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.knowledge = v);
                    }
                ></textarea>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Token budget (per call window)"</span>
                <input
                    type="number"
                    class="w-40 px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    prop:value=move || state.get().token_budget
                    on:input=move |ev| {
                        let v: u64 = event_target_value(&ev).parse().unwrap_or(0);
                        set_state.update(|s| s.token_budget = v);
                    }
                />
            </label>
        </div>
    }
}

#[component]
fn WorldStep(
    state: ReadSignal<CreateAgentState>,
    set_state: WriteSignal<CreateAgentState>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Skill kind"</span>
                <select
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100"
                    on:change=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.skill_kind = v);
                    }
                >
                    {["tool", "conp", "mcp", "http", "memory", "fabric"].into_iter().map(|k| {
                        let selected = {
                            let k = k.to_string();
                            Memo::new(move |_| state.get().skill_kind == k)
                        };
                        view! { <option value=k selected=move || selected.get()>{k}</option> }
                    }).collect::<Vec<_>>()}
                </select>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Capability (optional)"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono"
                    placeholder="web_search · or machine.move_axis"
                    prop:value=move || state.get().skill_cap
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.skill_cap = v);
                    }
                />
                <p class="mt-1 text-[11px] text-zinc-500">"Empty = no bound skill yet; Charter can add more. If set, tools/CONP must match."</p>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Portal type"</span>
                <select
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100"
                    on:change=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.portal_type = v);
                    }
                >
                    {["http_api", "machine", "device", "sensor", "actuator", "mqtt", "mcp", "a2a", "cluster", "custom"]
                        .into_iter()
                        .map(|k| {
                            let selected = {
                                let k = k.to_string();
                                Memo::new(move |_| state.get().portal_type == k)
                            };
                            view! { <option value=k selected=move || selected.get()>{k}</option> }
                        })
                        .collect::<Vec<_>>()}
                </select>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Portal entity (optional)"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono"
                    placeholder="machine:arm-1 or https://…"
                    prop:value=move || state.get().portal_entity
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.portal_entity = v);
                    }
                />
            </label>
            <label class="inline-flex items-center gap-2 text-sm text-zinc-200">
                <input
                    type="checkbox"
                    prop:checked=move || state.get().harden
                    on:change=move |ev| {
                        let on = event_target_checked(&ev);
                        set_state.update(|s| s.harden = on);
                    }
                />
                "Harden membrane (HITL≥tool, forensic≥standard, network deny)"
            </label>
        </div>
    }
}

#[component]
fn ReviewStep(
    state: ReadSignal<CreateAgentState>,
    err: ReadSignal<Option<String>>,
    existing_pid: ReadSignal<String>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            {move || {
                let s = state.get();
                let json = serde_json::to_string_pretty(&s).unwrap_or_default();
                view! {
                    <pre class="rounded-lg border border-zinc-800/60 bg-zinc-950/60 px-3 py-3 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap max-h-72 overflow-auto">{json}</pre>
                }
            }}
            {move || err.get().map(|m| view! {
                <p class="text-xs text-amber-300">{m}</p>
            })}
            {move || {
                let pid = existing_pid.get();
                if pid.is_empty() {
                    return ().into_any();
                }
                view! {
                    <button
                        type="button"
                        class="rounded-lg border border-cyan-800/60 bg-cyan-950/40 px-3 py-2 text-sm font-medium text-cyan-100 hover:bg-cyan-950/70"
                        on:click=move |_| open_agent_workbench(pid.clone())
                    >
                        "Open Demo Workbench"
                    </button>
                }.into_any()
            }}
            <p class="text-[11px] text-zinc-500">
                "Finish applies register → setup → contract → knowledge → activate. Audited membrane crossings only — not SIL-certified robotics. Court green only with WC+CFNI."
            </p>
        </div>
    }
}
