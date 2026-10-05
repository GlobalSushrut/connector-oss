//! Install-a-workflow wizard — `/setup/install-workflow/:template_id`.
//!
//! Phase 4.4 surface. Operators can also reach this from the Apps Hub
//! template cards (the one-click `[ Install ]` path bypasses the
//! wizard); this is the *guided* variant for operators who want to
//! preview the CCL and pick a namespace before they commit.
//!
//! Steps:
//!
//! 1. **Preview** — show the reference template's metadata + CCL.
//! 2. **Configure** — choose workflow id, namespace, version label.
//! 3. **Confirm** — display the final payload, POST `/workflows`.
//! 4. **Done** — land on `/workflows/{id}`.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::layout::Header;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};

const WIZARD_ID: &str = "install-workflow";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InstallWorkflowState {
    workflow_id: String,
    namespace: String,
    version_label: String,
}

#[component]
pub fn InstallWorkflowWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("PKG · Workflow load");

    let params = use_params_map();
    let template_id_signal = Memo::new(move |_| {
        params
            .with(|p| p.get("template_id").map(|s| s.to_string()))
            .unwrap_or_default()
    });

    let template_res = LocalResource::new(|| api::get_value("/workflows/reference-templates"));

    let steps = vec![
        WizardStep::new("preview", "Preview template")
            .with_subtitle("CCL source + which plugins this workflow uses."),
        WizardStep::new("configure", "Choose namespace + id")
            .with_subtitle("Workflow id is what shows in `/workflows`. Namespace scopes RBAC."),
        WizardStep::new("confirm", "Confirm + install")
            .with_subtitle("Sends the POST to /api/v1/workflows."),
        WizardStep::new("done", "Installed")
            .with_subtitle("Click Finish to open the workflow's run page.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<InstallWorkflowState>(WIZARD_ID);

    // Default the workflow id once we know the template id.
    Effect::new(move |_| {
        let id = template_id_signal.get();
        if !id.is_empty() {
            set_state.update(|s| {
                if s.workflow_id.is_empty() {
                    s.workflow_id = format!("ref-{id}");
                }
                if s.namespace.is_empty() {
                    s.namespace = "default".into();
                }
                if s.version_label.is_empty() {
                    s.version_label = "v1".into();
                }
            });
        }
    });

    let (final_id, set_final_id) = signal::<Option<String>>(None);
    let (install_err, set_install_err) = signal::<Option<String>>(None);

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! {
                <PreviewStep
                    template_res=template_res
                    template_id=template_id_signal
                />
            }.into_any(),
            1 => view! { <ConfigureStep state=state set_state=set_state /> }.into_any(),
            2 => view! {
                <ConfirmStep
                    template_res=template_res
                    template_id=template_id_signal
                    state=state
                    final_id=final_id
                    set_final_id=set_final_id
                    install_err=install_err
                    set_install_err=set_install_err
                />
            }.into_any(),
            3 => view! { <DoneStep final_id=final_id /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    view! {
        <div class="page-wrapper">
            <Header title="PKG · Workflow load" auth=auth />
            <div class="page-content max-w-3xl fcs-install">
                <WizardShell
                    class="fcs-wizard"
                    controller=controller
                    steps=steps
                    step_view=step_view
                    on_finish=Callback::new(move |()| {
                        let wid = final_id.get().unwrap_or_else(|| state.get().workflow_id);
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href(&format!("/workflows/{wid}"));
                        }
                    })
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

fn find_template<'a>(templates: &'a Value, id: &str) -> Option<&'a Value> {
    templates
        .get("templates")
        .and_then(|x| x.as_array())
        .and_then(|arr| arr.iter().find(|t| t.get("id").and_then(|v| v.as_str()) == Some(id)))
}

#[component]
fn PreviewStep(
    template_res: LocalResource<Result<Value, api::ApiError>>,
    template_id: Memo<String>,
) -> impl IntoView {
    view! {
        <Suspense fallback=|| view! { <p class="text-sm text-zinc-500">"Loading template…"</p> }>
            {move || Suspend::new(async move {
                let id = template_id.get();
                if id.is_empty() {
                    return view! {
                        <p class="text-sm text-amber-300">"No template id in URL. Pick one from /apps."</p>
                    }.into_any();
                }
                match template_res.await {
                    Ok(v) => {
                        let tpl_opt = find_template(&v, &id).cloned();
                        match tpl_opt {
                            None => view! {
                                <p class="text-sm text-amber-300">{format!("Template `{id}` not found on this server.")}</p>
                            }.into_any(),
                            Some(tpl) => {
                                let name = tpl.get("name").and_then(|x| x.as_str()).unwrap_or(&id).to_string();
                                let desc = tpl.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let cls = tpl.get("cls_source").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let plugins: Vec<String> = tpl.get("plugins")
                                    .and_then(|x| x.as_array())
                                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                                    .unwrap_or_default();
                                view! {
                                    <div class="space-y-3">
                                        <div>
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Template"</p>
                                            <h3 class="text-lg font-semibold text-zinc-100">{name}</h3>
                                            <p class="text-sm text-zinc-400 mt-1">{desc}</p>
                                        </div>
                                        {
                                            let plugins_when = plugins.clone();
                                            view! {
                                                <Show when=move || !plugins_when.is_empty()>
                                                    <div class="flex flex-wrap gap-1.5">
                                                        {plugins.iter().cloned().map(|p| view! {
                                                            <span class="px-2 py-0.5 rounded-md bg-zinc-800/60 text-zinc-400 border border-zinc-700/60 font-mono text-[10px]">{p}</span>
                                                        }).collect::<Vec<_>>()}
                                                    </div>
                                                </Show>
                                            }
                                        }
                                        <details class="rounded-lg border border-zinc-800/60 bg-zinc-950/60 px-3 py-2">
                                            <summary class="text-[10px] uppercase tracking-wider text-zinc-500 cursor-pointer hover:text-zinc-300">
                                                "CCL source"
                                            </summary>
                                            <pre class="mt-2 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap max-h-72 overflow-auto">{cls}</pre>
                                        </details>
                                    </div>
                                }.into_any()
                            }
                        }
                    }
                    Err(e) => view! {
                        <p class="text-sm text-amber-300">{format!("Failed to load templates: {}", e.message)}</p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

#[component]
fn ConfigureStep(
    state: ReadSignal<InstallWorkflowState>,
    set_state: WriteSignal<InstallWorkflowState>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Workflow id"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    prop:value=move || state.get().workflow_id
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.workflow_id = v);
                    }
                />
                <p class="text-[11px] text-zinc-500 mt-1">"Visible in /workflows. The default `ref-<template>` keeps reference installs distinct."</p>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Namespace"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    prop:value=move || state.get().namespace
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.namespace = v);
                    }
                />
                <p class="text-[11px] text-zinc-500 mt-1">"RBAC scope — operators only see workflows in their assigned namespaces."</p>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Version label"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    prop:value=move || state.get().version_label
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.version_label = v);
                    }
                />
            </label>
        </div>
    }
}

#[component]
fn ConfirmStep(
    template_res: LocalResource<Result<Value, api::ApiError>>,
    template_id: Memo<String>,
    state: ReadSignal<InstallWorkflowState>,
    final_id: ReadSignal<Option<String>>,
    set_final_id: WriteSignal<Option<String>>,
    install_err: ReadSignal<Option<String>>,
    set_install_err: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);

    let on_install = move |_| {
        if busy.get() || final_id.get().is_some() {
            return;
        }
        set_busy.set(true);
        set_install_err.set(None);
        let tpl_id = template_id.get();
        let s = state.get();
        spawn_local(async move {
            let body = match template_res.await {
                Ok(v) => match find_template(&v, &tpl_id) {
                    None => {
                        set_install_err.set(Some(format!("Template `{tpl_id}` not found.")));
                        set_busy.set(false);
                        return;
                    }
                    Some(t) => t.clone(),
                },
                Err(e) => {
                    set_install_err.set(Some(format!("Could not load template: {}", e.message)));
                    set_busy.set(false);
                    return;
                }
            };
            let cls_source = body
                .get("cls_source")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            // Prefer template-declared accounting; else infer from plugin list (service vs action).
            let accounting_mode = body
                .pointer("/accounting/mode")
                .or_else(|| body.get("accounting_mode"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    let plugins = body
                        .get("plugins")
                        .and_then(|p| p.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let has_dg = plugins.iter().any(|p| p.as_str() == Some("devguard"));
                    let has_svc = plugins.iter().any(|p| {
                        matches!(p.as_str(), Some("tracetramp") | Some("witnessctl"))
                    });
                    if has_dg {
                        "action".into()
                    } else if has_svc {
                        "service_monitoring".into()
                    } else {
                        "action".into()
                    }
                });
            let payload = json!({
                "workflow_id": s.workflow_id,
                "package_id": tpl_id,
                "version": s.version_label,
                "cls_source": cls_source,
                "accounting_mode": accounting_mode,
            });
            match api::post_value("/workflows", payload).await {
                Ok(_) => set_final_id.set(Some(s.workflow_id.clone())),
                Err(e) => set_install_err.set(Some(format!("Install failed: {}", e.message))),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            {move || {
                let s = state.get();
                view! {
                    <dl class="grid grid-cols-3 gap-x-4 gap-y-1 text-xs">
                        <dt class="text-zinc-500">"Template"</dt>
                        <dd class="col-span-2 text-zinc-200 font-mono">{template_id.get()}</dd>
                        <dt class="text-zinc-500">"Workflow id"</dt>
                        <dd class="col-span-2 text-zinc-200 font-mono">{s.workflow_id.clone()}</dd>
                        <dt class="text-zinc-500">"Namespace"</dt>
                        <dd class="col-span-2 text-zinc-200 font-mono">{s.namespace.clone()}</dd>
                        <dt class="text-zinc-500">"Version"</dt>
                        <dd class="col-span-2 text-zinc-200 font-mono">{s.version_label.clone()}</dd>
                    </dl>
                }
            }}
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-60"
                prop:disabled=move || busy.get() || final_id.get().is_some()
                on:click=on_install
            >
                {move || if final_id.get().is_some() {
                    "Installed ✓".to_string()
                } else if busy.get() {
                    "Installing…".to_string()
                } else {
                    "Install workflow".to_string()
                }}
            </button>
            {move || install_err.get().map(|m| view! {
                <p class="text-xs text-amber-300">{m}</p>
            })}
            {move || final_id.get().map(|id| view! {
                <p class="text-xs text-emerald-300">{format!("Workflow `{id}` registered. Click Next to continue.")}</p>
            })}
            <p class="text-[11px] text-zinc-500 dev-only">"POST /api/v1/workflows with the shipped CCL source. Server may re-parse the contract; if it rejects you'll see an error above."</p>
        </div>
    }
}

#[component]
fn DoneStep(final_id: ReadSignal<Option<String>>) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-200">"Workflow installed."</p>
            {move || final_id.get().map(|id| {
                let href = format!("/workflows/{id}");
                let label = format!("Open /workflows/{id} →");
                view! {
                    <A href=href attr:class="text-xs text-indigo-400 hover:text-indigo-300 underline-offset-2 hover:underline">
                        {label}
                    </A>
                }
            })}
            <p class="text-xs text-zinc-500">"Finish takes you straight to the workflow's run page."</p>
        </div>
    }
}
