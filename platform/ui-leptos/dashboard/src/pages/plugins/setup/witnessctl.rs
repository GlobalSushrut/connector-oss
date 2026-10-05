//! WitnessCtl setup wizard — `/plugins/witnessctl/setup`.
//!
//! Service institution: management URL + admin token for evidence APIs.
//! Uses real `POST /plugins/witnessctl/configure` + probe `GET /plugins/witnessctl/health`.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};

const WIZARD_ID: &str = "witnessctl-setup";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WitnessCtlState {
    management_url: String,
    admin_token: String,
    save_msg: String,
    probe_json: String,
}

impl Default for WitnessCtlState {
    fn default() -> Self {
        Self {
            management_url: "http://127.0.0.1:7443".into(),
            admin_token: String::new(),
            save_msg: String::new(),
            probe_json: String::new(),
        }
    }
}

#[component]
pub fn WitnessCtlSetupWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("WitnessCtl setup");
    let navigate = use_navigate();

    let steps = vec![
        WizardStep::new("kind", "Service tool")
            .with_subtitle("WitnessCtl seals evidence — configure the management plane, not a coding workspace."),
        WizardStep::new("creds", "Management credentials")
            .with_subtitle("Saved via POST /plugins/witnessctl/configure (env vars still override)."),
        WizardStep::new("probe", "Probe health")
            .with_subtitle("GET /plugins/witnessctl/health — proves the hub can reach WitnessCtl.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<WitnessCtlState>(WIZARD_ID);

    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(v) = api::get_value("/plugins/witnessctl/configure").await {
                if let Some(vals) = v.get("values").and_then(|x| x.as_object()) {
                    set_state.update(|s| {
                        if let Some(u) = vals.get("management_url").and_then(|x| x.as_str()) {
                            if !u.is_empty() {
                                s.management_url = u.to_string();
                            }
                        }
                        if s.admin_token.is_empty() {
                            if let Some(t) = vals.get("admin_token").and_then(|x| x.as_str()) {
                                s.admin_token = t.to_string();
                            }
                        }
                    });
                }
            }
        });
    });

    let on_finish = Callback::new(move |()| {
        navigate("/plugins/witnessctl", Default::default());
    });

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! { <KindStep /> }.into_any(),
            1 => view! { <CredsStep state=state set_state=set_state /> }.into_any(),
            2 => view! { <ProbeStep state=state set_state=set_state /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    let _ = auth;
    view! {
        <div class="w-full px-4 py-6 pb-10">
            <div class="mx-auto w-full max-w-3xl space-y-4">
                <div>
                    <h1 class="text-lg font-semibold text-zinc-100">"WitnessCtl · Setup"</h1>
                    <p class="mt-1 text-xs text-zinc-500">"Service tool — management URL + token. License unlock still applies."</p>
                </div>
                <WizardShell
                    controller=controller
                    steps=steps
                    step_view=step_view
                    on_finish=on_finish
                    on_cancel=Callback::new(|()| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href("/plugins/witnessctl");
                        }
                    })
                />
                <p class="text-center text-[11px] text-zinc-600">
                    "License: open SETUP → License topic."
                </p>
            </div>
        </div>
    }
}

#[component]
fn KindStep() -> impl IntoView {
    view! {
        <div class="space-y-3 text-sm text-zinc-300">
            <p>"WitnessCtl is a "<span class="text-zinc-100 font-medium">"service tool"</span>" — seal/receipt APIs behind a management URL. Policy toggles that looked like a 5-module install were never persisted by a real endpoint."</p>
            <ul class="list-disc pl-5 space-y-1 text-xs text-zinc-500">
                <li>"Real API: POST /plugins/witnessctl/configure"</li>
                <li>"Probe: GET /plugins/witnessctl/health and /plugins/witnessctl/status"</li>
                <li>"Fake removed: POST /plugins/witnessctl/setup"</li>
            </ul>
        </div>
    }
}

#[component]
fn CredsStep(
    state: ReadSignal<WitnessCtlState>,
    set_state: WriteSignal<WitnessCtlState>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);

    let on_save = move |_| {
        if busy.get() {
            return;
        }
        let url = state.get().management_url.trim().to_string();
        let token = state.get().admin_token.trim().to_string();
        if url.is_empty() || token.is_empty() {
            set_state.update(|s| {
                s.save_msg = "Management URL and admin token are both required.".into();
            });
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            let body = serde_json::json!({
                "values": {
                    "management_url": url,
                    "admin_token": token
                }
            });
            match api::post_value("/plugins/witnessctl/configure", body).await {
                Ok(v) => {
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        set_state.update(|s| {
                            s.save_msg = v
                                .get("error")
                                .and_then(|x| x.as_str())
                                .unwrap_or("configure failed")
                                .to_string();
                        });
                    } else {
                        set_state.update(|s| {
                            s.save_msg =
                                "Saved. Proxies use overlay now; process env still wins if set."
                                    .into();
                        });
                    }
                }
                Err(e) => set_state.update(|s| s.save_msg = e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Management URL"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono"
                    prop:value=move || state.get().management_url
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.management_url = v);
                    }
                />
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Admin token"</span>
                <input
                    type="password"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono"
                    prop:value=move || state.get().admin_token
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.admin_token = v);
                    }
                />
            </label>
            <p class="text-[11px] text-zinc-500 font-mono">
                "Equivalent env: CONNECTOR_WITNESSCTL_MANAGEMENT_URL + CONNECTOR_WITNESSCTL_ADMIN_TOKEN"
            </p>
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-60"
                prop:disabled=move || busy.get()
                on:click=on_save
            >
                {move || if busy.get() { "Saving…" } else { "Save configure" }}
            </button>
            {move || {
                let m = state.get().save_msg;
                if m.is_empty() {
                    view! { <span></span> }.into_any()
                } else {
                    view! { <p class="text-xs text-zinc-300">{m}</p> }.into_any()
                }
            }}
        </div>
    }
}

#[component]
fn ProbeStep(
    state: ReadSignal<WitnessCtlState>,
    set_state: WriteSignal<WitnessCtlState>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);

    let on_probe = move |_| {
        if busy.get() {
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            let mut out = String::new();
            match api::get_value("/plugins/witnessctl/health").await {
                Ok(v) => {
                    out.push_str("GET /plugins/witnessctl/health\n");
                    out.push_str(&serde_json::to_string_pretty(&v).unwrap_or_default());
                }
                Err(e) => out.push_str(&format!("health: {}\n", e.message)),
            }
            match api::get_value("/plugins/witnessctl/status").await {
                Ok(v) => {
                    out.push_str("\n\nGET /plugins/witnessctl/status\n");
                    out.push_str(&serde_json::to_string_pretty(&v).unwrap_or_default());
                }
                Err(e) => out.push_str(&format!("\nstatus: {}", e.message)),
            }
            set_state.update(|s| s.probe_json = out);
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-300">
                "Probe before Finish. Health can succeed with URL only; sessions/export need the admin token."
            </p>
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-60"
                prop:disabled=move || busy.get()
                on:click=on_probe
            >
                {move || if busy.get() { "Probing…" } else { "Probe WitnessCtl" }}
            </button>
            {move || {
                let j = state.get().probe_json;
                if j.is_empty() {
                    view! { <p class="text-xs text-zinc-500">"No probe yet."</p> }.into_any()
                } else {
                    view! {
                        <pre class="rounded-lg border border-zinc-800/60 bg-zinc-950/60 px-3 py-3 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap max-h-80 overflow-auto">{j}</pre>
                    }.into_any()
                }
            }}
        </div>
    }
}
