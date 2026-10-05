//! DevGuard setup wizard — `/plugins/devguard/setup`.
//!
//! Action-tool institution: hub can save a workstation profile and mint sessions,
//! but host cage / folder / git hooks require the DevGuard CLI on the machine.
//! Does **not** call nonexistent `POST /plugins/devguard/setup`.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};

const WIZARD_ID: &str = "devguard-setup";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DevGuardState {
    project_path: String,
    primary_tool: String,
    role: String,
    management_url: String,
    profile_saved: bool,
    save_error: String,
}

#[component]
pub fn DevGuardSetupWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("DevGuard setup");
    let navigate = use_navigate();

    let steps = vec![
        WizardStep::new("kind", "Action tool")
            .with_subtitle("DevGuard binds coding agents to a workspace — not a remote service URL alone."),
        WizardStep::new("workspace", "Workspace + tool")
            .with_subtitle("Absolute repo path + primary agent. Saved via POST /plugins/devguard/local-profile."),
        WizardStep::new("service", "Optional status API")
            .with_subtitle("If a workstation runs status-api, save management URL via /plugins/devguard/configure."),
        WizardStep::new("verify", "CLI cage + connect")
            .with_subtitle("Host enforcement is CLI-only; agent credentials come from Connect tool.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<DevGuardState>(WIZARD_ID);

    Effect::new(move |_| {
        set_state.update(|s| {
            if s.role.is_empty() {
                s.role = "developer".into();
            }
            if s.primary_tool.is_empty() {
                s.primary_tool = "cursor".into();
            }
            if s.management_url.is_empty() {
                s.management_url = "http://127.0.0.1:19555".into();
            }
        });
    });

    let on_finish = Callback::new(move |()| {
        navigate("/setup/connect-tool", Default::default());
    });

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! { <KindStep /> }.into_any(),
            1 => view! { <WorkspaceStep state=state set_state=set_state /> }.into_any(),
            2 => view! { <ServiceStep state=state set_state=set_state /> }.into_any(),
            3 => view! { <VerifyStep state=state /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    let _ = auth;
    view! {
        <div class="w-full px-4 py-6 pb-10">
            <div class="mx-auto w-full max-w-3xl space-y-4">
                <div>
                    <h1 class="text-lg font-semibold text-zinc-100">"DevGuard · Setup"</h1>
                    <p class="mt-1 text-xs text-zinc-500">
                        "Action tool — workspace bind + connect. Host cage is CLI-only."
                    </p>
                </div>
                <WizardShell
                    controller=controller
                    steps=steps
                    step_view=step_view
                    on_finish=on_finish
                    on_cancel=Callback::new(|()| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href("/plugins/devguard");
                        }
                    })
                />
            </div>
        </div>
    }
}

#[component]
fn KindStep() -> impl IntoView {
    view! {
        <div class="space-y-3 text-sm text-zinc-300">
            <p>"DevGuard is an "<span class="text-zinc-100 font-medium">"action tool"</span>" for team projects: bind a local folder or a GitHub checkout path, route the coding agent through the gateway, then CLI-cage the agentic workspace."</p>
            <ul class="list-disc pl-5 space-y-1 text-xs text-zinc-500">
                <li><span class="text-zinc-400">"Folder / GitHub:"</span>" clone yourself ("<code class="text-zinc-400">"gh repo clone"</code>"), then paste the absolute checkout — hub does not OAuth-clone."</li>
                <li><span class="text-zinc-400">"Firewall:"</span>" host cage = DevGuard CLI ("<code class="text-zinc-400">"devguard connect … --cage"</code>"); Graph Firewall is separate."</li>
                <li><span class="text-zinc-400">"APIs:"</span>" POST /devguard/connect, local-profile, configure — not fake /plugins/devguard/setup"</li>
            </ul>
        </div>
    }
}

#[component]
fn WorkspaceStep(
    state: ReadSignal<DevGuardState>,
    set_state: WriteSignal<DevGuardState>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (discovering, set_discovering) = signal(false);
    let (discovered, set_discovered) = signal::<Vec<serde_json::Value>>(Vec::new());
    let (discovery_note, set_discovery_note) = signal(String::new());

    let on_discover = move |_| {
        if discovering.get() {
            return;
        }
        set_discovering.set(true);
        set_discovery_note.set(String::new());
        spawn_local(async move {
            match api::get_value("/devguard/workspaces/discover").await {
                Ok(v) => {
                    let repos = v
                        .get("repos")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let note = if repos.is_empty() {
                        "No git checkout found in the Connector node discovery roots. Paste a path or set CONNECTOR_DEVGUARD_DISCOVERY_ROOTS."
                    } else {
                        "Select a checkout detected on the Connector node."
                    };
                    set_discovered.set(repos);
                    set_discovery_note.set(note.into());
                }
                Err(e) => set_discovery_note.set(e.message),
            }
            set_discovering.set(false);
        });
    };

    let on_save = move |_| {
        if busy.get() {
            return;
        }
        let path = state.get().project_path.trim().to_string();
        let tool = state.get().primary_tool.trim().to_string();
        let role = {
            let r = state.get().role.trim().to_string();
            if r.is_empty() {
                "developer".into()
            } else {
                r
            }
        };
        if path.is_empty() || !path.starts_with('/') || path == "/workspace" {
            set_state.update(|s| {
                s.save_error =
                    "Enter an absolute workspace path (not /workspace).".into();
                s.profile_saved = false;
            });
            return;
        }
        set_busy.set(true);
        set_state.update(|s| s.save_error.clear());
        spawn_local(async move {
            let body = serde_json::json!({
                "profile": {
                    "schema_version": 1,
                    "primary_tool": tool,
                    "workspace_root_hint": path,
                    "default_role_name": role,
                    "single_workstation_acknowledged": true,
                    "roles": [{
                        "name": role,
                        "description": "From DevGuard setup wizard",
                        "tool_access": [{ "tool": tool, "mode": "allow" }]
                    }]
                }
            });
            match api::post_value("/plugins/devguard/local-profile", body).await {
                Ok(v) => {
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        set_state.update(|s| {
                            s.profile_saved = false;
                            s.save_error = v
                                .get("error")
                                .and_then(|x| x.as_str())
                                .unwrap_or("local-profile failed")
                                .to_string();
                        });
                    } else {
                        set_state.update(|s| {
                            s.profile_saved = true;
                            s.save_error.clear();
                        });
                    }
                }
                Err(e) => set_state.update(|s| {
                    s.profile_saved = false;
                    s.save_error = e.message;
                }),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <div class="rounded-lg border border-zinc-800/70 bg-zinc-950/40 p-3 space-y-2">
                <div class="flex items-center justify-between gap-3">
                    <div>
                        <p class="text-xs font-medium text-zinc-300">"Discover git checkouts"</p>
                        <p class="text-[11px] text-zinc-500">"Scans configured roots on the Connector node; it never claims access to a different browser machine."</p>
                    </div>
                    <button
                        type="button"
                        class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700/60 disabled:opacity-60"
                        prop:disabled=move || discovering.get()
                        on:click=on_discover
                    >
                        {move || if discovering.get() { "Scanning…" } else { "Find projects" }}
                    </button>
                </div>
                {move || {
                    discovered
                        .get()
                        .into_iter()
                        .map(|repo| {
                            let path = repo
                                .get("path")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let label = repo
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("repository")
                                .to_string();
                            let remote = repo
                                .get("remote")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let selected_path = path.clone();
                            view! {
                                <button
                                    type="button"
                                    class="block w-full rounded-md border border-zinc-800 px-2 py-1.5 text-left hover:border-indigo-500/50"
                                    on:click=move |_| {
                                        let value = selected_path.clone();
                                        set_state.update(|s| s.project_path = value);
                                    }
                                >
                                    <span class="block text-xs text-zinc-200">{label}</span>
                                    <span class="block text-[10px] font-mono text-zinc-500">{path}</span>
                                    {(!remote.is_empty()).then(|| view! {
                                        <span class="block text-[10px] text-zinc-600">{remote}</span>
                                    })}
                                </button>
                            }
                        })
                        .collect_view()
                }}
                {move || (!discovery_note.get().is_empty()).then(|| view! {
                    <p class="text-[11px] text-zinc-500">{discovery_note.get()}</p>
                })}
            </div>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Workspace root (absolute)"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    placeholder="/home/you/Projects/acme-repo"
                    prop:value=move || state.get().project_path
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.project_path = v);
                    }
                />
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Primary coding agent"</span>
                <select
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100"
                    prop:value=move || state.get().primary_tool
                    on:change=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.primary_tool = v);
                    }
                >
                    <option value="cursor">"Cursor"</option>
                    <option value="claude_code">"Claude Code"</option>
                    <option value="windsurf">"Windsurf"</option>
                    <option value="kiro">"Kiro"</option>
                    <option value="generic">"Generic OpenAI client"</option>
                </select>
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Role"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono"
                    prop:value=move || state.get().role
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.role = v);
                    }
                />
            </label>
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-60"
                prop:disabled=move || busy.get()
                on:click=on_save
            >
                {move || if busy.get() { "Saving profile…" } else { "Save local-profile" }}
            </button>
            {move || {
                let s = state.get();
                if !s.save_error.is_empty() {
                    view! { <p class="text-xs text-amber-300">{s.save_error}</p> }.into_any()
                } else if s.profile_saved {
                    view! { <p class="text-xs text-emerald-400">"Saved via POST /plugins/devguard/local-profile"</p> }.into_any()
                } else {
                    view! { <p class="text-xs text-zinc-500">"GitHub clone paths work the same once the repo exists locally — pick the checkout directory."</p> }.into_any()
                }
            }}
        </div>
    }
}

#[component]
fn ServiceStep(
    state: ReadSignal<DevGuardState>,
    set_state: WriteSignal<DevGuardState>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (msg, set_msg) = signal::<Option<String>>(None);

    let on_save = move |_| {
        if busy.get() {
            return;
        }
        let url = state.get().management_url.trim().to_string();
        set_busy.set(true);
        set_msg.set(None);
        spawn_local(async move {
            let body = serde_json::json!({
                "values": {
                    "management_url": url,
                    "enforce_mode": true
                }
            });
            match api::post_value("/plugins/devguard/configure", body).await {
                Ok(v) => {
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        set_msg.set(Some(
                            v.get("error")
                                .and_then(|x| x.as_str())
                                .unwrap_or("configure failed")
                                .to_string(),
                        ));
                    } else {
                        set_msg.set(Some(
                            "Saved management URL via POST /plugins/devguard/configure (env still overrides)."
                                .into(),
                        ));
                    }
                }
                Err(e) => set_msg.set(Some(e.message)),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <p class="text-xs text-zinc-500">
                "Optional: only needed when a workstation exposes DevGuard status-api for hub probes. Skip if you only use embedded sessions + CLI cage."
            </p>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"CONNECTOR_DEVGUARD_MANAGEMENT_URL"</span>
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
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700/60 disabled:opacity-60"
                prop:disabled=move || busy.get()
                on:click=on_save
            >
                {move || if busy.get() { "Saving…" } else { "Save configure" }}
            </button>
            {move || msg.get().map(|m| view! { <p class="text-xs text-zinc-400">{m}</p> })}
        </div>
    }
}

#[component]
fn VerifyStep(state: ReadSignal<DevGuardState>) -> impl IntoView {
    let (status, set_status) = signal(String::new());
    let (busy, set_busy) = signal(false);

    let on_probe = move |_| {
        if busy.get() {
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            let mut out = String::new();
            match api::get_value("/plugins/devguard/status").await {
                Ok(v) => {
                    out.push_str("GET /plugins/devguard/status\n");
                    out.push_str(&serde_json::to_string_pretty(&v).unwrap_or_default());
                }
                Err(e) => out.push_str(&format!("status error: {}\n", e.message)),
            }
            match api::get_value("/plugins/devguard/local-profile").await {
                Ok(v) => {
                    out.push_str("\n\nGET /plugins/devguard/local-profile\n");
                    out.push_str(&serde_json::to_string_pretty(&v).unwrap_or_default());
                }
                Err(e) => out.push_str(&format!("\nlocal-profile error: {}", e.message)),
            }
            set_status.set(out);
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            {move || {
                let s = state.get();
                let cli = format!(
                    "cd {}\ndevguard init\ndevguard connect {} --cage",
                    if s.project_path.is_empty() { "/path/to/repo".into() } else { s.project_path.clone() },
                    if s.primary_tool.is_empty() { "cursor".into() } else { s.primary_tool.clone() }
                );
                let cli_copy = cli.clone();
                view! {
                    <p class="text-sm text-zinc-300">"1) Host cage (required for folder / git enforcement):"</p>
                    <pre class="rounded-lg border border-amber-500/20 bg-amber-950/10 px-3 py-3 text-[11px] font-mono text-amber-100/90 whitespace-pre-wrap">{cli}</pre>
                    <button
                        type="button"
                        class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700/60"
                        on:click=move |_| {
                            if let Some(win) = web_sys::window() {
                                let _ = win.navigator().clipboard().write_text(&cli_copy);
                            }
                        }
                    >"Copy CLI"</button>
                }
            }}
            <p class="text-sm text-zinc-300 mt-2">
                "2) Finish opens "
                <A href="/setup/connect-tool" attr:class="text-indigo-400 underline-offset-2 hover:underline">"Connect tool"</A>
                " to bind a repo (POST /devguard/connect), then attach an agent for a cg_ token."
            </p>
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-60"
                prop:disabled=move || busy.get()
                on:click=on_probe
            >
                {move || if busy.get() { "Probing…" } else { "Probe DevGuard APIs" }}
            </button>
            {move || {
                let s = status.get();
                if s.is_empty() {
                    view! { <span></span> }.into_any()
                } else {
                    view! {
                        <pre class="rounded-lg border border-zinc-800/60 bg-zinc-950/60 px-3 py-3 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap max-h-72 overflow-auto">{s}</pre>
                    }.into_any()
                }
            }}
        </div>
    }
}
