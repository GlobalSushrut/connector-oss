//! First-run wizard — `/setup/first-run`.
//!
//! Phase 4.2 surface. Mirrors the TUI's shared boot + capability
//! handshake. Step list:
//!
//! 1. **Welcome**
//! 2. **Connector connection** — ping `/api/v1/deployment/info` and
//!    `/api/v1/healthz` to prove the dashboard can reach its server.
//! 3. **Workspace detect** — display the deployment edition + host.
//! 4. **License activation** *(self-deploy only)* — paste a license
//!    key; sends it to `/api/v1/license/activate`.
//! 5. **First plugin** — pick one of the three featured plugins and
//!    point at its `/setup` wizard.
//! 6. **Invite teammate** *(optional)* — opens the operator settings
//!    page; pure deflect to keep the wizard short.
//! 7. **Done**.
//!
//! Playground mode skips step 4 (license is hosted; not an operator
//! concern) and renames "Self-deploy"-flavoured copy where it appears.
//!
//! State is persisted to `localStorage["wizard:first-run:*"]`.

use leptos::prelude::*;
use leptos_router::components::A;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};
use crate::deployment::{use_deployment, use_deployment_mode, DeploymentMode};
use crate::routing::post_auth;
use serde_json::json;

const WIZARD_ID: &str = "first-run";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FirstRunState {
    license_key: String,
    chosen_plugin: String,
    invite_email: String,
    #[serde(default)]
    import_acked: bool,
}

#[component]
pub fn FirstRunWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("First-run setup");
    let mode = use_deployment_mode();
    let deployment = use_deployment();

    // Step list — playground bundles drop the license-activation +
    // import steps. Self-deploy gets all six.
    let is_playground = mode.get_untracked() == DeploymentMode::Playground;

    // Build the step list and a parallel id list so step dispatch can
    // index by symbolic name instead of fragile numeric offsets
    // (Phase 5.10 added an extra Self-deploy-only step).
    let (steps, step_ids): (Vec<WizardStep>, Vec<&'static str>) = {
        let mut v: Vec<WizardStep> = Vec::new();
        let mut ids: Vec<&'static str> = Vec::new();

        v.push(WizardStep::new("welcome", "Welcome to Connector")
            .with_subtitle("Short setup. Your progress is saved automatically."));
        ids.push("welcome");

        v.push(WizardStep::new("connection", "Verify your platform connection")
            .with_subtitle("Make sure the dashboard can reach the kernel."));
        ids.push("connection");

        v.push(WizardStep::new("workspace", "Workspace detected")
            .with_subtitle("Edition, host, and runtime info pulled from the server."));
        ids.push("workspace");

        if !is_playground {
            v.push(WizardStep::new("import", "Import from playground session")
                .with_subtitle("Drop a connector-trial-*.tar.gz to pre-fill plugins, workflows, and agents.")
                .skippable());
            ids.push("import");

            v.push(WizardStep::new("license", "Activate your license")
                .with_subtitle("Paste your enterprise key, or skip to stay in community mode.")
                .skippable());
            ids.push("license");
        }

        v.push(WizardStep::new("plugin", "Install your first plugin")
            .with_subtitle("Featured: DevGuard, TraceTramp, WitnessCtl. Pick one to set up next.")
            .skippable());
        ids.push("plugin");

        v.push(WizardStep::new("invite", "Invite a teammate (optional)")
            .with_subtitle("Operators sharing this node — set them up in Settings.")
            .skippable());
        ids.push("invite");

        v.push(WizardStep::new("done", "All set")
            .with_subtitle("Drop into the dashboard, or open the Setup hub for more.")
            .finish());
        ids.push("done");

        (v, ids)
    };

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<FirstRunState>(WIZARD_ID);

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        let id = step_ids.get(idx).copied().unwrap_or("done");
        match id {
            "welcome" => welcome_step().into_any(),
            "connection" => connection_step().into_any(),
            "workspace" => workspace_step(deployment).into_any(),
            "import" => import_session_step(state, set_state).into_any(),
            "license" => license_step(state, set_state).into_any(),
            "plugin" => plugin_step(state, set_state).into_any(),
            "invite" => invite_step(state, set_state).into_any(),
            "done" => done_step().into_any(),
            _ => view! { <p class="text-zinc-500 text-sm">"Unknown step."</p> }.into_any(),
        }
    });

    let _ = auth;

    view! {
        <div class="w-full">
            <div class="mx-auto flex w-full max-w-3xl flex-col gap-4 px-4 py-6 sm:px-6">
                <div>
                    <h1 class="text-lg font-semibold text-zinc-100">"First-run setup"</h1>
                    <p class="mt-1 text-xs text-zinc-500">
                        "Verifies the platform, optionally activates a license, and lines up your first plugin."
                    </p>
                </div>
                <WizardShell
                    controller=controller
                    steps=steps
                    step_view=step_view
                    on_finish=Callback::new(|_| {
                        post_auth::mark_onboarding_complete();
                        spawn_local(async move {
                            let _ = api::post_value(
                                "/setup/complete",
                                json!({ "wizard_id": "first_run" }),
                            )
                            .await;
                            if let Some(win) = web_sys::window() {
                                let _ = win.location().set_href("/run");
                            }
                        });
                    })
                    on_cancel=Callback::new(|_| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href("/setup");
                        }
                    })
                />
                <p class="text-center text-[11px] text-zinc-600">
                    "Progress is saved in "
                    <span class="font-mono">"localStorage[wizard:first-run:*]"</span>
                    " and mirrored via POST /setup/complete."
                </p>
            </div>
        </div>
    }
}

// ── individual step bodies ────────────────────────────────────────────────

fn welcome_step() -> impl IntoView {
    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-300">
                "Connector is the policy + audit substrate for AI agents. This wizard verifies the platform is reachable, optionally activates a license, and lines up your first plugin."
            </p>
            <ul class="text-sm text-zinc-400 space-y-1 list-disc pl-5">
                <li>"Nothing here changes server state until you click "<span class="font-medium text-zinc-200">"Finish"</span>"."</li>
                <li>"Each step is saved as you go; close the tab and pick up here later."</li>
            </ul>
        </div>
    }
}

#[component]
fn ConnectionStepBody() -> impl IntoView {
    // `/healthz` is root-mounted (not under /api/v1). Use monitor health + deployment.
    let health = LocalResource::new(|| api::get_value("/monitor/health"));
    let info = LocalResource::new(|| api::get_value("/deployment/info"));
    view! {
        <div class="space-y-3">
            <Suspense fallback=|| view! { <p class="text-sm text-zinc-500">"Pinging the kernel…"</p> }>
                {move || Suspend::new(async move {
                    let h = health.await;
                    let i = info.await;
                    let h_ok = h.as_ref().map(|v| v.get("error").is_none()).unwrap_or(false);
                    let i_ok = i.as_ref().map(|v| v.get("error").is_none()).unwrap_or(false);
                    let ok = h_ok && i_ok;
                    view! {
                        <div class={
                            if ok {
                                "rounded-xl border border-emerald-500/30 bg-emerald-500/5 px-4 py-3"
                            } else {
                                "rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3"
                            }
                        }>
                            <p class={
                                if ok {
                                    "text-sm font-medium text-emerald-200"
                                } else {
                                    "text-sm font-medium text-amber-200"
                                }
                            }>
                                {if ok { "Connection healthy." } else { "Kernel is reachable but some checks failed." }}
                            </p>
                            <ul class="mt-2 space-y-1 font-mono text-xs text-zinc-400">
                                <li>"GET /api/v1/monitor/health · " {if h_ok { "OK" } else { "FAIL" }}</li>
                                <li>"GET /api/v1/deployment/info · " {if i_ok { "OK" } else { "FAIL" }}</li>
                            </ul>
                        </div>
                    }
                })}
            </Suspense>
            <p class="text-xs text-zinc-500">
                "Both endpoints should succeed before continuing. Root probes (/health, /healthz) are outside /api/v1."
            </p>
        </div>
    }
}

fn connection_step() -> impl IntoView {
    view! { <ConnectionStepBody /> }
}

fn workspace_step(deployment: ReadSignal<crate::deployment::DeploymentInfo>) -> impl IntoView {
    view! {
        <div class="space-y-3">
            {move || {
                let info = deployment.get();
                view! {
                    <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                        <dt class="text-zinc-500">"Mode"</dt>
                        <dd class="text-zinc-200 font-mono">{format!("{:?}", info.mode)}</dd>
                        <dt class="text-zinc-500">"Edition"</dt>
                        <dd class="text-zinc-200 font-mono">{info.edition.clone()}</dd>
                        <dt class="text-zinc-500">"Version"</dt>
                        <dd class="text-zinc-200 font-mono">{info.version.clone()}</dd>
                        <dt class="text-zinc-500">"Public URL"</dt>
                        <dd class="text-zinc-200 font-mono break-all">{
                            if info.public_url.is_empty() { "—".into() } else { info.public_url.clone() }
                        }</dd>
                    </dl>
                }
            }}
            <p class="text-xs text-zinc-500">
                "These values are pulled live from "
                <span class="font-mono dev-only">"GET /api/v1/deployment/info"</span>" — if anything looks wrong, fix the server-side env before continuing."
            </p>
        </div>
    }
}

fn import_session_step(
    state: ReadSignal<FirstRunState>,
    set_state: WriteSignal<FirstRunState>,
) -> impl IntoView {
    let (probe_result, set_probe) = signal::<Option<ImportProbe>>(None);
    let (busy, set_busy) = signal(false);
    let (flash, set_flash) = signal::<Option<(String, bool)>>(None);

    // One-shot probe on mount: ask the server whether anything is
    // sitting in `/var/lib/connector/import/`. Graceful 404 if the
    // endpoint isn't shipped yet — the step still offers a manual
    // upload path.
    Effect::new(move |has_run: Option<bool>| {
        if has_run.unwrap_or(false) {
            return true;
        }
        spawn_local(async move {
            if let Ok(v) = api::get_value("/import/playground-session/probe").await {
                let detected = v.get("detected").and_then(|b| b.as_bool()).unwrap_or(false);
                let filename = v
                    .get("filename")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let tenant = v
                    .get("tenant")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                set_probe.set(Some(ImportProbe { detected, filename, tenant }));
            }
        });
        true
    });

    let on_import = move |_| {
        if busy.get() { return; }
        set_busy.set(true);
        spawn_local(async move {
            match api::post_value("/import/playground-session", serde_json::json!({})).await {
                Ok(v) => {
                    let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                    if ok {
                        set_state.update(|s| s.import_acked = true);
                    }
                    let msg = v
                        .get("summary")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| {
                            if ok { "Imported.".into() } else { "Server rejected the import.".into() }
                        });
                    set_flash.set(Some((msg, ok)));
                }
                Err(e) => set_flash.set(Some((format!("Import failed: {}", e.message), false))),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-300">
                "If you ran a playground session at try.connector.dev, you can download "
                <span class="font-mono text-zinc-200">"my-session.tar.gz"</span>
                " and drop it into "
                <span class="font-mono text-zinc-200">"/var/lib/connector/import/"</span>
                " on this node. The first-run wizard will pre-fill plugins, workflows, and agents from it."
            </p>
            {move || match probe_result.get() {
                None => view! {
                    <p class="text-xs text-zinc-500">"Checking for a pending import…"</p>
                }.into_any(),
                Some(probe) if probe.detected => {
                    let filename = probe.filename.clone();
                    let tenant = probe.tenant.clone();
                    view! {
                        <div class="rounded-xl border border-emerald-500/30 bg-emerald-500/5 px-4 py-3">
                            <p class="text-sm font-medium text-emerald-200">
                                "Found a playground bundle ready to import."
                            </p>
                            <ul class="mt-2 text-xs text-zinc-400 space-y-0.5 font-mono">
                                <li>"file · "{filename.clone()}</li>
                                <li>"tenant · "{tenant.clone()}</li>
                            </ul>
                            <div class="mt-3 flex items-center gap-2">
                                <button
                                    type="button"
                                    class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-60"
                                    prop:disabled=move || busy.get() || state.get().import_acked
                                    on:click=on_import.clone()
                                >
                                    {move || {
                                        if state.get().import_acked { "Imported ✓".to_string() }
                                        else if busy.get() { "Importing…".to_string() }
                                        else { "Import this bundle".to_string() }
                                    }}
                                </button>
                                <span class="text-[11px] text-zinc-500 dev-only">"Idempotent — runs against "<span class="font-mono">"POST /api/v1/import/playground-session"</span>"."</span>
                            </div>
                        </div>
                    }.into_any()
                }
                Some(_) => view! {
                    <div class="rounded-xl border border-zinc-700/60 bg-zinc-900/40 px-4 py-3 text-sm text-zinc-400">
                        <p class="font-medium text-zinc-200">"No playground bundle detected."</p>
                        <p class="text-xs text-zinc-500 mt-1">
                            "Drop "<span class="font-mono">"connector-trial-{tenant}.tar.gz"</span>" into "
                            <span class="font-mono">"/var/lib/connector/import/"</span>
                            " and reload this step, or skip to continue without importing."
                        </p>
                    </div>
                }.into_any(),
            }}
            {move || flash.get().map(|(msg, ok)| view! {
                <p class={if ok { "text-xs text-emerald-300" } else { "text-xs text-amber-300" }}>{msg}</p>
            })}
            <p class="text-xs text-zinc-500">
                "Don't have a tarball? "
                <A href="https://try.connector.dev" attr:class="text-indigo-400 hover:text-indigo-300">"Start a playground session"</A>
                " and export it from "<A href="/install" attr:class="text-indigo-400 hover:text-indigo-300">"/install"</A>"."
            </p>
        </div>
    }
}

#[derive(Clone)]
struct ImportProbe {
    detected: bool,
    filename: String,
    tenant: String,
}

fn license_step(
    state: ReadSignal<FirstRunState>,
    set_state: WriteSignal<FirstRunState>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (flash, set_flash) = signal::<Option<(String, bool)>>(None);

    let on_activate = move |_| {
        if busy.get() { return; }
        let key = state.get().license_key.trim().to_string();
        if key.is_empty() {
            set_flash.set(Some(("Paste a license key first.".into(), false)));
            return;
        }
        set_busy.set(true);
        spawn_local(async move {
            match api::post_value("/license/activate", serde_json::json!({ "license_key": key })).await {
                Ok(v) => {
                    // Backend returns `{ activated: true, tier, … }` or soft `{ error, status }`.
                    let ok = v.get("activated").and_then(|x| x.as_bool()).unwrap_or(false)
                        && v.get("error").is_none();
                    let msg = if ok {
                        format!(
                            "License activated ({})",
                            v.get("tier").and_then(|t| t.as_str()).unwrap_or("ok")
                        )
                    } else {
                        v.get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("Server rejected the key.")
                            .to_string()
                    };
                    set_flash.set(Some((msg, ok)));
                }
                Err(e) => set_flash.set(Some((format!("Activation failed: {}", e.message), false))),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"License key"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    placeholder="cnk-XXXXX-XXXXX-XXXXX"
                    prop:value=move || state.get().license_key
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.license_key = v);
                    }
                />
            </label>
            <div class="flex items-center gap-2">
                <button
                    type="button"
                    class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-60"
                    prop:disabled=move || busy.get()
                    on:click=on_activate
                >
                    {move || if busy.get() { "Activating…" } else { "Activate" }}
                </button>
                <A href="/license" attr:class="text-xs text-zinc-500 hover:text-zinc-300 underline-offset-2 hover:underline">
                    "Open full License page →"
                </A>
            </div>
            {move || flash.get().map(|(msg, ok)| view! {
                <p class={if ok {
                    "text-xs text-emerald-300"
                } else {
                    "text-xs text-amber-300"
                }}>{msg}</p>
            })}
            <p class="text-xs text-zinc-500">
                "No key? Skip this step to stay in community mode. You can activate any time from the License page."
            </p>
        </div>
    }
}

fn plugin_step(
    state: ReadSignal<FirstRunState>,
    set_state: WriteSignal<FirstRunState>,
) -> impl IntoView {
    let choices: Vec<(&'static str, &'static str, &'static str)> = vec![
        ("devguard", "DevGuard", "Policy & secret enforcement"),
        ("tracetramp", "TraceTramp", "LLM trace + budget governance"),
        ("witnessctl", "WitnessCtl", "Cryptographic audit receipts"),
    ];
    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-300">"Pick a plugin — the next step opens its dedicated setup wizard."</p>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {choices.into_iter().map(|(slug, name, desc)| {
                    let slug_owned = slug.to_string();
                    let is_selected_signal = {
                        let slug = slug_owned.clone();
                        Memo::new(move |_| state.get().chosen_plugin == slug)
                    };
                    let slug_for_click = slug_owned.clone();
                    view! {
                        <button
                            type="button"
                            class=move || {
                                if is_selected_signal.get() {
                                    "rounded-xl border border-indigo-500/50 bg-indigo-500/10 px-3 py-3 text-left"
                                } else {
                                    "rounded-xl border border-zinc-800/60 bg-zinc-900/40 px-3 py-3 text-left hover:border-zinc-700/80"
                                }
                            }
                            on:click=move |_| {
                                let v = slug_for_click.clone();
                                set_state.update(|s| s.chosen_plugin = v);
                            }
                        >
                            <p class="text-sm font-semibold text-zinc-100">{name}</p>
                            <p class="text-xs text-zinc-500 mt-0.5">{desc}</p>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>
            {move || {
                let slug = state.get().chosen_plugin;
                if slug.is_empty() {
                    view! { <p class="text-xs text-zinc-500">"Or skip this step to choose later."</p> }.into_any()
                } else {
                    let href = format!("/plugins/{slug}/setup");
                    let label = format!("Open {slug} setup wizard →");
                    view! {
                        <A href=href attr:class="text-xs text-indigo-400 hover:text-indigo-300 underline-offset-2 hover:underline">
                            {label}
                        </A>
                    }.into_any()
                }
            }}
        </div>
    }
}

fn invite_step(
    state: ReadSignal<FirstRunState>,
    set_state: WriteSignal<FirstRunState>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-300">
                "Share this node with another operator. Invites create a real local account via POST /auth/signup (no /invites route)."
            </p>
            <label class="block">
                <span class="mb-1 block text-xs uppercase tracking-wider text-zinc-500">"Teammate email (optional note)"</span>
                <input
                    type="email"
                    class="w-full rounded-lg border border-zinc-700/60 bg-zinc-900/60 px-3 py-2 text-sm text-zinc-100 focus:border-indigo-500/60 focus:outline-none"
                    placeholder="ops@example.com"
                    prop:value=move || state.get().invite_email
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.invite_email = v);
                    }
                />
            </label>
            <A
                href="/setup/invite"
                attr:class="inline-flex text-xs text-indigo-400 underline-offset-2 hover:text-indigo-300 hover:underline"
            >
                "Open Invite wizard →"
            </A>
            <p class="text-xs text-zinc-500">
                "Optional — skip to finish without inviting. The invite wizard also lists GET /auth/users."
            </p>
        </div>
    }
}

fn done_step() -> impl IntoView {
    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-200">
                "You're set. "
                <span class="font-medium">"Finish"</span>
                " marks first_run complete (local + POST /setup/complete) and opens RUN."
            </p>
            <ul class="list-disc space-y-1 pl-5 text-sm text-zinc-400">
                <li>"Re-open from "<A href="/setup" attr:class="text-indigo-400">"/setup"</A>"."</li>
                <li>"Plugin setup: "<span class="font-mono">"/plugins/&lt;slug&gt;/setup"</span>"."</li>
                <li>"Invite teammates: "<A href="/setup/invite" attr:class="text-indigo-400">"/setup/invite"</A>"."</li>
            </ul>
        </div>
    }
}
