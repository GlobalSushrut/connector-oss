//! Light operator consoles for DevGuard / TraceTramp / WitnessCtl.
//!
//! Default `/plugins/<id>` surface — matches backend contracts.

use leptos::prelude::*;
use leptos_router::components::A;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::overlays::forensics::OpFniMomentBadge;
use crate::components::operator::primitives::{OpButton, OpButtonVariant};
use crate::components::page_title::use_page_title;
use super::contract_live::{DevGuardConfigureAndTeamsPanel, LiveContractMap};
use super::rules_panels::{
    DevGuardRulesPanel, TraceTrampRulesHitlPanel, WitnessCtlRulesHitlPanel,
};
use crate::ui_state::use_developer_view;

fn soft_err(v: &Value) -> Option<String> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let code = v.get("error").and_then(|e| e.as_str()).unwrap_or("Request failed");
        if code == "admission_denied" || v.get("code").and_then(|c| c.as_str()) == Some("admission_denied")
        {
            let why = v
                .get("message")
                .and_then(|m| m.as_str())
                .or_else(|| v.get("denial_reason").and_then(|d| d.as_str()))
                .unwrap_or("denied by admission");
            return Some(format!("admission_denied: {why}"));
        }
        return Some(
            v.get("error")
                .and_then(|e| e.as_str())
                .or_else(|| v.get("hint").and_then(|h| h.as_str()))
                .unwrap_or("Request failed")
                .into(),
        );
    }
    if let Some(status) = v.get("status").and_then(|s| s.as_u64()) {
        if status >= 400 {
            return Some(
                v.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Request failed")
                    .into(),
            );
        }
    }
    v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string())
}

fn api_err(message: String) -> api::ApiError {
    api::ApiError {
        status: 400,
        code: None,
        message,
        detail: None,
        hints: vec![],
        docs: None,
    }
}

#[component]
fn ConsoleChrome(
    title: &'static str,
    kind: &'static str,
    setup_href: &'static str,
    /// `devguard` | `tracetramp` | `witnessctl` — drives pattern / accent tokens.
    plugin: &'static str,
    children: Children,
) -> impl IntoView {
    let isolation = LocalResource::new(|| async move {
        api::get_value("/substrate/status").await.ok().map(|v| {
            let runtime = v
                .pointer("/data/isolation/declared_runtime")
                .or_else(|| v.pointer("/isolation/declared_runtime"))
                .and_then(|x| x.as_str())
                .unwrap_or("unavailable");
            let ok = v
                .pointer("/data/cage_security/isolation_grade_ok")
                .or_else(|| v.pointer("/cage_security/isolation_grade_ok"))
                .and_then(|x| x.as_bool());
            let break_glass = v
                .pointer("/data/isolation/subprocess_break_glass")
                .or_else(|| v.pointer("/isolation/subprocess_break_glass"))
                .and_then(|x| x.as_bool())
                == Some(true);
            let prodish = v
                .pointer("/data/isolation/prodish_enforced")
                .or_else(|| v.pointer("/isolation/prodish_enforced"))
                .and_then(|x| x.as_bool())
                == Some(true);
            let grade = match ok {
                Some(true) => "grade_ok",
                Some(false) => "grade_fail",
                None => "grade_unknown",
            };
            if prodish && break_glass {
                format!("isolation: {runtime} · {grade} · break-glass")
            } else {
                format!("isolation: {runtime} · {grade}")
            }
        })
    });
    // Static class strings so Tailwind JIT keeps per-plugin pattern modifiers.
    let shell = match plugin {
        "tracetramp" => {
            "lc-console lc-console--tracetramp w-full px-4 py-5 sm:px-6 pb-10"
        }
        "witnessctl" => {
            "lc-console lc-console--witnessctl w-full px-4 py-5 sm:px-6 pb-10"
        }
        _ => {
            "lc-console lc-console--devguard w-full px-4 py-5 sm:px-6 pb-10"
        }
    };
    view! {
        <div class=shell>
            <div class="lc-stack">
                {if plugin != "devguard" {
                    view! {
                        <Suspense fallback=|| ()>
                            {move || Suspend::new(async move {
                                match isolation.await {
                                    Some(badge) => view! {
                                        <p class="mb-2 font-mono text-[10px] uppercase tracking-wide text-zinc-500">{badge}</p>
                                    }.into_any(),
                                    None => ().into_any(),
                                }
                            })}
                        </Suspense>
                    }.into_any()
                } else {
                    ().into_any()
                }}
                <header class="lc-header">
                    <div>
                        <h1 class="lc-header__title">{title}</h1>
                        <p class="lc-header__kind">{kind}</p>
                    </div>
                    {if plugin == "devguard" {
                        view! { <span></span> }.into_any()
                    } else {
                        view! {
                            <div class="flex flex-wrap gap-2">
                                <A href=setup_href attr:class="lc-nav-link">"Setup"</A>
                                <A href="/setup" attr:class="lc-nav-link lc-nav-link--muted">"SETUP"</A>
                            </div>
                        }.into_any()
                    }}
                </header>
                {children()}
            </div>
        </div>
    }
}

#[component]
fn KvRow(label: &'static str, value: String) -> impl IntoView {
    view! {
        <div class="lc-kv">
            <dt>{label}</dt>
            <dd>{value}</dd>
        </div>
    }
}

/// P5.1 — shared principal / policy lineage snippet (GET /runtime/policy-lineage).
#[component]
fn PolicyLineageSnippet() -> impl IntoView {
    let lineage = LocalResource::new(|| async move { api::get_value("/runtime/policy-lineage").await });
    view! {
        <Suspense fallback=move || view! {
            <section class="lc-panel">
                <p class="lc-panel__eyebrow">"Policy lineage · GET /runtime/policy-lineage"</p>
                <p class="mt-1 text-[11px] text-zinc-600">"Loading…"</p>
            </section>
        }>
            {move || Suspend::new(async move {
                match lineage.await {
                    Ok(v) => {
                        if let Some(e) = soft_err(&v) {
                            return view! {
                                <section class="lc-panel">
                                    <p class="lc-panel__eyebrow">"Policy lineage · GET /runtime/policy-lineage"</p>
                                    <p class="mt-1 text-[11px] text-amber-400">{e}</p>
                                </section>
                            }.into_any();
                        }
                        let implemented = v
                            .get("implemented")
                            .map(|x| x.to_string())
                            .unwrap_or_else(|| "—".into());
                        let policy_id = v
                            .pointer("/lineage/kernel_policy/id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("—")
                            .to_string();
                        let fingerprint = v
                            .pointer("/lineage/kernel_policy/fingerprint")
                            .and_then(|x| x.as_str())
                            .unwrap_or("—")
                            .to_string();
                        let instance = v
                            .pointer("/lineage/node_instance_id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("—")
                            .to_string();
                        let principal = v
                            .pointer("/lineage/principal_contract")
                            .and_then(|x| x.as_str())
                            .unwrap_or("—")
                            .to_string();
                        let fp_short = if fingerprint.len() > 48 {
                            format!("{}…", &fingerprint[..48])
                        } else {
                            fingerprint.clone()
                        };
                        view! {
                            <section class="lc-panel">
                                <p class="lc-panel__eyebrow">"Policy lineage · GET /runtime/policy-lineage"</p>
                                <p class="mt-1 text-[11px] text-zinc-500">
                                    "Shared principal/policy ids with gateway · TT · WC · DG (honesty partial until revision store)."
                                </p>
                                <dl class="mt-2 space-y-1.5">
                                    <KvRow label="implemented" value=implemented />
                                    <KvRow label="principal" value=principal />
                                    <KvRow label="policy.id" value=policy_id />
                                    <KvRow label="instance" value=instance />
                                    <KvRow label="fingerprint" value=fp_short />
                                </dl>
                            </section>
                        }.into_any()
                    }
                    Err(e) => view! {
                        <section class="lc-panel">
                            <p class="lc-panel__eyebrow">"Policy lineage · GET /runtime/policy-lineage"</p>
                            <p class="mt-1 text-[11px] text-amber-400">{e.message}</p>
                        </section>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

// ── DevGuard ─────────────────────────────────────────────────────────────────

fn copy_text(text: &str) {
    if let Some(win) = web_sys::window() {
        let _ = win.navigator().clipboard().write_text(text);
    }
}

#[component]
fn EasyDevGuardStart() -> impl IntoView {
    let (project, set_project) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal(String::new());
    let (out, set_out) = signal(Option::<Value>::None);
    let (copied, set_copied) = signal(String::new());
    let (show_agents, set_show_agents) = signal(false);

    let start = move |_| {
        if busy.get_untracked() { return; }
        let name = project.get_untracked().trim().to_string();
        if name.is_empty() {
            set_err.set("Paste a GitHub URL or org/repo.".into());
            return;
        }
        set_busy.set(true);
        set_err.set(String::new());
        spawn_local(async move {
            match api::post_value("/devguard/connect", json!({
                "project": name,
                "tool": "generic",
                "role": "developer",
            })).await {
                Ok(v) => {
                    if let Some(e) = soft_err(&v) {
                        set_err.set(e);
                        set_out.set(None);
                    } else {
                        set_out.set(Some(v));
                    }
                }
                Err(e) => set_err.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <section class="lc-panel space-y-4">
            <div>
                <p class="text-[11px] font-semibold uppercase tracking-wider text-emerald-400/90">"Repo first"</p>
                <h2 class="mt-1 text-lg font-semibold text-zinc-100">"Put a repo under DevGuard."</h2>
                <p class="mt-1 text-sm text-zinc-400">
                    "This node holds the working copy. Agents work here — not a laptop clone. After you attach an agent, they get a cage address and a cg_ token. No ID + role → even read is denied."
                </p>
            </div>

            <label class="block">
                <span class="lc-label">"GitHub URL or org/repo"</span>
                <input
                    type="text"
                    class="lc-field"
                    placeholder="https://github.com/you/repo  or  you/repo"
                    prop:value=move || project.get()
                    on:input=move |ev| {
                        set_project.set(event_target_value(&ev));
                        set_err.set(String::new());
                    }
                />
            </label>

            <button
                type="button"
                class="w-full rounded-xl bg-emerald-500 px-4 py-3 text-sm font-bold text-emerald-950 hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
                disabled=move || busy.get()
                on:click=start
            >
                {move || if busy.get() { "Binding the repo…" } else { "Put this repo under DevGuard →" }}
            </button>
            <Show when=move || !err.get().is_empty()>
                <p class="text-xs text-amber-400">{move || err.get()}</p>
            </Show>

            {move || out.get().map(|v| {
                let token = v.pointer("/repo_address/api_key")
                    .or_else(|| v.get("token"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let base = v.pointer("/repo_address/openai_base_url")
                    .or_else(|| v.get("openai_base_url"))
                    .or_else(|| v.get("gateway_base"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let clone = v.pointer("/cage_firewall/clone_hint")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let write_cmd = v.pointer("/repo_config/write_command")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let cage_cmd = v.pointer("/repo_cage/command")
                    .and_then(|x| x.as_str())
                    .unwrap_or("devguard init && devguard cage start")
                    .to_string();
                let github = v.get("github_url").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let repo_id = v.get("repo_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let tools: Vec<(String, String, String)> = v.get("all_tools")
                    .and_then(|a| a.as_array())
                    .map(|a| a.iter().filter_map(|t| {
                        let name = t.get("display").and_then(|x| x.as_str())?.to_string();
                        let steps = t.get("steps").and_then(|s| s.as_array())
                            .map(|s| s.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" · "))
                            .unwrap_or_default();
                        let env = t.get("env_snippet").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        Some((name, steps, env))
                    }).collect())
                    .unwrap_or_default();
                let token_c = token.clone();
                let base_c = base.clone();
                let write_c = write_cmd.clone();
                let cage_c = cage_cmd.clone();
                let clone_c = clone.clone();
                view! {
                    <div class="space-y-4 rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-4">
                        <div>
                            <p class="text-sm font-semibold text-zinc-100">
                                {if github.is_empty() {
                                    format!("Repo {repo_id} is under DevGuard.")
                                } else {
                                    format!("{github} is under DevGuard.")
                                }}
                            </p>
                            <p class="mt-1 text-xs text-zinc-400">
                                "The working copy is this node's workspace. Attach an agent to get a cg_ token. A raw clone on a laptop is not this repo."
                            </p>
                        </div>

                        {(!clone.is_empty()).then(|| view! {
                            <div>
                                <p class="text-[10px] uppercase tracking-wider text-zinc-500">"1. Git / GitHub — get the checkout"</p>
                                <pre class="mt-1 overflow-x-auto rounded-lg bg-zinc-950/70 p-3 font-mono text-[11px] text-zinc-300">{clone.clone()}</pre>
                                <button type="button" class="mt-1 text-[11px] text-emerald-300 hover:text-emerald-200"
                                    on:click=move |_| { copy_text(&clone_c); set_copied.set("clone".into()); }>
                                    {move || if copied.get() == "clone" { "Copied" } else { "Copy clone" }}
                                </button>
                            </div>
                        })}

                        <div>
                            <p class="text-[10px] uppercase tracking-wider text-zinc-500">"2. Address — any agent uses this pair"</p>
                            <div class="mt-2 space-y-2">
                                <div class="flex items-center justify-between gap-2">
                                    <div class="min-w-0">
                                        <p class="text-[10px] uppercase tracking-wider text-zinc-600">"Base URL"</p>
                                        <p class="truncate font-mono text-xs text-zinc-200">{base.clone()}</p>
                                    </div>
                                    <button type="button" class="shrink-0 rounded-lg border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200 hover:bg-zinc-800"
                                        on:click=move |_| { copy_text(&base_c); set_copied.set("url".into()); }>
                                        {move || if copied.get() == "url" { "Copied" } else { "Copy" }}
                                    </button>
                                </div>
                                {(!token.is_empty()).then(|| view! {
                                <div class="flex items-center justify-between gap-2">
                                    <div class="min-w-0">
                                        <p class="text-[10px] uppercase tracking-wider text-zinc-600">"API key"</p>
                                        <p class="truncate font-mono text-xs text-zinc-200">{token.clone()}</p>
                                    </div>
                                    <button type="button" class="shrink-0 rounded-lg border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200 hover:bg-zinc-800"
                                        on:click=move |_| { copy_text(&token_c); set_copied.set("key".into()); }>
                                        {move || if copied.get() == "key" { "Copied" } else { "Copy" }}
                                    </button>
                                </div>
                                })}
                                {(token.is_empty()).then(|| view! {
                                    <p class="text-[11px] text-zinc-500">"Attach an agent to receive a cg_ token. Binding the repo is not an identity."</p>
                                })}
                            </div>
                        </div>

                        <div>
                            <p class="text-[10px] uppercase tracking-wider text-zinc-500">"3. Config + cage — run once in the repo"</p>
                            <pre class="mt-1 overflow-x-auto rounded-lg bg-zinc-950/70 p-3 font-mono text-[11px] text-zinc-300">{cage_cmd.clone()}</pre>
                            <div class="mt-2 flex flex-wrap gap-2">
                                <button type="button" class="rounded-lg border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200 hover:bg-zinc-800"
                                    on:click=move |_| { copy_text(&cage_c); set_copied.set("cage".into()); }>
                                    {move || if copied.get() == "cage" { "Cage copied" } else { "Copy cage command" }}
                                </button>
                                {(!write_cmd.is_empty()).then(move || {
                                    let w = write_c.clone();
                                    view! {
                                        <button type="button" class="rounded-lg border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200 hover:bg-zinc-800"
                                            on:click=move |_| { copy_text(&w); set_copied.set("cfg".into()); }>
                                            {move || if copied.get() == "cfg" { "Config copied" } else { "Copy .devguard/connector.json" }}
                                        </button>
                                    }
                                })}
                            </div>
                            <p class="mt-2 text-xs text-zinc-500">
                                "Cage writes git hooks and file/exec guards into the checkout. After that, any agent — not just the one you opened first — is bound."
                            </p>
                        </div>

                        <button type="button" class="text-[11px] text-emerald-300 hover:text-emerald-200"
                            on:click=move |_| set_show_agents.update(|v| *v = !*v)>
                            {move || if show_agents.get() { "Hide per-agent steps" } else { "How to point Cursor / Claude / Codex at this address" }}
                        </button>
                        <Show when=move || show_agents.get()>
                            <ul class="space-y-2">
                                {tools.clone().into_iter().map(|(name, steps, env)| {
                                    let env_c = env.clone();
                                    view! {
                                        <li class="rounded-lg border border-zinc-800 bg-zinc-950/40 px-3 py-2">
                                            <p class="text-xs font-semibold text-zinc-200">{name}</p>
                                            <p class="mt-0.5 text-[11px] text-zinc-400">{steps}</p>
                                            {(!env.is_empty()).then(move || {
                                                let e = env_c.clone();
                                                view! {
                                                    <button type="button" class="mt-1 text-[11px] text-emerald-300"
                                                        on:click=move |_| { copy_text(&e); set_copied.set(format!("env-{e}")); }>
                                                        "Copy env"
                                                    </button>
                                                }
                                            })}
                                        </li>
                                    }
                                }).collect_view()}
                            </ul>
                        </Show>
                    </div>
                }
            })}
        </section>
    }
}

#[component]
pub fn DevGuardLightConsole(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("DevGuard");
    let _auth = auth;
    let (dev, _) = use_developer_view();

    view! {
        <ConsoleChrome
            title="DevGuard"
            kind="Git manages the repo. DevGuard gives the checkout an address, config, and cage — any agent inside must follow the rules."
            setup_href="/plugins/devguard/setup"
            plugin="devguard"
        >
            <EasyDevGuardStart />
            <Show when=move || dev.get()>
                <LiveContractMap plugin="devguard" />
                <DevGuardConfigureAndTeamsPanel />
                <DevGuardRulesPanel />
            </Show>
        </ConsoleChrome>
    }
}

// ── TraceTramp ───────────────────────────────────────────────────────────────

#[component]
pub fn TraceTrampLightConsole(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("TraceTramp");
    let (dev, _) = use_developer_view();
    let (reload, set_reload) = signal(0u32);
    let (url, set_url) = signal("http://127.0.0.1:9742".to_string());
    let (token, set_token) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (msg, set_msg) = signal(Option::<(String, bool)>::None);
    let (stats, set_stats) = signal(Option::<Value>::None);

    let status = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/plugins/tracetramp/status").await }
    });

    Effect::new(move |_| {
        let _ = reload.get();
        spawn_local(async move {
            if let Ok(v) = api::get_value("/plugins/tracetramp/configure").await {
                if let Some(u) = v
                    .pointer("/values/management_url")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                {
                    set_url.set(u.to_string());
                }
            }
            if let Ok(s) = api::get_value("/plugins/tracetramp/admin/stats").await {
                set_stats.set(Some(s));
            }
        });
    });

    view! {
        <ConsoleChrome
            title="TraceTramp"
            kind="Live contract — configure · HITL · policies · blocks · quarantine · traces."
            setup_href="/plugins/tracetramp/setup"
            plugin="tracetramp"
        >
            <LiveContractMap plugin="tracetramp" />
            <PolicyLineageSnippet />
            <section class="lc-panel">
                <p class="lc-panel__eyebrow">"FNI · forensics join (P6.4)"</p>
                <OpFniMomentBadge />
            </section>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading TraceTramp…".to_string() /> }>
                {move || Suspend::new(async move {
                    match status.await {
                        Ok(v) => {
                            if let Some(e) = soft_err(&v) {
                                return view! { <OpApiErrorBanner error=api_err(e) /> }.into_any();
                            }
                            let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                            let reachable = v.get("upstream_reachable").and_then(|x| x.as_bool());
                            let control = v
                                .get("control_status")
                                .and_then(|x| x.as_str())
                                .unwrap_or(if !ok {
                                    "not_configured"
                                } else if reachable == Some(true) {
                                    "reachable"
                                } else if reachable == Some(false) {
                                    "unavailable"
                                } else {
                                    "unknown"
                                })
                                .to_string();
                            let enforce = v
                                .get("enforce_posture")
                                .and_then(|x| x.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let badge_class = match control.as_str() {
                                "reachable" => "mt-2 inline-flex rounded px-2 py-0.5 text-[11px] font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/50",
                                "unavailable" => "mt-2 inline-flex rounded px-2 py-0.5 text-[11px] font-medium bg-amber-950/50 text-amber-200 border border-amber-800/40",
                                _ => "mt-2 inline-flex rounded px-2 py-0.5 text-[11px] font-medium bg-zinc-900 text-zinc-400 border border-zinc-700/60",
                            };
                            let hint = v.get("hint").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let raw = serde_json::to_string_pretty(&v).unwrap_or_default();
                            view! {
                                <section class="lc-panel">
                                    <p class="lc-panel__eyebrow">"Status · GET /plugins/tracetramp/status"</p>
                                    <span class=badge_class>{format!("TT · {control} · {enforce}")}</span>
                                    <dl class="mt-2 space-y-1.5">
                                        <KvRow label="configured" value=if ok { "yes".into() } else { "no".into() } />
                                        <KvRow label="control" value=control.clone() />
                                        <KvRow label="enforce" value=enforce />
                                        <KvRow label="upstream" value=reachable.map(|b| b.to_string()).unwrap_or_else(|| "—".into()) />
                                        <KvRow label="url set" value=v.get("management_url_explicit").and_then(|x| x.as_bool()).map(|b| b.to_string()).unwrap_or_else(|| "—".into()) />
                                    </dl>
                                    <p class="mt-2 text-[11px] text-zinc-500">"unavailable ≠ healthy — green only when control=reachable. Talk does not hop :9741 on this trial. Empty graph is expected. Prove writes playground receipts, not TraceTramp nodes."</p>
                                    {(!hint.is_empty()).then(|| view! { <p class="mt-1 text-[11px] text-zinc-500">{hint}</p> })}
                                </section>

                                <section class="space-y-3 lc-panel">
                                    <p class="lc-panel__eyebrow">"Configure · POST /plugins/tracetramp/configure"</p>
                                    <label class="block">
                                        <span class="lc-label">"Management URL"</span>
                                        <input
                                            type="url"
                                            class="lc-field"
                                            prop:value=move || url.get()
                                            on:input=move |ev| set_url.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <label class="block">
                                        <span class="lc-label">"Admin token"</span>
                                        <input
                                            type="password"
                                            class="lc-field"
                                            placeholder="leave blank to keep existing"
                                            prop:value=move || token.get()
                                            on:input=move |ev| set_token.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <div class="flex flex-wrap gap-2">
                                        <OpButton
                                            label="Save".to_string()
                                            variant=OpButtonVariant::Primary
                                            loading=busy.get()
                                            on_click=Arc::new(move |_| {
                                                set_busy.set(true);
                                                set_msg.set(None);
                                                let mut values = json!({ "management_url": url.get().trim() });
                                                let t = token.get();
                                                if !t.trim().is_empty() {
                                                    values.as_object_mut().unwrap().insert("admin_token".into(), json!(t.trim()));
                                                }
                                                spawn_local(async move {
                                                    match api::post_value("/plugins/tracetramp/configure", json!({ "values": values })).await {
                                                        Ok(v) => {
                                                            if let Some(e) = soft_err(&v) {
                                                                set_msg.set(Some((e, false)));
                                                            } else {
                                                                set_msg.set(Some(("Saved. Env overrides still win when set.".into(), true)));
                                                                set_reload.update(|n| *n = n.wrapping_add(1));
                                                            }
                                                        }
                                                        Err(e) => set_msg.set(Some((e.message, false))),
                                                    }
                                                    set_busy.set(false);
                                                });
                                            })
                                        />
                                        <OpButton
                                            label="Probe + stats".to_string()
                                            variant=OpButtonVariant::Secondary
                                            on_click=Arc::new(move |_| {
                                                set_busy.set(true);
                                                spawn_local(async move {
                                                    let st = api::get_value("/plugins/tracetramp/status").await;
                                                    let stats_v = api::get_value("/plugins/tracetramp/admin/stats").await.ok();
                                                    match st {
                                                        Ok(v) => {
                                                            if let Some(e) = soft_err(&v) {
                                                                set_msg.set(Some((e, false)));
                                                            } else {
                                                                let up = v.get("upstream_reachable").and_then(|x| x.as_bool());
                                                                let control = v
                                                                    .get("control_status")
                                                                    .and_then(|x| x.as_str())
                                                                    .unwrap_or("unknown");
                                                                let healthy = up == Some(true);
                                                                set_msg.set(Some((format!(
                                                                    "control={} ok={} upstream={}",
                                                                    control,
                                                                    v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false),
                                                                    up.map(|b| b.to_string()).unwrap_or_else(|| "n/a".into())
                                                                ), healthy)));
                                                                set_stats.set(stats_v);
                                                                set_reload.update(|n| *n = n.wrapping_add(1));
                                                            }
                                                        }
                                                        Err(e) => set_msg.set(Some((e.message, false))),
                                                    }
                                                    set_busy.set(false);
                                                });
                                            })
                                        />
                                    </div>
                                    <Show when=move || msg.get().is_some()>
                                        <p class=move || if msg.get().map(|(_, ok)| ok).unwrap_or(false) {
                                            "text-xs text-emerald-400"
                                        } else {
                                            "text-xs text-amber-400"
                                        }>
                                            {move || msg.get().map(|(m, _)| m).unwrap_or_default()}
                                        </p>
                                    </Show>
                                    {move || stats.get().map(|s| {
                                        view! {
                                            <dl class="lc-inset space-y-1">
                                                <KvRow label="active_calls" value=s.get("active_calls").map(|x| x.to_string()).unwrap_or_else(|| "—".into()) />
                                                <KvRow label="policy_hits_5m" value=s.get("policy_hits_last_5m").map(|x| x.to_string()).unwrap_or_else(|| "—".into()) />
                                                <KvRow label="budget_burn/min" value=s.get("budget_burn_per_min").map(|x| x.to_string()).unwrap_or_else(|| "—".into()) />
                                            </dl>
                                        }
                                    })}
                                </section>

                                <Show when=move || dev.get()>
                                    <OpDevDisclosure label="Status JSON".to_string() raw=raw.clone() />
                                </Show>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
            <TraceTrampRulesHitlPanel auth=auth />
        </ConsoleChrome>
    }
}

// ── WitnessCtl ───────────────────────────────────────────────────────────────

#[component]
pub fn WitnessCtlLightConsole(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("WitnessCtl");
    let (dev, _) = use_developer_view();
    let (reload, set_reload) = signal(0u32);
    let (url, set_url) = signal("http://127.0.0.1:7443".to_string());
    let (token, set_token) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (msg, set_msg) = signal(Option::<(String, bool)>::None);
    let (health_label, set_health_label) = signal(Option::<String>::None);
    let (sessions_n, set_sessions_n) = signal(Option::<usize>::None);

    let status = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/plugins/witnessctl/status").await }
    });

    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(v) = api::get_value("/plugins/witnessctl/configure").await {
                if let Some(u) = v
                    .pointer("/values/management_url")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                {
                    set_url.set(u.to_string());
                }
            }
        });
    });

    view! {
        <ConsoleChrome
            title="WitnessCtl"
            kind="Live contract — sessions · HITL · compliance · custody · ingest · export."
            setup_href="/plugins/witnessctl/setup"
            plugin="witnessctl"
        >
            <LiveContractMap plugin="witnessctl" />
            <PolicyLineageSnippet />
            <section class="lc-panel">
                <p class="lc-panel__eyebrow">"FNI · forensics join (P6.4)"</p>
                <OpFniMomentBadge />
            </section>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading WitnessCtl…".to_string() /> }>
                {move || Suspend::new(async move {
                    match status.await {
                        Ok(v) => {
                            if let Some(e) = soft_err(&v) {
                                return view! { <OpApiErrorBanner error=api_err(e) /> }.into_any();
                            }
                            let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                            let hint = v.get("hint").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let raw = serde_json::to_string_pretty(&v).unwrap_or_default();
                            view! {
                                <section class="lc-panel">
                                    <p class="lc-panel__eyebrow">"Status · GET /plugins/witnessctl/status"</p>
                                    <dl class="mt-2 space-y-1.5">
                                        <KvRow label="api proxy" value=if ok { "configured".into() } else { "missing".into() } />
                                        <KvRow label="health proxy" value=v.get("health_proxy_configured").and_then(|x| x.as_bool()).map(|b| b.to_string()).unwrap_or_else(|| "—".into()) />
                                        <KvRow label="upstream" value=v.get("upstream_reachable").and_then(|x| x.as_bool()).map(|b| b.to_string()).unwrap_or_else(|| "—".into()) />
                                    </dl>
                                    {(!hint.is_empty()).then(|| view! { <p class="mt-2 text-[11px] text-zinc-500">{hint}</p> })}
                                </section>

                                <section class="space-y-3 lc-panel">
                                    <p class="lc-panel__eyebrow">"Configure · POST /plugins/witnessctl/configure"</p>
                                    <label class="block">
                                        <span class="lc-label">"Management URL"</span>
                                        <input
                                            type="url"
                                            class="lc-field"
                                            prop:value=move || url.get()
                                            on:input=move |ev| set_url.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <label class="block">
                                        <span class="lc-label">"Admin / API token"</span>
                                        <input
                                            type="password"
                                            class="lc-field"
                                            placeholder="leave blank to keep existing"
                                            prop:value=move || token.get()
                                            on:input=move |ev| set_token.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <div class="flex flex-wrap gap-2">
                                        <OpButton
                                            label="Save".to_string()
                                            variant=OpButtonVariant::Primary
                                            loading=busy.get()
                                            on_click=Arc::new(move |_| {
                                                set_busy.set(true);
                                                set_msg.set(None);
                                                let mut values = json!({ "management_url": url.get().trim() });
                                                let t = token.get();
                                                if !t.trim().is_empty() {
                                                    values.as_object_mut().unwrap().insert("admin_token".into(), json!(t.trim()));
                                                }
                                                spawn_local(async move {
                                                    match api::post_value("/plugins/witnessctl/configure", json!({ "values": values })).await {
                                                        Ok(v) => {
                                                            if let Some(e) = soft_err(&v) {
                                                                set_msg.set(Some((e, false)));
                                                            } else {
                                                                set_msg.set(Some(("Saved.".into(), true)));
                                                                set_reload.update(|n| *n = n.wrapping_add(1));
                                                            }
                                                        }
                                                        Err(e) => set_msg.set(Some((e.message, false))),
                                                    }
                                                    set_busy.set(false);
                                                });
                                            })
                                        />
                                        <OpButton
                                            label="Probe health".to_string()
                                            variant=OpButtonVariant::Secondary
                                            on_click=Arc::new(move |_| {
                                                set_busy.set(true);
                                                spawn_local(async move {
                                                    let h = api::get_value("/plugins/witnessctl/health").await;
                                                    let sess = api::get_value("/plugins/witnessctl/sessions").await.ok();
                                                    match h {
                                                        Ok(v) => {
                                                            if let Some(e) = soft_err(&v) {
                                                                set_msg.set(Some((e, false)));
                                                                set_health_label.set(None);
                                                            } else {
                                                                let label = v
                                                                    .get("status")
                                                                    .or_else(|| v.get("ok"))
                                                                    .map(|x| x.to_string())
                                                                    .unwrap_or_else(|| "ok".into());
                                                                set_health_label.set(Some(label));
                                                                let n = sess.as_ref().and_then(|s| {
                                                                    s.get("sessions")
                                                                        .or_else(|| s.get("items"))
                                                                        .and_then(|a| a.as_array())
                                                                        .map(|a| a.len())
                                                                });
                                                                set_sessions_n.set(n);
                                                                set_msg.set(Some(("Health probe ok.".into(), true)));
                                                                set_reload.update(|n| *n = n.wrapping_add(1));
                                                            }
                                                        }
                                                        Err(e) => set_msg.set(Some((e.message, false))),
                                                    }
                                                    set_busy.set(false);
                                                });
                                            })
                                        />
                                    </div>
                                    <Show when=move || msg.get().is_some()>
                                        <p class=move || if msg.get().map(|(_, ok)| ok).unwrap_or(false) {
                                            "text-xs text-emerald-400"
                                        } else {
                                            "text-xs text-amber-400"
                                        }>
                                            {move || msg.get().map(|(m, _)| m).unwrap_or_default()}
                                        </p>
                                    </Show>
                                    <Show when=move || health_label.get().is_some() || sessions_n.get().is_some()>
                                        <dl class="lc-inset space-y-1">
                                            <KvRow label="health" value=health_label.get().unwrap_or_else(|| "—".into()) />
                                            <KvRow label="sessions" value=sessions_n.get().map(|n| n.to_string()).unwrap_or_else(|| "—".into()) />
                                        </dl>
                                    </Show>
                                </section>

                                <Show when=move || dev.get()>
                                    <OpDevDisclosure label="Status JSON".to_string() raw=raw.clone() />
                                </Show>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
            <WitnessCtlRulesHitlPanel auth=auth />
        </ConsoleChrome>
    }
}
