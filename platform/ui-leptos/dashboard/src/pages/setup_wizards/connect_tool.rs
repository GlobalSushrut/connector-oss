//! Connect-a-tool wizard — `/setup/connect-tool`.
//!
//! Action-tool path for coding agents (DevGuard):
//! 1. Pick IDE/agent tool
//! 2. Enter real workspace path (local repo)
//! 3. POST `/devguard/connect` → bind repo only (no cg_ mint)
//! 4. Attach an agent to receive a repo-bound cg_ token
//! 5. Copy tool snippet + CLI cage commands
//! 6. Verify via curl / WATCH

use leptos::prelude::*;
use leptos_router::components::A;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::layout::Header;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};

const WIZARD_ID: &str = "connect-tool";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConnectToolState {
    tool: String,
    workspace: String,
    role: String,
    /// `local_folder` | `github_checkout`
    origin_kind: String,
    github_url: String,
    base_url: String,
    api_key: String,
    session_id: String,
    agent_pid: String,
    instructions_json: String,
    cli_hint: String,
}

fn normalize_tool(tool: &str) -> String {
    match tool.trim().to_ascii_lowercase().as_str() {
        "claude-code" | "claude_code" | "claude" => "claude_code".into(),
        other => other.replace('-', "_"),
    }
}

#[component]
pub fn ConnectToolWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("Connect a coding tool");

    let steps = vec![
        WizardStep::new("pick", "Pick coding agent")
            .with_subtitle("Action tool — binds an IDE/agent through DevGuard to a workspace."),
        WizardStep::new("workspace", "Team project path")
            .with_subtitle("Local folder or GitHub checkout path — then CLI cage firewalls the agentic workspace."),
        WizardStep::new("creds", "Bind repo (then attach agent)")
            .with_subtitle("POST /devguard/connect binds the repo only. Attach an agent to receive a cg_ token."),
        WizardStep::new("snippet", "Wire the agent + cage")
            .with_subtitle("Paste settings into the tool; run CLI for host cage (browser cannot install cage)."),
        WizardStep::new("verify", "Verify first request")
            .with_subtitle("curl or chat — traffic should appear under WATCH.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<ConnectToolState>(WIZARD_ID);

    // Sensible defaults once.
    Effect::new(move |_| {
        set_state.update(|s| {
            if s.role.is_empty() {
                s.role = "developer".into();
            }
            if s.origin_kind.is_empty() {
                s.origin_kind = "local_folder".into();
            }
        });
    });

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! { <PickToolStep state=state set_state=set_state /> }.into_any(),
            1 => view! { <WorkspaceStep state=state set_state=set_state /> }.into_any(),
            2 => view! { <CredsStep state=state set_state=set_state /> }.into_any(),
            3 => view! { <SnippetStep state=state /> }.into_any(),
            4 => view! { <VerifyStep state=state /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    view! {
        <div class="page-wrapper">
            <Header title="Connect a coding tool" auth=auth />
            <div class="page-content max-w-3xl">
                <div class="mb-4 rounded-lg border border-amber-500/25 bg-amber-950/15 p-3 text-[11px] text-amber-100/90">
                    <p class="font-semibold">"Action tool (DevGuard) vs service institutions"</p>
                    <p class="mt-1 text-amber-200/80">
                        "This wizard binds Cursor/Claude/etc. to a local workspace via DevGuard + the LLM gateway. TraceTramp and WitnessCtl are service tools — configure management URL/token under their consoles, not here."
                    </p>
                </div>
                <WizardShell
                    controller=controller
                    steps=steps
                    step_view=step_view
                    on_finish=Callback::new(|()| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href("/watch");
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

const TOOLS: &[(&str, &str, &str)] = &[
    ("cursor", "Cursor", "OpenAI-compatible provider in Settings → Models."),
    ("windsurf", "Windsurf", "Custom OpenAI provider / model router."),
    ("claude_code", "Claude Code", "ANTHROPIC_BASE_URL + ANTHROPIC_API_KEY (or OpenAI-compat)."),
    ("kiro", "Kiro", "Tool-router base URL."),
    ("generic", "Generic OpenAI client", "Any client with Base URL + API key."),
];

#[component]
fn PickToolStep(
    state: ReadSignal<ConnectToolState>,
    set_state: WriteSignal<ConnectToolState>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {TOOLS.iter().map(|(slug, name, hint)| {
                    let slug_owned = slug.to_string();
                    let selected = {
                        let s = slug_owned.clone();
                        Memo::new(move |_| normalize_tool(&state.get().tool) == s)
                    };
                    let slug_click = slug_owned.clone();
                    view! {
                        <button
                            type="button"
                            class=move || if selected.get() {
                                "rounded-xl border border-indigo-500/50 bg-indigo-500/10 px-3 py-3 text-left"
                            } else {
                                "rounded-xl border border-zinc-800/60 bg-zinc-900/40 px-3 py-3 text-left hover:border-zinc-700/80"
                            }
                            on:click=move |_| {
                                let t = slug_click.clone();
                                set_state.update(|s| s.tool = t);
                            }
                        >
                            <p class="text-sm font-semibold text-zinc-100">{*name}</p>
                            <p class="text-xs text-zinc-500 mt-0.5">{*hint}</p>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>
        </div>
    }
}

#[component]
fn WorkspaceStep(
    state: ReadSignal<ConnectToolState>,
    set_state: WriteSignal<ConnectToolState>,
) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <div class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-[11px] text-zinc-400 space-y-1">
                <p class="font-medium text-zinc-200">"How team projects are bound"</p>
                <p>"Local folder: path to the shared checkout on the workstation running the agent."</p>
                <p>"GitHub: clone with "<code class="text-zinc-300">"gh repo clone org/repo"</code>" (or git clone), then bind that absolute path. Hub does not OAuth-clone repos."</p>
                <p>"Firewall: after bind, CLI cage applies git/FS/exec guardrails over that agentic workspace."</p>
            </div>
            <div class="flex flex-wrap gap-2">
                <button
                    type="button"
                    class=move || if state.get().origin_kind != "github_checkout" {
                        "rounded-lg border border-indigo-500/50 bg-indigo-500/10 px-3 py-1.5 text-xs text-zinc-100"
                    } else {
                        "rounded-lg border border-zinc-800/60 bg-zinc-900/40 px-3 py-1.5 text-xs text-zinc-400"
                    }
                    on:click=move |_| set_state.update(|s| s.origin_kind = "local_folder".into())
                >"Local folder"</button>
                <button
                    type="button"
                    class=move || if state.get().origin_kind == "github_checkout" {
                        "rounded-lg border border-indigo-500/50 bg-indigo-500/10 px-3 py-1.5 text-xs text-zinc-100"
                    } else {
                        "rounded-lg border border-zinc-800/60 bg-zinc-900/40 px-3 py-1.5 text-xs text-zinc-400"
                    }
                    on:click=move |_| set_state.update(|s| s.origin_kind = "github_checkout".into())
                >"GitHub checkout"</button>
            </div>
            {move || if state.get().origin_kind == "github_checkout" {
                view! {
                    <label class="block">
                        <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"GitHub URL (metadata)"</span>
                        <input
                            type="text"
                            class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                            placeholder="https://github.com/acme/team-repo"
                            prop:value=move || state.get().github_url
                            on:input=move |ev| {
                                let v = event_target_value(&ev);
                                set_state.update(|s| s.github_url = v);
                            }
                        />
                    </label>
                }.into_any()
            } else {
                view! { <span></span> }.into_any()
            }}
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Absolute checkout path (required)"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    placeholder="/home/you/Projects/acme-repo"
                    prop:value=move || state.get().workspace
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.workspace = v);
                    }
                />
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Role"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    placeholder="developer"
                    prop:value=move || state.get().role
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.role = v);
                    }
                />
            </label>
            <p class="text-xs text-zinc-500">
                "Host cage (agentic firewall) is CLI-only: "
                <code class="text-zinc-400">"devguard init && devguard connect … --cage"</code>
                ". Browser bind does not mint identity — attach an agent for a cg_ token."
            </p>
        </div>
    }
}

#[component]
fn CredsStep(
    state: ReadSignal<ConnectToolState>,
    set_state: WriteSignal<ConnectToolState>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal::<Option<String>>(None);

    let on_issue = move |_| {
        if busy.get() {
            return;
        }
        let tool = normalize_tool(&state.get().tool);
        let workspace = state.get().workspace.trim().to_string();
        let role = {
            let r = state.get().role.trim().to_string();
            if r.is_empty() {
                "developer".into()
            } else {
                r
            }
        };
        if tool.is_empty() {
            set_err.set(Some("Pick a tool first.".into()));
            return;
        }
        if workspace.is_empty()
            || workspace == "/workspace"
            || workspace == "."
            || !workspace.starts_with('/')
        {
            set_err.set(Some(
                "Enter an absolute local path (e.g. /home/you/Projects/repo). Placeholder /workspace is rejected."
                    .into(),
            ));
            return;
        }
        set_busy.set(true);
        set_err.set(None);
        let origin_kind = {
            let o = state.get().origin_kind.trim().to_string();
            if o.is_empty() {
                "local_folder".into()
            } else {
                o
            }
        };
        let github_url = state.get().github_url.trim().to_string();
        let mut payload = serde_json::json!({
            "tool": tool,
            "role": role,
            "workspace": workspace,
            "origin_kind": origin_kind,
        });
        if !github_url.is_empty() {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("github_url".into(), serde_json::json!(github_url));
            }
        }
        spawn_local(async move {
            match api::post_value("/devguard/connect", payload).await {
                Ok(v) => {
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        set_err.set(Some(
                            v.get("error")
                                .and_then(|x| x.as_str())
                                .unwrap_or("connect failed")
                                .to_string(),
                        ));
                        set_busy.set(false);
                        return;
                    }
                    let base = extract_first_string(
                        &v,
                        &["openai_base_url", "gateway_base", "base_url", "gateway_url"],
                    )
                    .unwrap_or_default();
                    // Prefer /v1 OpenAI-compat URL when only gateway_base returned.
                    let base = if base.ends_with("/v1") {
                        base
                    } else if !base.is_empty() {
                        format!("{}/v1", base.trim_end_matches('/'))
                    } else {
                        String::new()
                    };
                    let key = extract_first_string(&v, &["token", "session_token", "api_key"])
                        .unwrap_or_default();
                    let session_id =
                        extract_first_string(&v, &["session_id", "bind_id"]).unwrap_or_default();
                    let agent_pid =
                        extract_first_string(&v, &["agent_pid"]).unwrap_or_default();
                    let instructions = v
                        .get("instructions")
                        .map(|x| serde_json::to_string_pretty(x).unwrap_or_default())
                        .unwrap_or_default();
                    let ws = v
                        .get("workspace")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let cli = format!(
                        "# Repo is bound on this node (workspace API — not a laptop clone).\n\
                         # Attach an agent to mint a cg_ token, then:\n\
                         cd {workspace}\n\
                         devguard init\n\
                         devguard connect {tool} --cage\n\
                         # Bind id: {session_id}"
                    );
                    if base.is_empty() {
                        set_err.set(Some(format!(
                            "Connect succeeded but response missing base URL. Raw keys: {}",
                            v.as_object()
                                .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
                                .unwrap_or_default()
                        )));
                    } else if key.is_empty() {
                        set_err.set(Some(
                            "Repo bound. Attach an agent with a name and role to get a cg_ token."
                                .into(),
                        ));
                    }
                    let tool_for_profile = tool.clone();
                    let role_for_profile = role.clone();
                    let workspace_for_profile = workspace.clone();
                    set_state.update(|s| {
                        s.base_url = base;
                        s.api_key = key;
                        s.session_id = session_id;
                        s.agent_pid = agent_pid;
                        s.instructions_json = instructions;
                        s.cli_hint = cli;
                        if !ws.is_empty() {
                            s.workspace = ws;
                        }
                        s.tool = tool;
                    });
                    // Persist hub-side workstation hint (real API).
                    let profile = serde_json::json!({
                        "profile": {
                            "schema_version": 1,
                            "primary_tool": tool_for_profile,
                            "workspace_root_hint": workspace_for_profile,
                            "default_role_name": role_for_profile,
                            "single_workstation_acknowledged": true,
                            "roles": [{
                                "name": role_for_profile,
                                "description": "Connected from connect-tool wizard",
                                "tool_access": [{ "tool": tool_for_profile, "mode": "allow" }]
                            }]
                        }
                    });
                    let _ = api::post_value("/plugins/devguard/local-profile", profile).await;
                }
                Err(e) => set_err.set(Some(e.message)),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <p class="text-xs text-zinc-500 font-mono">
                {move || format!(
                    "Will POST /devguard/connect {{ tool:{}, role:{}, workspace:{} }}",
                    normalize_tool(&state.get().tool),
                    state.get().role,
                    state.get().workspace
                )}
            </p>
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-60"
                prop:disabled=move || busy.get()
                on:click=on_issue
            >
                {move || if busy.get() { "Issuing session…" } else { "Issue DevGuard session" }}
            </button>
            {move || err.get().map(|m| view! {
                <p class="text-xs text-amber-300 whitespace-pre-wrap">{m}</p>
            })}
            {move || {
                let s = state.get();
                if s.api_key.is_empty() {
                    view! {
                        <p class="text-xs text-zinc-500">"Issue a session after setting the workspace path."</p>
                    }.into_any()
                } else {
                    view! {
                        <div class="space-y-2">
                            <CredentialRow label="OpenAI base" value=s.base_url.clone() />
                            <CredentialRow label="Token" value=s.api_key.clone() mask=true />
                            <CredentialRow label="Session" value=s.session_id.clone() />
                            <CredentialRow label="Agent PID" value=s.agent_pid.clone() />
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[component]
fn CredentialRow(label: &'static str, value: String, #[prop(optional)] mask: bool) -> impl IntoView {
    let display = if mask && value.len() > 12 {
        format!("{}…{}", &value[..6], &value[value.len() - 4..])
    } else {
        value.clone()
    };
    let value_for_copy = value.clone();
    view! {
        <div class="rounded-lg border border-zinc-800/60 bg-zinc-950/40 px-3 py-2 flex items-center gap-2">
            <span class="text-[10px] uppercase tracking-wider text-zinc-500 w-24 shrink-0">{label}</span>
            <code class="flex-1 text-xs font-mono text-zinc-100 truncate">{display}</code>
            <button
                type="button"
                class="text-[11px] px-2 py-0.5 rounded border border-zinc-700/60 text-zinc-400 hover:text-zinc-200"
                on:click=move |_| {
                    if let Some(win) = web_sys::window() {
                        let _ = win.navigator().clipboard().write_text(&value_for_copy);
                    }
                }
            >
                "Copy"
            </button>
        </div>
    }
}

fn extract_first_string(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

#[component]
fn SnippetStep(state: ReadSignal<ConnectToolState>) -> impl IntoView {
    view! {
        {move || {
            let s = state.get();
            if s.api_key.is_empty() {
                return view! {
                    <p class="text-sm text-zinc-500">"Issue credentials on the previous step first."</p>
                }.into_any();
            }
            let snippet = snippet_for(&s.tool, &s.base_url, &s.api_key);
            let snippet_for_copy = snippet.clone();
            let cli = s.cli_hint.clone();
            let cli_copy = cli.clone();
            view! {
                <div class="space-y-3">
                    <p class="text-sm text-zinc-300">"1) Wire the coding agent (settings / env):"</p>
                    <pre class="rounded-lg border border-zinc-800/60 bg-zinc-950/60 px-3 py-3 text-[11px] font-mono text-zinc-100 whitespace-pre-wrap leading-relaxed">{snippet}</pre>
                    <button
                        type="button"
                        class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700/60"
                        on:click=move |_| {
                            if let Some(win) = web_sys::window() {
                                let _ = win.navigator().clipboard().write_text(&snippet_for_copy);
                            }
                        }
                    >"Copy agent snippet"</button>
                    <p class="text-sm text-zinc-300 mt-4">"2) Host cage (CLI on the workstation — required for folder/git enforcement):"</p>
                    <pre class="rounded-lg border border-amber-500/20 bg-amber-950/10 px-3 py-3 text-[11px] font-mono text-amber-100/90 whitespace-pre-wrap leading-relaxed">{cli}</pre>
                    <button
                        type="button"
                        class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700/60"
                        on:click=move |_| {
                            if let Some(win) = web_sys::window() {
                                let _ = win.navigator().clipboard().write_text(&cli_copy);
                            }
                        }
                    >"Copy CLI commands"</button>
                    <p class="text-[11px] text-zinc-500">
                        "Data flow: coding agent → Connector gateway (token) → TraceTramp (if wired) → model; DevGuard CLI cages host FS/exec/git for "
                        {s.workspace.clone()}
                        "."
                    </p>
                </div>
            }.into_any()
        }}
    }
}

fn snippet_for(tool: &str, base_url: &str, api_key: &str) -> String {
    match normalize_tool(tool).as_str() {
        "cursor" => format!(
            "// Cursor → Settings → Models → Custom OpenAI Provider\n{{\n  \"openai\": {{\n    \"baseUrl\": \"{base_url}\",\n    \"apiKey\": \"{api_key}\"\n  }}\n}}"
        ),
        "windsurf" => format!(
            "// Windsurf → Settings → Models → Custom Provider\nopenai:\n  base_url: {base_url}\n  api_key: {api_key}"
        ),
        "claude_code" => format!(
            "# Claude Code\nexport ANTHROPIC_BASE_URL={base_url}\nexport ANTHROPIC_API_KEY={api_key}\n# or OpenAI-compat:\nexport OPENAI_BASE_URL={base_url}\nexport OPENAI_API_KEY={api_key}"
        ),
        "kiro" => format!(
            "# Kiro tool-router\nrouter.base_url = \"{base_url}\"\nrouter.api_key = \"{api_key}\""
        ),
        _ => format!(
            "// Any OpenAI-compatible client\nimport OpenAI from \"openai\";\nconst client = new OpenAI({{\n  baseURL: \"{base_url}\",\n  apiKey: \"{api_key}\",\n}});"
        ),
    }
}

#[component]
fn VerifyStep(state: ReadSignal<ConnectToolState>) -> impl IntoView {
    view! {
        {move || {
            let s = state.get();
            if s.api_key.is_empty() {
                return view! {
                    <p class="text-sm text-zinc-500">"Issue credentials first."</p>
                }.into_any();
            }
            let curl = format!(
                "curl -s {}/chat/completions \\\n  -H \"authorization: Bearer {}\" \\\n  -H \"content-type: application/json\" \\\n  -d '{{\"model\":\"gpt-4o-mini\",\"messages\":[{{\"role\":\"user\",\"content\":\"Hello from Connector\"}}]}}'",
                s.base_url.trim_end_matches('/'), s.api_key
            );
            let curl_copy = curl.clone();
            view! {
                <div class="space-y-3">
                    <p class="text-sm text-zinc-300">
                        "Send a test completion. Then open WATCH — you should see the governed call for session "
                        <span class="font-mono text-zinc-100">{s.session_id.clone()}</span>
                        "."
                    </p>
                    <pre class="rounded-lg border border-zinc-800/60 bg-zinc-950/60 px-3 py-3 text-[11px] font-mono text-zinc-100 whitespace-pre-wrap leading-relaxed">{curl}</pre>
                    <div class="flex flex-wrap items-center gap-2">
                        <button
                            type="button"
                            class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700/60"
                            on:click=move |_| {
                                if let Some(win) = web_sys::window() {
                                    let _ = win.navigator().clipboard().write_text(&curl_copy);
                                }
                            }
                        >"Copy curl"</button>
                        <A href="/watch" attr:class="text-xs text-indigo-400 hover:text-indigo-300 underline-offset-2 hover:underline">
                            "Open WATCH →"
                        </A>
                        <A href="/plugins/devguard" attr:class="text-xs text-indigo-400 hover:text-indigo-300 underline-offset-2 hover:underline">
                            "DevGuard console →"
                        </A>
                    </div>
                </div>
            }.into_any()
        }}
    }
}
