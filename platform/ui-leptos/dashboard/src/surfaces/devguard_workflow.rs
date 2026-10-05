//! DevGuard as a dashboard workflow: generate or link a repo, cage it,
//! attach N agents with different rules on the same node.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;

fn copy_text(text: &str) {
    if let Some(win) = web_sys::window() {
        let _ = win.navigator().clipboard().write_text(text);
    }
}

fn soft_err(v: &Value) -> Option<String> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return Some(
            v.get("message")
                .or_else(|| v.get("error"))
                .and_then(|e| e.as_str())
                .unwrap_or("Request failed")
                .into(),
        );
    }
    None
}

#[component]
pub fn DevGuardWorkflowPanel() -> impl IntoView {
    let (mode, set_mode) = signal("link".to_string());
    let (project, set_project) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal(String::new());
    let (out, set_out) = signal(Option::<Value>::None);
    let (copied, set_copied) = signal(String::new());
    let (agent_name, set_agent_name) = signal(String::new());
    let (agent_role, set_agent_role) = signal("junior".to_string());
    let (agent_tool, set_agent_tool) = signal("cursor".to_string());
    let (agents, set_agents) = signal(Vec::<Value>::new());

    let bind = move |_| {
        if busy.get_untracked() {
            return;
        }
        let name = project.get_untracked().trim().to_string();
        if name.is_empty() {
            set_err.set("Paste a GitHub URL, org/repo, or a name to generate.".into());
            return;
        }
        set_busy.set(true);
        set_err.set(String::new());
        let generate = mode.get_untracked() == "generate";
        spawn_local(async move {
            match api::post_value(
                "/devguard/connect",
                json!({
                    "project": name,
                    "generate": generate,
                    "tool": "generic",
                    "role": "developer",
                }),
            )
            .await
            {
                Ok(v) => {
                    if let Some(e) = soft_err(&v) {
                        set_err.set(e);
                        set_out.set(None);
                    } else {
                        let list = v
                            .get("agents")
                            .and_then(|a| a.as_array())
                            .cloned()
                            .unwrap_or_default();
                        set_agents.set(list);
                        set_out.set(Some(v));
                    }
                }
                Err(e) => set_err.set(e.message),
            }
            set_busy.set(false);
        });
    };

    let attach = move |_| {
        let Some(v) = out.get_untracked() else { return };
        let repo_id = v.get("repo_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if repo_id.is_empty() {
            return;
        }
        let name = agent_name.get_untracked().trim().to_string();
        if name.is_empty() {
            set_err.set("Name the agent — Cursor-1, intern-bot, reviewer…".into());
            return;
        }
        set_busy.set(true);
        set_err.set(String::new());
        let role = agent_role.get_untracked();
        let tool = agent_tool.get_untracked();
        spawn_local(async move {
            match api::post_value(
                &format!("/devguard/repos/{repo_id}/agents"),
                json!({ "name": name, "role": role, "tool": tool }),
            )
            .await
            {
                Ok(v) => {
                    if let Some(e) = soft_err(&v) {
                        set_err.set(e);
                    } else if let Some(row) = v.get("agent").cloned() {
                        set_agents.update(|a| a.push(row));
                        set_agent_name.set(String::new());
                    }
                }
                Err(e) => set_err.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <section class="mb-4 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-4 sm:p-5">
            <p class="text-[11px] font-semibold uppercase tracking-wider text-emerald-400/90">"Workflow · DevGuard"</p>
            <h2 class="mt-1 text-lg font-semibold text-zinc-100">"Generate or link a repo. Then attach agents."</h2>
            <p class="mt-1 text-sm text-zinc-400">
                "This node holds the working copy. Attach agents. They get a cage address and a cg_ token — not a folder. No ID + role → even read is denied. A raw clone is not this repo."
            </p>

            <div class="mt-3 flex flex-wrap gap-2">
                <button type="button"
                    class=move || if mode.get() == "link" { "rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-semibold text-emerald-950" } else { "rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200" }
                    on:click=move |_| set_mode.set("link".into())>
                    "Link GitHub"
                </button>
                <button type="button"
                    class=move || if mode.get() == "generate" { "rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-semibold text-emerald-950" } else { "rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200" }
                    on:click=move |_| set_mode.set("generate".into())>
                    "Generate repo"
                </button>
            </div>

            <label class="mt-3 block">
                <span class="mb-1 block text-[10px] uppercase tracking-wider text-zinc-500">
                    {move || if mode.get() == "generate" { "New repo name" } else { "GitHub URL or org/repo" }}
                </span>
                <input
                    type="text"
                    class="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
                    placeholder=move || if mode.get() == "generate" { "acme-api" } else { "you/repo or https://github.com/you/repo" }
                    prop:value=move || project.get()
                    on:input=move |ev| {
                        set_project.set(event_target_value(&ev));
                        set_err.set(String::new());
                    }
                />
            </label>
            <button
                type="button"
                class="mt-3 w-full rounded-xl bg-emerald-500 px-4 py-2.5 text-sm font-bold text-emerald-950 hover:brightness-110 disabled:opacity-60"
                disabled=move || busy.get()
                on:click=bind
            >
                {move || if busy.get() { "Working…" } else if mode.get() == "generate" { "Generate and cage →" } else { "Link and cage →" }}
            </button>
            <Show when=move || !err.get().is_empty()>
                <p class="mt-2 text-xs text-amber-400">{move || err.get()}</p>
            </Show>

            {move || out.get().map(|v| {
                let token = v.pointer("/repo_address/api_key").or_else(|| v.get("token")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let base = v.pointer("/repo_address/openai_base_url").or_else(|| v.get("openai_base_url")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let workspace_url = v.pointer("/workspace_api/tree").or_else(|| v.pointer("/workspace_api/repo_url")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let repo_id = v.get("repo_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let token_c = token.clone();
                let base_c = base.clone();
                let workspace_c = workspace_url.clone();
                view! {
                    <div class="mt-4 space-y-3 border-t border-emerald-500/15 pt-4">
                        <p class="text-sm font-semibold text-zinc-100">{format!("Repo {repo_id} is under DevGuard.")}</p>
                        <div class="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
                            <p class="text-xs font-semibold text-amber-200">"No Connector ID → even read is denied."</p>
                            <p class="mt-1 text-[11px] text-zinc-400">
                                "Open the cage address in Cursor. Do not open a raw clone. A raw clone is not this repo. Attach an agent below, or POST /api/v1/devguard/admit with header X-Connector-Repo."
                            </p>
                        </div>
                        {v.get("owner_roles").and_then(|r| r.as_object()).map(|roles| {
                            let cards: Vec<(String, String, String)> = roles.iter().map(|(k, e)| {
                                (
                                    k.clone(),
                                    e.get("label").and_then(|x| x.as_str()).unwrap_or(k).to_string(),
                                    e.get("summary").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                )
                            }).collect();
                            view! {
                                <div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
                                    {cards.into_iter().map(|(id, label, summary)| view! {
                                        <div class="rounded-lg border border-zinc-800 bg-zinc-950/50 px-3 py-2">
                                            <p class="text-xs font-semibold text-zinc-100">{label}</p>
                                            <p class="mt-0.5 font-mono text-[10px] text-zinc-500">{id}</p>
                                            <p class="mt-1 text-[11px] text-zinc-400">{summary}</p>
                                        </div>
                                    }).collect_view()}
                                </div>
                            }
                        })}
                        {(!workspace_url.is_empty()).then(|| view! {
                            <div class="flex items-center justify-between gap-2">
                                <div class="min-w-0">
                                    <p class="text-[10px] uppercase text-zinc-600">"Workspace (this node)"</p>
                                    <p class="truncate font-mono text-xs text-zinc-200">{workspace_url.clone()}</p>
                                </div>
                                <button type="button" class="shrink-0 rounded-lg border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200"
                                    on:click=move |_| { copy_text(&workspace_c); set_copied.set("ws".into()); }>
                                    {move || if copied.get() == "ws" { "Copied" } else { "Copy" }}
                                </button>
                            </div>
                        })}
                        <div class="flex items-center justify-between gap-2">
                            <div class="min-w-0">
                                <p class="text-[10px] uppercase text-zinc-600">"Cage address"</p>
                                <p class="truncate font-mono text-xs text-zinc-200">{base.clone()}</p>
                            </div>
                            <button type="button" class="shrink-0 rounded-lg border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200"
                                on:click=move |_| { copy_text(&base_c); set_copied.set("url".into()); }>
                                {move || if copied.get() == "url" { "Copied" } else { "Copy" }}
                            </button>
                        </div>
                        {(!token.is_empty()).then(|| view! {
                            <div class="flex items-center justify-between gap-2">
                                <div class="min-w-0">
                                    <p class="text-[10px] uppercase text-zinc-600">"Repo key"</p>
                                    <p class="truncate font-mono text-xs text-zinc-200">{token.clone()}</p>
                                </div>
                                <button type="button" class="shrink-0 rounded-lg border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200"
                                    on:click=move |_| { copy_text(&token_c); set_copied.set("key".into()); }>
                                    {move || if copied.get() == "key" { "Copied" } else { "Copy" }}
                                </button>
                            </div>
                        })}
                        <p class="text-[11px] text-zinc-500">"Attach an agent below to get a cg_ token. Link is not an identity."</p>
                        <div class="grid grid-cols-1 gap-2 sm:grid-cols-3">
                            <input class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-100" placeholder="Agent name"
                                prop:value=move || agent_name.get()
                                on:input=move |ev| set_agent_name.set(event_target_value(&ev)) />
                            <select class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-100"
                                prop:value=move || agent_role.get()
                                on:change=move |ev| set_agent_role.set(event_target_value(&ev))>
                                <option value="junior">"junior — src/tests only"</option>
                                <option value="builder">"builder"</option>
                                <option value="reviewer">"reviewer — read only"</option>
                                <option value="senior">"senior"</option>
                                <option value="devops">"devops — infra"</option>
                                <option value="owner">"owner"</option>
                            </select>
                            <select class="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-xs text-zinc-100"
                                prop:value=move || agent_tool.get()
                                on:change=move |ev| set_agent_tool.set(event_target_value(&ev))>
                                <option value="cursor">"Cursor"</option>
                                <option value="claude_code">"Claude Code"</option>
                                <option value="codex">"Codex"</option>
                                <option value="windsurf">"Windsurf"</option>
                                <option value="generic">"Any agent"</option>
                            </select>
                        </div>
                        <button type="button" class="rounded-lg border border-emerald-500/40 px-3 py-2 text-xs font-semibold text-emerald-200"
                            disabled=move || busy.get()
                            on:click=attach>
                            "Attach agent to this repo"
                        </button>
                        <ul class="space-y-1">
                            {agents.get().into_iter().map(|a| {
                                let n = a.get("name").and_then(|x| x.as_str()).unwrap_or("agent").to_string();
                                let r = a.get("role").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let s = a.get("summary").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let t = a.get("token").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let t_c = t.clone();
                                view! {
                                    <li class="flex items-center justify-between gap-2 rounded-lg border border-zinc-800 px-3 py-2">
                                        <div class="min-w-0">
                                            <p class="truncate text-xs text-zinc-200">{format!("{n} · {r}")}</p>
                                            <p class="truncate text-[11px] text-zinc-500">{s}</p>
                                            <p class="truncate font-mono text-[10px] text-zinc-500">{t}</p>
                                        </div>
                                        <button type="button" class="shrink-0 text-[11px] text-emerald-300"
                                            on:click=move |_| { copy_text(&t_c); set_copied.set(n.clone()); }>
                                            "Copy token"
                                        </button>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    </div>
                }
            })}
        </section>
    }
}
