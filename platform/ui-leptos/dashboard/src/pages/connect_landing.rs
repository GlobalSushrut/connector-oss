use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;
use crate::api;

#[component]
pub fn ConnectLanding() -> impl IntoView {
    let (tool, set_tool) = signal("windsurf".to_string());
    let (role, set_role) = signal("developer".to_string());
    let (workspace, set_workspace) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (result, set_result) = signal::<Option<Value>>(None);
    let (err, set_err) = signal(String::new());
    let (copied_url, set_copied_url) = signal(false);
    let (copied_key, set_copied_key) = signal(false);

    let info_res = LocalResource::new(|| api::get_value("/devguard/connect/info"));

    let do_connect = move |_| {
        if busy.get() { return; }
        set_busy.set(true);
        set_err.set(String::new());
        set_result.set(None);
        let body = serde_json::json!({
            "tool": tool.get(),
            "role": role.get(),
            "workspace": if workspace.get().is_empty() { "/workspace".to_string() } else { workspace.get() },
        });
        spawn_local(async move {
            match api::post_value("/devguard/connect", body).await {
                Ok(v) => set_result.set(Some(v)),
                Err(e) => set_err.set(e.message),
            }
            set_busy.set(false);
        });
    };

    let copy_to_clipboard = |text: String| {
        if let Some(win) = web_sys::window() {
            let _ = win.navigator().clipboard().write_text(&text);
        }
    };

    view! {
        // Phase 7.4 — re-skinned with the 6-token palette so /connect
        // matches the rest of the dashboard. Still pre-auth (no
        // Sidebar/Header chrome), just visually consistent.
        <div class="min-h-screen overflow-y-auto bg-zinc-950 text-zinc-100 flex flex-col font-sans antialiased">

            // ── Header ─────────────────────────────────────────────────────
            <header class="border-b border-zinc-800 px-4 sm:px-6 py-4 flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <a href="https://cnktros.com" class="flex items-center" aria-label="cnktros">
                        <img src="/logo.png" alt="cnktros" class="h-8 w-auto max-w-[9rem]" />
                    </a>
                    <span class="text-xs text-muted">"DevGuard playground"</span>
                </div>
                <a href="/" class="text-xs text-muted hover:text-zinc-300 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 rounded-sm">
                    "Open Dashboard →"
                </a>
            </header>

            // ── Hero ────────────────────────────────────────────────────────
            <div class="flex-1 flex flex-col items-center px-4 py-10 sm:py-12">
                <div class="w-full max-w-2xl space-y-8">

                    <div class="text-center space-y-3">
                        <Suspense fallback=|| view! {
                            <div role="status" aria-live="polite" class="inline-flex items-center gap-2 rounded-full bg-zinc-800/60 ring-1 ring-zinc-700 px-3 py-1">
                                <span class="text-xs text-zinc-400 font-medium">"Checking playground…"</span>
                            </div>
                        }>
                            {move || Suspend::new(async move {
                                match info_res.await {
                                    Ok(_) => view! {
                                        <div role="status" aria-live="polite" class="inline-flex items-center gap-2 rounded-full bg-success-10 ring-1 ring-success/30 px-3 py-1">
                                            <span aria-hidden="true" class="h-1.5 w-1.5 rounded-full bg-success animate-pulse"></span>
                                            <span class="text-xs text-success font-medium">"Playground live"</span>
                                        </div>
                                    }.into_any(),
                                    Err(_) => view! {
                                        <div role="status" aria-live="polite" class="inline-flex items-center gap-2 rounded-full bg-amber-950/40 ring-1 ring-amber-700/40 px-3 py-1">
                                            <span class="text-xs text-amber-200 font-medium">"Playground unreachable"</span>
                                        </div>
                                    }.into_any(),
                                }
                            })}
                        </Suspense>
                        <h1 class="text-2xl sm:text-3xl font-bold text-zinc-50">
                            "Connect your AI tool in "
                            <span class="text-brand">"30 seconds"</span>
                        </h1>
                        <p class="text-zinc-400 text-sm leading-relaxed max-w-lg mx-auto">
                            "Every LLM call from Cursor, Windsurf, Claude Code or any OpenAI-compatible tool "
                            "is governed by DevGuard — hallucination blocking, audit log, policy enforcement. "
                            "No install. Just swap your Base URL."
                        </p>
                    </div>

                    // ── Node info ────────────────────────────────────────────
                    <Suspense fallback=|| view! { <span></span> }>
                        {move || Suspend::new(async move {
                            if let Ok(v) = info_res.await {
                                let base = v.get("gateway_base")
                                    .and_then(|x| x.as_str()).unwrap_or("").to_string();
                                if !base.is_empty() {
                                    return view! {
                                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-3 flex items-center gap-3">
                                            <span aria-hidden="true" class="h-2 w-2 rounded-full bg-success shrink-0"></span>
                                            <span class="text-xs text-zinc-400">"Gateway: "</span>
                                            <span class="text-xs font-mono text-success">{base}</span>
                                        </div>
                                    }.into_any();
                                }
                            }
                            view! { <span></span> }.into_any()
                        })}
                    </Suspense>

                    // ── Connect form ─────────────────────────────────────────
                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 p-6 space-y-5">
                        <p class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                            "1. Select your tool"
                        </p>

                        // Tool pills
                        <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
                            {[
                                ("windsurf", "Windsurf", "🌊"),
                                ("cursor", "Cursor", "🖱"),
                                ("claude_code", "Claude Code", "🤖"),
                                ("generic", "Generic", "⚙"),
                            ].map(|(val, label, icon)| {
                                let val_owned = val.to_string();
                                let label_owned = label.to_string();
                                let icon_owned = icon.to_string();
                                view! {
                                    <button
                                        type="button"
                                        aria-pressed=move || (tool.get() == val).to_string()
                                        class=move || {
                                            let base = "rounded-lg border px-3 py-2.5 text-sm font-medium transition-all flex items-center gap-2 justify-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50";
                                            if tool.get() == val {
                                                format!("{} border-brand bg-brand-20 text-brand", base)
                                            } else {
                                                format!("{} border-zinc-700 bg-zinc-800 text-zinc-400 hover:border-zinc-600 hover:text-zinc-300", base)
                                            }
                                        }
                                        on:click={
                                            let v2 = val_owned.clone();
                                            move |_| set_tool.set(v2.clone())
                                        }
                                    >
                                        <span aria-hidden="true">{icon_owned.clone()}</span>
                                        <span>{label_owned.clone()}</span>
                                    </button>
                                }
                            }).collect_view()}
                        </div>

                        // Role + workspace
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <label class="block space-y-1.5">
                                <span class="text-[10px] uppercase tracking-wider text-zinc-500">"Your role"</span>
                                <select
                                    class="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-brand focus-visible:ring-2 focus-visible:ring-brand/50"
                                    on:change=move |ev| set_role.set(event_target_value(&ev))
                                >
                                    <option value="developer" selected=true>"Developer"</option>
                                    <option value="reviewer">"Reviewer"</option>
                                    <option value="operator">"Operator"</option>
                                </select>
                            </label>
                            <label class="block space-y-1.5">
                                <span class="text-[10px] uppercase tracking-wider text-zinc-500">"Workspace path (optional)"</span>
                                <input
                                    type="text"
                                    class="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-200 font-mono placeholder-zinc-600 focus:outline-none focus:border-brand focus-visible:ring-2 focus-visible:ring-brand/50"
                                    placeholder="/home/you/project"
                                    prop:value=move || workspace.get()
                                    on:input=move |ev| set_workspace.set(event_target_value(&ev))
                                />
                            </label>
                        </div>

                        // Error
                        {move || {
                            let e = err.get();
                            if e.is_empty() { view! { <span></span> }.into_any() }
                            else { view! {
                                <div role="alert" class="rounded-lg bg-danger-10 border border-danger-30 px-3 py-2 text-xs text-danger">
                                    {e}
                                </div>
                            }.into_any() }
                        }}

                        <button
                            type="button"
                            prop:disabled=move || busy.get()
                            on:click=do_connect
                            class="w-full rounded-lg bg-brand hover:brightness-110 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-3 text-sm transition-colors flex items-center justify-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                        >
                            {move || if busy.get() {
                                view! { <span>"Creating governed session…"</span> }.into_any()
                            } else {
                                view! { <span>"⚡  Get My Base URL + API Key"</span> }.into_any()
                            }}
                        </button>
                    </div>

                    // ── Result ───────────────────────────────────────────────
                    {move || {
                        let res = result.get();
                        match res {
                            None => view! { <span></span> }.into_any(),
                            Some(v) => {
                                let token = v.get("token").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let openai_url = v.get("openai_base_url").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let tool_str = tool.get();
                                let steps: Vec<String> = v.get("instructions")
                                    .and_then(|i| i.get("steps"))
                                    .and_then(|s| s.as_array())
                                    .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                                    .unwrap_or_default();
                                let snippet = v.get("instructions")
                                    .and_then(|i| i.get("env_snippet"))
                                    .and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let session_id = v.get("session_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let token_for_url = token.clone();
                                let token_for_key = token.clone();
                                let url_for_copy = openai_url.clone();

                                view! {
                                    <div role="status" aria-live="polite" class="rounded-xl border border-success/30 bg-zinc-900 p-6 space-y-5">
                                        // Success header
                                        <div class="flex items-center gap-3">
                                            <div aria-hidden="true" class="h-8 w-8 rounded-full bg-success-20 flex items-center justify-center shrink-0">
                                                <span class="text-success text-base">"✓"</span>
                                            </div>
                                            <div>
                                                <p class="font-semibold text-zinc-100 text-sm">"Session created!"</p>
                                                <p class="text-[11px] text-zinc-500">"Session: "{session_id.clone()}</p>
                                            </div>
                                        </div>

                                        // Step 2 label
                                        <p class="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                                            "2. Paste these into "{tool_str}
                                        </p>

                                        // Base URL + API Key cards
                                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                            <div class="rounded-lg border border-zinc-700 bg-zinc-800/50 p-3 space-y-2">
                                                <div class="flex items-center justify-between">
                                                    <span class="text-[10px] uppercase tracking-wider text-zinc-500">"Base URL / OpenAI Endpoint"</span>
                                                    <button
                                                        type="button"
                                                        aria-label="Copy base URL"
                                                        class="text-[10px] text-brand hover:brightness-125 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 rounded-sm"
                                                        on:click={
                                                            let url = url_for_copy.clone();
                                                            move |_| {
                                                                copy_to_clipboard(url.clone());
                                                                set_copied_url.set(true);
                                                            }
                                                        }
                                                    >
                                                        {move || if copied_url.get() { "Copied!" } else { "Copy" }}
                                                    </button>
                                                </div>
                                                <p class="text-xs font-mono text-brand break-all select-all leading-relaxed">
                                                    {openai_url.clone()}
                                                </p>
                                            </div>
                                            <div class="rounded-lg border border-zinc-700 bg-zinc-800/50 p-3 space-y-2">
                                                <div class="flex items-center justify-between">
                                                    <span class="text-[10px] uppercase tracking-wider text-zinc-500">"API Key / Token"</span>
                                                    <button
                                                        type="button"
                                                        aria-label="Copy API key"
                                                        class="text-[10px] text-brand hover:brightness-125 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 rounded-sm"
                                                        on:click={
                                                            let key = token_for_key.clone();
                                                            move |_| {
                                                                copy_to_clipboard(key.clone());
                                                                set_copied_key.set(true);
                                                            }
                                                        }
                                                    >
                                                        {move || if copied_key.get() { "Copied!" } else { "Copy" }}
                                                    </button>
                                                </div>
                                                <p class="text-xs font-mono text-warn break-all select-all leading-relaxed">
                                                    {token_for_url.clone()}
                                                </p>
                                            </div>
                                        </div>

                                        // Steps
                                        {if !steps.is_empty() {
                                            view! {
                                                <div class="rounded-lg border border-zinc-700 bg-zinc-800/30 p-4 space-y-2">
                                                    <p class="text-[10px] uppercase tracking-wider text-zinc-500">"Step-by-step setup"</p>
                                                    <ol class="space-y-1.5">
                                                        {steps.into_iter().enumerate().map(|(i, s)| view! {
                                                            <li class="flex gap-2.5 text-xs text-zinc-300">
                                                                <span aria-hidden="true" class="shrink-0 h-4 w-4 rounded-full bg-brand-20 text-brand text-[10px] font-bold flex items-center justify-center">
                                                                    {i + 1}
                                                                </span>
                                                                <span>{s}</span>
                                                            </li>
                                                        }).collect_view()}
                                                    </ol>
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! { <span></span> }.into_any()
                                        }}

                                        // Snippet
                                        {if !snippet.is_empty() {
                                            view! {
                                                <div class="space-y-1.5">
                                                    <p class="text-[10px] uppercase tracking-wider text-zinc-500">"Or copy this snippet"</p>
                                                    <pre class="rounded-lg border border-zinc-700 bg-zinc-950 px-4 py-3 text-xs font-mono text-brand select-all overflow-x-auto">
                                                        {snippet}
                                                    </pre>
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! { <span></span> }.into_any()
                                        }}

                                        // Try another + dashboard link
                                        <div class="flex items-center gap-4 pt-1 border-t border-zinc-800">
                                            <button
                                                type="button"
                                                class="text-xs text-zinc-500 hover:text-zinc-300 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 rounded-sm"
                                                on:click=move |_| set_result.set(None)
                                            >
                                                "← Try another tool"
                                            </button>
                                            <a href="/plugins/devguard"
                                                class="text-xs text-brand hover:brightness-125 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 rounded-sm">
                                                "View sessions in dashboard →"
                                            </a>
                                        </div>
                                    </div>
                                }.into_any()
                            }
                        }
                    }}

                    // ── How it works (shown before connecting) ────────────────
                    {move || {
                        if result.get().is_some() {
                            view! { <span></span> }.into_any()
                        } else {
                            view! {
                                <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                                    {[
                                        ("1", "Pick your tool", "Select Cursor, Windsurf, Claude Code, or any OpenAI-compatible tool you use."),
                                        ("2", "Get Base URL + Key", "DevGuard creates an isolated governed session and returns your unique gateway URL and token."),
                                        ("3", "Paste & start coding", "Swap your AI provider's base URL. Every LLM call is now governed — audited, policy-enforced, hallucination-filtered."),
                                    ].map(|(num, title, desc)| view! {
                                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/40 p-4 space-y-2">
                                            <div aria-hidden="true" class="h-6 w-6 rounded-full bg-brand-20 text-brand text-xs font-bold flex items-center justify-center">
                                                {num}
                                            </div>
                                            <p class="text-sm font-semibold text-zinc-200">{title}</p>
                                            <p class="text-xs text-zinc-500 leading-relaxed">{desc}</p>
                                        </div>
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }
                    }}

                </div>
            </div>

            // ── Footer ──────────────────────────────────────────────────────
            <footer class="border-t border-zinc-800 px-6 py-4 text-center text-xs text-zinc-600">
                "Connector Platform · DevGuard Playground · Sessions expire after 90 min"
            </footer>
        </div>
    }
}
