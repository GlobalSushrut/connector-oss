//! Trial onboarding — `/trial`.
//!
//! One click → 90-minute node → one Demo agent with Isolate / Govern / Stop / Prove.
//! Matches how people start Cursor / Claude / v0: no key dump first.

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use serde_json::Value;
use gloo_net::http::Request;
use wasm_bindgen_futures::spawn_local;
use crate::api;
use crate::routing::post_auth;

fn enter_node(key: &str, tenant_id: &str) {
    let _ = LocalStorage::set("trial_api_key", key);
    let _ = LocalStorage::set("api_key", key);
    if !tenant_id.is_empty() {
        let _ = LocalStorage::set("tenant_id", tenant_id);
    }
    post_auth::mark_onboarding_complete();
}

#[component]
pub fn TrialPage() -> impl IntoView {
    let navigate = use_navigate();

    let (email, set_email) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal(String::new());
    let (server_note, set_server_note) = signal(String::new());
    let (queue_position, set_queue_position) = signal(None::<u64>);
    let (quota_remaining, set_quota_remaining) = signal(None::<u64>);
    let (unlimited, set_unlimited) = signal(false);
    let status_res = LocalResource::new(|| api::get_value("/playground/status"));

    let start = move |_| {
        if busy.get_untracked() { return; }
        let em = email.get_untracked().trim().to_string();
        let at = em.find('@');
        let valid = at.map(|i| em[i+1..].contains('.')).unwrap_or(false);
        if !valid {
            set_err.set("Enter your email. That address owns this 90-minute playground.".into());
            return;
        }
        set_busy.set(true);
        set_err.set(String::new());
        set_server_note.set(String::new());
        set_queue_position.set(None);
        let body = serde_json::json!({ "email": em, "label": "trial-session" });
        let navigate = navigate.clone();
        spawn_local(async move {
            match Request::post("/api/v1/playground/session")
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .and_then(|req| Ok(req.send()))
            {
                Ok(fut) => match fut.await {
                    Ok(resp) => {
                        let ok = resp.ok();
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        let v: Value = serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "error": text }));
                        let quota = v.get("quota").cloned().unwrap_or(Value::Null);
                        set_unlimited.set(quota.get("unlimited").and_then(|x| x.as_bool()).unwrap_or(false));
                        set_quota_remaining.set(quota.get("sessions_remaining").and_then(|x| x.as_u64()));
                        if ok {
                    let key = v["api_key"].as_str().unwrap_or("").to_string();
                    let tid = v["tenant_id"].as_str().unwrap_or("").to_string();
                    if key.is_empty() {
                        set_err.set("Server error: no session key. Try again.".into());
                        set_busy.set(false);
                        return;
                    }
                    enter_node(&key, &tid);
                    if let Some(w) = web_sys::window() {
                        let _ = w.location().set_href("/login?from=trial&next=/run");
                    } else {
                        navigate("/login", Default::default());
                    }
                        } else {
                            let msg = v.get("error").and_then(|x| x.as_str()).unwrap_or("Something went wrong. Please try again.");
                            set_queue_position.set(v.get("queue_position").and_then(|x| x.as_u64()));
                            if status == 429 && v.get("code").and_then(|x| x.as_str()) == Some("PLAYGROUND_QUEUED") {
                                set_server_note.set(v.get("hint").and_then(|x| x.as_str()).unwrap_or("").to_string());
                            }
                            set_err.set(msg.to_string());
                            set_busy.set(false);
                        }
                    }
                    Err(_) => {
                        set_err.set("Something went wrong. Please try again.".into());
                        set_busy.set(false);
                    }
                },
                Err(_) => {
                    set_err.set("Something went wrong. Please try again.".into());
                    set_busy.set(false);
                },
            }
        });
    };

    view! {
        <div class="min-h-screen overflow-y-auto bg-zinc-950 text-zinc-200 font-sans antialiased">
            <header class="flex items-center justify-between border-b border-zinc-800/60 px-4 sm:px-8 py-4">
                <a href="https://cnktros.com" class="flex items-center no-underline" aria-label="cnktros">
                    <img src="/logo.png" alt="cnktros" class="h-8 w-auto max-w-[10rem]" />
                </a>
                <span class="text-[11px] sm:text-xs text-zinc-500">
                    "Hosted on Fly.io · 90 minutes · 1 demo agent · isolated tenant"
                </span>
            </header>

            <div class="flex justify-center px-4 py-12 sm:py-16">
                <div class="w-full max-w-2xl">
                    <p class="text-center text-[11px] font-semibold uppercase tracking-wider text-emerald-400/90 mb-3">
                        "Live node · no install"
                    </p>
                    <h1 class="text-3xl sm:text-4xl font-extrabold text-zinc-100 text-center tracking-tight mb-3">
                        "Open a private sandbox. Try Isolate, Govern, Stop, Prove."
                    </h1>
                    <p class="text-zinc-400 text-center mb-10 text-sm sm:text-base max-w-lg mx-auto">
                        "Email required. Up to 10 people at once — each gets a fully isolated tenant (other sessions cannot see yours). Most emails: 3 sessions × 90 minutes. Demo verbs need no LLM key. Paste a key only for free-text Talk."
                    </p>

                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-8">
                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-4">
                            <p class="text-[10px] font-bold uppercase tracking-wider text-emerald-400 mb-1">"Ready"</p>
                            <p class="font-bold text-sm text-zinc-100">"Demo agent"</p>
                            <p class="text-[12px] text-zinc-400 mt-1 leading-snug">"Isolate, Govern, Stop, Prove on the Workbench Admit path — no LLM key."</p>
                        </div>
                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-4">
                            <p class="text-[10px] font-bold uppercase tracking-wider text-sky-400 mb-1">"Isolated"</p>
                            <p class="font-bold text-sm text-zinc-100">"Private tenant"</p>
                            <p class="text-[12px] text-zinc-400 mt-1 leading-snug">"Your agents and memory stay in your sandbox — not shared with other visitors."</p>
                        </div>
                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-4">
                            <p class="text-[10px] font-bold uppercase tracking-wider text-amber-400 mb-1">"Quota"</p>
                            <p class="font-bold text-sm text-zinc-100">"3 × 90 min"</p>
                            <p class="text-[12px] text-zinc-400 mt-1 leading-snug">"Per email (unless unlimited). Queue when all 10 slots are full."</p>
                        </div>
                    </div>

                    <label for="trial-email" class="block text-xs font-semibold text-zinc-400 mb-1.5 uppercase tracking-wider">
                        "Your email — this playground is yours"
                    </label>
                    <input
                        id="trial-email"
                        type="email"
                        placeholder="you@company.com"
                        autocomplete="email"
                        class="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 outline-none mb-4 focus:ring-2 focus:ring-emerald-500/50 focus:border-emerald-500"
                        on:input=move |e| {
                            set_email.set(event_target_value(&e));
                            set_err.set(String::new());
                        }
                    />

                    <button
                        type="button"
                        class="w-full bg-emerald-500 text-emerald-950 font-bold text-sm px-4 py-3.5 rounded-xl cursor-pointer hover:brightness-110 disabled:opacity-60 disabled:cursor-not-allowed transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500/50"
                        disabled=move || busy.get()
                        on:click=start
                    >
                        {move || if busy.get() { "Opening your node…" } else { "Start my 90 minutes →" }}
                    </button>
                    <div class="mt-3 space-y-2">
                        <Suspense fallback=move || view! {
                            <p class="text-center text-[11px] text-zinc-500">
                                "Checking live capacity and trial rules…"
                            </p>
                        }>
                            {move || Suspend::new(async move {
                                match status_res.await {
                                    Ok(v) => {
                                        let active = v.get("active_sessions").and_then(|x| x.as_u64()).unwrap_or(0);
                                        let max = v.get("max_sessions").and_then(|x| x.as_u64()).unwrap_or(10);
                                        let queue = v.get("queue_depth").and_then(|x| x.as_u64()).unwrap_or(0);
                                        let tries = v.get("default_session_limit_per_email").and_then(|x| x.as_u64()).unwrap_or(3);
                                        view! {
                                            <div class="rounded-lg border border-zinc-800 bg-zinc-900/40 px-3 py-3 text-xs text-zinc-400 space-y-1">
                                                <p>{format!("Live capacity: {active}/{max} active sessions")}</p>
                                                <p>{format!("Queue depth: {queue} · default trial limit: {tries} sessions per email")}</p>
                                                <p>"`umeshlamton@gmail.com` has unlimited access."</p>
                                            </div>
                                        }.into_any()
                                    }
                                    Err(_) => view! {
                                        <p class="text-center text-[11px] text-zinc-500">
                                            "Playground status is temporarily unreachable."
                                        </p>
                                    }.into_any(),
                                }
                            })}
                        </Suspense>
                        {move || {
                            let mut bits = Vec::new();
                            if unlimited.get() {
                                bits.push("Unlimited access enabled for this email.".to_string());
                            } else if let Some(n) = quota_remaining.get() {
                                bits.push(format!("{n} trial session(s) remaining for this email."));
                            }
                            if let Some(pos) = queue_position.get() {
                                bits.push(format!("Queue position: {pos}."));
                            }
                            let note = server_note.get();
                            if !note.is_empty() {
                                bits.push(note);
                            }
                            if bits.is_empty() {
                                view! { <span></span> }.into_any()
                            } else {
                                view! {
                                    <div class="rounded-lg border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
                                        {bits.join(" ")}
                                    </div>
                                }.into_any()
                            }
                        }}
                    </div>
                    <div
                        role="alert"
                        style=move || if err.get().is_empty() { "display:none" } else { "display:block" }
                        class="text-red-400 text-xs mt-4 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2"
                    >
                        {move || err.get()}
                    </div>
                </div>
            </div>
        </div>
    }
}
