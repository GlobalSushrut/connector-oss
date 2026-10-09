use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use crate::api;
use crate::routing as post_auth;

fn enter_node(key: &str, tenant_id: &str) {
    let _ = LocalStorage::set("trial_api_key", key);
    let _ = LocalStorage::set("api_key", key);
    if !tenant_id.is_empty() {
        let _ = LocalStorage::set("tenant_id", tenant_id);
    }
    post_auth::mark_onboarding_complete();
    if let Some(w) = web_sys::window() {
        if let Ok(Some(ss)) = w.session_storage() {
            let _ = ss.set_item("trial_auto_login", "1");
        }
        let _ = w.location().set_href("/login?from=trial&next=/run");
    }
}

#[component]
pub fn TrialPage() -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (err, set_err) = signal(String::new());

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
        let body = serde_json::json!({ "email": em, "label": "trial-trio" });
        spawn_local(async move {
            match api::post_value("/playground/session", body).await {
                Ok(v) => {
                    let key = v["api_key"].as_str().unwrap_or("").to_string();
                    let tid = v["tenant_id"].as_str().unwrap_or("").to_string();
                    if key.is_empty() {
                        set_err.set("Server error: no session key. Try again.".into());
                        set_busy.set(false);
                        return;
                    }
                    enter_node(&key, &tid);
                }
                Err(e) => {
                    set_err.set(if e.message.is_empty() {
                        "Something went wrong. Please try again.".into()
                    } else { e.message });
                    set_busy.set(false);
                }
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
                    "Hosted on Fly.io · 90 minutes · 1 demo agent"
                </span>
            </header>

            <div class="flex justify-center px-4 py-12 sm:py-16">
                <div class="w-full max-w-2xl">
                    <p class="text-center text-[11px] font-semibold uppercase tracking-wider text-emerald-400/90 mb-3">
                        "Private trial sandbox · no install"
                    </p>
                    <h1 class="text-3xl sm:text-4xl font-extrabold text-zinc-100 text-center tracking-tight mb-3">
                        "Your email. Your sandbox. Isolate, Govern, Stop, Prove."
                    </h1>
                    <p class="text-zinc-400 text-center mb-10 text-sm sm:text-base max-w-lg mx-auto">
                        "Up to 10 people at once. Each email gets an isolated tenant and one Demo agent. Isolate / Govern / Stop / Prove need no LLM key. Most emails: 3 sessions × 90 minutes."
                    </p>

                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-8">
                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-4">
                            <p class="text-[10px] font-bold uppercase tracking-wider text-emerald-400 mb-1">"Ready"</p>
                            <p class="font-bold text-sm text-zinc-100">"Demo agent"</p>
                            <p class="text-[12px] text-zinc-400 mt-1 leading-snug">"Isolate, Govern, Stop, Prove — then Admit. No LLM key."</p>
                        </div>
                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-4">
                            <p class="text-[10px] font-bold uppercase tracking-wider text-sky-400 mb-1">"Isolated"</p>
                            <p class="font-bold text-sm text-zinc-100">"Private tenant"</p>
                            <p class="text-[12px] text-zinc-400 mt-1 leading-snug">"No other visitor can see your session."</p>
                        </div>
                        <div class="rounded-xl border border-zinc-800 bg-zinc-900/50 px-4 py-4">
                            <p class="text-[10px] font-bold uppercase tracking-wider text-amber-400 mb-1">"Quota"</p>
                            <p class="font-bold text-sm text-zinc-100">"3 × 90 min"</p>
                            <p class="text-[12px] text-zinc-400 mt-1 leading-snug">"Queue when 10 slots are full."</p>
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
                        class="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-2.5 text-sm text-zinc-100 placeholder-zinc-500 outline-none mb-4"
                        on:input=move |e| {
                            set_email.set(event_target_value(&e));
                            set_err.set(String::new());
                        }
                    />

                    <button
                        type="button"
                        class="w-full bg-emerald-500 text-emerald-950 font-bold text-sm px-4 py-3.5 rounded-xl cursor-pointer hover:brightness-110 disabled:opacity-60 disabled:cursor-not-allowed transition-colors"
                        disabled=move || busy.get()
                        on:click=start
                    >
                        {move || if busy.get() { "Opening your node…" } else { "Start my 90 minutes →" }}
                    </button>
                    <p class="text-center text-[11px] text-zinc-500 mt-3">
                        "Up to 10 people at once · Each email is a separate node"
                    </p>

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
