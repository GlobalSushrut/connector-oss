use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use crate::auth::{fetch_me, login_with_api_key, AuthState};
use crate::routing as post_auth;

const PORTAL_URL: &str = "https://portal.connector.dev";
const AUTO_LOGIN_FLAG: &str = "trial_auto_login";

fn clear_cached_auth() {
    let _ = LocalStorage::delete("trial_api_key");
    let _ = LocalStorage::delete("api_key");
    let _ = LocalStorage::delete("access_token");
    let _ = LocalStorage::delete("refresh_token");
    if let Some(w) = web_sys::window() {
        if let Ok(Some(ss)) = w.session_storage() {
            let _ = ss.remove_item(AUTO_LOGIN_FLAG);
        }
    }
}

fn query_param(name: &str) -> Option<String> {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|search| {
            web_sys::UrlSearchParams::new_with_str(&search)
                .ok()
                .and_then(|p| p.get(name))
        })
}

/// Auto-login when /trial just handed off a fresh key.
fn fresh_trial_key() -> Option<String> {
    let key = LocalStorage::get::<String>("trial_api_key")
        .ok()
        .filter(|k| k.starts_with("cpk_pg_"))?;
    if query_param("from").as_deref() == Some("trial") {
        return Some(key);
    }
    let w = web_sys::window()?;
    let ss = w.session_storage().ok()??;
    if ss.get_item(AUTO_LOGIN_FLAG).ok().flatten().as_deref() == Some("1") {
        return Some(key);
    }
    None
}

fn existing_session() -> bool {
    let token = LocalStorage::get::<String>("access_token").unwrap_or_default();
    let key = LocalStorage::get::<String>("api_key")
        .or_else(|_| LocalStorage::get::<String>("trial_api_key"))
        .unwrap_or_default();
    token.contains('.') && key.starts_with("cpk_")
}

fn friendly_login_error(raw: &str) -> String {
    if raw.contains("Playground session key not found") {
        return "That playground key expired or was cleared (e.g. after a deploy). \
                Start a new free session — keys begin with cpk_pg_ and last ~90 minutes."
            .into();
    }
    raw.to_string()
}

/// Dashboard routes live in the full-dashboard WASM, not this trial app —
/// a full browser navigation makes the server serve the dashboard bundle.
fn hard_redirect(route: &str) {
    if let Some(w) = web_sys::window() {
        let _ = w.location().set_href(route);
    }
}

fn resolve_post_route() -> String {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|search| {
            web_sys::UrlSearchParams::new_with_str(&search).ok().and_then(|p| {
                p.get("next").filter(|r| r.starts_with('/') && !r.starts_with("//"))
            })
        })
        .unwrap_or_else(|| {
            match post_auth::get_preferred_product().as_deref() {
                Some("tracetramp") => "/plugins/tracetramp",
                Some("witnessctl") => "/plugins/witnessctl",
                Some("devguard") => "/run",
                _ => "/run",
            }
            .to_string()
        })
}

#[component]
pub fn Login(set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let post_route = resolve_post_route();
    let trial_key = fresh_trial_key();
    let has_trial_handoff = trial_key.is_some();
    let prefill = trial_key.unwrap_or_default();
    let (api_key,  set_api_key)  = signal(prefill);
    let (show_key, set_show_key) = signal(false);
    let (error,    set_error)    = signal(String::new());
    let (loading,  set_loading)  = signal(false);

    if has_trial_handoff {
        let key   = api_key.get_untracked();
        let route = post_route.clone();
        set_loading.set(true);
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(50).await;
            match login_with_api_key(set_auth, key).await {
                Ok(()) => {
                    if let Some(w) = web_sys::window() {
                        if let Ok(Some(ss)) = w.session_storage() {
                            let _ = ss.remove_item(AUTO_LOGIN_FLAG);
                        }
                    }
                    hard_redirect(&route);
                }
                Err(e) => {
                    clear_cached_auth();
                    set_api_key.set(String::new());
                    set_error.set(friendly_login_error(&e));
                    set_loading.set(false);
                }
            }
        });
    } else if existing_session() && query_param("next").is_some() {
        // Bounced from dashboard auth gate — session still valid, skip re-login.
        let route = post_route.clone();
        set_loading.set(true);
        spawn_local(async move {
            fetch_me(set_auth).await;
            let still_valid = LocalStorage::get::<String>("access_token")
                .ok()
                .filter(|t| t.contains('.'))
                .is_some();
            if still_valid {
                hard_redirect(&route);
            } else {
                clear_cached_auth();
                set_loading.set(false);
            }
        });
    }

    let handle_submit = {
        let route = post_route.clone();
        move |ev: web_sys::SubmitEvent| {
            ev.prevent_default();
            let key = api_key.get_untracked().trim().to_string();
            if key.is_empty() {
                set_error.set("API key is required".into());
                return;
            }
            if !key.starts_with("cpk_") {
                set_error.set("Invalid format — API keys start with cpk_".into());
                return;
            }
            set_error.set(String::new());
            set_loading.set(true);
            let route = route.clone();
            spawn_local(async move {
                match login_with_api_key(set_auth, key).await {
                    Ok(()) => { hard_redirect(&route); }
                    Err(e) => {
                        clear_cached_auth();
                        set_api_key.set(String::new());
                        set_error.set(friendly_login_error(&e));
                        set_loading.set(false);
                    }
                }
            });
        }
    };

    view! {
        <div class="flex min-h-screen items-center justify-center overflow-y-auto bg-zinc-950 px-4 py-8">
            <div class="w-full max-w-sm">
                <div class="mb-8 text-center">
                    <a href="https://cnktros.com" class="mx-auto mb-4 flex justify-center" aria-label="cnktros">
                        <img src="/logo.png" alt="cnktros" class="h-10 w-auto max-w-[12rem]" />
                    </a>
                    <h1 class="text-xl font-semibold text-zinc-50">"Playground"</h1>
                    <p class="mt-1 text-sm text-zinc-500">"Paste your session key (cpk_pg_…) or start a new trial"</p>
                </div>

                <div class="mb-4 rounded-lg border border-indigo-500/20 bg-indigo-500/5 px-3 py-2.5 text-xs text-zinc-400 leading-relaxed">
                    "No key yet? "
                    <a href="/trial" class="text-indigo-400 hover:text-indigo-300 font-medium">"Start a free 90-minute session →"</a>
                </div>

                <form on:submit=handle_submit class="space-y-4">
                    {move || if !error.get().is_empty() {
                        let msg = error.get();
                        let expired = msg.contains("expired") || msg.contains("cpk_pg_");
                        view! {
                            <div class="rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-400 space-y-2">
                                <p>{msg.clone()}</p>
                                {move || if expired {
                                    view! {
                                        <a href="/trial" class="inline-block text-indigo-300 hover:text-indigo-200 font-medium">
                                            "Get a new playground key →"
                                        </a>
                                    }.into_any()
                                } else {
                                    view! { <span /> }.into_any()
                                }}
                            </div>
                        }.into_any()
                    } else {
                        view! { <span /> }.into_any()
                    }}

                    <div>
                        <div class="mb-1.5 flex items-center justify-between">
                            <label class="text-xs font-medium text-zinc-400">"Playground API key"</label>
                            <a href="/trial" class="text-xs text-indigo-400 hover:text-indigo-300">
                                "Start new session →"
                            </a>
                        </div>
                        <div class="relative">
                            <input
                                type=move || if show_key.get() { "text" } else { "password" }
                                prop:value=api_key
                                on:input=move |ev| set_api_key.set(event_target_value(&ev))
                                class="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-2.5 text-sm text-zinc-100 font-mono outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 pr-10"
                                placeholder="cpk_pg_••••••••••••••••••"
                                autofocus=true
                                autocomplete="off"
                                spellcheck="false"
                            />
                            <button type="button"
                                on:click=move |_| set_show_key.update(|v| *v = !*v)
                                class="absolute right-2.5 top-2.5 text-zinc-500 hover:text-zinc-300"
                                tabindex="-1">
                                {move || if show_key.get() { "◉" } else { "○" }}
                            </button>
                        </div>
                    </div>

                    <button type="submit" disabled=loading
                        class="w-full bg-indigo-600 text-white font-semibold text-sm px-4 py-2.5 rounded-lg hover:bg-indigo-500 disabled:opacity-60 disabled:cursor-not-allowed transition-colors">
                        {move || if loading.get() { "Verifying…" } else { "Access Dashboard" }}
                    </button>
                </form>

                <div class="mt-6 border-t border-zinc-800 pt-4 text-center text-[11px] text-zinc-600 space-y-1">
                    <p>"Self-hosted operator? "</p>
                    <a href=format!("{PORTAL_URL}/app/api-keys")
                        target="_blank" rel="noreferrer"
                        class="text-indigo-400 hover:text-indigo-300">"Portal API keys ↗"</a>
                </div>
            </div>
        </div>
    }
}
