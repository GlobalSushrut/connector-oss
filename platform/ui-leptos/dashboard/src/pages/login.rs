use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use leptos_router::hooks::*;
use crate::auth::{accept_sso_token, dev_bypass, login_with_api_key, AuthState};
use crate::routing::post_auth;

/// Reads `#sso_token=` / `#sso_error=` once and removes it from the address bar and history.
fn take_sso_fragment() -> (Option<String>, Option<String>) {
    let Some(w) = web_sys::window() else { return (None, None) };
    let hash = w.location().hash().unwrap_or_default();
    let hash = hash.trim_start_matches('#');
    if hash.is_empty() {
        return (None, None);
    }
    let Ok(params) = web_sys::UrlSearchParams::new_with_str(hash) else { return (None, None) };
    let token = params.get("sso_token");
    let error = params.get("sso_error");
    if token.is_some() || error.is_some() {
        if let Ok(history) = w.history() {
            let path = w.location().pathname().unwrap_or_else(|_| "/login".into());
            let search = w.location().search().unwrap_or_default();
            let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&format!("{path}{search}")));
        }
    }
    (token, error)
}

fn page_is_loopback() -> bool {
    web_sys::window()
        .and_then(|w| w.location().hostname().ok())
        .map(|host| {
            let host = host.trim().to_ascii_lowercase();
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
        })
        .unwrap_or(false)
}

const PORTAL_URL: &str = "https://portal.connector.dev";

#[component]
pub fn Login(set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let navigate = use_navigate();
    let nav1 = navigate.clone();
    let nav_local = navigate.clone();
    #[cfg(feature = "dev-bypass")]
    let nav2 = navigate.clone();
    let local_gate = page_is_loopback();

    // Pre-fill API key if arriving from /trial.
    let prefill: String = LocalStorage::get::<String>("trial_api_key").unwrap_or_default();
    let has_prefill = !prefill.is_empty();
    let (api_key, set_api_key) = signal(prefill);
    let (show_key, set_show_key) = signal(false);
    let (error, set_error) = signal(String::new());
    let (loading, set_loading) = signal(false);

    // After login, land on the dashboard. DevGuard is a workflow on /run.
    let post_route = web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|search| {
            web_sys::UrlSearchParams::new_with_str(&search).ok().and_then(|p| {
                p.get("next").filter(|r| r.starts_with('/') && !r.starts_with("//"))
            })
        })
        .unwrap_or_else(|| {
            match post_auth::get_preferred_product().as_deref() {
                Some("tracetramp") => "/plugins/tracetramp".into(),
                Some("witnessctl") => "/plugins/witnessctl".into(),
                _ => "/run".into(),
            }
        });

    let (sso_login_path, set_sso_login_path) = signal(None::<String>);
    spawn_local(async move {
        if let Ok(body) = crate::api::get_value("/auth/sso").await {
            let path = body
                .get("providers")
                .and_then(|v| v.as_array())
                .and_then(|list| {
                    list.iter().find(|p| {
                        p.get("id").and_then(|v| v.as_str()) == Some("keycloak")
                            && p.get("configured").and_then(|v| v.as_bool()) == Some(true)
                    })
                })
                .and_then(|p| p.get("login_path").and_then(|v| v.as_str()))
                .filter(|p| p.starts_with("/api/"))
                .map(String::from);
            set_sso_login_path.set(path);
        }
    });

    let (sso_token, sso_error) = take_sso_fragment();
    if let Some(code) = sso_error {
        set_error.set(format!("Keycloak sign-in was refused: {code}"));
    }
    if let Some(token) = sso_token {
        let nav = nav1.clone();
        let route = post_route.clone();
        set_loading.set(true);
        spawn_local(async move {
            match accept_sso_token(set_auth, token).await {
                Ok(()) => nav(&route, Default::default()),
                Err(e) => {
                    set_error.set(e);
                    set_loading.set(false);
                }
            }
        });
    }

    // Auto-submit when arriving from /trial with a pre-filled key.
    if has_prefill {
        let key = api_key.get_untracked();
        let nav = nav1.clone();
        let route = post_route.clone();
        set_loading.set(true);
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(100).await;
            let _ = LocalStorage::delete("trial_api_key");
            match login_with_api_key(set_auth, key).await {
                Ok(()) => { nav(&route, Default::default()); }
                Err(e) => { set_error.set(e); set_loading.set(false); }
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
            if key == "dev-token" && page_is_loopback() {
                set_error.set(String::new());
                set_loading.set(true);
                let nav = nav1.clone();
                let route = route.clone();
                spawn_local(async move {
                    dev_bypass(set_auth).await;
                    nav(&route, Default::default());
                });
                return;
            }
            if !key.starts_with("cpk_") {
                set_error.set("Invalid format — API keys start with cpk_".into());
                return;
            }
            set_error.set(String::new());
            set_loading.set(true);
            let nav = nav1.clone();
            let route = route.clone();
            spawn_local(async move {
                let _ = LocalStorage::delete("trial_api_key");
                match login_with_api_key(set_auth, key).await {
                    Ok(()) => { nav(&route, Default::default()); }
                    Err(e) => { set_error.set(e); set_loading.set(false); }
                }
            });
        }
    };

    view! {
        <div class="flex min-h-screen items-center justify-center overflow-y-auto bg-zinc-950 px-4 py-8">
            <div class="w-full max-w-sm">
                <div class="mb-8 text-center">
                    <a href="/" class="mx-auto mb-4 flex justify-center" aria-label="cnktros">
                        <img src="/logo.png" alt="cnktros" class="h-10 w-auto max-w-[12rem]" />
                    </a>
                    <h1 class="text-xl font-semibold text-zinc-50">
                        {if local_gate { "Local node" } else { "Operator dashboard" }}
                    </h1>
                    <p class="mt-1 text-sm text-zinc-500">
                        {if local_gate {
                            "This computer. A portal key is not required."
                        } else {
                            "Operator Dashboard · Token access only"
                        }}
                    </p>
                </div>

                {if local_gate {
                    let nav_for_local = nav_local.clone();
                    let route_for_local = post_route.clone();
                    view! {
                        <div class="mb-5 space-y-2">
                            <button
                                type="button"
                                on:click=move |_| {
                                    set_loading.set(true);
                                    set_error.set(String::new());
                                    let nav = nav_for_local.clone();
                                    let route = route_for_local.clone();
                                    spawn_local(async move {
                                        dev_bypass(set_auth).await;
                                        nav(&route, Default::default());
                                    });
                                }
                                class="btn-primary w-full"
                            >
                                "Open on this machine"
                            </button>
                            <p class="text-center text-[11px] text-zinc-500">
                                "Uses the local dev-token. It stays on this computer."
                            </p>
                        </div>
                    }.into_any()
                } else {
                    ().into_any()
                }}

                {move || match sso_login_path.get() {
                    Some(path) => view! {
                        <div class="mb-5 space-y-2">
                            <a href=path class="btn-secondary block w-full text-center">"Sign in with Keycloak"</a>
                            <p class="text-center text-[11px] text-zinc-500">
                                "Keycloak signs you in. Connector checks its ID token against Keycloak's keys before opening a session."
                            </p>
                        </div>
                    }.into_any(),
                    None => ().into_any(),
                }}

                {
                    // Dev-bypass-only callout. Production builds compile this to nothing.
                    // Phase 5.2 — the runtime mode also hides this UI in
                    // Playground deployments even when the feature is on.
                    #[cfg(feature = "dev-bypass")]
                    {
                        let mode = crate::deployment::use_deployment_mode();
                        view! {
                            <Show when=move || !local_gate && mode.get() != crate::deployment::DeploymentMode::Playground>
                                <div class="mb-4 space-y-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5">
                                    <div class="flex items-center gap-2">
                                        <span class="text-amber-400 text-sm">"⚠"</span>
                                        <p class="text-xs text-amber-300 font-medium">"Dev build — bypass available below for local operator workflows."</p>
                                    </div>
                                    <p class="text-[11px] text-zinc-500 leading-relaxed pl-6">
                                        "Production keys: "
                                        <a href=PORTAL_URL target="_blank" rel="noreferrer"
                                            class="text-indigo-400 hover:text-indigo-300">"portal ↗"</a>
                                        " · "
                                        <a href=format!("{PORTAL_URL}/app/api-keys") target="_blank" rel="noreferrer"
                                            class="text-indigo-400 hover:text-indigo-300">"API keys ↗"</a>
                                    </p>
                                </div>
                            </Show>
                        }.into_any()
                    }
                    #[cfg(not(feature = "dev-bypass"))]
                    {
                        ().into_any()
                    }
                }

                <form on:submit=handle_submit class="space-y-4">
                    {move || if !error.get().is_empty() {
                        view! {
                            <div class="rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                                {error.get()}
                            </div>
                        }.into_any()
                    } else {
                        view! { <span /> }.into_any()
                    }}

                    <div>
                        <div class="mb-1.5 flex items-center justify-between">
                            <label class="text-xs font-medium text-zinc-400">"Dashboard API Key"</label>
                            <a href=format!("{PORTAL_URL}/app/api-keys")
                                target="_blank" rel="noreferrer"
                                class="text-xs text-indigo-400 hover:text-indigo-300">
                                "Get key from portal ↗"
                            </a>
                        </div>
                        <div class="relative">
                            <input
                                type=move || if show_key.get() { "text" } else { "password" }
                                prop:value=api_key
                                on:input=move |ev| set_api_key.set(event_target_value(&ev))
                                class="input w-full pr-10 font-mono text-sm"
                                placeholder="cpk_••••••••••••••••••"
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

                    <button type="submit" disabled=loading class="btn-primary w-full">
                        {move || if loading.get() { "Verifying…" } else { "Access Dashboard" }}
                    </button>
                </form>

                {
                    // Dev-bypass-only entry point. Production builds compile this to nothing.
                    // Phase 5.2 — even with feature compiled in, refuse to
                    // render against a Playground server (auto-login of
                    // an anonymous visitor is a security footgun).
                    #[cfg(feature = "dev-bypass")]
                    {
                        let mode = crate::deployment::use_deployment_mode();
                        let nav_for_show = nav2.clone();
                        view! {
                            <Show
                                when=move || !local_gate && mode.get() != crate::deployment::DeploymentMode::Playground
                                fallback=|| view! { <span></span> }
                            >
                                {
                                    let nav_for_btn = nav_for_show.clone();
                                    view! {
                                        <div class="mt-5 space-y-2 border-t border-amber-500/20 pt-4">
                                            <p class="text-[10px] text-amber-500/60 uppercase tracking-wider font-medium text-center">"Development Only"</p>
                                            <button
                                                type="button"
                                                on:click=move |_| {
                                                    set_loading.set(true);
                                                    set_error.set(String::new());
                                                    let nav = nav_for_btn.clone();
                                                    spawn_local(async move {
                                                        dev_bypass(set_auth).await;
                                                        nav("/", Default::default());
                                                    });
                                                }
                                                class="w-full rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-sm font-medium text-amber-300 hover:bg-amber-500/20 transition-colors"
                                            >
                                                "⚡  Dev Bypass — Skip Auth"
                                            </button>
                                            <p class="text-[10px] text-zinc-600 text-center">"Sets dev-token · super_admin role · no API call"</p>
                                        </div>
                                    }
                                }
                            </Show>
                        }.into_any()
                    }
                    #[cfg(not(feature = "dev-bypass"))]
                    {
                        ().into_any()
                    }
                }

                <div class="mt-6 border-t border-zinc-800 pt-4 text-center text-[11px] text-zinc-600">
                    <a href=PORTAL_URL target="_blank" rel="noreferrer"
                        class="text-indigo-400 hover:text-indigo-300">"Open hosted portal →"</a>
                </div>
            </div>
        </div>
    }
}
