use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use leptos_router::hooks::use_navigate;
use gloo_storage::{LocalStorage, Storage};
use crate::auth::{check_auth, AuthState};
use crate::api;

#[component]
pub fn Login(set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let nav = StoredValue::new(use_navigate());
    let (email,    set_email)    = create_signal(String::new());
    let (password, set_password) = create_signal(String::new());
    let (error,    set_error)    = create_signal(String::new());
    let (loading,  set_loading)  = create_signal(false);
    let (mode,     set_mode)     = create_signal("credentials".to_string()); // "credentials" | "key"
    let (key,      set_key)      = create_signal(String::new());

    // Login with email + password → POST /api/v1/admin/auth
    let do_login_creds = move || {
        let em = email.get();
        let pw = password.get();
        set_error.set(String::new());
        if em.is_empty() || pw.is_empty() {
            set_error.set("Email and password required.".into());
            return;
        }
        set_loading.set(true);
        spawn_local(async move {
            match api::post_admin_login(&em, &pw).await {
                Ok(v) => {
                    if let Some(admin_key) = v["admin_key"].as_str() {
                        let _ = LocalStorage::set("admin_api_key", admin_key);
                        set_auth.set(check_auth());
                        nav.with_value(|n| n("/admin", Default::default()));
                    } else if let Some(e) = v["error"].as_str() {
                        set_error.set(e.to_string());
                        set_loading.set(false);
                    } else {
                        set_error.set("Unexpected response from server.".into());
                        set_loading.set(false);
                    }
                }
                Err(e) => {
                    set_error.set(format!("Authentication failed: {}", e.message));
                    set_loading.set(false);
                }
            }
        });
    };

    // Login with direct API key → validate against /admin/stats
    let do_login_key = move || {
        let k = key.get();
        set_error.set(String::new());
        if !k.starts_with("sk_admin_") || k.len() < 20 {
            set_error.set("Invalid key — must start with sk_admin_ (min 20 chars).".into());
            return;
        }
        set_loading.set(true);
        let _ = LocalStorage::set("admin_api_key", &k);
        spawn_local(async move {
            match api::get_value("/admin/stats").await {
                Ok(v) if v.get("error").is_none() => {
                    set_auth.set(check_auth());
                    nav.with_value(|n| n("/admin", Default::default()));
                }
                _ => {
                    let _ = LocalStorage::delete("admin_api_key");
                    set_error.set("Access denied — key rejected by server.".into());
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div class="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
            <div class="w-full max-w-sm">
                <div class="mb-8 text-center">
                    <div class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 ring-1 ring-red-500/20">
                        <span class="text-red-400 text-xl font-bold">"C"</span>
                    </div>
                    <h1 class="text-xl font-semibold text-zinc-50">"Admin Control Panel"</h1>
                    <p class="mt-1 text-sm text-zinc-500">"Authorized personnel only"</p>
                </div>

                <div class="mb-5 rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
                    <p class="text-xs text-zinc-500 leading-relaxed">
                        "Secured admin-only control panel. Access requires valid credentials issued to authorized operators."
                    </p>
                </div>

                // Tab selector: Credentials vs API Key
                <div class="flex mb-4 rounded-lg border border-zinc-800 overflow-hidden">
                    <button
                        on:click=move |_| set_mode.set("credentials".into())
                        class=move || if mode.get() == "credentials" {
                            "flex-1 py-2 text-xs font-medium bg-zinc-800 text-zinc-100"
                        } else {
                            "flex-1 py-2 text-xs font-medium text-zinc-500 hover:text-zinc-300"
                        }
                    >"Email + Password"</button>
                    <button
                        on:click=move |_| set_mode.set("key".into())
                        class=move || if mode.get() == "key" {
                            "flex-1 py-2 text-xs font-medium bg-zinc-800 text-zinc-100"
                        } else {
                            "flex-1 py-2 text-xs font-medium text-zinc-500 hover:text-zinc-300"
                        }
                    >"API Key"</button>
                </div>

                <div class="space-y-4">
                    {move || if !error.get().is_empty() {
                        view!{ <div class="rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-400">{error.get()}</div> }.into_any()
                    } else { view!{ <span /> }.into_any() }}

                    // Credentials form
                    {move || if mode.get() == "credentials" {
                        view! {
                            <div class="space-y-3">
                                <div>
                                    <label class="block text-xs font-medium text-zinc-400 mb-1">"Email"</label>
                                    <input class="input w-full text-sm" type="email"
                                        autocomplete="email"
                                        placeholder="admin@cnktros.com"
                                        prop:value=email
                                        on:input=move|e| set_email.set(event_target_value(&e))
                                    />
                                </div>
                                <div>
                                    <label class="block text-xs font-medium text-zinc-400 mb-1">"Password"</label>
                                    <input class="input w-full text-sm" type="password"
                                        autocomplete="current-password"
                                        placeholder="••••••••••••"
                                        prop:value=password
                                        on:input=move|e| set_password.set(event_target_value(&e))
                                        on:keydown=move|e: web_sys::KeyboardEvent| {
                                            if e.key() == "Enter" { do_login_creds(); }
                                        }
                                    />
                                </div>
                                <button class="btn-primary w-full" disabled=loading
                                    on:click=move|_| do_login_creds()>
                                    {move || if loading.get() { "Verifying…" } else { "Sign In" }}
                                </button>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-3">
                                <div>
                                    <label class="block text-xs font-medium text-zinc-400 mb-1">"Admin Secret Key"</label>
                                    <input class="input w-full font-mono text-sm" type="password"
                                        autocomplete="off"
                                        placeholder="sk_admin_••••••••••••••••"
                                        prop:value=key
                                        on:input=move|e| set_key.set(event_target_value(&e))
                                        on:keydown=move|e: web_sys::KeyboardEvent| {
                                            if e.key() == "Enter" { do_login_key(); }
                                        }
                                    />
                                </div>
                                <button class="btn-primary w-full" disabled=loading
                                    on:click=move|_| do_login_key()>
                                    {move || if loading.get() { "Verifying…" } else { "Authenticate" }}
                                </button>
                            </div>
                        }.into_any()
                    }}

                    <p class="text-center text-[11px] text-zinc-600 mt-4">
                        "All access attempts are logged. Unauthorized access is prohibited."
                    </p>
                </div>
            </div>
        </div>
    }
}
