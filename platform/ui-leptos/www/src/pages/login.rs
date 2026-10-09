use crate::auth::{login, AuthState};
use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use wasm_bindgen_futures::spawn_local;

fn is_dev_mode() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
        .and_then(|el| el.get_attribute("data-dev"))
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[component]
pub fn Login(set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let nav1 = use_navigate();
    let nav2 = nav1.clone();
    let (email, set_email) = create_signal(String::new());
    let (password, set_password) = create_signal(String::new());
    let (totp, set_totp) = create_signal(String::new());
    let (error, set_error) = create_signal(String::new());
    let (loading, set_loading) = create_signal(false);
    let (show_totp, set_show_totp) = create_signal(false);
    let dev_mode = is_dev_mode();

    let handle_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let e = email.get();
        let p = password.get();
        if e.is_empty() || p.is_empty() {
            set_error.set("Email and password required".into());
            return;
        }
        set_loading.set(true);
        set_error.set(String::new());
        let totp_val = if totp.get().is_empty() {
            None
        } else {
            Some(totp.get())
        };
        let nav = nav1.clone();
        spawn_local(async move {
            match login(set_auth, e, p, totp_val).await {
                Ok(()) => {
                    nav("/app", Default::default());
                }
                Err(e) if e.contains("totp") || e.contains("2fa") || e.contains("otp") => {
                    set_show_totp.set(true);
                    set_loading.set(false);
                    set_error.set(e);
                }
                Err(e) => {
                    set_error.set(e);
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div style="min-height:100svh;display:flex;align-items:center;justify-content:center;padding:1rem;background:var(--cn-bg)">
            <div style="width:100%;max-width:22rem">
                <div style="text-align:center;margin-bottom:2rem">
                    <div style="margin:0 auto 1rem;width:2.75rem;height:2.75rem;border-radius:10px;background:var(--cn-accent);color:#0a0a0b;font-weight:800;font-size:1.1rem;display:flex;align-items:center;justify-content:center">"C"</div>
                    <h1 style="font-size:1.2rem;font-weight:700;color:var(--cn-text);margin:0">"Welcome back"</h1>
                    <p style="font-size:0.82rem;color:var(--cn-muted);margin:0.4rem 0 0">"Sign in to your Connector account"</p>
                </div>

                {move || if dev_mode {
                    view!{
                        <div class="cn-warn-box" style="margin-bottom:1rem">
                            <p style="font-size:0.78rem;font-weight:600;color:var(--cn-warn);margin:0">"⚠ Dev mode active"</p>
                        </div>
                    }.into_any()
                } else { view!{ <span /> }.into_any() }}

                <div class="card" style="display:flex;flex-direction:column;gap:1rem">
                    {move || if !error.get().is_empty() {
                        view!{ <div class="badge-red" style="padding:0.5rem 0.75rem;border-radius:8px;font-size:0.8rem;display:block">{error.get()}</div> }.into_any()
                    } else { view!{ <span /> }.into_any() }}

                    <form on:submit=handle_submit style="display:flex;flex-direction:column;gap:0.9rem">
                        <div>
                            <label style="display:block;font-size:0.72rem;font-weight:600;color:var(--cn-muted);margin-bottom:0.35rem">"Email"</label>
                            <input class="input" type="email" placeholder="you@example.com"
                                prop:value=email on:input=move|e|set_email.set(event_target_value(&e)) />
                        </div>
                        <div>
                            <label style="display:block;font-size:0.72rem;font-weight:600;color:var(--cn-muted);margin-bottom:0.35rem">"Password"</label>
                            <input class="input" type="password" placeholder="••••••••"
                                prop:value=password on:input=move|e|set_password.set(event_target_value(&e)) />
                        </div>
                        {move || if show_totp.get() {
                            view!{
                                <div>
                                    <label style="display:block;font-size:0.72rem;font-weight:600;color:var(--cn-muted);margin-bottom:0.35rem">"Authenticator Code"</label>
                                    <input class="input" style="font-family:'JetBrains Mono',monospace;letter-spacing:.15em" type="text"
                                        placeholder="000000" maxlength="6"
                                        prop:value=totp on:input=move|e|set_totp.set(event_target_value(&e)) />
                                </div>
                            }.into_any()
                        } else { view!{ <span /> }.into_any() }}
                        <button type="submit" disabled=loading class="btn-primary" style="width:100%;margin-top:0.25rem">
                            {move || if loading.get() { "Signing in…" } else { "Sign in" }}
                        </button>
                    </form>

                    {move || if dev_mode {
                        let nav = nav2.clone();
                        view!{
                            <div style="border-top:1px solid var(--cn-border);padding-top:0.75rem">
                                <button type="button"
                                    on:click=move |_| {
                                        use gloo_storage::{LocalStorage, Storage};
                                        let _ = LocalStorage::set("portal_token", "dev-token");
                                        nav("/app", Default::default());
                                    }
                                    style="width:100%;border:1px solid rgba(255,176,32,.3);background:rgba(255,176,32,.08);color:var(--cn-warn);font-size:0.8rem;font-weight:600;border-radius:8px;padding:0.5rem;cursor:pointer">
                                    "⚡  Dev Bypass — Skip Auth"
                                </button>
                            </div>
                        }.into_any()
                    } else { view!{ <span /> }.into_any() }}
                </div>

                <p style="margin-top:1rem;text-align:center;font-size:0.78rem;color:var(--cn-muted)">
                    "Don't have an account? "
                    <A href="/signup" attr:style="color:var(--cn-accent);text-decoration:none">"Join Beta"</A>
                </p>
            </div>
        </div>
    }
}
