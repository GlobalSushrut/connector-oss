use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use leptos_router::{components::A, hooks::use_navigate};
use crate::auth::{register, AuthState};

#[component]
pub fn Signup(set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let navigate = use_navigate();
    let (name, set_name) = create_signal(String::new());
    let (email, set_email) = create_signal(String::new());
    let (password, set_password) = create_signal(String::new());
    let (license_key, set_license_key) = create_signal(String::new());
    let (error, set_error) = create_signal(String::new());
    let (loading, set_loading) = create_signal(false);

    let handle_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let name_v = name.get().trim().to_string();
        let email_v = email.get().trim().to_string();
        let password_v = password.get();
        let key_v = license_key.get().trim().to_string();

        if name_v.is_empty() {
            set_error.set("Name is required".into());
            return;
        }
        if !email_v.contains('@') {
            set_error.set("Valid email is required".into());
            return;
        }
        if password_v.len() < 10 {
            set_error.set("Password must be at least 10 characters".into());
            return;
        }

        set_loading.set(true);
        set_error.set(String::new());
        let nav = navigate.clone();
        spawn_local(async move {
            match register(
                set_auth,
                name_v,
                email_v,
                password_v,
                if key_v.is_empty() { None } else { Some(key_v) },
            ).await {
                Ok(()) => nav("/app", Default::default()),
                Err(err) => {
                    set_error.set(err);
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div class="cn-page" style="padding:2rem 1.25rem">
            <div style="max-width:62rem;margin:0 auto;display:grid;gap:3rem;grid-template-columns:1fr 1fr;align-items:start;padding-top:3rem">

                // Left — value prop
                <div style="display:flex;flex-direction:column;gap:1.5rem;padding-top:1rem">
                    <A href="/" attr:style="font-size:0.8rem;font-weight:700;color:var(--cn-accent);text-decoration:none;letter-spacing:-0.01em">"← Connector"</A>
                    <div style="display:flex;flex-direction:column;gap:0.85rem">
                        <div style="display:inline-flex;align-items:center;gap:0.5rem;border:1px solid rgba(255,176,32,.3);background:rgba(255,176,32,.08);border-radius:9999px;padding:0.25rem 0.75rem;font-size:0.7rem;font-weight:700;color:var(--cn-warn);width:fit-content;letter-spacing:.04em;text-transform:uppercase">
                            "Controlled Beta"
                        </div>
                        <h1 style="font-size:clamp(1.6rem,3vw,2.4rem);font-weight:700;letter-spacing:-0.03em;line-height:1.15;color:var(--cn-text);margin:0">
                            "Get access to Connector"
                        </h1>
                        <p style="font-size:0.95rem;line-height:1.65;color:var(--cn-muted);margin:0">
                            "Selected teams only. Create your account, receive a license key, download the binary, and run a governed AI node on your own infrastructure."
                        </p>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem">
                        {[
                            ("Portal first",    "Account, billing, API keys, profile, and entitlement live here."),
                            ("Dashboard second","Your dashboard uses a token only — no portal auth on the node."),
                        ].into_iter().map(|(t, d)| view!{
                            <div style="background:var(--cn-panel);border:1px solid var(--cn-border);border-radius:12px;padding:1rem">
                                <p style="font-size:0.82rem;font-weight:600;color:var(--cn-text);margin:0">{t}</p>
                                <p style="font-size:0.78rem;color:var(--cn-muted);margin:0.4rem 0 0;line-height:1.5">{d}</p>
                            </div>
                        }).collect::<Vec<_>>()}
                    </div>
                </div>

                // Right — form
                <div class="card" style="display:flex;flex-direction:column;gap:1.25rem">
                    <div class="cn-warn-box">
                        <div>
                            <p style="font-size:0.78rem;font-weight:700;color:var(--cn-warn);margin:0">"Controlled Beta — selected teams only"</p>
                            <p style="font-size:0.75rem;color:var(--cn-muted);margin:0.3rem 0 0">"Accounts are reviewed manually. License key arrives by email within 48 h."</p>
                        </div>
                    </div>
                    <div>
                        <h2 style="font-size:1rem;font-weight:700;color:var(--cn-text);margin:0">"Request beta access"</h2>
                        <p style="font-size:0.78rem;color:var(--cn-muted);margin:0.3rem 0 0">"Submit your details. We will review and follow up."</p>
                    </div>

                    {move || if !error.get().is_empty() {
                        view! { <div class="badge-red" style="padding:0.5rem 0.75rem;border-radius:8px;font-size:0.8rem;display:block">{error.get()}</div> }.into_any()
                    } else { view! { <span /> }.into_any() }}

                    <form on:submit=handle_submit style="display:flex;flex-direction:column;gap:0.85rem">
                        <div>
                            <label style="display:block;font-size:0.72rem;font-weight:600;color:var(--cn-muted);margin-bottom:0.35rem">"Full name"</label>
                            <input class="input" type="text" placeholder="Ada Lovelace" prop:value=name on:input=move |ev| set_name.set(event_target_value(&ev)) />
                        </div>
                        <div>
                            <label style="display:block;font-size:0.72rem;font-weight:600;color:var(--cn-muted);margin-bottom:0.35rem">"Work email"</label>
                            <input class="input" type="email" placeholder="you@company.com" prop:value=email on:input=move |ev| set_email.set(event_target_value(&ev)) />
                        </div>
                        <div>
                            <label style="display:block;font-size:0.72rem;font-weight:600;color:var(--cn-muted);margin-bottom:0.35rem">"Password"</label>
                            <input class="input" type="password" placeholder="At least 10 characters" prop:value=password on:input=move |ev| set_password.set(event_target_value(&ev)) />
                        </div>
                        <div>
                            <label style="display:block;font-size:0.72rem;font-weight:600;color:var(--cn-muted);margin-bottom:0.35rem">"License key (if you have one)"</label>
                            <input class="input" style="font-family:'JetBrains Mono',monospace;font-size:0.82rem" type="text" placeholder="lic_..." prop:value=license_key on:input=move |ev| set_license_key.set(event_target_value(&ev)) />
                        </div>
                        <button type="submit" disabled=loading class="btn-primary" style="width:100%;margin-top:0.25rem">
                            {move || if loading.get() { "Submitting…" } else { "Request beta access" }}
                        </button>
                    </form>

                    <p style="text-align:center;font-size:0.78rem;color:var(--cn-muted)">
                        "Already have an account? "
                        <A href="/login" attr:style="color:var(--cn-accent);text-decoration:none">"Sign in"</A>
                    </p>
                </div>
            </div>
        </div>
    }
}
