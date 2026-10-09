use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;
use crate::components::layout::NavBar;

#[component]
pub fn Profile(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let me = LocalResource::new(|| api::get_value("/me"));
    let (name, set_name) = create_signal(String::new());
    let (email, set_email) = create_signal(String::new());
    let (message, set_message) = create_signal(String::new());
    let (error, set_error) = create_signal(String::new());
    let (saving, set_saving) = create_signal(false);

    let save_profile = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let current_name = name.get().trim().to_string();
        let current_email = email.get().trim().to_string();
        if current_name.is_empty() || !current_email.contains('@') {
            set_error.set("Provide a valid name and email".into());
            return;
        }
        set_error.set(String::new());
        set_message.set(String::new());
        set_saving.set(true);
        spawn_local(async move {
            match api::patch_value("/profile", serde_json::json!({
                "name": current_name,
                "email": current_email,
            })).await {
                Ok(_) => {
                    set_message.set("Profile updated".into());
                }
                Err(err) => set_error.set(err.message),
            }
            set_saving.set(false);
        });
    };

    view! {
        <div class="min-h-screen bg-zinc-50">
            <NavBar auth=auth set_auth=set_auth />
            <div class="mx-auto max-w-6xl px-4 py-8 space-y-6">
                <div>
                    <h1 class="text-2xl font-semibold text-zinc-950">"Profile"</h1>
                    <p class="mt-1 text-sm text-zinc-600">"Manage your hosted account identity here. Dashboard runtime access remains token-based on your node."</p>
                </div>

                {move || if !error.get().is_empty() {
                    view! { <div class="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600">{error.get()}</div> }.into_any()
                } else { view! { <span /> }.into_any() }}
                {move || if !message.get().is_empty() {
                    view! { <div class="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">{message.get()}</div> }.into_any()
                } else { view! { <span /> }.into_any() }}

                <div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
                    <Suspense fallback=|| view! { <div class="card h-72 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let me_value = me.await;
                            let v = me_value.as_ref().ok().unwrap_or(&Value::Null);
                            let current_name = v["name"].as_str().unwrap_or("").to_string();
                            let current_email = v["email"].as_str().unwrap_or("").to_string();
                            let created_at = v["created_at"].as_str().unwrap_or("—").to_string();
                            let last_login = v["last_login"].as_str().unwrap_or("—").to_string();
                            let billing_state = v["billing_state"].as_str().unwrap_or("Unknown").to_string();
                            let email_verified = v["email_verified"].as_bool().unwrap_or(false);
                            if name.get().is_empty() {
                                set_name.set(current_name.clone());
                            }
                            if email.get().is_empty() {
                                set_email.set(current_email.clone());
                            }
                            view! {
                                <form on:submit=save_profile class="card space-y-4">
                                    <div>
                                        <h2 class="text-lg font-semibold text-zinc-950">"Account details"</h2>
                                        <p class="mt-1 text-sm text-zinc-500">"These details are stored on the hosted control server."</p>
                                    </div>
                                    <div>
                                        <label class="mb-1 block text-xs font-medium text-zinc-700">"Full name"</label>
                                        <input class="input w-full" type="text" prop:value=name on:input=move |ev| set_name.set(event_target_value(&ev)) />
                                    </div>
                                    <div>
                                        <label class="mb-1 block text-xs font-medium text-zinc-700">"Email"</label>
                                        <input class="input w-full" type="email" prop:value=email on:input=move |ev| set_email.set(event_target_value(&ev)) />
                                    </div>
                                    <button type="submit" class="btn-primary" disabled=saving>
                                        {move || if saving.get() { "Saving…" } else { "Save profile" }}
                                    </button>

                                    <div class="grid gap-3 border-t border-zinc-200 pt-4 text-sm text-zinc-600 sm:grid-cols-2">
                                        <div>
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Created"</p>
                                            <p class="mt-1">{created_at}</p>
                                        </div>
                                        <div>
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Last login"</p>
                                            <p class="mt-1">{last_login}</p>
                                        </div>
                                        <div>
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Billing state"</p>
                                            <p class="mt-1">{billing_state}</p>
                                        </div>
                                        <div>
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Email verification"</p>
                                            <p class="mt-1">{if email_verified { "Verified" } else { "Pending" }}</p>
                                        </div>
                                    </div>
                                </form>
                            }
                        })}
                    </Suspense>

                    <Suspense fallback=|| view! { <div class="card h-72 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let me_value = me.await;
                            let v = me_value.as_ref().ok().unwrap_or(&Value::Null);
                            let tier = v["tier"].as_str().unwrap_or("Community").to_string();
                            let api_key_count = v["api_key_count"].as_u64().unwrap_or(0);
                            let backup_codes = v["backup_codes_remaining"].as_u64().unwrap_or(0);
                            view! {
                                <div class="card">
                                    <h2 class="text-lg font-semibold text-zinc-950">"Security posture"</h2>
                                    <div class="mt-5 space-y-3">
                                        <div class="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Tier"</p>
                                            <p class="mt-2 text-lg font-semibold text-zinc-950">{tier}</p>
                                        </div>
                                        <div class="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"API keys"</p>
                                            <p class="mt-2 text-lg font-semibold text-zinc-950">{api_key_count}</p>
                                        </div>
                                        <div class="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Backup codes remaining"</p>
                                            <p class="mt-2 text-lg font-semibold text-zinc-950">{backup_codes}</p>
                                        </div>
                                    </div>
                                </div>
                            }
                        })}
                    </Suspense>
                </div>
            </div>
        </div>
    }
}
