use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;
use crate::components::layout::NavBar;

#[component]
pub fn ApiKeys(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let (name, set_name) = create_signal(String::new());
    let (expires_days, set_expires_days) = create_signal(String::from("30"));
    let (created_key, set_created_key) = create_signal(String::new());
    let (message, set_message) = create_signal(String::new());
    let (error, set_error) = create_signal(String::new());
    let (creating, set_creating) = create_signal(false);
    let (refresh_tick, set_refresh_tick) = create_signal(0u32);

    let keys = LocalResource::new(move || {
        let _ = refresh_tick.get();
        api::get_value("/api-keys")
    });

    let create_key = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        let key_name = name.get().trim().to_string();
        if key_name.is_empty() {
            set_error.set("Key name is required".into());
            return;
        }
        let days = expires_days.get().parse::<u32>().ok();
        set_creating.set(true);
        set_error.set(String::new());
        set_message.set(String::new());
        set_created_key.set(String::new());
        spawn_local(async move {
            match api::post_value("/api-keys", serde_json::json!({
                "name": key_name,
                "expires_days": days,
            })).await {
                Ok(v) => {
                    set_created_key.set(v["api_key"].as_str().unwrap_or("").to_string());
                    set_message.set("API key created. Save it now — it will not be shown again.".into());
                    set_name.set(String::new());
                    set_refresh_tick.update(|tick| *tick += 1);
                }
                Err(err) => set_error.set(err.message),
            }
            set_creating.set(false);
        });
    };

    let revoke_key = move |key_id: String| {
        set_error.set(String::new());
        set_message.set(String::new());
        spawn_local(async move {
            match api::delete_value(&format!("/api-keys/{}", key_id)).await {
                Ok(_) => {
                    set_message.set("API key revoked".into());
                    set_refresh_tick.update(|tick| *tick += 1);
                }
                Err(err) => set_error.set(err.message),
            }
        });
    };

    view! {
        <div class="min-h-screen bg-zinc-50">
            <NavBar auth=auth set_auth=set_auth />
            <div class="mx-auto max-w-6xl px-4 py-8 space-y-6">
                <div>
                    <h1 class="text-2xl font-semibold text-zinc-950">"API keys"</h1>
                    <p class="mt-1 text-sm text-zinc-600">"Create keys here in the hosted portal, then use them in your local operator dashboard."</p>
                </div>

                {move || if !error.get().is_empty() {
                    view! { <div class="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-600">{error.get()}</div> }.into_any()
                } else { view! { <span /> }.into_any() }}
                {move || if !message.get().is_empty() {
                    view! { <div class="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">{message.get()}</div> }.into_any()
                } else { view! { <span /> }.into_any() }}

                {move || if !created_key.get().is_empty() {
                    view! {
                        <div class="rounded-2xl border border-indigo-200 bg-indigo-50 p-4">
                            <p class="text-xs font-medium uppercase tracking-wider text-indigo-700">"New API key"</p>
                            <p class="mt-2 rounded-lg bg-white px-3 py-2 font-mono text-sm text-zinc-900 break-all">{created_key.get()}</p>
                        </div>
                    }.into_any()
                } else { view! { <span /> }.into_any() }}

                <div class="grid gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
                    <form on:submit=create_key class="card space-y-4">
                        <div>
                            <h2 class="text-lg font-semibold text-zinc-950">"Create key"</h2>
                            <p class="mt-1 text-sm text-zinc-500">"Keys generated here are the tokens your node dashboard asks for."</p>
                        </div>
                        <div>
                            <label class="mb-1 block text-xs font-medium text-zinc-700">"Key name"</label>
                            <input class="input w-full" type="text" placeholder="Production dashboard" prop:value=name on:input=move |ev| set_name.set(event_target_value(&ev)) />
                        </div>
                        <div>
                            <label class="mb-1 block text-xs font-medium text-zinc-700">"Expiry (days)"</label>
                            <input class="input w-full" type="number" min="1" placeholder="30" prop:value=expires_days on:input=move |ev| set_expires_days.set(event_target_value(&ev)) />
                        </div>
                        <button type="submit" class="btn-primary w-full" disabled=creating>
                            {move || if creating.get() { "Creating key…" } else { "Create API key" }}
                        </button>
                    </form>

                    <Suspense fallback=|| view! { <div class="card h-64 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let keys_value = keys.await;
                            let v = keys_value.as_ref().ok().unwrap_or(&Value::Null);
                            let rows = v["keys"].as_array().cloned().unwrap_or_default();
                            view! {
                                <div class="card">
                                    <div class="flex items-center justify-between gap-3">
                                        <div>
                                            <h2 class="text-lg font-semibold text-zinc-950">"Active keys"</h2>
                                            <p class="mt-1 text-sm text-zinc-500">"Revoke keys here if a dashboard token should no longer work."</p>
                                        </div>
                                        <span class="badge-zinc">{format!("{} keys", rows.len())}</span>
                                    </div>
                                    <div class="mt-5 space-y-3">
                                        {if rows.is_empty() {
                                            vec![view! { <div class="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 px-4 py-6 text-sm text-zinc-500">"No keys yet. Create your first dashboard token here."</div> }.into_any()]
                                        } else {
                                            rows.into_iter().map(|row| {
                                                let key_id = row["key_id"].as_str().unwrap_or("-").to_string();
                                                let name = row["name"].as_str().unwrap_or("API key").to_string();
                                                let created_at = row["created_at"].as_str().unwrap_or("—").to_string();
                                                let expires_at = row["expires_at"].as_str().unwrap_or("No expiry").to_string();
                                                let revoke_id = key_id.clone();
                                                view! {
                                                    <div class="rounded-xl border border-zinc-200 bg-zinc-50 px-4 py-3">
                                                        <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                                                            <div>
                                                                <p class="text-sm font-medium text-zinc-950">{name}</p>
                                                                <p class="mt-1 text-xs font-mono text-zinc-500">{key_id}</p>
                                                                <p class="mt-1 text-xs text-zinc-500">{format!("Created: {} · Expires: {}", created_at, expires_at)}</p>
                                                            </div>
                                                            <button on:click=move |_| revoke_key(revoke_id.clone()) class="rounded-lg border border-red-200 bg-white px-3 py-2 text-xs font-medium text-red-600 hover:bg-red-50 transition-colors">
                                                                "Revoke"
                                                            </button>
                                                        </div>
                                                    </div>
                                                }.into_any()
                                            }).collect::<Vec<_>>()
                                        }}
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
