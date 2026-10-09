use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Customers(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh_tick, set_refresh_tick) = create_signal(0u32);
    let (message, set_message) = create_signal(String::new());
    let (error, set_error) = create_signal(String::new());
    let customers = LocalResource::new(move || {
        let _ = refresh_tick.get();
        api::get_value("/admin/customers")
    });

    let trigger_action = move |path: String, success: &'static str| {
        set_error.set(String::new());
        set_message.set(String::new());
        spawn_local(async move {
            match api::post_value(&path, serde_json::json!({})).await {
                Ok(_) => {
                    set_message.set(success.into());
                    set_refresh_tick.update(|tick| *tick += 1);
                }
                Err(err) => set_error.set(err.message),
            }
        });
    };

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Customer operations"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Customers"</h1>
                    <p class="text-sm text-zinc-500">"Review billing state and intervene when a customer needs restore or suspension."</p>
                </div>
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-xs text-zinc-500">
                    {move || format!("Admin key: {}", auth.get().key_hint)}
                </div>
            </div>

            {move || if !error.get().is_empty() {
                view! { <div class="rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error.get()}</div> }.into_any()
            } else { view! { <span /> }.into_any() }}
            {move || if !message.get().is_empty() {
                view! { <div class="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{message.get()}</div> }.into_any()
            } else { view! { <span /> }.into_any() }}

            <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = customers.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let rows = v["customers"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <div class="mb-4 flex items-center justify-between gap-4">
                                <div>
                                    <h2 class="text-lg font-semibold text-zinc-50">"Customer accounts"</h2>
                                    <p class="mt-1 text-sm text-zinc-500">{format!("{} accounts in view", rows.len())}</p>
                                </div>
                            </div>
                            <table class="min-w-full text-sm">
                                <thead>
                                    <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                        <th class="px-3 py-3">"Customer"</th>
                                        <th class="px-3 py-3">"Tier"</th>
                                        <th class="px-3 py-3">"Billing state"</th>
                                        <th class="px-3 py-3">"Aging"</th>
                                        <th class="px-3 py-3">"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows.into_iter().map(|row| {
                                        let customer_id = row["customer_id"].as_str().unwrap_or("-").to_string();
                                        let name = row["name"].as_str().unwrap_or("Unknown").to_string();
                                        let email = row["email"].as_str().unwrap_or("—").to_string();
                                        let tier = row["tier"].as_str().unwrap_or("—").to_string();
                                        let state = row["billing_state"].as_str().unwrap_or("—").to_string();
                                        let days_overdue = row["days_overdue"].as_i64().unwrap_or(0);
                                        let retry_count = row["retry_count"].as_i64().unwrap_or(0);
                                        let suspend_id = customer_id.clone();
                                        let restore_id = customer_id.clone();
                                        view! {
                                            <tr class="border-b border-zinc-900/80 align-top text-zinc-300">
                                                <td class="px-3 py-4">
                                                    <p class="font-medium text-zinc-100">{name}</p>
                                                    <p class="mt-1 text-xs text-zinc-500">{email}</p>
                                                    <p class="mt-1 text-[11px] font-mono text-zinc-600">{customer_id}</p>
                                                </td>
                                                <td class="px-3 py-4 text-zinc-400">{tier}</td>
                                                <td class="px-3 py-4">
                                                    <span class=if state.contains("Active") { "inline-flex rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300" } else if state.contains("Suspended") || state.contains("Cancelled") { "inline-flex rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-300" } else { "inline-flex rounded-full bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-300" }>{state.clone()}</span>
                                                </td>
                                                <td class="px-3 py-4 text-xs text-zinc-500">{format!("{} days overdue · {} retries", days_overdue, retry_count)}</td>
                                                <td class="px-3 py-4">
                                                    <div class="flex flex-wrap gap-2">
                                                        <button on:click=move |_| trigger_action(format!("/admin/customers/{}/restore", restore_id.clone()), "Customer restored") class="rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 transition-colors">
                                                            "Restore"
                                                        </button>
                                                        <button on:click=move |_| trigger_action(format!("/admin/customers/{}/suspend", suspend_id.clone()), "Customer suspended") class="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-500/20 transition-colors">
                                                            "Suspend"
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        }.into_any()
                                    }).collect::<Vec<_>>()}
                                </tbody>
                            </table>
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}
