use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Dunning(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh) = create_signal(0u32);
    let (flash, set_flash) = create_signal(Option::<(String, bool)>::None);

    let dunning = LocalResource::new(move || { let _ = refresh.get(); api::get_value("/admin/dunning") });

    let action = move |path: String, label: &'static str| {
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value(&path, serde_json::json!({})).await {
                Ok(_)  => { set_flash.set(Some((format!("{label} — done"), true))); set_refresh.update(|v| *v += 1); }
                Err(e) => { set_flash.set(Some((e.message, false))); }
            }
        });
    };

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Payment recovery"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Dunning"</h1>
                    <p class="text-sm text-zinc-500">"Failed payment state machine: past-due → degraded → suspended → cancelled. Intervene manually when needed."</p>
                </div>
                <button on:click=move |_| set_refresh.update(|v| *v += 1)
                    class="rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-700 transition-colors">
                    "Refresh"
                </button>
            </div>

            {move || flash.get().map(|(msg, ok)| view! {
                <div class=if ok { "rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300" }
                          else  { "rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300" }>
                    {msg}
                </div>
            })}

            <Suspense fallback=|| view! { <div class="grid gap-4 grid-cols-4"><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/></div> }>
                {move || Suspend::new(async move {
                    let value = dunning.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let active    = v["active"].as_u64().unwrap_or(0);
                    let past_due  = v["past_due"].as_u64().unwrap_or(0);
                    let degraded  = v["degraded"].as_u64().unwrap_or(0);
                    let suspended = v["suspended"].as_u64().unwrap_or(0);
                    let cancelled = v["cancelled"].as_u64().unwrap_or(0);
                    let recovery  = v["recovery_rate"].as_str().unwrap_or("—").to_string();
                    view! {
                        <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Active"</p>
                                <p class="mt-2 text-2xl font-semibold text-emerald-300">{active}</p>
                            </div>
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Past due"</p>
                                <p class="mt-2 text-2xl font-semibold text-amber-300">{past_due}</p>
                                <p class="mt-1 text-xs text-zinc-600">"Will degrade in 3 days"</p>
                            </div>
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Degraded"</p>
                                <p class="mt-2 text-2xl font-semibold text-orange-300">{degraded}</p>
                                <p class="mt-1 text-xs text-zinc-600">"Rate-limited access"</p>
                            </div>
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Suspended"</p>
                                <p class="mt-2 text-2xl font-semibold text-red-300">{suspended}</p>
                                <p class="mt-1 text-xs text-zinc-600">"No access"</p>
                            </div>
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Recovery rate"</p>
                                <p class="mt-2 text-2xl font-semibold text-zinc-50">{recovery}</p>
                                <p class="mt-1 text-xs text-zinc-600">{format!("{} cancelled", cancelled)}</p>
                            </div>
                        </div>
                    }
                })}
            </Suspense>

            <Suspense fallback=|| view! { <div class="card h-96 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = dunning.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let records = v["records"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <div class="mb-4">
                                <h2 class="text-lg font-semibold text-zinc-50">"Dunning records"</h2>
                                <p class="mt-1 text-sm text-zinc-500">"Customers in a non-active billing state. Restore resets state machine; suspend skips ahead."</p>
                            </div>
                            {if records.is_empty() {
                                view!{ <p class="text-sm text-zinc-600 py-8 text-center">"No customers in dunning — all payments current."</p> }.into_any()
                            } else {
                                view! {
                                    <table class="min-w-full text-sm">
                                        <thead>
                                            <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                                <th class="px-3 py-3">"Customer"</th>
                                                <th class="px-3 py-3">"State"</th>
                                                <th class="px-3 py-3">"Days overdue"</th>
                                                <th class="px-3 py-3">"Retry count"</th>
                                                <th class="px-3 py-3">"Next retry"</th>
                                                <th class="px-3 py-3">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {records.into_iter().map(|row| {
                                                let cid      = row["customer_id"].as_str().unwrap_or("-").to_string();
                                                let name     = row["name"].as_str().unwrap_or("—").to_string();
                                                let email    = row["email"].as_str().unwrap_or("—").to_string();
                                                let state    = row["state"].as_str().unwrap_or("—").to_string();
                                                let days     = row["days_overdue"].as_i64().unwrap_or(0);
                                                let retries  = row["retry_count"].as_i64().unwrap_or(0);
                                                let next     = row["next_retry"].as_str().unwrap_or("—").to_string();
                                                let restore_cid = cid.clone();
                                                let suspend_cid = cid.clone();
                                                let days_class = if days > 7 { "text-red-300" } else if days > 0 { "text-amber-300" } else { "text-zinc-400" };
                                                let state_class = format!("inline-flex rounded-full px-2 py-0.5 text-xs font-medium {}",
                                                    match state.as_str() {
                                                        "Active" => "bg-emerald-500/10 text-emerald-300",
                                                        "PastDue" => "bg-amber-500/10 text-amber-300",
                                                        "Degraded" => "bg-orange-500/10 text-orange-300",
                                                        "Suspended" => "bg-red-500/10 text-red-300",
                                                        _ => "bg-zinc-700 text-zinc-300",
                                                    });
                                                view! {
                                                    <tr class="border-b border-zinc-900/80 align-top text-zinc-300">
                                                        <td class="px-3 py-4">
                                                            <p class="font-medium text-zinc-100">{name}</p>
                                                            <p class="text-xs text-zinc-500">{email}</p>
                                                            <p class="text-[11px] font-mono text-zinc-600">{cid}</p>
                                                        </td>
                                                        <td class="px-3 py-4">
                                                            <span class=state_class>{state}</span>
                                                        </td>
                                                        <td class="px-3 py-4 text-sm">
                                                            <span class=days_class>{format!("{} days", days)}</span>
                                                        </td>
                                                        <td class="px-3 py-4 text-zinc-400">{retries}</td>
                                                        <td class="px-3 py-4 text-xs text-zinc-500">{next}</td>
                                                        <td class="px-3 py-4">
                                                            <div class="flex gap-2">
                                                                <button on:click=move |_| action(format!("/admin/customers/{}/restore", restore_cid.clone()), "Restored")
                                                                    class="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-500/20 transition-colors">
                                                                    "Restore"
                                                                </button>
                                                                <button on:click=move |_| action(format!("/admin/customers/{}/suspend", suspend_cid.clone()), "Suspended")
                                                                    class="rounded border border-red-500/20 bg-red-500/10 px-2 py-1 text-xs text-red-300 hover:bg-red-500/20 transition-colors">
                                                                    "Suspend"
                                                                </button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                }.into_any()
                                            }).collect::<Vec<_>>()}
                                        </tbody>
                                    </table>
                                }.into_any()
                            }}
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}
