use leptos::prelude::*;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Dashboard(auth: ReadSignal<AuthState>) -> impl IntoView {
    let stats = LocalResource::new(|| api::get_value("/admin/stats"));
    let dunning = LocalResource::new(|| api::get_value("/admin/dunning"));

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Control plane overview"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Admin dashboard"</h1>
                    <p class="text-sm text-zinc-500">"License issuance, activation posture, revenue signals, and dunning health for the hosted control server."</p>
                </div>
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-xs text-zinc-500">
                    {move || format!("Session: {}", auth.get().key_hint)}
                </div>
            </div>

            <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <Suspense fallback=|| view! { <div class="card h-28 animate-pulse" /> }>
                    {move || Suspend::new(async move {
                        let value = stats.await;
                        let v = value.ok().unwrap_or(Value::Null);
                        let total_keys  = v["total_keys"].as_u64().unwrap_or(0);
                        let active_keys = v["active_keys"].as_u64().unwrap_or(0);
                        let activations = v["active_activations"].as_u64().unwrap_or(0);
                        let mrr = v["mrr_display"].as_str().unwrap_or("$0.00").to_string();
                        view! {
                            <>
                                <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Keys issued"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{total_keys}</p></div>
                                <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Active keys"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{active_keys}</p></div>
                                <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Active activations"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{activations}</p></div>
                                <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"MRR"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{mrr}</p></div>
                            </>
                        }
                    })}
                </Suspense>
            </div>

            <div class="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
                <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                    {move || Suspend::new(async move {
                        let value = stats.await;
                        let v = value.ok().unwrap_or(Value::Null);
                        let breakdown = v["tier_breakdown"].as_object().cloned().unwrap_or_default();
                        let public_key = v["public_key"].as_str().unwrap_or("—").to_string();
                        view! {
                            <div class="card">
                                <div class="flex items-center justify-between gap-4">
                                    <div>
                                        <h2 class="text-lg font-semibold text-zinc-50">"Tier distribution"</h2>
                                        <p class="mt-1 text-sm text-zinc-500">"Current non-revoked license inventory by tier."</p>
                                    </div>
                                </div>
                                <div class="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                                    {breakdown.into_iter().map(|(tier, count)| {
                                        let count = count.as_u64().unwrap_or(0);
                                        view! {
                                            <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                                                <p class="text-xs uppercase tracking-wider text-zinc-500">{tier.clone()}</p>
                                                <p class="mt-2 text-2xl font-semibold text-zinc-50">{count}</p>
                                            </div>
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                                <div class="mt-5 rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Public signing key"</p>
                                    <p class="mt-2 break-all font-mono text-xs text-zinc-400">{public_key}</p>
                                </div>
                            </div>
                        }
                    })}
                </Suspense>

                <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                    {move || Suspend::new(async move {
                        let value = dunning.await;
                        let v = value.ok().unwrap_or(Value::Null);
                        let active = v["active"].as_u64().unwrap_or(0);
                        let past_due = v["past_due"].as_u64().unwrap_or(0);
                        let degraded = v["degraded"].as_u64().unwrap_or(0);
                        let suspended = v["suspended"].as_u64().unwrap_or(0);
                        let recovery_rate = v["recovery_rate"].as_str().unwrap_or("—").to_string();
                        view! {
                            <div class="card">
                                <h2 class="text-lg font-semibold text-zinc-50">"Dunning health"</h2>
                                <div class="mt-5 space-y-3">
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3"><p class="text-xs uppercase tracking-wider text-zinc-500">"Active"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{active}</p></div>
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3"><p class="text-xs uppercase tracking-wider text-zinc-500">"Past due"</p><p class="mt-2 text-2xl font-semibold text-amber-300">{past_due}</p></div>
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3"><p class="text-xs uppercase tracking-wider text-zinc-500">"Degraded / Suspended"</p><p class="mt-2 text-2xl font-semibold text-red-300">{format!("{} / {}", degraded, suspended)}</p></div>
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3"><p class="text-xs uppercase tracking-wider text-zinc-500">"Recovery rate"</p><p class="mt-2 text-2xl font-semibold text-emerald-300">{recovery_rate.clone()}</p></div>
                                </div>
                            </div>
                        }
                    })}
                </Suspense>
            </div>
        </div>
    }
}
