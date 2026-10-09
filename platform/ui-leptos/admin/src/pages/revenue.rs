use leptos::prelude::*;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Revenue(auth: ReadSignal<AuthState>) -> impl IntoView {
    let revenue = LocalResource::new(|| api::get_value("/payment/revenue"));

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Commercial metrics"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Revenue"</h1>
                    <p class="text-sm text-zinc-500">"Recurring revenue and active subscription posture surfaced by the hosted payment service."</p>
                </div>
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-xs text-zinc-500">
                    {move || format!("Admin key: {}", auth.get().key_hint)}
                </div>
            </div>

            <Suspense fallback=|| view! { <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4"><div class="card h-28 animate-pulse" /><div class="card h-28 animate-pulse" /><div class="card h-28 animate-pulse" /><div class="card h-28 animate-pulse" /></div> }>
                {move || Suspend::new(async move {
                    let value = revenue.await;
                    let v = value.ok().unwrap_or(Value::Null);
                    let mrr = v["mrr_display"].as_str().unwrap_or("$0.00").to_string();
                    let arr = v["arr_display"].as_str().unwrap_or("$0.00").to_string();
                    let active_subscriptions = v["active_subscriptions"].as_u64().unwrap_or(0);
                    let churn = v["churn_pct"].as_f64().unwrap_or(0.0);
                    view! {
                        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"MRR"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{mrr}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"ARR"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{arr}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Active subscriptions"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{active_subscriptions}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Churn"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{format!("{:.1}%", churn)}</p></div>
                        </div>
                    }
                })}
            </Suspense>

            <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = revenue.await;
                    let v = value.ok().unwrap_or(Value::Null);
                    let tier_revenue = v["tier_revenue"].as_object().cloned().unwrap_or_default();
                    let total_keys = v["total_keys_issued"].as_u64().unwrap_or(0);
                    let instances = v["active_instances"].as_u64().unwrap_or(0);
                    view! {
                        <div class="card">
                            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                                <div>
                                    <h2 class="text-lg font-semibold text-zinc-50">"Revenue mix"</h2>
                                    <p class="mt-1 text-sm text-zinc-500">"Revenue contribution by tier, plus inventory posture."</p>
                                </div>
                                <div class="text-xs text-zinc-500">{format!("{} keys issued · {} active instances", total_keys, instances)}</div>
                            </div>
                            <div class="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                                {tier_revenue.into_iter().map(|(tier, cents)| {
                                    let cents = cents.as_u64().unwrap_or(0);
                                    view! {
                                        <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">{tier.clone()}</p>
                                            <p class="mt-2 text-2xl font-semibold text-zinc-50">{format!("${:.2}", cents as f64 / 100.0)}</p>
                                        </div>
                                    }
                                }).collect::<Vec<_>>()}
                            </div>
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}
