use leptos::prelude::*;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;
use crate::components::layout::NavBar;

#[component]
pub fn Billing(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let me = LocalResource::new(|| api::get_value("/me"));

    view! {
        <div class="min-h-screen bg-zinc-50">
            <NavBar auth=auth set_auth=set_auth />
            <div class="mx-auto max-w-6xl px-4 py-8 space-y-6">
                <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
                    <div>
                        <h1 class="text-2xl font-semibold text-zinc-950">"Billing"</h1>
                        <p class="mt-1 text-sm text-zinc-600">"Manage plan posture in the hosted control-plane portal. Your local dashboard stays focused on runtime operations."</p>
                    </div>
                    <span class="rounded-full border border-amber-200 bg-amber-50 px-4 py-2 text-sm font-semibold text-amber-700">"Controlled Beta"</span>
                </div>

                // Beta notice
                <div class="rounded-xl border border-indigo-200 bg-indigo-50 px-5 py-4 flex gap-3">
                    <span class="text-indigo-500 text-lg mt-0.5">"ℹ"</span>
                    <div>
                        <p class="text-sm font-semibold text-indigo-900">"Controlled Beta — no self-service subscription yet"</p>
                        <p class="mt-0.5 text-sm text-indigo-700">
                            "You are on a pilot engagement. Self-service subscriptions are coming — they will appear here when available.
                            Your current access is managed directly by the Connector team."
                        </p>
                    </div>
                </div>

                <div class="grid gap-4 lg:grid-cols-3">
                    <Suspense fallback=|| view! { <div class="card h-56 animate-pulse lg:col-span-1" /> }>
                        {move || Suspend::new(async move {
                            let me_value = me.await;
                            let v = me_value.as_ref().ok().unwrap_or(&Value::Null);
                            let tier = v["tier"].as_str().unwrap_or("Beta Pilot").to_string();
                            let state = v["billing_state"].as_str().unwrap_or("Active").to_string();
                            let license_key_id = v["license_key_id"].as_str().unwrap_or("—").to_string();
                            view! {
                                <div class="card lg:col-span-1">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Your current access"</p>
                                    <p class="mt-3 text-2xl font-semibold text-zinc-950">{tier}</p>
                                    <p class="mt-2 text-sm text-zinc-600">{format!("Status: {}", state)}</p>
                                    <p class="mt-2 text-xs font-mono text-zinc-500">{format!("License: {}", license_key_id)}</p>
                                    <p class="mt-3 text-xs text-zinc-400">"Questions about your engagement? Contact the Connector team directly."</p>
                                </div>
                            }
                        })}
                    </Suspense>

                    // Upcoming plans card
                    <div class="card lg:col-span-2">
                        <div class="flex items-center justify-between gap-3 mb-5">
                            <div>
                                <h2 class="text-lg font-semibold text-zinc-950">"Subscription plans"</h2>
                                <p class="mt-1 text-sm text-zinc-500">"Self-service plans launching after controlled beta."</p>
                            </div>
                            <span class="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-700">"Upcoming"</span>
                        </div>
                        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                            {[
                                ("Indie", "$49/mo", "1 node · 3 agents · 10k events/day"),
                                ("Startup", "$199/mo", "3 nodes · 15 agents · 100k events/day"),
                                ("Professional", "$599/mo", "10 nodes · 50 agents · 1M events/day"),
                            ].into_iter().map(|(name, price, desc)| view! {
                                <div class="rounded-2xl border border-zinc-200 bg-zinc-50/60 p-4 relative overflow-hidden">
                                    <div class="absolute inset-0 bg-white/60 backdrop-blur-[1px] rounded-2xl flex items-center justify-center z-10">
                                        <span class="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-bold text-amber-600">"Upcoming"</span>
                                    </div>
                                    <p class="text-base font-semibold text-zinc-950">{name}</p>
                                    <p class="text-xl font-mono font-bold text-indigo-700 mt-1">{price}</p>
                                    <p class="text-xs text-zinc-500 mt-2">{desc}</p>
                                </div>
                            }).collect::<Vec<_>>()}
                        </div>
                        <p class="mt-4 text-xs text-zinc-400">"Pricing is indicative and subject to change. You will be notified when self-service subscriptions open."</p>
                    </div>
                </div>
            </div>
        </div>
    }
}
