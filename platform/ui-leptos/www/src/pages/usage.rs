use leptos::prelude::*;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;
use crate::components::layout::NavBar;

#[component]
pub fn Usage(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let me = LocalResource::new(|| api::get_value("/me"));
    let entitlement = LocalResource::new(|| api::get_value("/entitlement"));
    let pilot = LocalResource::new(|| api::get_value("/pilot"));

    view! {
        <div class="min-h-screen bg-zinc-50">
            <NavBar auth=auth set_auth=set_auth />
            <div class="mx-auto max-w-6xl px-4 py-8 space-y-6">
                <div>
                    <h1 class="text-2xl font-semibold text-zinc-950">"Usage & entitlement"</h1>
                    <p class="mt-1 text-sm text-zinc-600">"Your hosted account usage posture, current tier, and pilot-based capacity."</p>
                </div>

                <div class="grid gap-4 md:grid-cols-4">
                    <Suspense fallback=|| view! { <div class="card h-28 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let me_value = me.await;
                            let v = me_value.as_ref().ok().unwrap_or(&Value::Null);
                            let billing_state = v["billing_state"].as_str().unwrap_or("Unknown").to_string();
                            let api_keys = v["api_key_count"].as_u64().unwrap_or(0);
                            let verified = v["email_verified"].as_bool().unwrap_or(false);
                            view! {
                                <>
                                    <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Billing state"</p><p class="mt-2 text-2xl font-semibold text-zinc-950">{billing_state}</p></div>
                                    <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"API keys"</p><p class="mt-2 text-2xl font-semibold text-zinc-950">{api_keys}</p></div>
                                    <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Email verification"</p><p class="mt-2 text-2xl font-semibold text-zinc-950">{if verified { "Verified" } else { "Pending" }}</p></div>
                                </>
                            }
                        })}
                    </Suspense>

                    <Suspense fallback=|| view! { <div class="card h-28 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let entitlement_value = entitlement.await;
                            let v = entitlement_value.as_ref().ok().unwrap_or(&Value::Null);
                            let ent = &v["entitlement"];
                            let effective_tier = ent["effective_tier"].as_str().unwrap_or("Indie").to_string();
                            let agent_limit = ent["agent_limit"].as_u64().unwrap_or(0);
                            view! {
                                <div class="card">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Effective tier"</p>
                                    <p class="mt-2 text-2xl font-semibold text-zinc-950">{effective_tier}</p>
                                    <p class="mt-1 text-sm text-zinc-500">{format!("{} agents available", agent_limit)}</p>
                                </div>
                            }
                        })}
                    </Suspense>
                </div>

                <div class="grid gap-4 lg:grid-cols-2">
                    <Suspense fallback=|| view! { <div class="card h-64 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let entitlement_value = entitlement.await;
                            let v = entitlement_value.as_ref().ok().unwrap_or(&Value::Null);
                            let ent = &v["entitlement"];
                            let base_tier = ent["base_tier"].as_str().unwrap_or("Community").to_string();
                            let effective_tier = ent["effective_tier"].as_str().unwrap_or("Community").to_string();
                            let agent_limit = ent["agent_limit"].as_u64().unwrap_or(0);
                            let max_events = ent["event_limit"].as_u64().unwrap_or(0);
                            let retention_days = ent["retention_days"].as_u64().unwrap_or(0);
                            view! {
                                <div class="card">
                                    <h2 class="text-lg font-semibold text-zinc-950">"Plan capacity"</h2>
                                    <div class="mt-5 grid gap-4 sm:grid-cols-2">
                                        <div class="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Base tier"</p>
                                            <p class="mt-2 text-lg font-semibold text-zinc-950">{base_tier}</p>
                                        </div>
                                        <div class="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Effective tier"</p>
                                            <p class="mt-2 text-lg font-semibold text-zinc-950">{effective_tier}</p>
                                        </div>
                                        <div class="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Agent limit"</p>
                                            <p class="mt-2 text-lg font-semibold text-zinc-950">{agent_limit}</p>
                                        </div>
                                        <div class="rounded-xl border border-zinc-200 bg-zinc-50 p-4">
                                            <p class="text-xs uppercase tracking-wider text-zinc-500">"Retention"</p>
                                            <p class="mt-2 text-lg font-semibold text-zinc-950">{format!("{} days", retention_days)}</p>
                                        </div>
                                    </div>
                                    <p class="mt-4 text-sm text-zinc-500">{format!("Event capacity: {}", max_events)}</p>
                                </div>
                            }
                        })}
                    </Suspense>

                    <Suspense fallback=|| view! { <div class="card h-64 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let pilot_value = pilot.await;
                            let v = pilot_value.as_ref().ok().unwrap_or(&Value::Null);
                            let has_pilot = v["has_active_pilot"].as_bool().unwrap_or(false);
                            let pilot_obj = &v["pilot"];
                            let name = pilot_obj["name"].as_str().unwrap_or("No active pilot").to_string();
                            let reason = pilot_obj["reason"].as_str().unwrap_or("You are currently operating on your base tier.").to_string();
                            let expires_at = pilot_obj["expires_at"].as_str().unwrap_or("—").to_string();
                            view! {
                                <div class="card">
                                    <h2 class="text-lg font-semibold text-zinc-950">"Pilot grant"</h2>
                                    <p class="mt-1 text-sm text-zinc-500">"Temporary capacity and feature lift granted by the control plane."</p>
                                    <div class="mt-5 rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                                        <div class="flex items-center justify-between gap-3">
                                            <p class="text-sm font-medium text-zinc-950">{name}</p>
                                            <span class=if has_pilot { "badge-green" } else { "badge-zinc" }>{if has_pilot { "Active" } else { "Inactive" }}</span>
                                        </div>
                                        <p class="mt-3 text-sm text-zinc-600">{reason}</p>
                                        <p class="mt-3 text-xs text-zinc-500">{format!("Expires: {}", expires_at)}</p>
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
