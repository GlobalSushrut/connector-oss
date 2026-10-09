use leptos::prelude::*;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;
use crate::components::layout::NavBar;

#[component]
pub fn Dashboard(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let me = LocalResource::new(|| api::get_value("/me"));
    let keys = LocalResource::new(|| api::get_value("/api-keys"));
    let pilot = LocalResource::new(|| api::get_value("/pilot"));
    let entitlement = LocalResource::new(|| api::get_value("/entitlement"));

    view! {
        <div class="min-h-screen bg-zinc-50">
            <NavBar auth=auth set_auth=set_auth />
            <div class="mx-auto max-w-6xl px-4 py-8 space-y-6">
                <div class="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
                    <div>
                        <p class="text-xs font-medium uppercase tracking-wider text-indigo-600">"Customer workspace"</p>
                        <h1 class="mt-2 text-3xl font-semibold tracking-tight text-zinc-950">
                            {move || auth.get().user.map(|u| format!("Welcome back, {}", u.name)).unwrap_or("Connector Portal".into())}
                        </h1>
                        <p class="mt-1 text-sm text-zinc-600">"Manage your account, API keys, plan, and entitlement here. Use your local dashboard separately for live node operations."</p>
                    </div>
                    <div class="rounded-2xl border border-zinc-200 bg-white px-4 py-3 shadow-sm">
                        <p class="text-xs uppercase tracking-wider text-zinc-500">"Current plan"</p>
                        <p class="mt-1 text-lg font-semibold text-zinc-950">{move || auth.get().user.map(|u| u.plan).unwrap_or("Community".into())}</p>
                    </div>
                </div>

                <div class="grid gap-4 md:grid-cols-4">
                    <Suspense fallback=|| view! { <div class="card h-28 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let me_value = me.await;
                            let v = me_value.as_ref().ok().unwrap_or(&Value::Null);
                            let keys_count = v["api_key_count"].as_u64().unwrap_or(0);
                            let billing_state = v["billing_state"].as_str().unwrap_or("Unknown").to_string();
                            let backup_codes = v["backup_codes_remaining"].as_u64().unwrap_or(0);
                            view! {
                                <>
                                    <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Billing state"</p><p class="mt-2 text-2xl font-semibold text-zinc-950">{billing_state}</p></div>
                                    <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"API keys"</p><p class="mt-2 text-2xl font-semibold text-zinc-950">{keys_count}</p></div>
                                    <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"2FA backup codes"</p><p class="mt-2 text-2xl font-semibold text-zinc-950">{backup_codes}</p></div>
                                </>
                            }
                        })}
                    </Suspense>

                    <Suspense fallback=|| view! { <div class="card h-28 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let entitlement_value = entitlement.await;
                            let v = entitlement_value.as_ref().ok().unwrap_or(&Value::Null);
                            let ent = &v["entitlement"];
                            let tier = ent["effective_tier"].as_str().unwrap_or("Indie").to_string();
                            let agent_limit = ent["agent_limit"].as_u64().unwrap_or(0);
                            view! {
                                <div class="card">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Entitlement"</p>
                                    <p class="mt-2 text-2xl font-semibold text-zinc-950">{tier}</p>
                                    <p class="mt-1 text-sm text-zinc-500">{format!("{} agent slots", agent_limit)}</p>
                                </div>
                            }
                        })}
                    </Suspense>
                </div>

                <div class="grid gap-4 lg:grid-cols-3">
                    <Suspense fallback=|| view! { <div class="card h-72 animate-pulse lg:col-span-2" /> }>
                        {move || Suspend::new(async move {
                            let keys_value = keys.await;
                            let keys_json = keys_value.as_ref().ok().unwrap_or(&Value::Null);
                            let entries = keys_json["keys"].as_array().cloned().unwrap_or_default();
                            view! {
                                <div class="card lg:col-span-2">
                                    <div class="flex items-center justify-between">
                                        <div>
                                            <h2 class="text-lg font-semibold text-zinc-950">"Access keys"</h2>
                                            <p class="mt-1 text-sm text-zinc-500">"Create portal-managed keys here, then use them in your local dashboard."</p>
                                        </div>
                                        <a href="/app/api-keys" class="text-sm font-medium text-indigo-600 hover:text-indigo-500">"Manage keys"</a>
                                    </div>
                                    <div class="mt-5 space-y-3">
                                        {if entries.is_empty() {
                                            vec![view! { <div class="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 px-4 py-6 text-sm text-zinc-500">"No active keys yet. Create one from the API Keys page."</div> }.into_any()]
                                        } else {
                                            entries.into_iter().take(3).map(|entry| {
                                                let name = entry["name"].as_str().unwrap_or("API key").to_string();
                                                let key_id = entry["key_id"].as_str().unwrap_or("-").to_string();
                                                let expires = entry["expires_at"].as_str().unwrap_or("No expiry").to_string();
                                                view! {
                                                    <div class="rounded-xl border border-zinc-200 bg-zinc-50 px-4 py-3">
                                                        <div class="flex items-center justify-between gap-4">
                                                            <div>
                                                                <p class="text-sm font-medium text-zinc-950">{name}</p>
                                                                <p class="mt-1 text-xs font-mono text-zinc-500">{key_id}</p>
                                                            </div>
                                                            <span class="text-xs text-zinc-500">{expires}</span>
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

                    <Suspense fallback=|| view! { <div class="card h-72 animate-pulse" /> }>
                        {move || Suspend::new(async move {
                            let pilot_value = pilot.await;
                            let v = pilot_value.as_ref().ok().unwrap_or(&Value::Null);
                            let has_pilot = v["has_active_pilot"].as_bool().unwrap_or(false);
                            let pilot_name = v["pilot"]["name"].as_str().unwrap_or("No active pilot").to_string();
                            let pilot_reason = v["pilot"]["reason"].as_str().unwrap_or("Using your base entitlement").to_string();
                            view! {
                                <div class="card">
                                    <h2 class="text-lg font-semibold text-zinc-950">"Pilot status"</h2>
                                    <p class="mt-1 text-sm text-zinc-500">"Temporary grants and expanded capacity for current evaluation or rollout."</p>
                                    <div class="mt-5 rounded-2xl border border-zinc-200 bg-zinc-50 p-4">
                                        <p class="text-sm font-medium text-zinc-950">{pilot_name}</p>
                                        <p class="mt-2 text-sm text-zinc-600">{pilot_reason}</p>
                                        <span class=if has_pilot { "mt-3 inline-flex rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700" } else { "mt-3 inline-flex rounded-full bg-zinc-200 px-2 py-0.5 text-xs font-medium text-zinc-700" }>
                                            {if has_pilot { "Active pilot" } else { "Base tier only" }}
                                        </span>
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
