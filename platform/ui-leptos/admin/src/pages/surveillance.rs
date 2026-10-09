use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Surveillance(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh) = create_signal(0u32);
    let (flash, set_flash) = create_signal(Option::<(String, bool)>::None);
    let (show_events, set_show_events) = create_signal(false);

    let dashboard = LocalResource::new(move || { let _ = refresh.get(); api::get_value("/surveillance/dashboard") });
    let instances = LocalResource::new(move || { let _ = refresh.get(); api::get_value("/surveillance/instances") });
    let events    = LocalResource::new(move || { let _ = refresh.get(); api::get_value("/surveillance/events") });

    let do_action = move |path: String, label: &'static str| {
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
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Fleet control"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Node Surveillance"</h1>
                    <p class="text-sm text-zinc-500">"Phone-home telemetry from all activated Connector OS nodes. Kill, degrade, or block individual instances."</p>
                </div>
                <div class="flex gap-2">
                    <button on:click=move |_| set_show_events.update(|v| *v = !*v)
                        class="rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-700 transition-colors">
                        {move || if show_events.get() { "Hide events" } else { "Event log" }}
                    </button>
                    <button on:click=move |_| set_refresh.update(|v| *v += 1)
                        class="rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-700 transition-colors">
                        "Refresh"
                    </button>
                </div>
            </div>

            {move || flash.get().map(|(msg, ok)| view! {
                <div class=if ok { "rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300" }
                          else  { "rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300" }>
                    {msg}
                </div>
            })}

            <Suspense fallback=|| view! { <div class="grid gap-4 grid-cols-4"><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/></div> }>
                {move || Suspend::new(async move {
                    let value = dashboard.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let total_instances  = v["total_instances"].as_u64().unwrap_or(0);
                    let active_24h       = v["active_last_24h"].as_u64().unwrap_or(0);
                    let total_customers  = v["total_customers"].as_u64().unwrap_or(0);
                    let killed           = v["killed_instances"].as_u64().unwrap_or(0);
                    view! {
                        <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Total nodes"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{total_instances}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Active (24h)"</p><p class="mt-2 text-2xl font-semibold text-emerald-300">{active_24h}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Customers"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{total_customers}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Killed"</p><p class="mt-2 text-2xl font-semibold text-red-300">{killed}</p></div>
                        </div>
                    }
                })}
            </Suspense>

            <Suspense fallback=|| view! { <div class="card h-96 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = instances.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let rows = v["instances"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <div class="mb-4">
                                <h2 class="text-lg font-semibold text-zinc-50">"Active nodes"</h2>
                                <p class="mt-1 text-sm text-zinc-500">{format!("{} instances tracked", rows.len())}</p>
                            </div>
                            <table class="min-w-full text-sm">
                                <thead>
                                    <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                        <th class="px-3 py-3">"Node"</th>
                                        <th class="px-3 py-3">"Customer"</th>
                                        <th class="px-3 py-3">"Version"</th>
                                        <th class="px-3 py-3">"Last heartbeat"</th>
                                        <th class="px-3 py-3">"Status"</th>
                                        <th class="px-3 py-3">"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows.into_iter().map(|row| {
                                        let iid      = row["instance_id"].as_str().unwrap_or("-").to_string();
                                        let hostname = row["hostname"].as_str().unwrap_or("—").to_string();
                                        let customer = row["customer_email"].as_str().unwrap_or("—").to_string();
                                        let version  = row["version"].as_str().unwrap_or("—").to_string();
                                        let hb       = row["last_heartbeat"].as_str().unwrap_or("Never").to_string();
                                        let status   = row["status"].as_str().unwrap_or("unknown").to_string();
                                        let kill_id  = iid.clone();
                                        let degrade_id = iid.clone();
                                        let status_class = format!("inline-flex rounded-full px-2 py-0.5 text-xs font-medium {}",
                                            match status.as_str() {
                                                "active" | "ok" => "bg-emerald-500/10 text-emerald-300",
                                                "killed" => "bg-red-500/10 text-red-300",
                                                "degraded" => "bg-amber-500/10 text-amber-300",
                                                _ => "bg-zinc-700 text-zinc-300",
                                            });
                                        view! {
                                            <tr class="border-b border-zinc-900/80 align-top text-zinc-300">
                                                <td class="px-3 py-4">
                                                    <p class="font-medium text-zinc-100">{hostname}</p>
                                                    <p class="text-[11px] font-mono text-zinc-600">{iid}</p>
                                                </td>
                                                <td class="px-3 py-4 text-xs text-zinc-400">{customer}</td>
                                                <td class="px-3 py-4 text-xs font-mono text-zinc-500">{version}</td>
                                                <td class="px-3 py-4 text-xs text-zinc-500">{hb}</td>
                                                <td class="px-3 py-4">
                                                    <span class=status_class>{status}</span>
                                                </td>
                                                <td class="px-3 py-4">
                                                    <div class="flex gap-2 flex-wrap">
                                                        <button on:click=move |_| do_action(format!("/surveillance/degrade"), "Degraded")
                                                            class="rounded border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-xs text-amber-300 hover:bg-amber-500/20 transition-colors">
                                                            "Degrade"
                                                        </button>
                                                        <button on:click=move |_| do_action(format!("/surveillance/kill"), "Killed")
                                                            class="rounded border border-red-500/20 bg-red-500/10 px-2 py-1 text-xs text-red-300 hover:bg-red-500/20 transition-colors">
                                                            "Kill"
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

            {move || show_events.get().then(|| view! {
                <Suspense fallback=|| view! { <div class="card h-64 animate-pulse" /> }>
                    {move || Suspend::new(async move {
                        let value = events.await;
                        let v = value.as_ref().ok().unwrap_or(&Value::Null);
                        let evts = v["events"].as_array().cloned().unwrap_or_default();
                        view! {
                            <div class="card overflow-x-auto">
                                <h2 class="text-lg font-semibold text-zinc-50 mb-4">"Event log"</h2>
                                {if evts.is_empty() {
                                    view!{ <p class="text-sm text-zinc-600 py-6 text-center">"No events recorded yet."</p> }.into_any()
                                } else {
                                    view! {
                                        <table class="min-w-full text-sm">
                                            <thead>
                                                <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                                    <th class="px-3 py-3">"Time"</th>
                                                    <th class="px-3 py-3">"Event"</th>
                                                    <th class="px-3 py-3">"Instance"</th>
                                                    <th class="px-3 py-3">"Detail"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {evts.into_iter().map(|e| {
                                                    let t  = e["timestamp"].as_str().unwrap_or("—").to_string();
                                                    let ev = e["event"].as_str().unwrap_or("—").to_string();
                                                    let id = e["instance_id"].as_str().unwrap_or("—").to_string();
                                                    let detail = e["detail"].as_str().unwrap_or("").to_string();
                                                    view! {
                                                        <tr class="border-b border-zinc-900/80 text-zinc-400 text-xs">
                                                            <td class="px-3 py-2 font-mono text-zinc-600">{t}</td>
                                                            <td class="px-3 py-2 font-medium text-zinc-200">{ev}</td>
                                                            <td class="px-3 py-2 font-mono text-zinc-500">{id}</td>
                                                            <td class="px-3 py-2 text-zinc-500">{detail}</td>
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
            })}
        </div>
    }
}
