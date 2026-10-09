use leptos::prelude::*;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Instances(auth: ReadSignal<AuthState>) -> impl IntoView {
    let instances = LocalResource::new(|| api::get_value("/admin/instances"));

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Fleet activity"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Instances"</h1>
                    <p class="text-sm text-zinc-500">"Active and historical activations currently tracked by the licensing control plane."</p>
                </div>
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-xs text-zinc-500">
                    {move || format!("Admin key: {}", auth.get().key_hint)}
                </div>
            </div>

            <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = instances.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let rows = v["instances"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <div class="mb-4 flex items-center justify-between gap-4">
                                <div>
                                    <h2 class="text-lg font-semibold text-zinc-50">"Instance registry"</h2>
                                    <p class="mt-1 text-sm text-zinc-500">{format!("{} tracked activations", rows.len())}</p>
                                </div>
                            </div>
                            <table class="min-w-full text-sm">
                                <thead>
                                    <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                        <th class="px-3 py-3">"Instance"</th>
                                        <th class="px-3 py-3">"Key"</th>
                                        <th class="px-3 py-3">"Machine"</th>
                                        <th class="px-3 py-3">"Heartbeat"</th>
                                        <th class="px-3 py-3">"Status"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows.into_iter().map(|row| {
                                        let instance_id = row["instance_id"].as_str().unwrap_or("-").to_string();
                                        let key_id = row["key_id"].as_str().unwrap_or("-").to_string();
                                        let machine_id = row["machine_id"].as_str().unwrap_or("-").to_string();
                                        let hostname = row["hostname"].as_str().unwrap_or("—").to_string();
                                        let activated_at = row["activated_at"].as_str().unwrap_or("—").to_string();
                                        let heartbeat = row["last_heartbeat"].as_str().unwrap_or("—").to_string();
                                        let active = row["active"].as_bool().unwrap_or(false);
                                        view! {
                                            <tr class="border-b border-zinc-900/80 align-top text-zinc-300">
                                                <td class="px-3 py-4">
                                                    <p class="font-medium text-zinc-100">{hostname}</p>
                                                    <p class="mt-1 text-[11px] font-mono text-zinc-500">{instance_id}</p>
                                                    <p class="mt-1 text-xs text-zinc-600">{format!("Activated: {}", activated_at)}</p>
                                                </td>
                                                <td class="px-3 py-4 text-xs font-mono text-zinc-500">{key_id}</td>
                                                <td class="px-3 py-4 text-xs font-mono text-zinc-500 break-all">{machine_id}</td>
                                                <td class="px-3 py-4 text-xs text-zinc-500">{heartbeat}</td>
                                                <td class="px-3 py-4">
                                                    <span class=if active { "inline-flex rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300" } else { "inline-flex rounded-full bg-zinc-700 px-2 py-0.5 text-xs font-medium text-zinc-300" }>
                                                        {if active { "Active" } else { "Inactive" }}
                                                    </span>
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
