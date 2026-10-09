use leptos::prelude::*;
use serde_json::Value;
use crate::auth::AuthState;

const PLAYGROUND_URL: &str = "https://try.cnktros.com";

async fn fetch_pg(path: &str) -> Result<Value, String> {
    let resp = gloo_net::http::Request::get(&format!("{PLAYGROUND_URL}{path}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json::<Value>().await.map_err(|e| e.to_string())
}

#[component]
pub fn PluginHealth(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh) = create_signal(0u32);

    let tt_status = LocalResource::new(move || {
        let _ = refresh.get();
        async move { fetch_pg("/api/v1/plugins/tracetramp/status").await }
    });
    let wc_health = LocalResource::new(move || {
        let _ = refresh.get();
        async move { fetch_pg("/health").await }
    });

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-cyan-400">"Infrastructure"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Plugin Health"</h1>
                    <p class="text-sm text-zinc-500">"Status of TraceTramp, WitnessCtl, and DevGuard plugins running on the playground node."</p>
                </div>
                <button on:click=move |_| set_refresh.update(|v| *v += 1)
                    class="rounded-lg bg-cyan-500/10 border border-cyan-500/20 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 transition-colors">
                    "Refresh"
                </button>
            </div>

            <div class="grid gap-4 lg:grid-cols-3">
                // TraceTramp card
                <Suspense fallback=|| view! { <div class="card h-52 animate-pulse" /> }>
                    {move || Suspend::new(async move {
                        let val = tt_status.await;
                        let v = val.as_ref().ok().cloned().unwrap_or(Value::Null);
                        let ok = v["ok"].as_bool().unwrap_or(false);
                        let mgmt_url = v["management_url_explicit"].as_bool().unwrap_or(false);
                        let reachable = v["upstream_reachable"].as_bool();
                        let default_base = v["default_base"].as_str().unwrap_or("—").to_string();
                        view! {
                            <div class="card">
                                <div class="flex items-center gap-2 mb-3">
                                    <div class="h-3 w-3 rounded-full" class:bg-emerald-400=ok class:bg-red-400=!ok></div>
                                    <h2 class="text-lg font-semibold text-zinc-50">"TraceTramp"</h2>
                                </div>
                                <div class="space-y-2 text-sm">
                                    <div class="flex justify-between">
                                        <span class="text-zinc-500">"Configured"</span>
                                        <span class:text-emerald-300=ok class:text-red-300=!ok>{if ok {"Yes"} else {"No"}}</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-zinc-500">"Mgmt URL explicit"</span>
                                        <span class="text-zinc-300">{if mgmt_url {"Yes"} else {"Default"}}</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-zinc-500">"Upstream reachable"</span>
                                        <span class:text-emerald-300=reachable.unwrap_or(false) class:text-zinc-500=reachable.is_none()>
                                            {match reachable { Some(true) => "Yes", Some(false) => "No", None => "N/A" }}
                                        </span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-zinc-500">"Default base"</span>
                                        <span class="text-xs font-mono text-zinc-400">{default_base}</span>
                                    </div>
                                </div>
                                <p class="mt-3 text-xs text-zinc-600">"Data plane: :9741 · Management: :9742"</p>
                            </div>
                        }
                    })}
                </Suspense>

                // WitnessCtl card
                <div class="card">
                    <div class="flex items-center gap-2 mb-3">
                        <div class="h-3 w-3 rounded-full bg-amber-400"></div>
                        <h2 class="text-lg font-semibold text-zinc-50">"WitnessCtl"</h2>
                    </div>
                    <div class="space-y-2 text-sm">
                        <div class="flex justify-between">
                            <span class="text-zinc-500">"Port"</span>
                            <span class="text-zinc-300">":7443"</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-zinc-500">"Database"</span>
                            <span class="text-zinc-300">"PostgreSQL (connector-pg)"</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-zinc-500">"HMAC auth"</span>
                            <span class="text-emerald-300">"Configured"</span>
                        </div>
                    </div>
                    <p class="mt-3 text-xs text-zinc-600">"Attestation + audit plugin for AI agent actions"</p>
                </div>

                // DevGuard card
                <div class="card">
                    <div class="flex items-center gap-2 mb-3">
                        <div class="h-3 w-3 rounded-full bg-emerald-400"></div>
                        <h2 class="text-lg font-semibold text-zinc-50">"DevGuard"</h2>
                    </div>
                    <div class="space-y-2 text-sm">
                        <div class="flex justify-between">
                            <span class="text-zinc-500">"Mode"</span>
                            <span class="text-zinc-300">"Embedded in platform"</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-zinc-500">"Policy engine"</span>
                            <span class="text-emerald-300">"Active"</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-zinc-500">"Guard rails"</span>
                            <span class="text-zinc-300">"Code review + safety"</span>
                        </div>
                    </div>
                    <p class="mt-3 text-xs text-zinc-600">"AI coding agent guardrails — runs as part of connector-platform"</p>
                </div>
            </div>

            // Platform health
            <Suspense fallback=|| view! { <div class="card h-20 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let val = wc_health.await;
                    let v = val.as_ref().ok().cloned().unwrap_or(Value::Null);
                    let status = v["status"].as_str().unwrap_or(v["service"].as_str().unwrap_or("—")).to_string();
                    let version = v["version"].as_str().unwrap_or("—").to_string();
                    let license = v["license"].as_str().unwrap_or("—").to_string();
                    let agents = v["agents"].as_str().unwrap_or("—").to_string();
                    view! {
                        <div class="card">
                            <h2 class="text-lg font-semibold text-zinc-50">"Playground node health"</h2>
                            <div class="mt-3 grid gap-3 sm:grid-cols-4">
                                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Service"</p>
                                    <p class="mt-1 text-sm text-zinc-200">{status}</p>
                                </div>
                                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Version"</p>
                                    <p class="mt-1 text-sm text-zinc-200">{version}</p>
                                </div>
                                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"License"</p>
                                    <p class="mt-1 text-sm text-zinc-200">{license}</p>
                                </div>
                                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Agents"</p>
                                    <p class="mt-1 text-sm text-zinc-200">{agents}</p>
                                </div>
                            </div>
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}
