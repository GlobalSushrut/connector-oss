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
pub fn TrialSessions(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh) = create_signal(0u32);

    let status = LocalResource::new(move || {
        let _ = refresh.get();
        async move { fetch_pg("/api/v1/playground/status").await }
    });

    let sessions = LocalResource::new(move || {
        let _ = refresh.get();
        async move { fetch_pg("/api/v1/playground/sessions").await }
    });

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-violet-400">"Playground"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Trial Sessions & Emails"</h1>
                    <p class="text-sm text-zinc-500">"Live sessions on try.cnktros.com — every trial email, session status, and plugin usage."</p>
                </div>
                <button on:click=move |_| set_refresh.update(|v| *v += 1)
                    class="rounded-lg bg-violet-500/10 border border-violet-500/20 px-4 py-2 text-sm font-medium text-violet-300 hover:bg-violet-500/20 transition-colors">
                    "Refresh"
                </button>
            </div>

            // KPI cards
            <Suspense fallback=|| view! { <div class="grid grid-cols-4 gap-4">{(0..4).map(|_| view!{<div class="card h-24 animate-pulse" />}).collect::<Vec<_>>()}</div> }>
                {move || Suspend::new(async move {
                    let sv = status.await;
                    let s = sv.as_ref().ok().cloned().unwrap_or(Value::Null);
                    let dv = sessions.await;
                    let d = dv.as_ref().ok().cloned().unwrap_or(Value::Null);

                    let active      = s["active_sessions"].as_u64().unwrap_or(0);
                    let max         = s["max_sessions"].as_u64().unwrap_or(0);
                    let available   = s["available"].as_bool().unwrap_or(false);
                    let pg_enabled  = s["playground"].as_bool().unwrap_or(false);
                    let total       = d["total_sessions"].as_u64().unwrap_or(0);
                    let unique_em   = d["unique_emails"].as_u64().unwrap_or(0);

                    view! {
                        <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Status"</p>
                                <p class="mt-2 text-2xl font-semibold" class:text-emerald-300=pg_enabled class:text-red-300=!pg_enabled>
                                    {if pg_enabled { "Live" } else { "Offline" }}
                                </p>
                            </div>
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Active / Max"</p>
                                <p class="mt-2 text-2xl font-semibold text-zinc-50">{format!("{} / {}", active, max)}</p>
                                <p class="mt-1 text-xs" class:text-emerald-400=available class:text-red-400=!available>
                                    {if available { "Accepting trials" } else { "At capacity" }}
                                </p>
                            </div>
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Total Sessions"</p>
                                <p class="mt-2 text-2xl font-semibold text-zinc-50">{total.to_string()}</p>
                            </div>
                            <div class="card">
                                <p class="text-xs uppercase tracking-wider text-zinc-500">"Unique Emails"</p>
                                <p class="mt-2 text-2xl font-semibold text-violet-300">{unique_em.to_string()}</p>
                            </div>
                        </div>
                    }
                })}
            </Suspense>

            // Session table with emails
            <div class="card overflow-hidden">
                <div class="px-5 py-4 border-b border-zinc-800">
                    <h2 class="text-base font-semibold text-zinc-50">"All Trial Sessions"</h2>
                    <p class="text-xs text-zinc-500 mt-0.5">"Email, status, usage, and timing for every trial. Newest first."</p>
                </div>
                <Suspense fallback=|| view! { <div class="p-6 text-sm text-zinc-500">"Loading sessions…"</div> }>
                    {move || Suspend::new(async move {
                        let dv = sessions.await;
                        let d = dv.as_ref().ok().cloned().unwrap_or(Value::Null);
                        let list = d["sessions"].as_array().cloned().unwrap_or_default();

                        if list.is_empty() {
                            return view! {
                                <div class="p-8 text-center text-sm text-zinc-500">
                                    "No trial sessions yet. Share "
                                    <a href="https://try.cnktros.com/trial" target="_blank" class="text-violet-400 underline">"try.cnktros.com/trial"</a>
                                    " to collect emails."
                                </div>
                            }.into_any();
                        }

                        view! {
                            <div class="overflow-x-auto">
                                <table class="w-full text-sm">
                                    <thead>
                                        <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                            <th class="px-5 py-3">"Email"</th>
                                            <th class="px-3 py-3">"Status"</th>
                                            <th class="px-3 py-3">"Agents"</th>
                                            <th class="px-3 py-3">"Tokens"</th>
                                            <th class="px-3 py-3">"Created"</th>
                                            <th class="px-3 py-3">"Last Active"</th>
                                            <th class="px-3 py-3">"Session ID"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {list.into_iter().map(|s| {
                                            let email = s["email"].as_str().unwrap_or("(anonymous)").to_string();
                                            let active = s["active"].as_bool().unwrap_or(false);
                                            let ended = s["ended"].as_bool().unwrap_or(false);
                                            let agents = s["agents_created"].as_u64().unwrap_or(0);
                                            let tokens = s["tokens_used"].as_u64().unwrap_or(0);
                                            let created = s["created_at"].as_str().unwrap_or("-").to_string();
                                            let last_active = s["last_active"].as_str().unwrap_or("-").to_string();
                                            let sid = s["session_id"].as_str().unwrap_or("-").to_string();
                                            let created_short = created.get(..16).unwrap_or(&created).to_string();
                                            let la_short = last_active.get(..16).unwrap_or(&last_active).to_string();
                                            let sid_short = sid.get(..12).unwrap_or(&sid).to_string();

                                            let status_class = if active { "text-emerald-400" } else if ended { "text-red-400" } else { "text-zinc-500" };
                                            let status_text = if active { "Active" } else if ended { "Ended" } else { "Expired" };

                                            view! {
                                                <tr class="border-b border-zinc-800/50 hover:bg-zinc-900/50">
                                                    <td class="px-5 py-3 font-medium text-zinc-100">{email}</td>
                                                    <td class="px-3 py-3"><span class={status_class}>{status_text}</span></td>
                                                    <td class="px-3 py-3 text-zinc-400">{agents.to_string()}</td>
                                                    <td class="px-3 py-3 text-zinc-400">{format!("{}k", tokens / 1000)}</td>
                                                    <td class="px-3 py-3 text-zinc-500 text-xs">{created_short}</td>
                                                    <td class="px-3 py-3 text-zinc-500 text-xs">{la_short}</td>
                                                    <td class="px-3 py-3 text-zinc-600 font-mono text-xs">{format!("{}…", sid_short)}</td>
                                                </tr>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </tbody>
                                </table>
                            </div>
                        }.into_any()
                    })}
                </Suspense>
            </div>

            // Quick links
            <div class="grid gap-3 sm:grid-cols-3">
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Trial page"</p>
                    <a href="https://try.cnktros.com/trial" target="_blank" class="mt-1 text-sm text-violet-400 hover:text-violet-300 underline">"try.cnktros.com/trial"</a>
                </div>
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Playground health"</p>
                    <a href="https://try.cnktros.com/health" target="_blank" class="mt-1 text-sm text-violet-400 hover:text-violet-300 underline">"try.cnktros.com/health"</a>
                </div>
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                    <p class="text-xs uppercase tracking-wider text-zinc-500">"Marketing site"</p>
                    <a href="https://cnktros.com" target="_blank" class="mt-1 text-sm text-violet-400 hover:text-violet-300 underline">"cnktros.com (Try Me)"</a>
                </div>
            </div>
        </div>
    }
}
