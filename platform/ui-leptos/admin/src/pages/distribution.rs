use leptos::prelude::*;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

const PORTAL_URL: &str = "https://portal.cnktros.com";

async fn fetch_portal(path: &str) -> Result<Value, String> {
    let resp = gloo_net::http::Request::get(&format!("{PORTAL_URL}{path}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    resp.json::<Value>().await.map_err(|e| e.to_string())
}

#[component]
pub fn Distribution(auth: ReadSignal<AuthState>) -> impl IntoView {
    let releases = LocalResource::new(|| async move { fetch_portal("/api/v1/distribution/releases").await });

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-orange-400">"Distribution"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Software Distribution"</h1>
                    <p class="text-sm text-zinc-500">"Release management, download links, and distribution channels for Connector OS."</p>
                </div>
            </div>

            // Current release info
            <div class="card">
                <h2 class="text-lg font-semibold text-zinc-50">"Active release"</h2>
                <div class="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                        <p class="text-xs uppercase tracking-wider text-zinc-500">"Version"</p>
                        <p class="mt-1 text-xl font-bold text-zinc-50">"v0.1.0"</p>
                    </div>
                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                        <p class="text-xs uppercase tracking-wider text-zinc-500">"Platform"</p>
                        <p class="mt-1 text-sm text-zinc-200">"linux-amd64"</p>
                    </div>
                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                        <p class="text-xs uppercase tracking-wider text-zinc-500">"GitHub release"</p>
                        <a href="https://github.com/GlobalSushrut/connector-private/releases/tag/v0.1.0" target="_blank"
                            class="mt-1 text-sm text-orange-400 hover:text-orange-300 underline">"v0.1.0"</a>
                    </div>
                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                        <p class="text-xs uppercase tracking-wider text-zinc-500">"Install method"</p>
                        <p class="mt-1 text-sm text-zinc-200">"curl one-liner + tarball"</p>
                    </div>
                </div>
            </div>

            // Distribution channels
            <div class="card">
                <h2 class="text-lg font-semibold text-zinc-50">"Distribution channels"</h2>
                <div class="mt-4 space-y-3">
                    <div class="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                        <div>
                            <p class="text-sm font-medium text-zinc-200">"Portal download page"</p>
                            <p class="text-xs text-zinc-500">"Customer-facing download with platform selector and install guide"</p>
                        </div>
                        <a href="https://portal.cnktros.com/download" target="_blank"
                            class="rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:text-zinc-100">"Open →"</a>
                    </div>
                    <div class="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                        <div>
                            <p class="text-sm font-medium text-zinc-200">"GitHub Releases"</p>
                            <p class="text-xs text-zinc-500">"Tarballs + SHA256 checksums uploaded via package.sh"</p>
                        </div>
                        <a href="https://github.com/GlobalSushrut/connector-private/releases" target="_blank"
                            class="rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:text-zinc-100">"Releases →"</a>
                    </div>
                    <div class="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3">
                        <div>
                            <p class="text-sm font-medium text-zinc-200">"Marketing site"</p>
                            <p class="text-xs text-zinc-500">"cnktros.com — Try Me button → playground trial"</p>
                        </div>
                        <a href="https://cnktros.com" target="_blank"
                            class="rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:text-zinc-100">"Visit →"</a>
                    </div>
                </div>
            </div>

            // Release process
            <div class="card">
                <h2 class="text-lg font-semibold text-zinc-50">"Release process"</h2>
                <p class="mt-2 text-sm text-zinc-400">"Steps to cut a new release:"</p>
                <ol class="mt-3 space-y-2 text-sm text-zinc-300 list-decimal list-inside">
                    <li><code class="text-xs bg-zinc-800 px-1 py-0.5 rounded font-mono">"cd platform/release && bash package.sh VERSION"</code></li>
                    <li><code class="text-xs bg-zinc-800 px-1 py-0.5 rounded font-mono">"gh release create vVERSION dist/*.tar.gz dist/*.sha256"</code></li>
                    <li>"Update version strings in router.rs distribution_download_link + distribution_releases"</li>
                    <li>"Deploy portal: flyctl deploy --config platform/deploy/fly.portal.toml"</li>
                </ol>
            </div>

            // Releases table from API
            <Suspense fallback=|| view! { <div class="card h-40 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let val = releases.await;
                    let v = val.as_ref().ok().cloned().unwrap_or(Value::Null);
                    let rows = v["releases"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <h2 class="text-lg font-semibold text-zinc-50 mb-4">"Release history"</h2>
                            {if rows.is_empty() {
                                view! { <p class="text-sm text-zinc-500 py-4 text-center">"No release data from API — check portal endpoint."</p> }.into_any()
                            } else {
                                view! {
                                    <table class="min-w-full text-sm">
                                        <thead>
                                            <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                                <th class="px-3 py-3">"Version"</th>
                                                <th class="px-3 py-3">"Date"</th>
                                                <th class="px-3 py-3">"Platform"</th>
                                                <th class="px-3 py-3">"Status"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {rows.into_iter().map(|r| {
                                                let ver  = r["version"].as_str().unwrap_or("—").to_string();
                                                let date = r["date"].as_str().unwrap_or("—").to_string();
                                                let plat = r["platform"].as_str().unwrap_or("linux-amd64").to_string();
                                                let cur  = r["current"].as_bool().unwrap_or(false);
                                                view! {
                                                    <tr class="border-b border-zinc-900/80 text-zinc-300">
                                                        <td class="px-3 py-3 font-mono text-zinc-200">{ver}</td>
                                                        <td class="px-3 py-3 text-zinc-400">{date}</td>
                                                        <td class="px-3 py-3 text-zinc-400">{plat}</td>
                                                        <td class="px-3 py-3">
                                                            {if cur { view! {
                                                                <span class="rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 text-xs font-medium text-emerald-300">"Current"</span>
                                                            }.into_any() } else { view! {
                                                                <span class="text-xs text-zinc-500">"Archive"</span>
                                                            }.into_any() }}
                                                        </td>
                                                    </tr>
                                                }
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
