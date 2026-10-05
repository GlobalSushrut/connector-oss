use leptos::prelude::*;
use serde_json::Value;

#[component]
pub fn SurfaceEvidence(#[prop(into)] package: Value) -> impl IntoView {
    let evidence = package
        .get("evidence")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if evidence.is_empty() {
        return view! {
            <div class="card">
                <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Evidence"</p>
                <p class="text-sm text-zinc-400 mt-2">"No evidence attached to this surface."</p>
            </div>
        }.into_any();
    }

    view! {
        <div class="card">
            <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Evidence"</p>
            <div class="mt-3 space-y-2 text-xs">
                {evidence.into_iter().map(|item| {
                    let kind = item.get("kind").and_then(|v| v.as_str()).unwrap_or("evidence").to_string();
                    let label = item.get("label").and_then(|v| v.as_str()).unwrap_or("item").to_string();
                    let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("—").to_string();
                    let verified = item.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
                    view! {
                        <div class="flex items-center justify-between rounded-lg border border-zinc-800/50 bg-zinc-900/40 px-3 py-2">
                            <div>
                                <p class="text-zinc-300 font-medium">{label}</p>
                                <p class="text-zinc-500 font-mono text-[10px]">{id}</p>
                            </div>
                            <span class=format!("badge {}", if verified { "badge-green" } else { "badge-zinc" })>{kind}</span>
                        </div>
                    }
                }).collect::<Vec<_>>()} 
            </div>
        </div>
    }.into_any()
}
