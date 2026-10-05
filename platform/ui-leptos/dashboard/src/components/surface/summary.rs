use leptos::prelude::*;
use serde_json::Value;

use crate::utils::truncate;

#[component]
pub fn SurfaceSummary(#[prop(into)] package: Value) -> impl IntoView {
    let summary = package
        .get("summary")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "title": "Surface", "message": "No summary in this package" }));
    let title = summary.get("title").and_then(|v| v.as_str()).unwrap_or("Surface").to_string();
    let message = summary.get("message").and_then(|v| v.as_str()).unwrap_or("No message").to_string();
    let status = summary.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let why = summary.get("why").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let why_text = why.clone();

    view! {
        <div class="card surface-card">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Summary"</p>
                    <h2 class="text-lg font-semibold text-zinc-50 mt-1">{title}</h2>
                </div>
                <span class=format!("badge {}",
                    match status.as_str() {
                        "completed" | "ok" => "badge-green",
                        "failed" | "error" => "badge-red",
                        "degraded" => "badge-amber",
                        _ => "badge-zinc",
                    }
                )>{status.clone()}</span>
            </div>
            <p class="text-sm text-zinc-300 mt-3">{message}</p>
            <Show when=move || !why.is_empty()>
                <p class="text-xs text-zinc-500 mt-2">{truncate(&why_text, 160)}</p>
            </Show>
        </div>
    }
}
