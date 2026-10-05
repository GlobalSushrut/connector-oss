use leptos::prelude::*;
use serde_json::Value;

use crate::utils::truncate;

#[component]
pub fn SurfaceExec(#[prop(into)] package: Value) -> impl IntoView {
    let data = package.get("data").cloned().unwrap_or(Value::Null);
    let render = package.get("render").cloned().unwrap_or(Value::Null);
    let mode = package.get("presentation").and_then(|v| v.get("mode")).and_then(|v| v.as_str()).unwrap_or("detail").to_string();
    let source = package.get("meta").and_then(|v| v.get("source")).and_then(|v| v.as_str()).unwrap_or("surface").to_string();
    let payload_shape = if data.is_array() {
        "array".to_string()
    } else if data.is_object() {
        "object".to_string()
    } else {
        "scalar".to_string()
    };
    let redacted = render.get("redacted").and_then(|v| v.as_bool()).unwrap_or(false);
    let item_count = data.as_object().map(|o| o.len()).unwrap_or_else(|| data.as_array().map(|a| a.len()).unwrap_or(0));

    view! {
        <div class="card">
            <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Execution"</p>
            <div class="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                <div class="rounded-lg border border-zinc-800/50 bg-zinc-900/40 px-3 py-2">
                    <p class="text-zinc-500 text-xs uppercase tracking-wider">"Mode"</p>
                    <p class="mt-1 text-zinc-100 font-medium">{mode}</p>
                </div>
                <div class="rounded-lg border border-zinc-800/50 bg-zinc-900/40 px-3 py-2">
                    <p class="text-zinc-500 text-xs uppercase tracking-wider">"Source"</p>
                    <p class="mt-1 text-zinc-100 font-medium">{truncate(&source, 48)}</p>
                </div>
                <div class="rounded-lg border border-zinc-800/50 bg-zinc-900/40 px-3 py-2">
                    <p class="text-zinc-500 text-xs uppercase tracking-wider">"Payload Shape"</p>
                    <p class="mt-1 text-zinc-100 font-medium">{payload_shape}</p>
                </div>
                <div class="rounded-lg border border-zinc-800/50 bg-zinc-900/40 px-3 py-2">
                    <p class="text-zinc-500 text-xs uppercase tracking-wider">"Items"</p>
                    <p class="mt-1 text-zinc-100 font-medium">{item_count}</p>
                </div>
            </div>
            <div class="mt-3 flex items-center gap-2">
                <span class=format!("badge {}", if redacted { "badge-amber" } else { "badge-green" })>{if redacted { "Redacted" } else { "Visible" }}</span>
                <span class="text-xs text-zinc-500">"Renderer-safe package metadata"</span>
            </div>
        </div>
    }
}
