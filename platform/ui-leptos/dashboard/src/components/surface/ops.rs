use leptos::prelude::*;
use serde_json::Value;

use crate::utils::{time_ago_str, truncate};

#[component]
pub fn SurfaceOps(#[prop(into)] package: Value) -> impl IntoView {
    let ops = package
        .get("data")
        .and_then(|data| data.get("operations"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if ops.is_empty() {
        return view! {
            <div class="card">
                <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Operations"</p>
                <p class="text-sm text-zinc-400 mt-2">"No recent operations in this package."</p>
            </div>
        }.into_any();
    }

    view! {
        <div class="card overflow-hidden">
            <div class="flex items-center justify-between mb-2">
                <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Operations"</p>
                <span class="text-[10px] text-zinc-500">{format!("{} events", ops.len())}</span>
            </div>
            <div class="space-y-2 max-h-64 overflow-y-auto">
                {ops.into_iter().map(|op| {
                    let label = op.get("label").or_else(|| op.get("operation")).and_then(|v| v.as_str()).unwrap_or("op").to_string();
                    let status = op.get("status").and_then(|v| v.as_str()).unwrap_or("ok").to_string();
                    let target = op.get("target").and_then(|v| v.as_str()).unwrap_or("subject").to_string();
                    let ts = op.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    view! {
                        <div class="rounded-lg border border-zinc-800/50 bg-zinc-900/40 px-3 py-2 text-sm">
                            <div class="flex items-center justify-between gap-3">
                                <p class="text-zinc-200 font-medium">{truncate(&label, 48)}</p>
                                <span class=format!("badge {}", match status.as_str() {
                                    "ok" | "completed" => "badge-green",
                                    "degraded" | "pending" => "badge-amber",
                                    "failed" | "error" => "badge-red",
                                    _ => "badge-zinc",
                                })>{status.clone()}</span>
                            </div>
                            <p class="text-xs text-zinc-500 mt-1">{truncate(&target, 64)}</p>
                            <p class="text-[10px] text-zinc-600 mt-1">{if ts.is_empty() { "".to_string() } else { time_ago_str(&ts) }}</p>
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </div>
        </div>
    }.into_any()
}
