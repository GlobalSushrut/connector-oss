use leptos::prelude::*;
use serde_json::Value;

use crate::utils::truncate;

#[component]
pub fn SurfaceIdentity(#[prop(into)] package: Value) -> impl IntoView {
    let subject = package
        .get("intent")
        .and_then(|intent| intent.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("subject")
        .to_string();
    let actor = package
        .get("intent")
        .and_then(|intent| intent.get("actor"))
        .and_then(|v| v.as_str())
        .unwrap_or("system")
        .to_string();
    let role = package
        .get("render")
        .and_then(|render| render.get("role"))
        .and_then(|v| v.as_str())
        .unwrap_or("operator")
        .to_string();
    let namespace = package
        .get("meta")
        .and_then(|meta| meta.get("namespace"))
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();

    view! {
        <div class="card">
            <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Identity"</p>
            <div class="mt-3 space-y-2 text-sm text-zinc-300">
                <div class="flex items-center justify-between">
                    <span class="text-zinc-500">"Subject"</span>
                    <span class="font-mono text-xs text-zinc-100">{truncate(&subject, 48)}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-zinc-500">"Actor"</span>
                    <span class="font-mono text-xs text-zinc-100">{truncate(&actor, 48)}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-zinc-500">"Role"</span>
                    <span class="badge badge-zinc">{role}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-zinc-500">"Namespace"</span>
                    <span class="font-mono text-xs text-zinc-100">{namespace}</span>
                </div>
            </div>
        </div>
    }
}
