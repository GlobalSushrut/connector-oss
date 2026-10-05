use leptos::prelude::*;
use serde_json::Value;

use crate::utils::{trust_color, truncate};

#[component]
pub fn SurfaceTrust(#[prop(into)] package: Value) -> impl IntoView {
    let trust = package.get("trust").cloned().unwrap_or_else(|| serde_json::json!({}));
    let score = trust.get("score").and_then(|v| v.as_f64());
    let grade = trust.get("grade").and_then(|v| v.as_str()).unwrap_or("—").to_string();
    let verified = trust.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
    let message = package.get("summary").and_then(|s| s.get("message")).and_then(|v| v.as_str()).unwrap_or("No summary").to_string();
    // Unscored packages render neutral — never a red zero the backend never reported.
    let color = score.map(trust_color).unwrap_or("#71717a");
    let score_label = score
        .map(|s| format!("{s:.1}"))
        .unwrap_or_else(|| "—".to_string());
    let score_caption = if score.is_some() { "Score" } else { "Score unavailable" };

    view! {
        <div class="card">
            <p class="text-[11px] uppercase tracking-wider text-zinc-500">"Trust"</p>
            <div class="mt-3 flex items-center gap-4">
                <div>
                    <div class="text-4xl font-bold font-mono" style=format!("color:{}", color)>{score_label}</div>
                    <p class="text-xs text-zinc-500">{score_caption}</p>
                </div>
                <div class="flex-1">
                    <div class="flex items-center gap-2">
                        <span class="badge badge-zinc">{grade}</span>
                        <span class="badge">
                            {if verified { "Verified" } else { "Unverified" }}
                        </span>
                    </div>
                    <p class="text-xs text-zinc-400 mt-2">{truncate(&message, 120)}</p>
                </div>
            </div>
        </div>
    }
}
