//! Fallback plugin console for non-shipped / unknown plugin ids.
//!
//! DevGuard / TraceTramp / WitnessCtl use dedicated light consoles at
//! `/plugins/{devguard|tracetramp|witnessctl}`.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use serde_json::Value;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::cards::{OpCard, OpCardAccent};
use crate::components::operator::primitives::{OpGrid, OpText, OpTextVariant};
use crate::ui_state::use_developer_view;

#[component]
pub fn PluginConsoleCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let params = use_params_map();
    let (dev, _) = use_developer_view();

    let plugin_id = Memo::new(move |_| {
        params
            .with(|p| p.get("id").map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".into())
    });

    // Shipped institutions have dedicated light consoles — bounce there.
    Effect::new(move |_| {
        let id = plugin_id.get();
        let dest = match id.as_str() {
            "tracetramp" | "tt" => Some("/plugins/tracetramp"),
            "witnessctl" | "wc" => Some("/plugins/witnessctl"),
            "devguard" | "dg" => Some("/plugins/devguard"),
            _ => None,
        };
        if let Some(href) = dest {
            if let Some(w) = web_sys::window() {
                let _ = w.location().set_href(href);
            }
        }
    });

    let status = LocalResource::new(move || {
        let id = plugin_id.get();
        async move { api::get_value("/plugins/status").await.map(|v| (id, v)) }
    });

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10">
            <div class="mx-auto w-full max-w-3xl space-y-4">
                <OpText text="Plugin console".to_string() variant=OpTextVariant::Title />
                <p class="font-mono text-xs text-zinc-400">
                    {move || format!("plugin: {}", plugin_id.get())}
                </p>
                <Suspense fallback=move || view! { <OpLoadingBlock /> }>
                    {move || Suspend::new(async move {
                        match status.await {
                            Ok((id, v)) => {
                                let info = plugin_info(&id, &v);
                                let raw = serde_json::to_string_pretty(&info).unwrap_or_default();
                                let name = display_name(&id);
                                let subtitle = info
                                    .get("status_badge")
                                    .or_else(|| info.get("status"))
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                let accent = if info.get("enabled_in_deployment").and_then(|x| x.as_bool()) == Some(true) {
                                    OpCardAccent::Running
                                } else {
                                    OpCardAccent::Attention
                                };
                                view! {
                                    <OpGrid>
                                        <OpCard title=name subtitle=subtitle accent=accent>
                                            <dl class="w-full space-y-1 text-xs">
                                                <div class="flex justify-between gap-2">
                                                    <dt class="text-zinc-500">"enabled"</dt>
                                                    <dd class="font-mono">{bool_str(&info, "enabled_in_deployment")}</dd>
                                                </div>
                                                <div class="flex justify-between gap-2">
                                                    <dt class="text-zinc-500">"lifecycle"</dt>
                                                    <dd class="font-mono">{str_field(&info, "lifecycle")}</dd>
                                                </div>
                                            </dl>
                                        </OpCard>
                                        <OpCard title="Actions".to_string() subtitle="Hub links".to_string() accent=OpCardAccent::Idle>
                                            <div class="flex flex-col gap-2 text-xs">
                                                <A href="/setup" attr:class="text-indigo-400 hover:underline">"SETUP"</A>
                                                <p class="text-[10px] text-zinc-600">
                                                    "Shipped institutions (DevGuard / TraceTramp / WitnessCtl) use dedicated light consoles."
                                                </p>
                                            </div>
                                        </OpCard>
                                    </OpGrid>
                                    <Show when=move || dev.get()>
                                        <OpDevDisclosure label="Plugin status JSON".to_string() raw=raw.clone() />
                                    </Show>
                                }.into_any()
                            }
                            Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                        }
                    })}
                </Suspense>
            </div>
        </div>
    }
}

fn display_name(id: &str) -> String {
    match id {
        "tracetramp" | "tt" => "TraceTramp".into(),
        "witnessctl" | "wc" => "WitnessCtl".into(),
        "devguard" | "dg" => "DevGuard".into(),
        other => other.to_string(),
    }
}

fn plugin_info(id: &str, status: &Value) -> Value {
    status
        .pointer(&format!("/plugins/{id}"))
        .cloned()
        .or_else(|| status.get(id).cloned())
        .unwrap_or(Value::Null)
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("—").to_string()
}

fn bool_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_bool())
        .map(|b| b.to_string())
        .unwrap_or_else(|| "—".into())
}
