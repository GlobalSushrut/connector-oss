use leptos::prelude::*;
use serde_json::Value;
use std::sync::Arc;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::cards::{OpCard, OpCardAccent};
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpGrid, OpText, OpTextVariant,
};
use crate::ui_state::use_developer_view;

#[component]
pub fn AdvancedDevCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let (dev, set_dev) = use_developer_view();
    let (topic, set_topic) = signal("tools".to_string());

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10">
            <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
                <div>
                    <OpText text="Advanced / Dev".to_string() variant=OpTextVariant::Title />
                    <p class="mt-1 text-sm text-zinc-500">"Developer hub — raw JSON and invoke panels stay gated."</p>
                </div>
                <OpButton
                    label=if dev.get() { "Developer view: ON".to_string() } else { "Developer view: OFF".to_string() }
                    variant=if dev.get() { OpButtonVariant::Primary } else { OpButtonVariant::Secondary }
                    on_click=Arc::new(move |_| set_dev.update(|v| *v = !*v))
                />
            </div>

            <div class="mb-4 flex flex-wrap gap-2">
                {["tools", "protocols", "service-map", "infra", "runtime", "debug", "notebook"].into_iter().map(|id| {
                    view! {
                        <button
                            type="button"
                            class=move || if topic.get() == id {
                                "rounded-lg bg-zinc-800 px-3 py-1.5 text-xs text-zinc-100"
                            } else {
                                "rounded-lg px-3 py-1.5 text-xs text-zinc-500 hover:text-zinc-300"
                            }
                            on:click=move |_| set_topic.set(id.to_string())
                        >{id}</button>
                    }
                }).collect_view()}
            </div>

            <OpGrid>
                <OpCard title="Component gallery".to_string() subtitle="All Op* primitives".to_string() accent=OpCardAccent::Running>
                    <a href="/dev/components" class="text-xs text-indigo-400 hover:underline">"/dev/components"</a>
                </OpCard>
                <OpCard title="Plugins".to_string() subtitle="TT · WC · DG".to_string() accent=OpCardAccent::Idle>
                    <div class="flex flex-col gap-1 text-xs">
                        <a href="/plugins/tracetramp" class="text-indigo-400 hover:underline">"TraceTramp"</a>
                        <a href="/plugins/witnessctl" class="text-indigo-400 hover:underline">"WitnessCtl"</a>
                        <a href="/plugins/devguard" class="text-indigo-400 hover:underline">"DevGuard"</a>
                    </div>
                </OpCard>
            </OpGrid>

            <div class="mt-6 rounded-xl border border-zinc-800/60 bg-zinc-900/20 p-4">
                <h3 class="mb-3 text-sm font-medium text-zinc-200">{move || format!("Topic · {}", topic.get())}</h3>
                <DevTopicPanel topic=topic developer=dev />
            </div>
        </div>
    }
}

#[component]
fn DevTopicPanel(topic: ReadSignal<String>, developer: ReadSignal<bool>) -> impl IntoView {
    let resource = LocalResource::new(move || {
        let t = topic.get();
        async move {
            // Paths must exist on connector-platform (GET). Bare `/tools` 404s.
            let path = match t.as_str() {
                "protocols" => "/cnp/overview",
                "service-map" => "/plugins/service-map",
                "infra" => "/infra/orchestrator",
                "runtime" => "/runtime/mode",
                "debug" => "/debug/sessions",
                "notebook" => "/notebook/kernel",
                _ => "/monitor/tools",
            };
            api::get_value(path).await
        }
    });

    view! {
        <Suspense fallback=move || view! { <OpLoadingBlock /> }>
            {move || Suspend::new(async move {
                match resource.await {
                    Ok(v) => {
                        let summary = summarize(&v);
                        let mtls_note = v
                            .pointer("/data/mtls/honesty")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let peer_tls = v
                            .pointer("/data/mtls/peer_tls")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let raw = serde_json::to_string_pretty(&v).unwrap_or_default();
                        view! {
                            {if !mtls_note.is_empty() || !peer_tls.is_empty() {
                                view! {
                                    <p class="mb-2 text-[11px] text-amber-200/90">
                                        {format!(
                                            "CNP mTLS peer_tls={} — {}",
                                            if peer_tls.is_empty() { "—" } else { &peer_tls },
                                            if mtls_note.is_empty() {
                                                "fail-closed without lab stub"
                                            } else {
                                                &mtls_note
                                            }
                                        )}
                                    </p>
                                }.into_any()
                            } else {
                                ().into_any()
                            }}
                            <dl class="mb-3 space-y-1 text-xs">
                                {summary.into_iter().map(|(k, val)| {
                                    view! {
                                        <div class="flex justify-between gap-2">
                                            <dt class="text-zinc-500">{k}</dt>
                                            <dd class="font-mono text-zinc-300">{val}</dd>
                                        </div>
                                    }
                                }).collect_view()}
                            </dl>
                            <Show when=move || developer.get()>
                                <OpDevDisclosure label="Raw JSON".to_string() raw=raw.clone() />
                            </Show>
                            <Show when=move || !developer.get()>
                                <p class="text-[11px] text-zinc-600">"Enable Developer view to inspect raw responses and invoke forms."</p>
                            </Show>
                        }.into_any()
                    }
                    Err(e) => view! {
                        <OpApiErrorBanner error=e />
                        <p class="mt-2 text-[11px] text-zinc-600">"Unavailable endpoints render as errors — never as healthy green."</p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

fn summarize(v: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for key in ["ok", "status", "schema", "count", "mode", "version"] {
        if let Some(x) = v.get(key) {
            out.push((key.into(), match x {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            }));
        }
    }
    if let Some(name) = v.pointer("/data/name").and_then(|x| x.as_str()) {
        out.push(("protocol".into(), name.to_string()));
    }
    if let Some(tls) = v.pointer("/data/mtls/peer_tls").and_then(|x| x.as_str()) {
        out.push(("cnp_mtls".into(), tls.to_string()));
    }
    if let Some(auth) = v
        .pointer("/data/mtls/mutual_auth_product")
        .and_then(|x| x.as_bool())
    {
        out.push(("mutual_auth_product".into(), auth.to_string()));
    }
    if out.is_empty() {
        out.push(("keys".into(), v.as_object().map(|o| o.len().to_string()).unwrap_or_else(|| "—".into())));
    }
    out
}
