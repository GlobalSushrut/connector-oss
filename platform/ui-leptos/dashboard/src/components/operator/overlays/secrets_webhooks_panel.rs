//! Secrets + Webhooks drawers with real create/test/store actions.

use leptos::prelude::*;
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpLoadingBlock};
use crate::components::operator::overlays::result_sheet::OpResultSheet;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpText, OpTextVariant, OpTextField,
};
use crate::request_store::bump_reload;

#[component]
pub fn OpSecretsPanel() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (name, set_name) = signal(String::from("operator-secret"));
    let (value, set_value) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());

    let audit = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/secrets/audit").await }
    });
    let vault = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/infra/vault/status").await }
    });

    view! {
        <div class="space-y-4 p-4">
            <OpText text="Secrets".to_string() variant=OpTextVariant::Title />
            <p class="text-xs text-zinc-500">"Store via POST /secrets/store · audit via GET /secrets/audit. Values are never shown."</p>

            <div class="space-y-2 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                <OpTextField label="Secret ID".to_string() value=name set_value=set_name placeholder="api-key-name" />
                <OpTextField label="Value".to_string() value=value set_value=set_value placeholder="••••••••" password=true />
                <OpButton
                    label="Store secret".to_string()
                    variant=OpButtonVariant::Primary
                    loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let n = name.get_untracked();
                        let val = value.get_untracked();
                        if n.trim().is_empty() || val.is_empty() {
                            set_result_title.set("Validation".into());
                            set_result_summary.set("Secret ID and value are required.".into());
                            set_result_open.set(true);
                            return;
                        }
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value(
                                "/secrets/store",
                                json!({
                                    "secret_id": n,
                                    "agent_pid": "operator-ui",
                                    "value": val,
                                    "description": "Stored from operator SETUP secrets drawer"
                                }),
                            )
                            .await
                            {
                                Ok(v) => {
                                    set_value.set(String::new());
                                    set_result_title.set("Secret stored".into());
                                    set_result_summary.set(format!(
                                        "POST /secrets/store\n{}",
                                        serde_json::to_string_pretty(&v).unwrap_or_default()
                                    ));
                                    set_result_open.set(true);
                                    set_reload.update(|x| *x = x.wrapping_add(1));
                                    bump_reload();
                                }
                                Err(e) => {
                                    set_result_title.set("Store failed".into());
                                    set_result_summary.set(format!("POST /secrets/store\n{}", e.message));
                                    set_result_open.set(true);
                                }
                            }
                            set_busy.set(false);
                        });
                    })
                />
            </div>

            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading vault…".to_string() /> }>
                {move || Suspend::new(async move {
                    let vault_res = vault.await;
                    let audit_res = audit.await;
                    view! {
                        <div class="space-y-3">
                            {match vault_res {
                                Ok(v) => view! {
                                    <dl class="space-y-1.5 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs">
                                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"vault"</dt><dd class="font-mono text-zinc-200">"/infra/vault/status"</dd></div>
                                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"ok"</dt><dd class="font-mono text-zinc-200">{v.get("ok").map(|x| x.to_string()).unwrap_or_else(|| "—".into())}</dd></div>
                                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"status"</dt><dd class="font-mono text-zinc-200">{v.get("status").and_then(|x| x.as_str()).unwrap_or("—").to_string()}</dd></div>
                                    </dl>
                                }.into_any(),
                                Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                            }}
                            {match audit_res {
                                Ok(v) => {
                                    let count = v
                                        .get("audit_count")
                                        .and_then(|x| x.as_u64())
                                        .map(|n| n.to_string())
                                        .unwrap_or_else(|| "unavailable".into());
                                    let entries = v.get("entries").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                                    view! {
                                        <div class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                                            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Audit"</p>
                                            <p class="mt-1 font-mono text-xs text-zinc-300">{format!("count={count} · GET /secrets/audit")}</p>
                                            <div class="mt-2 max-h-48 space-y-1 overflow-auto">
                                                {if entries.is_empty() {
                                                    view! { <p class="text-xs text-zinc-600">"No audit entries yet."</p> }.into_any()
                                                } else {
                                                    entries.into_iter().take(20).map(|e| {
                                                        let line = e.get("action").or_else(|| e.get("event")).and_then(|x| x.as_str()).unwrap_or("event");
                                                        let when = e.get("at").or_else(|| e.get("timestamp")).and_then(|x| x.as_str()).unwrap_or("—");
                                                        let verdict = e.get("verdict").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                                        let verdict_class = if verdict == "denied" {
                                                            "shrink-0 text-rose-300"
                                                        } else {
                                                            "shrink-0 text-emerald-300/80"
                                                        };
                                                        view! {
                                                            <div class="flex justify-between gap-2 border-b border-zinc-800/40 py-1 text-[11px]">
                                                                <span class="truncate font-mono text-zinc-300">{line.to_string()}</span>
                                                                <span class=verdict_class>{verdict}</span>
                                                                <span class="shrink-0 text-zinc-600">{when.to_string()}</span>
                                                            </div>
                                                        }
                                                    }).collect_view().into_any()
                                                }}
                                            </div>
                                        </div>
                                    }.into_any()
                                }
                                Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                            }}
                        </div>
                    }.into_any()
                })}
            </Suspense>

            <OpResultSheet
                open=result_open
                set_open=set_result_open
                title=result_title
                summary=result_summary
            />
        </div>
    }
}

#[component]
pub fn OpWebhooksPanel() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (name, set_name) = signal(String::from("operator-hook"));
    let (url, set_url) = signal(String::from("https://example.com/hooks/connector"));
    let (busy, set_busy) = signal(false);
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());

    let list = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/webhooks").await }
    });

    view! {
        <div class="space-y-4 p-4">
            <OpText text="Webhooks".to_string() variant=OpTextVariant::Title />
            <p class="text-xs text-zinc-500">"Register via POST /webhooks · test via POST /webhooks/:id/test."</p>

            <div class="space-y-2 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                <OpTextField label="Name".to_string() value=name set_value=set_name placeholder="ops-alerts" />
                <OpTextField label="URL".to_string() value=url set_value=set_url placeholder="https://…" />
                <OpButton
                    label="Register webhook".to_string()
                    variant=OpButtonVariant::Primary
                    loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let n = name.get_untracked();
                        let u = url.get_untracked();
                        if u.trim().is_empty() {
                            set_result_title.set("Validation".into());
                            set_result_summary.set("URL is required.".into());
                            set_result_open.set(true);
                            return;
                        }
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value(
                                "/webhooks",
                                json!({
                                    "name": n,
                                    "url": u,
                                    "events": ["workflow.lifecycle", "agent.denied"]
                                }),
                            )
                            .await
                            {
                                Ok(v) => {
                                    if v.get("error").is_some() || v.get("status").and_then(|x| x.as_u64()) == Some(401) {
                                        set_result_title.set("Register failed".into());
                                        set_result_summary.set(format!(
                                            "POST /webhooks\n{}",
                                            serde_json::to_string_pretty(&v).unwrap_or_default()
                                        ));
                                    } else {
                                        set_result_title.set("Webhook registered".into());
                                        set_result_summary.set(format!(
                                            "POST /webhooks\n{}",
                                            serde_json::to_string_pretty(&v).unwrap_or_default()
                                        ));
                                        set_reload.update(|x| *x = x.wrapping_add(1));
                                        bump_reload();
                                    }
                                    set_result_open.set(true);
                                }
                                Err(e) => {
                                    set_result_title.set("Register failed".into());
                                    set_result_summary.set(format!("POST /webhooks\n{}", e.message));
                                    set_result_open.set(true);
                                }
                            }
                            set_busy.set(false);
                        });
                    })
                />
            </div>

            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading webhooks…".to_string() /> }>
                {move || Suspend::new(async move {
                    match list.await {
                        Ok(v) => {
                            if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
                                return view! {
                                    <div class="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-100">
                                        <p class="font-semibold">"GET /webhooks"</p>
                                        <p class="mt-1 font-mono">{err.to_string()}</p>
                                        <p class="mt-2 text-amber-200/80">"Operator auth required — use Skip Auth / operator token."</p>
                                    </div>
                                }.into_any();
                            }
                            let hooks = v
                                .get("webhooks")
                                .or_else(|| v.get("items"))
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            view! {
                                <div class="space-y-2">
                                    <p class="font-mono text-[10px] text-zinc-600">{format!("{} webhook(s)", hooks.len())}</p>
                                    {if hooks.is_empty() {
                                        view! { <p class="text-xs text-zinc-600">"No webhooks registered."</p> }.into_any()
                                    } else {
                                        hooks.into_iter().map(|h| {
                                            let id = h.get("webhook_id").or_else(|| h.get("id")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            let name = h.get("name").and_then(|x| x.as_str()).unwrap_or(&id).to_string();
                                            let url = h.get("url").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let enabled = h.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
                                            let id_test = id.clone();
                                            let id_del = id.clone();
                                            view! {
                                                <div class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                                                    <div class="flex items-start justify-between gap-2">
                                                        <div class="min-w-0">
                                                            <p class="truncate text-sm text-zinc-100">{name}</p>
                                                            <p class="truncate font-mono text-[10px] text-zinc-500">{url}</p>
                                                            <p class="mt-1 font-mono text-[10px] text-zinc-600">{format!("{id} · {}", if enabled { "enabled" } else { "disabled" })}</p>
                                                        </div>
                                                        <div class="flex shrink-0 flex-col gap-1">
                                                            <OpButton
                                                                label="Test".to_string()
                                                                variant=OpButtonVariant::Secondary
                                                                on_click=Arc::new(move |_| {
                                                                    let id = id_test.clone();
                                                                    set_busy.set(true);
                                                                    spawn_local(async move {
                                                                        match api::post_value(&format!("/webhooks/{id}/test"), json!({})).await {
                                                                            Ok(v) => {
                                                                                set_result_title.set(format!("Test {id}"));
                                                                                set_result_summary.set(format!(
                                                                                    "POST /webhooks/{id}/test\n{}",
                                                                                    serde_json::to_string_pretty(&v).unwrap_or_default()
                                                                                ));
                                                                                set_result_open.set(true);
                                                                            }
                                                                            Err(e) => {
                                                                                set_result_title.set("Test failed".into());
                                                                                set_result_summary.set(format!("POST /webhooks/{id}/test\n{}", e.message));
                                                                                set_result_open.set(true);
                                                                            }
                                                                        }
                                                                        set_busy.set(false);
                                                                    });
                                                                })
                                                            />
                                                            <OpButton
                                                                label="Delete".to_string()
                                                                variant=OpButtonVariant::Ghost
                                                                on_click=Arc::new(move |_| {
                                                                    let id = id_del.clone();
                                                                    set_busy.set(true);
                                                                    spawn_local(async move {
                                                                        match api::delete_value(&format!("/webhooks/{id}")).await {
                                                                            Ok(v) => {
                                                                                set_result_title.set("Deleted".into());
                                                                                set_result_summary.set(format!(
                                                                                    "DELETE /webhooks/{id}\n{}",
                                                                                    serde_json::to_string_pretty(&v).unwrap_or_default()
                                                                                ));
                                                                                set_result_open.set(true);
                                                                                set_reload.update(|x| *x = x.wrapping_add(1));
                                                                                bump_reload();
                                                                            }
                                                                            Err(e) => {
                                                                                set_result_title.set("Delete failed".into());
                                                                                set_result_summary.set(format!(
                                                                                    "DELETE /webhooks/{id}\n{}",
                                                                                    e.message
                                                                                ));
                                                                                set_result_open.set(true);
                                                                            }
                                                                        }
                                                                        set_busy.set(false);
                                                                    });
                                                                })
                                                            />
                                                        </div>
                                                    </div>
                                                </div>
                                            }
                                        }).collect_view().into_any()
                                    }}
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>

            <OpResultSheet
                open=result_open
                set_open=set_result_open
                title=result_title
                summary=result_summary
            />
        </div>
    }
}
