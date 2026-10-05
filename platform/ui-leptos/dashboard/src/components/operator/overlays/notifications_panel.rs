//! Full notifications drawer — list, scan, acknowledge.

use leptos::prelude::*;
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpLoadingBlock};
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpText, OpTextVariant};
use crate::request_store::bump_reload;
use crate::ui_state::{open_topic_drawer, DrawerTopic};

#[component]
pub fn OpNotificationsPanel() -> impl IntoView {
    let (tick, set_tick) = signal(0u32);
    let (busy, set_busy) = signal(String::new());
    let (err, set_err) = signal(Option::<String>::None);
    let resource = LocalResource::new(move || {
        let _ = tick.get();
        async move { api::get_value("/notifications").await }
    });

    view! {
        <div class="space-y-4 p-4">
            <div class="flex items-start justify-between gap-2">
                <div>
                    <OpText text="Notifications".to_string() variant=OpTextVariant::Title />
                    <p class="mt-1 text-xs text-zinc-500">"Alerts for certs, trust, budgets, and anomalies."</p>
                </div>
                <OpButton
                    label="Scan now".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        spawn_local(async move {
                            let _ = api::post_value("/notifications/scan", json!({})).await;
                            set_tick.update(|n| *n += 1);
                            bump_reload();
                        });
                    })
                />
            </div>

            <Show when=move || err.get().is_some()>
                <p class="rounded-md border border-amber-900/50 bg-amber-950/40 px-3 py-2 text-xs text-amber-200">
                    {move || err.get().unwrap_or_default()}
                </p>
            </Show>

            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading notifications…".to_string() /> }>
                {move || Suspend::new(async move {
                    match resource.await {
                        Ok(v) => {
                            let pending = v.get("pending").and_then(|x| x.as_u64()).unwrap_or(0);
                            let critical = v.get("critical").and_then(|x| x.as_u64()).unwrap_or(0);
                            let total = v.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
                            let items = v
                                .get("notifications")
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            view! {
                                <p class="text-[10px] text-zinc-600">{format!("{total} total · {pending} pending · {critical} critical")}</p>
                                {if items.is_empty() {
                                    view! {
                                        <p class="py-8 text-center text-xs text-zinc-600">"Inbox empty. Run Scan to emit due reminders."</p>
                                    }.into_any()
                                } else {
                                    view! {
                                        <ul class="divide-y divide-zinc-800/50 rounded-lg border border-zinc-800/60">
                                            {items.into_iter().map(|n| {
                                                let id = n.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                                let title = n.get("title").and_then(|x| x.as_str()).unwrap_or("Notification").to_string();
                                                let message = n.get("message").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                                let severity = n.get("severity").and_then(|x| x.as_str()).unwrap_or("INFO").to_string();
                                                let status = n.get("status").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                                let pid = n.get("subject_pid").and_then(|x| x.as_str()).map(|s| s.to_string());
                                                let pending = matches!(
                                                    status.to_ascii_uppercase().as_str(),
                                                    "PENDING" | "DELIVERED" | "SNOOZED"
                                                );
                                                let id_busy = id.clone();
                                                let id_ack = id.clone();
                                                let id_nonempty = !id.is_empty();
                                                let sev_class = match severity.to_ascii_uppercase().as_str() {
                                                    "CRITICAL" | "PAGED" => "text-red-400",
                                                    "WARNING" | "HIGH" => "text-amber-400",
                                                    _ => "text-zinc-400",
                                                };
                                                let show_ack = pending && id_nonempty;
                                                let related_pid = pid.clone();
                                                view! {
                                                    <li class="px-3 py-3">
                                                        <div class="flex items-start justify-between gap-2">
                                                            <div class="min-w-0 flex-1">
                                                                <div class="flex flex-wrap items-center gap-2">
                                                                    <span class=format!("text-[10px] font-semibold uppercase {sev_class}")>{severity}</span>
                                                                    <span class="text-[10px] text-zinc-600">{status}</span>
                                                                </div>
                                                                <p class="mt-1 text-sm font-medium text-zinc-100">{title}</p>
                                                                <p class="mt-0.5 text-xs text-zinc-500">{message}</p>
                                                                {related_pid.map(|agent_pid| {
                                                                    view! {
                                                                        <button
                                                                            type="button"
                                                                            class="mt-1 text-[10px] text-indigo-400 hover:text-indigo-300"
                                                                            on:click=move |_| open_topic_drawer(DrawerTopic::Agent(agent_pid.clone()))
                                                                        >"Open related agent"</button>
                                                                    }
                                                                })}
                                                            </div>
                                                            <Show when=move || show_ack>
                                                                <button
                                                                    type="button"
                                                                    class="shrink-0 text-[11px] text-indigo-400 hover:text-indigo-300 disabled:opacity-40"
                                                                    disabled={
                                                                        let id_busy = id_busy.clone();
                                                                        move || busy.get() == id_busy
                                                                    }
                                                                    on:click={
                                                                        let id_ack = id_ack.clone();
                                                                        move |_| {
                                                                            let id_ack = id_ack.clone();
                                                                            set_busy.set(id_ack.clone());
                                                                            set_err.set(None);
                                                                            spawn_local(async move {
                                                                                match api::patch_value(
                                                                                    &format!("/notifications/{id_ack}/acknowledge"),
                                                                                    json!({"action": "acknowledge"}),
                                                                                ).await {
                                                                                    Ok(_) => {
                                                                                        set_tick.update(|n| *n += 1);
                                                                                        bump_reload();
                                                                                    }
                                                                                    Err(e) => set_err.set(Some(e.message)),
                                                                                }
                                                                                set_busy.set(String::new());
                                                                            });
                                                                        }
                                                                    }
                                                                >"Acknowledge"</button>
                                                            </Show>
                                                        </div>
                                                    </li>
                                                }
                                            }).collect_view()}
                                        </ul>
                                    }.into_any()
                                }}
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}
