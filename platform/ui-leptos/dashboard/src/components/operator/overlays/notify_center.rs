use leptos::prelude::*;
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::OpApiErrorBanner;
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpScrollArea};
use crate::request_store::{bump_reload, use_shared_requests};
use crate::ui_state::{open_topic_drawer, DrawerTopic};

#[derive(Clone)]
struct NoteRow {
    id: String,
    title: String,
    body: String,
    severity: String,
    status: String,
    created: String,
    pending: bool,
}

#[component]
pub fn OpNotifyCenter(
    open: ReadSignal<bool>,
    set_open: WriteSignal<bool>,
) -> impl IntoView {
    let shared = use_shared_requests();
    let (busy_id, set_busy_id) = signal(String::new());
    let (action_err, set_action_err) = signal(Option::<String>::None);
    // Ignore outside-clicks for one frame so the bell click that opened us
    // cannot immediately dismiss the panel (classic popup race).
    let (armed, set_armed) = signal(false);

    Effect::new(move |_| {
        if open.get() {
            set_armed.set(false);
            spawn_local(async move {
                gloo_timers::future::TimeoutFuture::new(80).await;
                set_armed.set(true);
            });
        } else {
            set_armed.set(false);
        }
    });

    // Escape closes
    Effect::new(move |_| {
        if !open.get() {
            return;
        }
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;
        let cb = Closure::<dyn FnMut(_)>::new(move |ev: web_sys::KeyboardEvent| {
            if ev.key() == "Escape" {
                set_open.set(false);
            }
        });
        if let Some(w) = web_sys::window() {
            let _ = w.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
            cb.forget();
        }
    });

    view! {
        <Show when=move || open.get()>
            // Fixed layer — escapes shell overflow-hidden clipping
            <div class="fixed inset-0 z-[90]" role="presentation">
                <button
                    type="button"
                    class="absolute inset-0 cursor-default bg-transparent"
                    aria-label="Dismiss notifications"
                    on:click=move |_| {
                        if armed.get() {
                            set_open.set(false);
                        }
                    }
                ></button>
                <div
                    class="absolute right-3 top-12 w-[22rem] overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl sm:right-4"
                    role="dialog"
                    aria-label="Notifications"
                    on:click=move |ev| ev.stop_propagation()
                >
                    <div class="flex items-center justify-between border-b border-zinc-800/60 px-4 py-2">
                        <span class="text-sm font-medium text-zinc-200">"Notifications"</span>
                        <div class="flex items-center gap-2">
                            <button
                                type="button"
                                class="text-xs text-zinc-500 hover:text-zinc-300"
                                title="Scan for due alerts"
                                on:click=move |_| {
                                    spawn_local(async move {
                                        let _ = api::post_value("/notifications/scan", json!({})).await;
                                        bump_reload();
                                    });
                                }
                            >"Scan"</button>
                            <button
                                type="button"
                                class="text-xs text-indigo-400 hover:text-indigo-300"
                                on:click=move |_| {
                                    set_open.set(false);
                                    open_topic_drawer(DrawerTopic::Notifications);
                                }
                            >"Open all"</button>
                            <button
                                type="button"
                                class="text-xs text-zinc-500 hover:text-zinc-300"
                                on:click=move |_| set_open.set(false)
                            >"Close"</button>
                        </div>
                    </div>
                    <Show when=move || action_err.get().is_some()>
                        <p class="border-b border-amber-900/40 bg-amber-950/40 px-4 py-1.5 text-[11px] text-amber-300">
                            {move || action_err.get().unwrap_or_default()}
                        </p>
                    </Show>
                    <OpScrollArea class="max-h-80">
                        <Suspense fallback=move || view! {
                            <p class="px-4 py-6 text-center text-xs text-zinc-600">"Loading…"</p>
                        }>
                            {move || Suspend::new(async move {
                                match shared.notifications.await {
                                    Ok(notes) => {
                                        let items = parse_notes(&notes);
                                        let pending = notes.get("pending").and_then(|x| x.as_u64()).unwrap_or(0);
                                        let critical = notes.get("critical").and_then(|x| x.as_u64()).unwrap_or(0);
                                        if items.is_empty() {
                                            view! {
                                                <div class="px-4 py-6 text-center">
                                                    <p class="text-xs text-zinc-500">"No notifications yet."</p>
                                                    <p class="mt-1 text-[10px] text-zinc-600">"Use Scan to check certs, trust, and budget alerts."</p>
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <div class="border-b border-zinc-800/40 px-4 py-1.5 text-[10px] text-zinc-600">
                                                    {format!("{pending} pending · {critical} critical")}
                                                </div>
                                                <ul>
                                                    {items.into_iter().map(|row| {
                                                        let id_for_busy = row.id.clone();
                                                        let id_ack = row.id.clone();
                                                        let sev = severity_class(&row.severity);
                                                        let pending = row.pending;
                                                        view! {
                                                            <li class="border-b border-zinc-800/40 px-4 py-3">
                                                                <div class="flex items-start justify-between gap-2">
                                                                    <div class="min-w-0 flex-1">
                                                                        <div class="flex items-center gap-2">
                                                                            <span class=format!("rounded px-1 py-0.5 text-[9px] font-semibold uppercase {sev}")>
                                                                                {row.severity.clone()}
                                                                            </span>
                                                                            <span class="truncate text-[10px] text-zinc-600">{row.status.clone()}</span>
                                                                        </div>
                                                                        <p class="mt-1 text-xs font-medium text-zinc-200">{row.title.clone()}</p>
                                                                        <p class="mt-0.5 line-clamp-2 text-[11px] text-zinc-500">{row.body.clone()}</p>
                                                                        <p class="mt-1 text-[10px] text-zinc-700">{row.created.clone()}</p>
                                                                    </div>
                                                                    <Show when=move || pending>
                                                                        <button
                                                                            type="button"
                                                                            class="shrink-0 text-[10px] text-indigo-400 hover:text-indigo-300 disabled:opacity-40"
                                                                            disabled={
                                                                                let id_for_busy = id_for_busy.clone();
                                                                                move || busy_id.get() == id_for_busy
                                                                            }
                                                                            on:click={
                                                                                let id_ack = id_ack.clone();
                                                                                move |_| {
                                                                                    let id_ack = id_ack.clone();
                                                                                    set_busy_id.set(id_ack.clone());
                                                                                    set_action_err.set(None);
                                                                                    spawn_local(async move {
                                                                                        match api::patch_value(
                                                                                            &format!("/notifications/{id_ack}/acknowledge"),
                                                                                            json!({"action": "acknowledge"}),
                                                                                        ).await {
                                                                                            Ok(_) => bump_reload(),
                                                                                            Err(e) => set_action_err.set(Some(e.message)),
                                                                                        }
                                                                                        set_busy_id.set(String::new());
                                                                                    });
                                                                                }
                                                                            }
                                                                        >"Ack"</button>
                                                                    </Show>
                                                                </div>
                                                            </li>
                                                        }
                                                    }).collect_view()}
                                                </ul>
                                            }.into_any()
                                        }
                                    }
                                    Err(e) => view! {
                                        <div class="p-3">
                                            <OpApiErrorBanner error=e />
                                        </div>
                                    }.into_any(),
                                }
                            })}
                        </Suspense>
                    </OpScrollArea>
                    <div class="border-t border-zinc-800/60 px-4 py-2">
                        <OpButton
                            label="Open notification center".to_string()
                            variant=OpButtonVariant::Ghost
                            on_click=Arc::new(move |_| {
                                set_open.set(false);
                                open_topic_drawer(DrawerTopic::Notifications);
                            })
                        />
                    </div>
                </div>
            </div>
        </Show>
    }
}

fn severity_class(sev: &str) -> &'static str {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" | "PAGED" => "bg-red-950 text-red-300",
        "WARNING" | "HIGH" => "bg-amber-950 text-amber-300",
        _ => "bg-zinc-800 text-zinc-400",
    }
}

fn parse_notes(v: &serde_json::Value) -> Vec<NoteRow> {
    v.get("notifications")
        .or_else(|| v.get("items"))
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .take(25)
                .map(|n| {
                    let status = n
                        .get("status")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let pending = matches!(
                        status.to_ascii_uppercase().as_str(),
                        "PENDING" | "DELIVERED" | "SNOOZED" | ""
                    ) && n.get("acknowledged_at").map(|a| a.is_null()).unwrap_or(true);
                    NoteRow {
                        id: n
                            .get("id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                        title: n
                            .get("title")
                            .or_else(|| n.get("subject"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("Notification")
                            .to_string(),
                        body: n
                            .get("message")
                            .or_else(|| n.get("body"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                        severity: n
                            .get("severity")
                            .and_then(|x| x.as_str())
                            .unwrap_or("INFO")
                            .to_string(),
                        status,
                        created: n
                            .get("created_at")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                        pending,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
