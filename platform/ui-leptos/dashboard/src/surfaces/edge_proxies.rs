//! Cloudflare-style Edge & Proxies — domains, API gateway, LLM/WF proxy routes.
//! Shown inline on SETUP (not buried in a drawer card).

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpLoadingBlock};
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpText, OpTextVariant};
use crate::ui_state::{open_topic_drawer, DrawerTopic};

#[component]
pub fn EdgeProxiesPanel() -> impl IntoView {
    let navigate = use_navigate();
    let (reload, set_reload) = signal(0u32);
    let networking = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/settings/system/networking").await }
    });
    let domains = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/settings/networking/custom-domains").await }
    });
    let edge = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/operator/edge/plane").await }
    });

    let (host, set_host) = signal(String::new());
    let (plugin, set_plugin) = signal("tracetramp".to_string());
    let (tls_mode, set_tls_mode) = signal("lets_encrypt".to_string());
    let (public_domain, set_public_domain) = signal(String::new());
    let (status, set_status) = signal(Option::<String>::None);
    let (saving, set_saving) = signal(false);
    let (cfg_snapshot, set_cfg_snapshot) = signal(json!({}));

    let go_tt = {
        let navigate = navigate.clone();
        Arc::new(move |_| navigate("/plugins/tracetramp", Default::default()))
    };
    let go_full = Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("network".into())));

    view! {
        <section class="mb-8 rounded-xl border border-orange-500/30 bg-gradient-to-b from-orange-950/20 to-zinc-950/40 p-4 sm:p-5">
            <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
                <div>
                    <OpText text="Edge & proxies".to_string() variant=OpTextVariant::Title />
                    <p class="mt-1 text-sm text-zinc-400">
                        "Cloudflare-style control plane: public API, host aliases, LLM proxy, and workflow routes."
                    </p>
                </div>
                <div class="flex flex-wrap gap-2">
                    <OpButton
                        label="Full network settings".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=go_full
                    />
                    <OpButton
                        label="LLM proxy (TraceTramp)".to_string()
                        variant=OpButtonVariant::Primary
                        on_click=go_tt
                    />
                </div>
            </div>

            // Route tiles — like Cloudflare "Products"
            <div class="mb-5 grid gap-3 sm:grid-cols-3">
                <RouteTile
                    title="API gateway"
                    detail="Public /api/v1 · trusted proxies"
                    badge="GATEWAY"
                />
                <RouteTile
                    title="LLM proxy"
                    detail="Host → TraceTramp cage · approvals"
                    badge="LLM"
                />
                <RouteTile
                    title="Workflow / plugins"
                    detail="/plugin/{slug} · WitnessCtl · DevGuard"
                    badge="WF"
                />
            </div>

            // Live networking summary
            <div class="mb-5 grid gap-3 lg:grid-cols-2">
                <div class="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-3">
                    <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-orange-400/90">"API & trusted proxies"</h3>
                    <Suspense fallback=move || view! { <OpLoadingBlock message="Loading…".to_string() /> }>
                        {move || Suspend::new(async move {
                            match networking.await {
                                Ok(v) => {
                                    let net = v.get("networking").cloned().unwrap_or(v);
                                    let public = net.get("public_url").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                    let gw = net.get("protocol_gateway_port").map(|x| x.to_string()).unwrap_or_else(|| "—".into());
                                    let proxies = net
                                        .get("trusted_proxies")
                                        .and_then(|x| x.as_array())
                                        .map(|a| {
                                            a.iter()
                                                .filter_map(|p| p.as_str())
                                                .collect::<Vec<_>>()
                                                .join(", ")
                                        })
                                        .filter(|s| !s.is_empty())
                                        .unwrap_or_else(|| "none configured".into());
                                    view! {
                                        <dl class="space-y-2 text-xs">
                                            <div class="flex justify-between gap-2">
                                                <dt class="text-zinc-500">"Public URL"</dt>
                                                <dd class="font-mono text-zinc-100">{public}</dd>
                                            </div>
                                            <div class="flex justify-between gap-2">
                                                <dt class="text-zinc-500">"Gateway port"</dt>
                                                <dd class="font-mono text-zinc-100">{gw}</dd>
                                            </div>
                                            <div class="flex justify-between gap-2">
                                                <dt class="text-zinc-500">"Trusted proxies"</dt>
                                                <dd class="max-w-[55%] break-all text-right font-mono text-zinc-300">{proxies}</dd>
                                            </div>
                                        </dl>
                                    }.into_any()
                                }
                                Err(e) => view! {
                                    <OpApiErrorBanner error=e />
                                    <p class="mt-2 text-[11px] text-zinc-600">
                                        "Start connector-platform (health shows Down) — then refresh."
                                    </p>
                                }.into_any(),
                            }
                        })}
                    </Suspense>
                </div>

                <div class="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-3">
                    <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-orange-400/90">"Edge plane"</h3>
                    <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading edge…"</p> }>
                        {move || Suspend::new(async move {
                            match edge.await {
                                Ok(v) => {
                                    let data = v.get("data").cloned().unwrap_or(v);
                                    let records = data
                                        .get("records")
                                        .and_then(|x| x.as_array())
                                        .cloned()
                                        .unwrap_or_default();
                                    if records.is_empty() {
                                        view! {
                                            <p class="text-xs text-zinc-500">"No edge records yet — add a host alias below."</p>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <ul class="max-h-40 space-y-1.5 overflow-auto">
                                                {records.into_iter().take(12).map(|r| {
                                                    let kind = r.get("kind").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                                    let host = r.get("host").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                                    view! {
                                                        <li class="flex items-center gap-2 text-xs">
                                                            <span class="rounded bg-zinc-800 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-zinc-400">{kind}</span>
                                                            <span class="truncate font-mono text-zinc-200">{host}</span>
                                                        </li>
                                                    }
                                                }).collect_view()}
                                            </ul>
                                        }.into_any()
                                    }
                                }
                                Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                            }
                        })}
                    </Suspense>
                </div>
            </div>

            // Domains / host aliases — Cloudflare DNS-like
            <div class="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-3">
                <h3 class="mb-1 text-[10px] font-semibold uppercase tracking-wide text-orange-400/90">"Custom domains (host → proxy)"</h3>
                <p class="mb-3 text-[11px] text-zinc-600">
                    "Point DNS CNAME at your Connector node. Example: llm.acme.com → tracetramp (LLM proxy)."
                </p>
                <Suspense fallback=move || view! { <OpLoadingBlock message="Loading domains…".to_string() /> }>
                    {move || Suspend::new(async move {
                        match domains.await {
                            Ok(v) => {
                                let cfg = v.get("custom_domains").cloned().unwrap_or(json!({}));
                                set_cfg_snapshot.set(cfg.clone());
                                if public_domain.get_untracked().is_empty() {
                                    if let Some(pd) = cfg.get("public_domain").and_then(|x| x.as_str()) {
                                        set_public_domain.set(pd.to_string());
                                    }
                                }
                                if let Some(tm) = cfg.get("tls_mode").and_then(|x| x.as_str()) {
                                    set_tls_mode.set(tm.to_string());
                                }
                                let aliases = cfg
                                    .get("aliases")
                                    .and_then(|x| x.as_array())
                                    .cloned()
                                    .unwrap_or_default();

                                view! {
                                    <div class="mb-3 grid gap-2 sm:grid-cols-2">
                                        <label class="block">
                                            <span class="text-[10px] uppercase text-zinc-600">"Public domain"</span>
                                            <input
                                                type="text"
                                                class="mt-1 w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
                                                placeholder="connector.example.com"
                                                prop:value=move || public_domain.get()
                                                on:input=move |ev| set_public_domain.set(event_target_value(&ev))
                                            />
                                        </label>
                                        <label class="block">
                                            <span class="text-[10px] uppercase text-zinc-600">"TLS mode"</span>
                                            <select
                                                class="mt-1 w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
                                                prop:value=move || tls_mode.get()
                                                on:change=move |ev| set_tls_mode.set(event_target_value(&ev))
                                            >
                                                <option value="lets_encrypt">"lets_encrypt"</option>
                                                <option value="manual">"manual"</option>
                                                <option value="terminator">"terminator"</option>
                                                <option value="off">"off"</option>
                                            </select>
                                        </label>
                                    </div>

                                    <div class="mb-3 overflow-hidden rounded-lg border border-zinc-800/60">
                                        <div class="grid grid-cols-[1fr_7rem_5rem] gap-2 border-b border-zinc-800/60 bg-zinc-900/60 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                            <span>"Host"</span>
                                            <span>"Proxy to"</span>
                                            <span></span>
                                        </div>
                                        {if aliases.is_empty() {
                                            view! {
                                                <p class="px-3 py-4 text-center text-xs text-zinc-600">
                                                    "No aliases — add llm.example.com → tracetramp below."
                                                </p>
                                            }.into_any()
                                        } else {
                                            aliases.into_iter().enumerate().map(|(idx, a)| {
                                                let h = a.get("host").or_else(|| a.get("domain")).and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                                let p = a.get("plugin_id").or_else(|| a.get("plugin")).and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                                view! {
                                                    <div class="grid grid-cols-[1fr_7rem_5rem] items-center gap-2 border-b border-zinc-800/40 px-3 py-2 text-xs last:border-0">
                                                        <span class="truncate font-mono text-zinc-200">{h}</span>
                                                        <span class="font-mono text-zinc-400">{p}</span>
                                                        <button
                                                            type="button"
                                                            class="text-left text-[10px] text-red-400 hover:text-red-300"
                                                            on:click=move |_| {
                                                                let mut cfg = cfg_snapshot.get();
                                                                if let Some(arr) = cfg.get_mut("aliases").and_then(|x| x.as_array_mut()) {
                                                                    if idx < arr.len() {
                                                                        arr.remove(idx);
                                                                    }
                                                                }
                                                                set_cfg_snapshot.set(cfg.clone());
                                                                set_saving.set(true);
                                                                spawn_local(async move {
                                                                    match api::post_value(
                                                                        "/settings/networking/custom-domains",
                                                                        json!({"value": cfg}),
                                                                    ).await {
                                                                        Ok(resp) => match api::body_error(&resp) {
                                                                            Some(e) => set_status.set(Some(e)),
                                                                            None => {
                                                                                set_status.set(Some("Alias removed.".into()));
                                                                                set_reload.update(|n| *n += 1);
                                                                            }
                                                                        },
                                                                        Err(e) => set_status.set(Some(e.message)),
                                                                    }
                                                                    set_saving.set(false);
                                                                });
                                                            }
                                                        >"Remove"</button>
                                                    </div>
                                                }
                                            }).collect_view().into_any()
                                        }}
                                    </div>

                                    <div class="flex flex-col gap-2 sm:flex-row">
                                        <input
                                            type="text"
                                            class="flex-1 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
                                            placeholder="llm.example.com"
                                            prop:value=move || host.get()
                                            on:input=move |ev| set_host.set(event_target_value(&ev))
                                        />
                                        <select
                                            class="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
                                            prop:value=move || plugin.get()
                                            on:change=move |ev| set_plugin.set(event_target_value(&ev))
                                        >
                                            <option value="tracetramp">"tracetramp (LLM)"</option>
                                            <option value="witnessctl">"witnessctl"</option>
                                            <option value="devguard">"devguard"</option>
                                        </select>
                                        <button
                                            type="button"
                                            class="rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-white hover:bg-orange-500 disabled:opacity-50"
                                            disabled=move || saving.get()
                                            on:click=move |_| {
                                                let h = host.get().trim().to_string();
                                                if h.is_empty() {
                                                    set_status.set(Some("Host is required.".into()));
                                                    return;
                                                }
                                                let p = plugin.get();
                                                let mut cfg = cfg_snapshot.get();
                                                if !cfg.is_object() {
                                                    cfg = json!({
                                                        "public_domain": public_domain.get(),
                                                        "tls_mode": tls_mode.get(),
                                                        "aliases": []
                                                    });
                                                }
                                                if let Some(obj) = cfg.as_object_mut() {
                                                    obj.insert("public_domain".into(), json!(public_domain.get()));
                                                    obj.insert("tls_mode".into(), json!(tls_mode.get()));
                                                    let aliases = obj
                                                        .entry("aliases".to_string())
                                                        .or_insert_with(|| json!([]));
                                                    if let Some(arr) = aliases.as_array_mut() {
                                                        arr.push(json!({
                                                            "host": h,
                                                            "plugin_id": p,
                                                            "enabled": true
                                                        }));
                                                    }
                                                }
                                                set_saving.set(true);
                                                set_status.set(None);
                                                spawn_local(async move {
                                                    match api::post_value(
                                                        "/settings/networking/custom-domains",
                                                        json!({"value": cfg}),
                                                    ).await {
                                                        Ok(resp) => {
                                                            if resp.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                                                                set_status.set(Some(
                                                                    resp.get("error").and_then(|x| x.as_str()).unwrap_or("Save failed").into()
                                                                ));
                                                            } else {
                                                                set_host.set(String::new());
                                                                set_status.set(Some("Alias saved — point DNS CNAME at this node.".into()));
                                                                set_reload.update(|n| *n += 1);
                                                            }
                                                        }
                                                        Err(e) => set_status.set(Some(e.message)),
                                                    }
                                                    set_saving.set(false);
                                                });
                                            }
                                        >{move || if saving.get() { "Saving…" } else { "Add alias" }}</button>
                                        <button
                                            type="button"
                                            class="rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-900"
                                            disabled=move || saving.get()
                                            on:click=move |_| {
                                                let mut cfg = cfg_snapshot.get();
                                                if !cfg.is_object() {
                                                    cfg = json!({"aliases": []});
                                                }
                                                if let Some(obj) = cfg.as_object_mut() {
                                                    obj.insert("public_domain".into(), json!(public_domain.get()));
                                                    obj.insert("tls_mode".into(), json!(tls_mode.get()));
                                                }
                                                set_saving.set(true);
                                                spawn_local(async move {
                                                    match api::post_value(
                                                        "/settings/networking/custom-domains",
                                                        json!({"value": cfg}),
                                                    ).await {
                                                        Ok(resp) => match api::body_error(&resp) {
                                                            Some(e) => set_status.set(Some(e)),
                                                            None => {
                                                                set_status.set(Some("Domain / TLS saved.".into()));
                                                                set_reload.update(|n| *n += 1);
                                                            }
                                                        },
                                                        Err(e) => set_status.set(Some(e.message)),
                                                    }
                                                    set_saving.set(false);
                                                });
                                            }
                                        >"Save TLS"</button>
                                    </div>
                                    <Show when=move || status.get().is_some()>
                                        <p class="mt-2 text-xs text-zinc-300">{move || status.get().unwrap_or_default()}</p>
                                    </Show>
                                }.into_any()
                            }
                            Err(e) => view! {
                                <OpApiErrorBanner error=e />
                                <p class="mt-2 text-[11px] text-zinc-600">
                                    "API Down — rebuild/restart connector-platform so /settings/networking/* is available."
                                </p>
                            }.into_any(),
                        }
                    })}
                </Suspense>
            </div>
        </section>
    }
}

#[component]
fn RouteTile(title: &'static str, detail: &'static str, badge: &'static str) -> impl IntoView {
    view! {
        <div class="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-3">
            <div class="mb-1 flex items-center justify-between gap-2">
                <p class="text-sm font-medium text-zinc-100">{title}</p>
                <span class="rounded bg-orange-950 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-orange-300">{badge}</span>
            </div>
            <p class="text-[11px] text-zinc-500">{detail}</p>
        </div>
    }
}
