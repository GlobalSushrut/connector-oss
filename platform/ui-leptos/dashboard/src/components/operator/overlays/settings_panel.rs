//! Settings drawer — Node · Network & Proxy · LLM · System (UI_PAGE_DESIGN §6).
//! Network tab is Cloudflare-style: public URL, host aliases → plugin cages, edge plane.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::overlays::llm_connect::OpLlmQuickConnect;
use crate::components::operator::primitives::{OpText, OpTextVariant};
use crate::ui_state::use_developer_view;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsTab {
    Node,
    Network,
    Llm,
    System,
}

impl SettingsTab {
    fn label(self) -> &'static str {
        match self {
            Self::Node => "Node",
            Self::Network => "Network & proxy",
            Self::Llm => "LLM routing",
            Self::System => "System",
        }
    }

    fn from_kind(kind: &str) -> Self {
        match kind.to_ascii_lowercase().as_str() {
            "network" | "networking" | "proxy" | "domains" | "edge" => Self::Network,
            "llm" | "llms" | "routing" => Self::Llm,
            "system" | "backup" | "telemetry" | "identity" => Self::System,
            _ => Self::Node,
        }
    }
}

#[component]
pub fn OpSettingsPanel(#[prop(into)] kind: String) -> impl IntoView {
    let (tab, set_tab) = signal(SettingsTab::from_kind(&kind));
    let (dev, _) = use_developer_view();

    view! {
        <div class="flex h-full min-h-0 flex-col">
            <div class="flex shrink-0 flex-wrap gap-1 border-b border-zinc-800/60 px-3 py-2">
                {[SettingsTab::Node, SettingsTab::Network, SettingsTab::Llm, SettingsTab::System]
                    .into_iter()
                    .map(|t| {
                        let active = move || tab.get() == t;
                        view! {
                            <button
                                type="button"
                                class=move || if active() {
                                    "rounded-md bg-zinc-800 px-2.5 py-1 text-[11px] font-medium text-zinc-100"
                                } else {
                                    "rounded-md px-2.5 py-1 text-[11px] text-zinc-500 hover:bg-zinc-900 hover:text-zinc-300"
                                }
                                on:click=move |_| set_tab.set(t)
                            >{t.label()}</button>
                        }
                    })
                    .collect_view()}
            </div>
            <div class="min-h-0 flex-1 overflow-y-auto p-4">
                {move || match tab.get() {
                    SettingsTab::Node => view! { <NodeTab /> }.into_any(),
                    SettingsTab::Network => view! { <NetworkTab dev=dev /> }.into_any(),
                    SettingsTab::Llm => view! { <LlmTab /> }.into_any(),
                    SettingsTab::System => view! { <SystemTab /> }.into_any(),
                }}
            </div>
        </div>
    }
}

#[component]
fn NodeTab() -> impl IntoView {
    let mode_res = LocalResource::new(|| api::get_value("/runtime/mode"));
    let deploy_res = LocalResource::new(|| api::get_value("/deployment/info"));
    let (saving, set_saving) = signal(false);
    let (msg, set_msg) = signal(Option::<String>::None);
    let (mode_draft, set_mode_draft) = signal(String::new());

    view! {
        <OpText text="Node".to_string() variant=OpTextVariant::Title />
        <p class="mb-4 mt-1 text-xs text-zinc-500">"Runtime mode and deployment identity."</p>

        <Suspense fallback=move || view! { <OpLoadingBlock message="Loading runtime…".to_string() /> }>
            {move || Suspend::new(async move {
                match mode_res.await {
                    Ok(v) => {
                        let current = v
                            .get("mode")
                            .or_else(|| v.get("runtime_mode"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        if mode_draft.get_untracked().is_empty() {
                            set_mode_draft.set(current.clone());
                        }
                        view! {
                            <label class="mb-1 block text-[10px] uppercase tracking-wide text-zinc-600">"Runtime mode"</label>
                            <div class="flex gap-2">
                                <select
                                    class="flex-1 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
                                    prop:value=move || mode_draft.get()
                                    on:change=move |ev| set_mode_draft.set(event_target_value(&ev))
                                >
                                    <option value="dev">"dev"</option>
                                    <option value="pilots">"pilots"</option>
                                    <option value="production">"production"</option>
                                </select>
                                <button
                                    type="button"
                                    class="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
                                    disabled=move || saving.get()
                                    on:click=move |_| {
                                        let mode = mode_draft.get();
                                        set_saving.set(true);
                                        set_msg.set(None);
                                        spawn_local(async move {
                                            match api::post_value("/runtime/mode", json!({"mode": mode})).await {
                                                Ok(v) => {
                                                    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                                                        set_msg.set(Some(
                                                            v.get("error")
                                                                .and_then(|x| x.as_str())
                                                                .unwrap_or("Runtime mode rejected")
                                                                .into(),
                                                        ));
                                                    } else {
                                                        set_msg.set(Some(format!(
                                                            "Runtime mode → {}",
                                                            v.get("mode")
                                                                .and_then(|x| x.as_str())
                                                                .unwrap_or(&mode)
                                                        )));
                                                    }
                                                }
                                                Err(e) => set_msg.set(Some(e.message)),
                                            }
                                            set_saving.set(false);
                                        });
                                    }
                                >{move || if saving.get() { "Saving…" } else { "Save" }}</button>
                            </div>
                            <p class="mt-1 text-[10px] text-zinc-600">
                                {format!("Current: {current} · POST /runtime/mode accepts dev | pilots | production")}
                            </p>
                        }.into_any()
                    }
                    Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                }
            })}
        </Suspense>

        <Show when=move || msg.get().is_some()>
            <p class="mt-2 text-xs text-zinc-400">{move || msg.get().unwrap_or_default()}</p>
        </Show>

        <div class="mt-6">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-600">"Deployment"</h3>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading deployment…".to_string() /> }>
                {move || Suspend::new(async move {
                    match deploy_res.await {
                        Ok(v) => {
                            let pairs = kv_pairs(&v, &[
                                "mode",
                                "edition",
                                "public_url",
                                "version",
                                "license_tier",
                                "license_status",
                            ]);
                            view! { <KvList pairs=pairs /> }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn NetworkTab(dev: ReadSignal<bool>) -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let domains = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/settings/networking/custom-domains").await }
    });
    let networking = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/settings/system/networking").await }
    });
    let edge = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/operator/edge/plane").await }
    });
    let ha = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/runtime/ha-federation").await }
    });
    let mesh = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/runtime/mesh").await }
    });

    let (host, set_host) = signal(String::new());
    let (plugin, set_plugin) = signal("tracetramp".to_string());
    let (tls_mode, set_tls_mode) = signal("lets_encrypt".to_string());
    let (public_domain, set_public_domain) = signal(String::new());
    let (status, set_status) = signal(Option::<String>::None);
    let (saving, set_saving) = signal(false);
    let (cfg_snapshot, set_cfg_snapshot) = signal(json!({}));
    let (join_busy, set_join_busy) = signal(false);
    let (join_msg, set_join_msg) = signal(Option::<String>::None);

    view! {
        <OpText text="Network & proxy".to_string() variant=OpTextVariant::Title />
        <p class="mb-4 mt-1 text-xs text-zinc-500">
            "Public hostname, API base, and host aliases that route to plugin cages — Cloudflare-style DNS → origin, without leaving Connector."
        </p>

        // Proxy / public URL
        <section class="mb-6 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"API & trusted proxies"</h3>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading networking…"</p> }>
                {move || Suspend::new(async move {
                    match networking.await {
                        Ok(v) => {
                            let net = v.get("networking").cloned().unwrap_or(v);
                            let public = net.get("public_url").and_then(|x| x.as_str()).unwrap_or("—");
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
                                        <dd class="font-mono text-zinc-200">{public.to_string()}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"Gateway port"</dt>
                                        <dd class="font-mono text-zinc-200">{gw}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"Trusted proxies"</dt>
                                        <dd class="max-w-[60%] break-all text-right font-mono text-zinc-300">{proxies}</dd>
                                    </div>
                                </dl>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>

        // Custom domains / host aliases
        <section class="mb-6">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Custom domains (host → plugin)"</h3>
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
                                <div class="mb-3 space-y-2">
                                    <label class="block text-[10px] uppercase text-zinc-600">"Public domain"</label>
                                    <input
                                        type="text"
                                        class="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
                                        placeholder="connector.example.com"
                                        prop:value=move || public_domain.get()
                                        on:input=move |ev| set_public_domain.set(event_target_value(&ev))
                                    />
                                    <label class="mt-2 block text-[10px] uppercase text-zinc-600">"TLS mode"</label>
                                    <select
                                        class="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200"
                                        prop:value=move || tls_mode.get()
                                        on:change=move |ev| set_tls_mode.set(event_target_value(&ev))
                                    >
                                        <option value="lets_encrypt">"lets_encrypt"</option>
                                        <option value="manual">"manual"</option>
                                        <option value="terminator">"terminator (external)"</option>
                                        <option value="off">"off"</option>
                                    </select>
                                </div>

                                <ul class="mb-3 divide-y divide-zinc-800/50 rounded-lg border border-zinc-800/60">
                                    {if aliases.is_empty() {
                                        view! {
                                            <li class="px-3 py-4 text-center text-xs text-zinc-600">
                                                "No host aliases yet. Add one below (e.g. llm.acme.com → tracetramp)."
                                            </li>
                                        }.into_any()
                                    } else {
                                        aliases.into_iter().enumerate().map(|(idx, a)| {
                                            let h = a.get("host").or_else(|| a.get("domain")).and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let p = a.get("plugin_id").or_else(|| a.get("plugin")).and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let enabled = a.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
                                            view! {
                                                <li class="flex items-center justify-between gap-2 px-3 py-2.5 text-xs">
                                                    <div class="min-w-0">
                                                        <p class="truncate font-mono text-zinc-200">{h.clone()}</p>
                                                        <p class="text-[10px] text-zinc-500">
                                                            {format!("→ /plugin/{p} · {}", if enabled { "enabled" } else { "disabled" })}
                                                        </p>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        class="text-[10px] text-red-400 hover:text-red-300"
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
                                                                let body = json!({"value": cfg});
                                                                match api::post_value("/settings/networking/custom-domains", body).await {
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
                                                </li>
                                            }
                                        }).collect_view().into_any()
                                    }}
                                </ul>

                                <div class="rounded-lg border border-dashed border-zinc-700/80 p-3">
                                    <p class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Add host alias"</p>
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
                                            <option value="tracetramp">"tracetramp"</option>
                                            <option value="witnessctl">"witnessctl"</option>
                                            <option value="devguard">"devguard"</option>
                                        </select>
                                    </div>
                                    <div class="mt-2 flex gap-2">
                                        <button
                                            type="button"
                                            class="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
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
                                                                set_status.set(Some("Alias saved. Point DNS CNAME at your Connector node.".into()));
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
                                            class="rounded-lg border border-zinc-700 px-3 py-2 text-sm text-zinc-300 hover:bg-zinc-900 disabled:opacity-50"
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
                                                                set_status.set(Some("Domain settings saved.".into()));
                                                                set_reload.update(|n| *n += 1);
                                                            }
                                                        },
                                                        Err(e) => set_status.set(Some(e.message)),
                                                    }
                                                    set_saving.set(false);
                                                });
                                            }
                                        >"Save domain / TLS"</button>
                                    </div>
                                </div>
                                <Show when=move || status.get().is_some()>
                                    <p class="mt-2 text-xs text-zinc-400">{move || status.get().unwrap_or_default()}</p>
                                </Show>
                                <Show when=move || dev.get()>
                                    <div class="mt-3">
                                        <OpDevDisclosure
                                            label="Raw custom_domains JSON".to_string()
                                            raw=serde_json::to_string_pretty(&cfg_snapshot.get()).unwrap_or_default()
                                        />
                                    </div>
                                </Show>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>

        // Mesh / HA peers (P8.5 + P8.8)
        <section class="mb-6 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"HA · mesh peers"</h3>
            <p class="mb-2 text-[11px] text-zinc-600">
                "HA panel from GET /runtime/ha-federation · placement/spiffe from /runtime/mesh. Join-token API not shipping — env bootstrap only."
            </p>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading mesh…"</p> }>
                {move || Suspend::new(async move {
                    let ha_v = ha.await;
                    let mesh_v = mesh.await;
                    match (ha_v, mesh_v) {
                        (Ok(ha), Ok(mesh)) => {
                            let peers = ha
                                .pointer("/env/peer_urls")
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let role = ha.pointer("/env/role").and_then(|x| x.as_str()).unwrap_or("standalone").to_string();
                            let mtls_required = ha
                                .pointer("/env/mtls_required")
                                .and_then(|x| x.as_bool())
                                .unwrap_or(false);
                            let automatic_failover = ha
                                .get("automatic_failover")
                                .and_then(|x| x.as_bool())
                                .unwrap_or(false);
                            let region = mesh
                                .pointer("/local_placement/region")
                                .and_then(|x| x.as_str())
                                .unwrap_or("local")
                                .to_string();
                            let spiffe = mesh
                                .get("spiffe_id")
                                .and_then(|x| x.as_str())
                                .unwrap_or("—")
                                .to_string();
                            let peers_seen = mesh
                                .get("peers_seen")
                                .and_then(|x| x.as_u64())
                                .unwrap_or(1)
                                .to_string();
                            let steps = ha
                                .pointer("/join/steps")
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let docs = ha
                                .pointer("/join/docs")
                                .and_then(|x| x.as_str())
                                .unwrap_or("docs/architecture/ha-federation.md")
                                .to_string();
                            let mesh_fabric = ha
                                .get("mesh_fabric")
                                .or_else(|| mesh.get("mesh_fabric"))
                                .and_then(|x| x.as_bool())
                                .map(|b| b.to_string())
                                .unwrap_or_else(|| "—".to_string());
                            let join_token_api = ha
                                .pointer("/join/join_token_api")
                                .and_then(|x| x.as_bool())
                                .unwrap_or(false);
                            view! {
                                <dl class="mb-3 space-y-1 text-xs">
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"Role"</dt>
                                        <dd class="font-mono text-zinc-200">{role}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"Peers (env)"</dt>
                                        <dd class="font-mono text-zinc-200">{peers.len().to_string()}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"mTLS required"</dt>
                                        <dd class="font-mono text-zinc-200">{mtls_required.to_string()}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"automatic_failover"</dt>
                                        <dd class="font-mono text-amber-200/90">{automatic_failover.to_string()}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"Cell region"</dt>
                                        <dd class="font-mono text-zinc-200">{region}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"peers_seen"</dt>
                                        <dd class="font-mono text-zinc-200">{peers_seen}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"mesh_fabric"</dt>
                                        <dd class="font-mono text-zinc-400">{mesh_fabric}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"spiffe_id"</dt>
                                        <dd class="max-w-[60%] truncate font-mono text-zinc-400" title=spiffe.clone()>{spiffe.clone()}</dd>
                                    </div>
                                </dl>
                                <p class="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">"Peers"</p>
                                {if peers.is_empty() {
                                    view! { <p class="mb-2 text-xs text-zinc-500">"No peers — set CONNECTOR_HA_PEER_URLS."</p> }.into_any()
                                } else {
                                    view! {
                                        <ul class="mb-2 space-y-1 font-mono text-[11px] text-zinc-300">
                                            {peers.into_iter().filter_map(|p| p.as_str().map(|s| s.to_string())).map(|u| {
                                                view! { <li class="truncate">{u}</li> }
                                            }).collect_view()}
                                        </ul>
                                    }.into_any()
                                }}
                                <p class="mb-1 text-[10px] uppercase tracking-wide text-zinc-600">"Join instructions"</p>
                                <ol class="mb-2 list-decimal space-y-1 pl-4 text-[11px] text-zinc-400">
                                    {steps.into_iter().filter_map(|s| s.as_str().map(|x| x.to_string())).take(5).map(|s| {
                                        view! { <li>{s}</li> }
                                    }).collect_view()}
                                </ol>
                                <p class="mb-3 text-[10px] text-zinc-600">"Docs: "{docs}</p>
                                <div class="space-y-2 border-t border-zinc-800/50 pt-2">
                                    {if join_token_api {
                                        view! {
                                            <div class="space-y-2">
                                                <p class="text-[10px] text-zinc-500">
                                                    "Lab join-token mint enabled — POST /runtime/mesh/join-token. Tokens are process-local and clear on restart."
                                                </p>
                                                <button
                                                    type="button"
                                                    class="rounded-lg border border-zinc-700 px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-zinc-900 disabled:opacity-50"
                                                    disabled=move || join_busy.get()
                                                    on:click=move |_| {
                                                        set_join_busy.set(true);
                                                        set_join_msg.set(None);
                                                        spawn_local(async move {
                                                            match api::post_value("/runtime/mesh/join-token", json!({})).await {
                                                                Ok(v) => {
                                                                    let msg = if v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
                                                                        v.get("token")
                                                                            .and_then(|x| x.as_str())
                                                                            .map(|t| format!("Minted lab token: {t}"))
                                                                            .unwrap_or_else(|| "Mint succeeded but returned no token".to_string())
                                                                    } else {
                                                                        v.get("error")
                                                                            .and_then(|x| x.as_str())
                                                                            .unwrap_or("Mint refused")
                                                                            .to_string()
                                                                    };
                                                                    set_join_msg.set(Some(msg));
                                                                }
                                                                Err(e) => set_join_msg.set(Some(e.message)),
                                                            }
                                                            set_join_busy.set(false);
                                                        });
                                                    }
                                                >"Mint lab join token"</button>
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <p class="text-[10px] text-amber-200/90">
                                                "No add-peer API is mounted. Bootstrap peers with CONNECTOR_HA_PEER_URLS on the joining node; set CONNECTOR_MESH_JOIN_LAB=1 to enable lab token mint."
                                            </p>
                                        }.into_any()
                                    }}
                                    {move || join_msg.get().map(|m| view! {
                                        <p class="break-all font-mono text-[10px] text-zinc-400">{m}</p>
                                    })}
                                </div>
                            }.into_any()
                        }
                        (Err(e), _) | (_, Err(e)) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>

        // Edge plane overview
        <section>
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Edge plane"</h3>
            <p class="mb-2 text-[11px] text-zinc-600">"Merged view of gateway, host aliases, and cage DNS — GET /operator/edge/plane."</p>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading edge plane…"</p> }>
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
                                    <p class="text-xs text-zinc-600">"No edge records reported."</p>
                                }.into_any()
                            } else {
                                view! {
                                    <ul class="divide-y divide-zinc-800/40 rounded-lg border border-zinc-800/60">
                                        {records.into_iter().take(40).map(|r| {
                                            let kind = r.get("kind").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let host = r.get("host").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let hint = r
                                                .pointer("/dns_hints/message")
                                                .or_else(|| r.pointer("/status/status"))
                                                .and_then(|x| x.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            let hint_view = if hint.is_empty() {
                                                None
                                            } else {
                                                Some(hint)
                                            };
                                            view! {
                                                <li class="px-3 py-2 text-xs">
                                                    <div class="flex items-center gap-2">
                                                        <span class="rounded bg-zinc-800 px-1.5 py-0.5 text-[9px] font-semibold uppercase text-zinc-400">{kind}</span>
                                                        <span class="truncate font-mono text-zinc-200">{host}</span>
                                                    </div>
                                                    {hint_view.map(|h| view! {
                                                        <p class="mt-0.5 text-[10px] text-zinc-600">{h}</p>
                                                    })}
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
        </section>
    }
}

#[component]
fn LlmTab() -> impl IntoView {
    view! {
        <OpText text="LLM routing".to_string() variant=OpTextVariant::Title />
        <p class="mb-3 mt-1 text-xs text-zinc-500">
            "Pick a known market provider or a custom/self-host OpenAI-compatible URL (DI-1). Keys go to vault + platform LlmRouter — never into DockLock cage env. "
            "CLI: "
            <code class="font-mono text-zinc-400">"connectorctl llm link --provider … --key …"</code>
        </p>
        <div class="mb-4 max-w-xl">
            <OpLlmQuickConnect />
        </div>
        <div class="mb-3 flex flex-wrap gap-2">
            <a
                href="/agents/create"
                class="rounded-md border border-zinc-700 px-2.5 py-1.5 text-[11px] text-zinc-300 hover:border-emerald-700 hover:text-zinc-100"
            >"Create intelligence"</a>
            <a
                href="/setup"
                class="rounded-md border border-zinc-700 px-2.5 py-1.5 text-[11px] text-zinc-300 hover:border-cyan-700 hover:text-zinc-100"
            >"World connect (Setup)"</a>
            <a
                href="/plugins/tracetramp"
                class="rounded-md border border-zinc-700 px-2.5 py-1.5 text-[11px] text-zinc-300 hover:border-violet-700 hover:text-zinc-100"
            >"TraceTramp audit"</a>
        </div>
        <p class="text-[11px] text-zinc-600">
            "Guardrails: GET /settings/llms/guardrails · Fallback: CONNECTOR_LLM_FALLBACK[+_KEY] still optional at boot."
        </p>
    }
}

fn event_target_value(ev: &web_sys::Event) -> String {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.value())
        .unwrap_or_default()
}

#[component]
fn SystemTab() -> impl IntoView {
    // Live license comes from /license/status (activation truth), not the
    // operator-editable settings blob at /settings/system/license.
    let license = LocalResource::new(|| api::get_value("/license/status"));
    view! {
        <OpText text="System".to_string() variant=OpTextVariant::Title />
        <p class="mb-4 mt-1 text-xs text-zinc-500">"Identity, backup, telemetry, and live license status."</p>
        <section class="mb-4 rounded-xl border border-zinc-800/70 bg-zinc-950/40 p-3">
            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Env runbook (restart required)"</p>
            <ul class="mt-2 list-disc space-y-1 pl-4 text-[11px] text-zinc-400">
                <li><code class="text-zinc-300">"CONNECTOR_LLM_BROKER_UNBYPASSABLE=1"</code></li>
                <li><code class="text-zinc-300">"CONNECTOR_SANDBOX_UNBYPASSABLE=1"</code></li>
                <li><code class="text-zinc-300">"CONNECTOR_KERNEL_ENFORCE=1"</code></li>
                <li><code class="text-zinc-300">"CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED=1"</code></li>
            </ul>
            <a class="mt-2 inline-block text-[11px] text-cyan-400 hover:underline" href="/runtime-enforcement">
                "Open runtime enforcement"
            </a>
            <a class="mt-2 ml-3 inline-block text-[11px] text-cyan-400 hover:underline" href="/monitor">
                "Monitor isolation posture"
            </a>
        </section>
        <SystemSection title="Identity" path="/settings/system/identity" key="identity" />
        <BackupTrustDomainSection />
        <NodeUpgradeSection />
        <RetentionPolicySection />
        <SystemSection title="Telemetry" path="/settings/system/telemetry" key="telemetry" />
        <section class="mb-4">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"License (live)"</h3>
            <p class="mb-2 text-[10px] text-zinc-600">"GET /license/status — open License topic to activate a key."</p>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading…"</p> }>
                {move || Suspend::new(async move {
                    match license.await {
                        Ok(v) => {
                            let pairs = kv_pairs(&v, &[
                                "tier", "valid_until", "instance_id", "price_cents",
                            ]);
                            let usage = v.get("usage").cloned().unwrap_or(json!({}));
                            let mut all = pairs;
                            let limits = v.get("limits").cloned().unwrap_or(json!({}));
                            all.extend(kv_pairs(&usage, &["agents", "packets"]));
                            all.extend(kv_pairs(&limits, &["max_agents", "max_packets", "retention_days"]));
                            view! { <KvList pairs=all /> }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn BackupTrustDomainSection() -> impl IntoView {
    let resource = LocalResource::new(|| api::get_value("/settings/system/backup"));
    view! {
        <section class="mb-4">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Backup / trust domain"</h3>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading…"</p> }>
                {move || Suspend::new(async move {
                    match resource.await {
                        Ok(v) => {
                            let schedule = v.get("backup").cloned().unwrap_or(json!({}));
                            let td = v.get("trust_domain").cloned().unwrap_or(json!({}));
                            let honesty = td.get("honesty").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let export_cmd = td.get("export_cmd").and_then(|x| x.as_str()).unwrap_or("connectorctl backup").to_string();
                            let restore_cmd = td.get("restore_cmd").and_then(|x| x.as_str()).unwrap_or("connectorctl restore …").to_string();
                            let docs = td.get("docs").and_then(|x| x.as_str()).unwrap_or("docs/TRUST_DOMAIN_BACKUP.md").to_string();
                            let schedule_pairs = flatten_object(&schedule);
                            view! {
                                <p class="mb-2 text-[10px] text-amber-200/90">{honesty}</p>
                                <p class="mb-1 text-[10px] text-zinc-500">"Schedule intent (does not execute backups):"</p>
                                <KvList pairs=schedule_pairs />
                                <div class="mt-3 space-y-1 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-[11px] text-zinc-300">
                                    <p><span class="text-zinc-500">"Export: "</span><code class="font-mono text-zinc-200">{export_cmd}</code></p>
                                    <p><span class="text-zinc-500">"Restore: "</span><code class="font-mono text-zinc-200">{restore_cmd}</code></p>
                                    <p><span class="text-zinc-500">"Docs: "</span>{docs}</p>
                                    <p class="text-zinc-500">"Incomplete without env key refs (JWT, audit HMAC, CFNI, cage) — see manifest."</p>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

/// P6.9 — simple retention policy editor + honest cold-tier stub.
#[component]
fn RetentionPolicySection() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (fabric_ttl, set_fabric_ttl) = signal("90".to_string());
    let (prune_days, set_prune_days) = signal("180".to_string());
    let (keep_skel, set_keep_skel) = signal(true);
    let (busy, set_busy) = signal(false);
    let (flash, set_flash) = signal(Option::<String>::None);
    let resource = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/settings/system/retention").await }
    });

    view! {
        <section class="mb-4">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Retention / cold tier"</h3>
            <p class="mb-2 text-[10px] text-amber-200/90">
                "Policy JSON is stored; jobs log TTL intent only — not yet moving cold tiers."
            </p>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading…"</p> }>
                {move || Suspend::new(async move {
                    match resource.await {
                        Ok(v) => {
                            let pol = v.get("retention").cloned().unwrap_or(json!({}));
                            let honesty = v
                                .get("honesty")
                                .or_else(|| pol.get("honesty"))
                                .and_then(|x| x.as_str())
                                .unwrap_or("not yet moving cold tiers")
                                .to_string();
                            let pairs = flatten_object(&pol);
                            // Seed editors from loaded policy once per successful fetch.
                            if let Some(n) = pol.get("fabric_ttl_days").and_then(|x| x.as_u64()) {
                                set_fabric_ttl.set(n.to_string());
                            }
                            if let Some(n) = pol.get("institution_prune_days").and_then(|x| x.as_u64()) {
                                set_prune_days.set(n.to_string());
                            }
                            if let Some(b) = pol.get("keep_skeletons").and_then(|x| x.as_bool()) {
                                set_keep_skel.set(b);
                            }
                            view! {
                                <p class="mb-2 text-[10px] text-zinc-500">{honesty}</p>
                                <KvList pairs=pairs />
                                <div class="mt-3 space-y-2 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs">
                                    <label class="flex items-center justify-between gap-2">
                                        <span class="text-zinc-500">"fabric_ttl_days"</span>
                                        <input
                                            class="w-24 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-zinc-200"
                                            prop:value=move || fabric_ttl.get()
                                            on:input=move |ev| set_fabric_ttl.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <label class="flex items-center justify-between gap-2">
                                        <span class="text-zinc-500">"institution_prune_days"</span>
                                        <input
                                            class="w-24 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-zinc-200"
                                            prop:value=move || prune_days.get()
                                            on:input=move |ev| set_prune_days.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <button
                                        type="button"
                                        class="flex w-full items-center justify-between gap-2 text-left text-zinc-400"
                                        on:click=move |_| set_keep_skel.update(|v| *v = !*v)
                                    >
                                        <span>"keep_skeletons (S retained after B move — intent)"</span>
                                        <span class="font-mono text-zinc-200">{move || if keep_skel.get() { "true" } else { "false" }}</span>
                                    </button>
                                    <div class="flex flex-wrap gap-2 pt-1">
                                        <button
                                            type="button"
                                            class="rounded-lg bg-indigo-600 px-3 py-1.5 text-[11px] font-medium text-white hover:bg-indigo-500 disabled:opacity-50"
                                            disabled=move || busy.get()
                                            on:click=move |_| {
                                                set_busy.set(true);
                                                set_flash.set(None);
                                                let body = json!({
                                                    "value": {
                                                        "schema": "retention_policy.v1",
                                                        "fabric_ttl_days": fabric_ttl.get().parse::<u32>().unwrap_or(90),
                                                        "institution_prune_days": prune_days.get().parse::<u32>().unwrap_or(180),
                                                        "keep_skeletons": keep_skel.get(),
                                                    }
                                                });
                                                spawn_local(async move {
                                                    match api::post_value("/settings/system/retention", body).await {
                                                        Ok(v) => {
                                                            if let Some(e) = api::body_error(&v) {
                                                                set_flash.set(Some(e));
                                                            } else {
                                                                set_flash.set(Some("Policy saved. Cold-tier moves are still intent-only.".into()));
                                                                set_reload.update(|n| *n = n.wrapping_add(1));
                                                            }
                                                        }
                                                        Err(e) => set_flash.set(Some(e.message)),
                                                    }
                                                    set_busy.set(false);
                                                });
                                            }
                                        >"Save policy"</button>
                                        <button
                                            type="button"
                                            class="rounded-lg border border-zinc-700 px-3 py-1.5 text-[11px] text-zinc-300 hover:bg-zinc-900 disabled:opacity-50"
                                            disabled=move || busy.get()
                                            on:click=move |_| {
                                                set_busy.set(true);
                                                set_flash.set(None);
                                                spawn_local(async move {
                                                    match api::post_value("/settings/system/retention/run-stub", json!({})).await {
                                                        Ok(v) => {
                                                            let num = |p: &str| {
                                                                v.pointer(p)
                                                                    .and_then(|x| x.as_u64())
                                                                    .map(|n| n.to_string())
                                                                    .unwrap_or_else(|| "—".to_string())
                                                            };
                                                            let status = v
                                                                .pointer("/result/status")
                                                                .and_then(|x| x.as_str())
                                                                .unwrap_or("unknown");
                                                            set_flash.set(Some(format!(
                                                                "{status}: scanned {} fabric objects, {} moments — nothing moved (TTL intent only)",
                                                                num("/result/observed/object_fabric_count"),
                                                                num("/result/observed/moment_count"),
                                                            )));
                                                        }
                                                        Err(e) => set_flash.set(Some(e.message)),
                                                    }
                                                    set_busy.set(false);
                                                });
                                            }
                                        >"Log TTL intent (dry-run)"</button>
                                    </div>
                                    {move || flash.get().map(|m| view! {
                                        <p class="text-[10px] text-amber-200/90">{m}</p>
                                    })}
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn NodeUpgradeSection() -> impl IntoView {
    let resource = LocalResource::new(|| api::get_value("/deployment/info"));
    view! {
        <section class="mb-4">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Node version / binary upgrade"</h3>
            <p class="mb-2 text-[10px] text-zinc-500">
                "Sidebar Upgrade is billing tiers. Node binary upgrade is stop → replace tarball → start (docs/PRODUCTION_UPGRADE.md)."
            </p>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading…"</p> }>
                {move || Suspend::new(async move {
                    match resource.await {
                        Ok(v) => {
                            let ver = v.get("version").and_then(|x| x.as_str())
                                .or_else(|| v.get("connector_version").and_then(|x| x.as_str()))
                                .unwrap_or("unknown")
                                .to_string();
                            view! {
                                <div class="space-y-1 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs">
                                    <div class="flex justify-between gap-2">
                                        <span class="text-zinc-500">"version"</span>
                                        <span class="font-mono text-zinc-200">{ver}</span>
                                    </div>
                                    <p class="pt-1 font-mono text-[11px] text-zinc-300">"connectorctl node-upgrade"</p>
                                    <p class="text-[10px] text-zinc-500">"No one-click remote binary install — verify SHA256SUMS / signatures first."</p>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn SystemSection(title: &'static str, path: &'static str, key: &'static str) -> impl IntoView {
    let resource = LocalResource::new(move || api::get_value(path));
    view! {
        <section class="mb-4">
            <h3 class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">{title}</h3>
            <Suspense fallback=move || view! { <p class="text-xs text-zinc-600">"Loading…"</p> }>
                {move || Suspend::new(async move {
                    match resource.await {
                        Ok(v) => {
                            let inner = v.get(key).cloned().unwrap_or(v);
                            let pairs = flatten_object(&inner);
                            view! { <KvList pairs=pairs /> }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn KvList(pairs: Vec<(String, String)>) -> impl IntoView {
    if pairs.is_empty() {
        return view! { <p class="text-xs text-zinc-600">"No fields."</p> }.into_any();
    }
    view! {
        <dl class="space-y-1.5 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
            {pairs.into_iter().map(|(k, v)| {
                view! {
                    <div class="flex justify-between gap-2 text-xs">
                        <dt class="text-zinc-500">{k}</dt>
                        <dd class="max-w-[65%] break-all text-right font-mono text-zinc-200">{v}</dd>
                    </div>
                }
            }).collect_view()}
        </dl>
    }.into_any()
}

fn kv_pairs(v: &Value, keys: &[&str]) -> Vec<(String, String)> {
    keys.iter()
        .filter_map(|k| {
            let val = v.get(*k)?;
            Some((
                (*k).to_string(),
                match val {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                },
            ))
        })
        .collect()
}

fn flatten_object(v: &Value) -> Vec<(String, String)> {
    match v.as_object() {
        Some(obj) => obj
            .iter()
            .map(|(k, val)| {
                (
                    k.clone(),
                    match val {
                        Value::String(s) => s.clone(),
                        Value::Bool(b) => b.to_string(),
                        Value::Number(n) => n.to_string(),
                        Value::Null => "null".into(),
                        other => other.to_string(),
                    },
                )
            })
            .collect(),
        None => vec![("value".into(), v.to_string())],
    }
}
