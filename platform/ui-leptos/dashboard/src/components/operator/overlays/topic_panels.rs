//! Lazy drawer topics for demoted pages (settings, memory, trust, etc.).

use leptos::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::overlays::books_economy_panel::OpBooksEconomyPanel;
use crate::components::operator::overlays::forensics::OpForensicsPanel;
use crate::components::operator::overlays::monitor_panel::OpMonitorPanel;
use crate::components::operator::overlays::result_sheet::OpResultSheet;
use crate::components::operator::overlays::secrets_webhooks_panel::{
    OpSecretsPanel, OpWebhooksPanel,
};
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpEmptyState, OpFmtUnknown, OpText, OpTextVariant,
};
use crate::request_store::bump_reload;
use crate::ui_state::{use_developer_view, DrawerTopic};

#[component]
pub fn OpTopicPanel(topic: DrawerTopic) -> impl IntoView {
    match topic {
        DrawerTopic::Monitor => view! { <OpMonitorPanel /> }.into_any(),
        DrawerTopic::Cost => view! { <OpBooksEconomyPanel /> }.into_any(),
        DrawerTopic::Memory => view! { <OpMemoryPanel /> }.into_any(),
        DrawerTopic::Secrets => view! { <OpSecretsPanel /> }.into_any(),
        DrawerTopic::Webhooks => view! { <OpWebhooksPanel /> }.into_any(),
        DrawerTopic::License => view! { <OpLicensePanel /> }.into_any(),
        DrawerTopic::Agent(pid) => view! { <crate::components::operator::overlays::OpAgentWorkbench pid=pid /> }.into_any(),
        other => view! { <OpGenericTopicPanel topic=other /> }.into_any(),
    }
}

/// Detect soft failures that return HTTP 200 with `{ error, status }` or `ok: false`.
fn soft_api_error(v: &Value) -> Option<api::ApiError> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let admission = v.get("error").and_then(|e| e.as_str()) == Some("admission_denied")
            || v.get("code").and_then(|c| c.as_str()) == Some("admission_denied");
        let message = if admission {
            let why = v
                .get("message")
                .and_then(|m| m.as_str())
                .or_else(|| v.get("denial_reason").and_then(|d| d.as_str()))
                .unwrap_or("denied by admission");
            format!("admission_denied: {why}")
        } else {
            v.get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("Request failed")
                .into()
        };
        return Some(api::ApiError {
            status: v.get("status").and_then(|s| s.as_u64()).unwrap_or(400) as u16,
            code: v
                .get("code")
                .and_then(|c| c.as_str())
                .or(if admission { Some("admission_denied") } else { None })
                .map(|s| s.to_string()),
            message,
            detail: None,
            hints: vec![],
            docs: None,
        });
    }
    if let Some(status) = v.get("status").and_then(|s| s.as_u64()) {
        if status >= 400 && v.get("error").is_some() {
            return Some(api::ApiError {
                status: status as u16,
                code: None,
                message: v
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Request failed")
                    .into(),
                detail: None,
                hints: vec![],
                docs: None,
            });
        }
    }
    None
}

#[component]
fn OpGenericTopicPanel(topic: DrawerTopic) -> impl IntoView {
    let (dev, _) = use_developer_view();
    let path = topic_api_path(&topic);
    let title = topic_title(&topic);
    let resource = LocalResource::new(move || {
        let path = path.clone();
        async move {
            match path {
                Some(p) => api::get_value(&p).await,
                None => Err(api::ApiError {
                    status: 0,
                    code: None,
                    message: "No API mapped for this topic".into(),
                    detail: None,
                    hints: vec![],
                    docs: None,
                }),
            }
        }
    });

    view! {
        <div class="space-y-4 p-4">
            <OpText text=title.to_string() variant=OpTextVariant::Title />
            <p class="text-xs text-zinc-500">{format!("GET {}", topic_api_path(&topic).unwrap_or_else(|| "—".into()))}</p>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading topic…".to_string() /> }>
                {move || {
                    let topic = topic.clone();
                    Suspend::new(async move {
                    match resource.await {
                        Ok(v) => {
                            if let Some(e) = soft_api_error(&v) {
                                return view! { <OpApiErrorBanner error=e /> }.into_any();
                            }
                            let summary = summarize_topic(&topic, &v);
                            let raw = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into());
                            view! {
                                <dl class="space-y-2 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                                    {summary.into_iter().map(|(k, val)| {
                                        view! {
                                            <div class="flex justify-between gap-2 text-xs">
                                                <dt class="text-zinc-500">{k}</dt>
                                                <dd class="font-mono text-zinc-200"><OpFmtUnknown value=val /></dd>
                                            </div>
                                        }
                                    }).collect_view()}
                                </dl>
                                <Show when=move || dev.get()>
                                    <OpDevDisclosure label="Raw JSON (developer)".to_string() raw=raw.clone() />
                                </Show>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}}
            </Suspense>
        </div>
    }
}

/// Memory / Moment — shows Object Fabric `storage_backend` (fs_cas) when API exposes it (P6.1).
#[component]
fn OpMemoryPanel() -> impl IntoView {
    let (dev, _) = use_developer_view();
    let (hydrate_msg, set_hydrate_msg) = signal(Option::<String>::None);
    let (hydrate_busy, set_hydrate_busy) = signal(false);
    let resource = LocalResource::new(|| async {
        let agents = api::get_value("/memory/agents").await;
        let moments = api::get_value("/memory/moments?limit=8").await.ok();
        let substrate = api::get_value("/substrate/status").await.ok();
        let federation = api::get_value("/runtime/federation-policy").await.ok();
        (agents, moments, substrate, federation)
    });

    view! {
        <div class="space-y-4 p-4">
            <OpText text="Memory".to_string() variant=OpTextVariant::Title />
            <p class="text-xs text-zinc-500">
                "MemPackets are SoT; Moments / Vector Box / Object Fabric are projections. storage_backend shown when present (fs_cas)."
            </p>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading memory…".to_string() /> }>
                {move || Suspend::new(async move {
                    match resource.await {
                        (Ok(agents_v), moments, substrate, federation) => {
                            if let Some(e) = soft_api_error(&agents_v) {
                                return view! { <OpApiErrorBanner error=e /> }.into_any();
                            }
                            let root = api::resource_object(&agents_v);
                            let n = root
                                .get("agents")
                                .or_else(|| root.get("items"))
                                .and_then(|x| x.as_array())
                                .map(|a| a.len().to_string())
                                .or_else(|| num_or_str(root, &["count"]))
                                .unwrap_or_else(|| "—".into());
                            let sub_root = substrate
                                .as_ref()
                                .map(|s| s.get("data").cloned().unwrap_or_else(|| s.clone()))
                                .unwrap_or(Value::Null);
                            let of = sub_root.get("object_fabric").cloned().unwrap_or(Value::Null);
                            let storage = of
                                .get("storage_backend")
                                .and_then(|x| x.as_str())
                                .unwrap_or("unavailable")
                                .to_string();
                            let of_count = of
                                .get("count")
                                .and_then(|x| x.as_u64())
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "—".into());
                            let of_honesty = of
                                .get("honesty")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .to_string();
                            let moment_root = moments
                                .as_ref()
                                .map(|m| m.get("data").cloned().unwrap_or_else(|| m.clone()))
                                .unwrap_or(Value::Null);
                            let moment_n = moment_root
                                .get("count")
                                .and_then(|x| x.as_u64())
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "—".into());
                            let moment_rows = moment_root
                                .get("moments")
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let storage_label = storage.clone();
                            let fed = federation.unwrap_or(Value::Null);
                            let deny = fed
                                .get("deny_overrides")
                                .and_then(|x| x.as_str())
                                .unwrap_or("local_only")
                                .to_string();
                            let mesh_fab = fed
                                .get("mesh_fabric")
                                .and_then(|x| x.as_bool())
                                .unwrap_or(false);
                            let fed_badge = if mesh_fab && deny != "local_only" {
                                "replicated"
                            } else {
                                "local_only"
                            };
                            let fed_tone = if fed_badge == "local_only" {
                                "bg-zinc-900 text-zinc-400 border-zinc-700/60"
                            } else {
                                "bg-emerald-950/50 text-emerald-200 border-emerald-800/40"
                            };
                            view! {
                                <dl class="space-y-2 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs">
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"memory agents"</dt>
                                        <dd class="font-mono text-zinc-200">{n}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"moments"</dt>
                                        <dd class="font-mono text-zinc-200">{moment_n}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"object_fabric count"</dt>
                                        <dd class="font-mono text-zinc-200">{of_count}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2">
                                        <dt class="text-zinc-500">"storage_backend"</dt>
                                        <dd class="font-mono text-emerald-200/90">{storage_label.clone()}</dd>
                                    </div>
                                    <div class="flex items-center justify-between gap-2">
                                        <dt class="text-zinc-500">"Knowledge federation"</dt>
                                        <dd>
                                            <span class=format!("inline-flex rounded px-2 py-0.5 font-mono text-[10px] border {fed_tone}")>
                                                {fed_badge}
                                            </span>
                                        </dd>
                                    </div>
                                </dl>
                                <p class="text-[10px] text-zinc-600">
                                    {format!(
                                        "GET /runtime/federation-policy · deny_overrides={deny} · mesh_fabric stays false until soak."
                                    )}
                                </p>
                                {if of_honesty.is_empty() {
                                    ().into_any()
                                } else {
                                    view! { <p class="text-[10px] text-amber-200/80">{of_honesty}</p> }.into_any()
                                }}
                                <section class="space-y-2">
                                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Recent moments"</p>
                                    <p class="text-[10px] text-zinc-600">
                                        "P6.2 range hydrate: GET /memory/objects/:hash?bytes=0-N (fs CAS seek stub)."
                                    </p>
                                    <Show when=move || hydrate_msg.get().is_some()>
                                        <p class="text-[11px] text-zinc-300 font-mono">
                                            {move || hydrate_msg.get().unwrap_or_default()}
                                        </p>
                                    </Show>
                                    {if moment_rows.is_empty() {
                                        // P6.11 UI — empty-state polish when Memory has no moments.
                                        view! {
                                            <OpEmptyState
                                                title="No moments yet"
                                                description="Moments are thin Object Fabric projections over MemPackets. Run a workflow or commit fabric parts — GET /memory/moments stays empty until SoT has data (unavailable ≠ zero)."
                                            />
                                        }.into_any()
                                    } else {
                                        moment_rows.into_iter().take(8).map(|m| {
                                            let id = m.get("moment_id").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                            let parts = m.get("parts").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
                                            let fabric_backend = storage_label.clone();
                                            let part_backend = m
                                                .pointer("/parts/0/fabric_meta/storage_backend")
                                                .and_then(|x| x.as_str())
                                                .map(|s| s.to_string())
                                                .unwrap_or_else(|| {
                                                    if fabric_backend == "unavailable" {
                                                        "—".into()
                                                    } else {
                                                        fabric_backend
                                                    }
                                                });
                                            let hash = m
                                                .pointer("/parts/0/content_hash")
                                                .or_else(|| m.pointer("/parts/0/object_ref"))
                                                .and_then(|x| x.as_str())
                                                .map(|s| s.trim().strip_prefix("sha256:").unwrap_or(s.trim()).to_string())
                                                .filter(|s| !s.is_empty() && s != "—");
                                            let hash_for_btn = hash.clone();
                                            let id_label = id.clone();
                                            view! {
                                                <div class="space-y-1 rounded border border-zinc-800/50 px-2 py-1.5 text-[11px]">
                                                    <div class="flex justify-between gap-2">
                                                        <span class="font-mono text-zinc-300" id=format!("moment-{}", id_label)>{id}</span>
                                                        <span class="text-zinc-500">{format!("{parts} parts · {part_backend}")}</span>
                                                    </div>
                                                    {match hash_for_btn {
                                                        Some(h) => {
                                                            let h2 = h.clone();
                                                            view! {
                                                                <div class="flex flex-wrap items-center gap-2">
                                                                    <span class="font-mono text-[10px] text-zinc-600 truncate max-w-[40%]">{format!("sha256:{h}")}</span>
                                                                    <OpButton
                                                                        label="Range hydrate 0-255".to_string()
                                                                        variant=OpButtonVariant::Ghost
                                                                        loading=hydrate_busy.get()
                                                                        on_click=Arc::new(move |_| {
                                                                            let path = format!("/memory/objects/{h2}?bytes=0-255");
                                                                            set_hydrate_busy.set(true);
                                                                            set_hydrate_msg.set(Some(format!("GET {path}…")));
                                                                            spawn_local(async move {
                                                                                match api::get_bytes(&path).await {
                                                                                    Ok(bytes) => {
                                                                                        set_hydrate_msg.set(Some(format!(
                                                                                            "GET {path} → {} bytes (x-connector-range-hydrate)"
                                                                                            , bytes.len()
                                                                                        )));
                                                                                    }
                                                                                    Err(e) => {
                                                                                        set_hydrate_msg.set(Some(format!(
                                                                                            "GET {path} failed: {}",
                                                                                            e.message
                                                                                        )));
                                                                                    }
                                                                                }
                                                                                set_hydrate_busy.set(false);
                                                                            });
                                                                        })
                                                                    />
                                                                </div>
                                                            }.into_any()
                                                        }
                                                        None => view! {
                                                            <p class="text-[10px] text-zinc-600">"No content_hash on part[0] — range hydrate unavailable."</p>
                                                        }.into_any(),
                                                    }}
                                                </div>
                                            }
                                        }).collect_view().into_any()
                                    }}
                                </section>
                                <OpForensicsPanel load_status=true />
                                <Show when=move || dev.get()>
                                    <OpDevDisclosure
                                        label="Raw agents JSON (developer)".to_string()
                                        raw=serde_json::to_string_pretty(&agents_v).unwrap_or_else(|_| "{}".into())
                                    />
                                </Show>
                            }.into_any()
                        }
                        (Err(e), _, _, _) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn OpLicensePanel() -> impl IntoView {
    let (dev, _) = use_developer_view();
    let (reload, set_reload) = signal(0u32);
    let (key, set_key) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (flash, set_flash) = signal(Option::<(String, bool)>::None);

    let resource = LocalResource::new(move || {
        let _ = reload.get();
        async move {
            let status = api::get_value("/license/status").await;
            let machine = api::get_value("/license/machine").await.ok();
            (status, machine)
        }
    });

    view! {
        <div class="space-y-4 p-4">
            <OpText text="License".to_string() variant=OpTextVariant::Title />
            <p class="text-xs text-zinc-500">
                "Live status from GET /license/status + machine binding. Activate with POST /license/activate { license_key }."
            </p>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading license…".to_string() /> }>
                {move || Suspend::new(async move {
                    let (status, machine) = resource.await;
                    match status {
                        Ok(v) => {
                            if let Some(e) = soft_api_error(&v) {
                                return view! { <OpApiErrorBanner error=e /> }.into_any();
                            }
                            let machine_id = machine
                                .as_ref()
                                .and_then(|m| m.get("machine_id").and_then(|x| x.as_str()))
                                .unwrap_or("—")
                                .to_string();
                            let hostname = machine
                                .as_ref()
                                .and_then(|m| m.get("hostname").and_then(|x| x.as_str()))
                                .unwrap_or("—")
                                .to_string();
                            let usage = v.get("usage").cloned().unwrap_or(json!({}));
                            let limits = v.get("limits").cloned().unwrap_or(json!({}));
                            let raw = serde_json::to_string_pretty(&v).unwrap_or_default();
                            view! {
                                <dl class="space-y-2 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                                    <div class="flex justify-between gap-2 text-xs">
                                        <dt class="text-zinc-500">"tier"</dt>
                                        <dd class="font-mono text-zinc-200">{str_field(&v, &["tier"]).unwrap_or_else(|| "—".into())}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2 text-xs">
                                        <dt class="text-zinc-500">"valid_until"</dt>
                                        <dd class="font-mono text-zinc-200">{str_field(&v, &["valid_until"]).unwrap_or_else(|| "—".into())}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2 text-xs">
                                        <dt class="text-zinc-500">"instance_id"</dt>
                                        <dd class="font-mono text-zinc-200">{str_field(&v, &["instance_id"]).unwrap_or_else(|| "—".into())}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2 text-xs">
                                        <dt class="text-zinc-500">"agents"</dt>
                                        <dd class="font-mono text-zinc-200">{format!(
                                            "{}/{}",
                                            num_or_str(&usage, &["agents"]).unwrap_or_else(|| "—".into()),
                                            num_or_str(&limits, &["max_agents"]).unwrap_or_else(|| "—".into()),
                                        )}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2 text-xs">
                                        <dt class="text-zinc-500">"packets"</dt>
                                        <dd class="font-mono text-zinc-200">{format!(
                                            "{}/{}",
                                            num_or_str(&usage, &["packets"]).unwrap_or_else(|| "—".into()),
                                            num_or_str(&limits, &["max_packets"]).unwrap_or_else(|| "—".into()),
                                        )}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2 text-xs">
                                        <dt class="text-zinc-500">"machine_id"</dt>
                                        <dd class="font-mono text-zinc-200">{machine_id}</dd>
                                    </div>
                                    <div class="flex justify-between gap-2 text-xs">
                                        <dt class="text-zinc-500">"hostname"</dt>
                                        <dd class="font-mono text-zinc-200">{hostname}</dd>
                                    </div>
                                </dl>
                                <Show when=move || dev.get()>
                                    <OpDevDisclosure label="Raw license JSON".to_string() raw=raw.clone() />
                                </Show>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>

            <section class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 space-y-2">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Activate key"</p>
                <input
                    type="text"
                    class="w-full rounded-lg border border-zinc-700/60 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 focus:border-indigo-500/60 focus:outline-none"
                    placeholder="cnk-XXXXX-XXXXX-XXXXX"
                    prop:value=move || key.get()
                    on:input=move |ev| set_key.set(event_target_value(&ev))
                />
                <OpButton
                    label=if busy.get() {
                        "Activating…".to_string()
                    } else {
                        "Activate".to_string()
                    }
                    variant=OpButtonVariant::Primary
                    loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let license_key = key.get().trim().to_string();
                        if license_key.is_empty() {
                            set_flash.set(Some(("Paste a license key first.".into(), false)));
                            return;
                        }
                        set_busy.set(true);
                        set_flash.set(None);
                        spawn_local(async move {
                            match api::post_value(
                                "/license/activate",
                                json!({ "license_key": license_key }),
                            )
                            .await
                            {
                                Ok(v) => {
                                    if let Some(e) = soft_api_error(&v) {
                                        set_flash.set(Some((e.message, false)));
                                    } else if v.get("activated").and_then(|x| x.as_bool()) == Some(true)
                                    {
                                        set_flash.set(Some((
                                            format!(
                                                "Activated · {}",
                                                v.get("tier")
                                                    .and_then(|t| t.as_str())
                                                    .unwrap_or("ok")
                                            ),
                                            true,
                                        )));
                                        set_key.set(String::new());
                                        set_reload.update(|n| *n = n.wrapping_add(1));
                                        bump_reload();
                                    } else {
                                        set_flash.set(Some((
                                            v.get("error")
                                                .and_then(|e| e.as_str())
                                                .unwrap_or("Activation failed")
                                                .into(),
                                            false,
                                        )));
                                    }
                                }
                                Err(e) => set_flash.set(Some((e.message, false))),
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <Show when=move || flash.get().is_some()>
                    <p class=move || {
                        let ok = flash.get().map(|(_, ok)| ok).unwrap_or(false);
                        if ok {
                            "text-xs text-emerald-400"
                        } else {
                            "text-xs text-amber-400"
                        }
                    }>
                        {move || flash.get().map(|(m, _)| m).unwrap_or_default()}
                    </p>
                </Show>
            </section>
        </div>
    }
}

#[component]
fn OpAgentPanel(pid: String) -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (busy, set_busy) = signal(false);
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());
    let pid_res = pid.clone();
    let resource = LocalResource::new(move || {
        let pid = pid_res.clone();
        let _ = reload.get();
        async move {
            let detail = api::get_value(&format!("/agents/{pid}")).await;
            let receipts = api::get_value(&format!("/agents/{pid}/audit/receipts")).await.ok();
            (detail, receipts)
        }
    });

    view! {
        <div class="space-y-4 p-4">
            <OpText text=format!("Agent {pid}") variant=OpTextVariant::Title />
            <p class="text-xs text-zinc-500">"Live agent detail, receipts, pause/resume/kill, HITL approve/deny."</p>
            <div class="flex flex-wrap gap-2">
                {
                    let pid_a = pid.clone();
                    view! {
                        <OpButton label="Pause".to_string() variant=OpButtonVariant::Secondary loading=busy.get()
                            on_click=Arc::new(move |_| {
                                let pid = pid_a.clone();
                                set_busy.set(true);
                                spawn_local(async move {
                                    post_agent_action(&pid, "pause", &set_result_title, &set_result_summary, &set_result_open, &set_reload).await;
                                    set_busy.set(false);
                                });
                            }) />
                    }
                }
                {
                    let pid_a = pid.clone();
                    view! {
                        <OpButton label="Resume".to_string() variant=OpButtonVariant::Secondary loading=busy.get()
                            on_click=Arc::new(move |_| {
                                let pid = pid_a.clone();
                                set_busy.set(true);
                                spawn_local(async move {
                                    post_agent_action(&pid, "resume", &set_result_title, &set_result_summary, &set_result_open, &set_reload).await;
                                    set_busy.set(false);
                                });
                            }) />
                    }
                }
                {
                    let pid_a = pid.clone();
                    view! {
                        <OpButton label="Kill / stop".to_string() variant=OpButtonVariant::Ghost loading=busy.get()
                            on_click=Arc::new(move |_| {
                                let pid = pid_a.clone();
                                set_busy.set(true);
                                spawn_local(async move {
                                    post_agent_action(&pid, "kill", &set_result_title, &set_result_summary, &set_result_open, &set_reload).await;
                                    set_busy.set(false);
                                });
                            }) />
                    }
                }
            </div>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading agent…".to_string() /> }>
                {move || {
                    let pid = pid.clone();
                    Suspend::new(async move {
                    let (detail, receipts) = resource.await;
                    match detail {
                        Ok(v) => {
                            let hitl = v
                                .get("hitl_requests")
                                .or_else(|| v.get("pending_hitl"))
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let receipt_rows = receipts
                                .as_ref()
                                .and_then(|r| {
                                    r.get("receipts")
                                        .or_else(|| r.get("items"))
                                        .or_else(|| r.get("data"))
                                        .and_then(|x| x.as_array())
                                        .cloned()
                                })
                                .unwrap_or_default();
                            view! {
                                <div class="space-y-3">
                                    <dl class="space-y-1.5 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3 text-xs">
                                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"pid"</dt><dd class="font-mono text-zinc-100">{str_field(&v, &["pid"]).unwrap_or_else(|| "—".into())}</dd></div>
                                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"name"</dt><dd class="font-mono text-zinc-200">{str_field(&v, &["name"]).unwrap_or_else(|| "—".into())}</dd></div>
                                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"status"</dt><dd class="font-mono text-zinc-200">{str_field(&v, &["status", "state"]).unwrap_or_else(|| "—".into())}</dd></div>
                                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"model"</dt><dd class="font-mono text-zinc-200">{str_field(&v, &["model"]).unwrap_or_else(|| "—".into())}</dd></div>
                                    </dl>
                                    <section class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                                        <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"HITL queue"</p>
                                        {if hitl.is_empty() {
                                            view! { <p class="mt-1 text-xs text-zinc-600">"No pending HITL requests on this agent payload."</p> }.into_any()
                                        } else {
                                            hitl.into_iter().map(|req| {
                                                let rid = req.get("request_id").or_else(|| req.get("id")).and_then(|x| x.as_str()).unwrap_or("").to_string();
                                                let summary = req.get("reason").or_else(|| req.get("operation")).and_then(|x| x.as_str()).unwrap_or("HITL").to_string();
                                                let pid_a = pid.clone();
                                                let pid_d = pid.clone();
                                                let rid_a = rid.clone();
                                                let rid_d = rid.clone();
                                                view! {
                                                    <div class="mt-2 flex items-start justify-between gap-2 border-t border-zinc-800/50 pt-2">
                                                        <div class="min-w-0">
                                                            <p class="truncate font-mono text-xs text-zinc-200">{rid.clone()}</p>
                                                            <p class="truncate text-[11px] text-zinc-500">{summary}</p>
                                                        </div>
                                                        <div class="flex shrink-0 gap-1">
                                                            <OpButton label="Approve".to_string() variant=OpButtonVariant::Primary
                                                                on_click=Arc::new(move |_| {
                                                                    let pid = pid_a.clone();
                                                                    let rid = rid_a.clone();
                                                                    set_busy.set(true);
                                                                    spawn_local(async move {
                                                                        match api::post_value(&format!("/agents/{pid}/hitl/{rid}/approve"), json!({"note":"operator-ui"})).await {
                                                                            Ok(v) => {
                                                                                set_result_title.set(format!("Approved {rid}"));
                                                                                set_result_summary.set(format!("POST /agents/{pid}/hitl/{rid}/approve\n{}", serde_json::to_string_pretty(&v).unwrap_or_default()));
                                                                                set_result_open.set(true);
                                                                                set_reload.update(|n| *n = n.wrapping_add(1));
                                                                                bump_reload();
                                                                            }
                                                                            Err(e) => {
                                                                                set_result_title.set("Approve failed".into());
                                                                                set_result_summary.set(format!("POST /agents/{pid}/hitl/{rid}/approve\n{}", e.message));
                                                                                set_result_open.set(true);
                                                                            }
                                                                        }
                                                                        set_busy.set(false);
                                                                    });
                                                                }) />
                                                            <OpButton label="Deny".to_string() variant=OpButtonVariant::Ghost
                                                                on_click=Arc::new(move |_| {
                                                                    let pid = pid_d.clone();
                                                                    let rid = rid_d.clone();
                                                                    set_busy.set(true);
                                                                    spawn_local(async move {
                                                                        match api::post_value(&format!("/agents/{pid}/hitl/{rid}/deny"), json!({"reason":"denied from operator-ui"})).await {
                                                                            Ok(v) => {
                                                                                set_result_title.set(format!("Denied {rid}"));
                                                                                set_result_summary.set(format!("POST /agents/{pid}/hitl/{rid}/deny\n{}", serde_json::to_string_pretty(&v).unwrap_or_default()));
                                                                                set_result_open.set(true);
                                                                                set_reload.update(|n| *n = n.wrapping_add(1));
                                                                                bump_reload();
                                                                            }
                                                                            Err(e) => {
                                                                                set_result_title.set("Deny failed".into());
                                                                                set_result_summary.set(format!("POST /agents/{pid}/hitl/{rid}/deny\n{}", e.message));
                                                                                set_result_open.set(true);
                                                                            }
                                                                        }
                                                                        set_busy.set(false);
                                                                    });
                                                                }) />
                                                        </div>
                                                    </div>
                                                }
                                            }).collect_view().into_any()
                                        }}
                                    </section>
                                    <section class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
                                        <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Audit receipts"</p>
                                        <p class="mt-1 font-mono text-[10px] text-zinc-600">{format!("GET /agents/{pid}/audit/receipts")}</p>
                                        {if receipt_rows.is_empty() {
                                            view! { <p class="mt-1 text-xs text-zinc-600">"No receipts for this agent."</p> }.into_any()
                                        } else {
                                            receipt_rows.into_iter().take(12).map(|r| {
                                                let id = r.get("receipt_id").or_else(|| r.get("entry_id")).or_else(|| r.get("id")).and_then(|x| x.as_str()).unwrap_or("receipt").to_string();
                                                let summary = r.get("summary").or_else(|| r.get("operation")).and_then(|x| x.as_str()).unwrap_or("receipt").to_string();
                                                view! {
                                                    <div class="mt-1 flex justify-between gap-2 border-b border-zinc-800/40 py-1 text-[11px]">
                                                        <span class="truncate font-mono text-zinc-300">{id}</span>
                                                        <span class="truncate text-zinc-500">{summary}</span>
                                                    </div>
                                                }
                                            }).collect_view().into_any()
                                        }}
                                    </section>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}}
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

async fn post_agent_action(
    pid: &str,
    action: &str,
    set_title: &WriteSignal<String>,
    set_summary: &WriteSignal<String>,
    set_open: &WriteSignal<bool>,
    set_reload: &WriteSignal<u32>,
) {
    let path = format!("/agents/{pid}/{action}");
    match api::post_value(&path, json!({})).await {
        Ok(v) => {
            set_title.set(format!("{action} · {pid}"));
            set_summary.set(format!(
                "POST {path}\n{}",
                serde_json::to_string_pretty(&v).unwrap_or_default()
            ));
            set_open.set(true);
            set_reload.update(|n| *n = n.wrapping_add(1));
            bump_reload();
        }
        Err(e) => {
            set_title.set(format!("{action} failed"));
            set_summary.set(format!("POST {path}\n{}", e.message));
            set_open.set(true);
        }
    }
}

fn topic_title(t: &DrawerTopic) -> &'static str {
    match t {
        DrawerTopic::Settings(_) => "Settings",
        DrawerTopic::Memory => "Memory",
        DrawerTopic::Trust => "Trust",
        DrawerTopic::Cost => "Books · economy",
        DrawerTopic::Safety => "Safety",
        DrawerTopic::Monitor => "Monitor",
        DrawerTopic::Conductor => "Conductor",
        DrawerTopic::Notifications => "Notifications",
        DrawerTopic::Secrets => "Secrets",
        DrawerTopic::Webhooks => "Webhooks",
        DrawerTopic::License => "License",
        DrawerTopic::Billing => "Billing",
        DrawerTopic::Agent(_) => "Agent",
        DrawerTopic::Workflow(_) => "Workflow",
        DrawerTopic::None => "Topic",
    }
}

fn topic_api_path(t: &DrawerTopic) -> Option<String> {
    match t {
        // Settings cards use OpSettingsPanel — these paths only matter if Settings
        // somehow falls through to the generic panel.
        DrawerTopic::Settings(kind) if kind == "llm" => Some("/deployment/info".into()),
        DrawerTopic::Settings(_) => Some("/deployment/info".into()),
        DrawerTopic::Memory => Some("/memory/agents".into()),
        // Live trust score lives on the monitor plane (no /trust/score route).
        DrawerTopic::Trust => Some("/monitor/trust".into()),
        DrawerTopic::Cost => Some("/books/costs".into()),
        DrawerTopic::Safety => Some("/firewall/status".into()),
        DrawerTopic::Monitor => Some("/monitor/health".into()),
        DrawerTopic::Conductor => Some("/multiagent/intelligence/standard".into()),
        DrawerTopic::Notifications => Some("/notifications".into()),
        DrawerTopic::Secrets => Some("/secrets/audit".into()),
        DrawerTopic::Webhooks => Some("/webhooks".into()),
        DrawerTopic::License => Some("/license/status".into()),
        DrawerTopic::Billing => Some("/billing/entitlements".into()),
        DrawerTopic::Agent(pid) => Some(format!("/agents/{pid}")),
        _ => None,
    }
}

fn summarize_topic(t: &DrawerTopic, v: &Value) -> Vec<(String, Option<String>)> {
    let root = api::resource_object(v);
    match t {
        DrawerTopic::License => vec![
            ("tier".into(), str_field(root, &["tier", "license_tier"])),
            ("valid_until".into(), str_field(root, &["valid_until", "expires_at"])),
            ("instance_id".into(), str_field(root, &["instance_id"])),
            (
                "agents".into(),
                num_or_str(root.get("usage").unwrap_or(&Value::Null), &["agents"]),
            ),
        ],
        DrawerTopic::Billing => vec![
            ("tier".into(), str_field(root, &["tier"])),
            ("tokens/day".into(), num_or_str(root, &["tokens_per_day"])),
            ("tokens/month".into(), num_or_str(root, &["tokens_per_month"])),
            ("max_agents".into(), num_or_str(root, &["max_agents"])),
            (
                "memory_retention_days".into(),
                num_or_str(root, &["memory_retention_days"]),
            ),
            (
                "sso".into(),
                root.get("sso_enabled").map(|x| x.to_string()),
            ),
        ],
        DrawerTopic::Settings(_) => vec![
            ("mode".into(), str_field(root, &["mode"])),
            ("edition".into(), str_field(root, &["edition"])),
            ("version".into(), str_field(root, &["version"])),
            ("public_url".into(), str_field(root, &["public_url"])),
            ("license_tier".into(), str_field(root, &["license_tier"])),
        ],
        DrawerTopic::Trust => vec![
            ("score".into(), num_or_str(root, &["score", "trust_score"])),
            ("grade".into(), str_field(root, &["trust_grade"])),
            (
                "verifiable".into(),
                root.get("verifiable").map(|x| x.to_string()),
            ),
            ("denied".into(), num_or_str(root, &["denied_total"])),
            ("failed".into(), num_or_str(root, &["failed_total"])),
        ],
        DrawerTopic::Cost => vec![
            ("tokens".into(), num_or_str(root, &["tokens", "token_count"])),
            ("calls".into(), num_or_str(root, &["api_calls", "calls"])),
            ("estimated_usd".into(), num_or_str(root, &["estimated_usd", "usd"])),
        ],
        DrawerTopic::Safety => {
            let agents = root
                .get("agents")
                .and_then(|a| a.as_array())
                .map(|a| a.len().to_string())
                .or_else(|| num_or_str(root, &["agents_tracked", "kernel_agents"]));
            vec![
                ("enabled".into(), root.get("enabled").map(|x| x.to_string())),
                ("breakers_open".into(), num_or_str(root, &["breakers_open"])),
                (
                    "dynamic_rules".into(),
                    num_or_str(root, &["dynamic_rules_loaded"]),
                ),
                ("agents".into(), agents),
            ]
        }
        DrawerTopic::Notifications => {
            let n = root
                .get("notifications")
                .or_else(|| root.get("items"))
                .and_then(|x| x.as_array())
                .map(|a| a.len().to_string());
            vec![("count".into(), n)]
        }
        DrawerTopic::Memory => {
            let n = root
                .get("agents")
                .or_else(|| root.get("items"))
                .and_then(|x| x.as_array())
                .map(|a| a.len().to_string())
                .or_else(|| num_or_str(root, &["count"]));
            let empty = n.as_ref().map(|s| s == "0").unwrap_or(true);
            vec![
                ("memory agents".into(), n),
                (
                    "empty_state".into(),
                    Some(if empty {
                        "No memory agents listed — not the same as Knot rebuild. Check GET /substrate/status for knot_node_count, last_flush_ms, and wal_status (rebuilding vs no data)."
                            .into()
                    } else {
                        "MemPackets are SoT; Knot rebuilds from packets; Vector Box / Moment are projections."
                            .into()
                    }),
                ),
                (
                    "hint".into(),
                    Some("Open an agent drawer for /agents/{pid}/memory/* · moment recall: POST /memory/moment/:id/recall".into()),
                ),
            ]
        }
        DrawerTopic::Conductor => vec![
            ("schema".into(), str_field(root, &["schema", "contract"])),
            ("title".into(), str_field(root, &["title", "name"])),
            (
                "empty_state".into(),
                Some(
                    "No multi-agent fleet listed here — catalog SoT is GET /api/v1/agents (VAC kernel ACBs via services::agents; dual_registry=false). See GET /agents/sot-status. Orphan agent_lifecycle::AgentRegistry is not a second list."
                        .into(),
                ),
            ),
            (
                "hint".into(),
                Some("Intelligence contract — fleet catalog is GET /agents, not a parallel registry".into()),
            ),
        ],
        _ => vec![
            ("ok".into(), root.get("ok").or_else(|| v.get("ok")).map(|x| x.to_string())),
            ("schema".into(), str_field(root, &["schema"])),
            ("count".into(), num_or_str(root, &["count"])),
        ],
    }
}

fn str_field(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
        if let Some(s) = v.pointer(&format!("/{k}")).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

fn num_or_str(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(n) = v.get(*k).and_then(|x| x.as_u64()) {
            return Some(n.to_string());
        }
        if let Some(n) = v.get(*k).and_then(|x| x.as_f64()) {
            return Some(format!("{n}"));
        }
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}
