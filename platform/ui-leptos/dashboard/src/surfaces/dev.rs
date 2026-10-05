//! DEV builder hub — packages, author, CLS, catalog, surface, SDK, console, lab.
//! Enable stays on RUN (lifecycle). Talk does not auto-dispatch tools.

use base64::Engine as _;
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpFilterTabs, OpSpinner, OpText, OpTextField, OpTextVariant,
};
use crate::surfaces::advanced_dev::AdvancedDevCanvas;
use crate::surfaces::console::ConsoleCanvas;

fn initial_tab() -> String {
    query_param("tab").unwrap_or_else(|| "packages".into())
}

fn query_param(key: &str) -> Option<String> {
    let w = web_sys::window()?;
    let search = w.location().search().ok()?;
    for part in search.trim_start_matches('?').split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key && !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

const TOOL_MAP: &[(&str, &str, &str)] = &[
    ("memory_write", "POST /api/v1/memory/write", "MemPacket + optional Object Fabric parts"),
    ("moment_commit", "Moment beside LLM/MemWrite", "MomentManifestV2"),
    ("usage_record", "UsageEventV2 append", "Fuel meter — never invent $"),
    ("artifact_append", "ArtifactLogRecordV2", "Execution artifacts"),
    ("mcp / tools", "POST /tools/mcp/invoke", "ToolDispatch after PATE admit"),
    ("DAL turn", "POST /dal/:run_id/turn", "tool_calls are proposals only"),
];

#[component]
pub fn DevCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let query = use_query_map();
    let (tab, set_tab) = signal(initial_tab());

    Effect::new(move |_| {
        if let Some(t) = query.get().get_str("tab").map(|s| s.to_string()) {
            if !t.is_empty() && t != tab.get_untracked() {
                set_tab.set(t);
            }
        }
    });

    view! {
        <div class="w-full">
            <div class="shrink-0 border-b border-zinc-800/60 px-4 py-4 sm:px-6">
                <OpText text="DEV".to_string() variant=OpTextVariant::Title />
                <p class="mt-1 text-sm text-zinc-500">
                    "Author CCL tools → compile → package. Enable on RUN. SDK drives the same PATE → ToolDispatch path."
                </p>
                <div class="mt-4">
                    <OpFilterTabs
                        tabs=vec![
                            ("packages", "Packages"),
                            ("author", "Author"),
                            ("cls", "CLS"),
                            ("catalog", "Catalog"),
                            ("surface", "Surface"),
                            ("sdk", "SDK"),
                            ("console", "Console"),
                            ("lab", "Lab"),
                        ]
                        active=tab
                        set_active=set_tab
                    />
                </div>
            </div>
            <div class="px-4 py-4 sm:px-6 pb-10">
                {move || match tab.get().as_str() {
                    "author" => view! { <DevAuthorPanel /> }.into_any(),
                    "cls" => view! { <DevClsPanel /> }.into_any(),
                    "catalog" => view! { <DevCatalogPanel /> }.into_any(),
                    "surface" => view! { <DevSurfacePanel /> }.into_any(),
                    "sdk" => view! { <DevSdkPanel /> }.into_any(),
                    "console" => view! { <ConsoleCanvas auth=auth /> }.into_any(),
                    "lab" => view! { <AdvancedDevCanvas auth=auth /> }.into_any(),
                    _ => view! { <DevPackagesPanel /> }.into_any(),
                }}
            </div>
        </div>
    }
}

#[component]
fn DevPackagesPanel() -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (error, set_error) = signal(String::new());
    let (notice, set_notice) = signal(String::new());
    let (cpkg_url, set_cpkg_url) = signal(String::new());
    let (cpkg_hub_id, set_cpkg_hub_id) = signal(String::new());
    let (cpkg_hub_ver, set_cpkg_hub_ver) = signal(String::new());
    let (cpkg_b64, set_cpkg_b64) = signal(String::new());
    let (cpkg_file_name, set_cpkg_file_name) = signal(String::new());
    let (result, set_result) = signal(String::new());

    let install = Arc::new(move |_| {
        set_busy.set(true);
        set_error.set(String::new());
        set_notice.set(String::new());
        set_result.set(String::new());
        let url = cpkg_url.get_untracked().trim().to_string();
        let hub_id = cpkg_hub_id.get_untracked().trim().to_string();
        let hub_ver = cpkg_hub_ver.get_untracked().trim().to_string();
        let b64 = cpkg_b64.get_untracked();
        spawn_local(async move {
            let body = if !b64.is_empty() {
                json!({ "bytes_b64": b64 })
            } else if !url.is_empty() {
                json!({ "url": url })
            } else if !hub_id.is_empty() {
                json!({
                    "hub_fetch": {
                        "plugin_id": hub_id,
                        "version": if hub_ver.is_empty() { Value::Null } else { json!(hub_ver) }
                    }
                })
            } else {
                set_error.set("Provide a .cpkg file, URL, or hub id.".into());
                set_busy.set(false);
                return;
            };
            match api::post_value("/plugins/cpkg/preflight", body.clone()).await {
                Ok(v) => {
                    if let Some(msg) = fail_message(&v) {
                        set_error.set(format!("Preflight: {msg}"));
                        set_busy.set(false);
                        return;
                    }
                    set_notice.set("Preflight ok — installing…".into());
                }
                Err(e) => {
                    set_error.set(format!("Preflight failed: {}", e.message));
                    set_busy.set(false);
                    return;
                }
            }
            match api::post_value("/plugins/cpkg/install", body).await {
                Ok(v) => {
                    if let Some(msg) = fail_message(&v) {
                        set_error.set(msg);
                    } else {
                        set_notice.set("Install accepted.".into());
                        set_result.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                    }
                }
                Err(e) => set_error.set(e.message),
            }
            set_busy.set(false);
        });
    });

    view! {
        <div class="mx-auto max-w-2xl space-y-4">
            <p class="text-sm text-zinc-400">
                "Install a signed .cpkg (file / URL / hub_fetch). Unsigned packages are refused when CONNECTOR_CPKG_REQUIRE_SIGNATURE=1. Enable the workflow on RUN after install."
            </p>
            <Show when=move || !error.get().is_empty()>
                <p class="rounded-md border border-red-900/40 bg-red-950/30 px-3 py-2 text-xs text-red-300">{move || error.get()}</p>
            </Show>
            <Show when=move || !notice.get().is_empty()>
                <p class="rounded-md border border-emerald-900/40 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200">{move || notice.get()}</p>
            </Show>
            <div class="space-y-3 rounded-lg border border-zinc-800/70 bg-zinc-900/30 p-4">
                <label class="block text-xs text-zinc-400">
                    ".cpkg file"
                    <input
                        type="file"
                        accept=".cpkg,.zip,application/octet-stream"
                        class="mt-1 block w-full text-xs text-zinc-300 file:mr-2 file:rounded file:border-0 file:bg-zinc-800 file:px-2 file:py-1 file:text-zinc-200"
                        on:change=move |ev| {
                            let Some(input) = ev
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                            else {
                                return;
                            };
                            let Some(files) = input.files() else { return };
                            let Some(file) = files.get(0) else { return };
                            let name = file.name();
                            set_cpkg_file_name.set(name.clone());
                            set_error.set(String::new());
                            let gf = gloo_file::File::from(file);
                            spawn_local(async move {
                                match gloo_file::futures::read_as_bytes(&gf).await {
                                    Ok(bytes) => {
                                        let n = bytes.len();
                                        set_cpkg_b64.set(
                                            base64::engine::general_purpose::STANDARD.encode(bytes),
                                        );
                                        set_notice.set(format!("Read {name} ({n} bytes). Click Preflight + install."));
                                    }
                                    Err(e) => {
                                        set_cpkg_b64.set(String::new());
                                        set_error.set(format!("Could not read file: {e}"));
                                    }
                                }
                            });
                        }
                    />
                </label>
                <Show when=move || !cpkg_file_name.get().is_empty()>
                    <p class="font-mono text-[11px] text-zinc-500">{move || cpkg_file_name.get()}</p>
                </Show>
                <OpTextField label="Or URL".to_string() value=cpkg_url set_value=set_cpkg_url placeholder="https://…/pkg.cpkg" />
                <div class="grid gap-2 sm:grid-cols-2">
                    <OpTextField label="Hub plugin id".to_string() value=cpkg_hub_id set_value=set_cpkg_hub_id placeholder="acme-slack" />
                    <OpTextField label="Hub version".to_string() value=cpkg_hub_ver set_value=set_cpkg_hub_ver placeholder="1.0.0" />
                </div>
                <OpButton label="Preflight + install".to_string() variant=OpButtonVariant::Primary loading=busy.get() on_click=install />
            </div>
            <Show when=move || !result.get().is_empty()>
                <pre class="overflow-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-400">{move || result.get()}</pre>
            </Show>
            <p class="text-[11px] text-zinc-500">
                "Hub workflow publish stays honesty-stub: "
                <a class="text-indigo-400 hover:underline" href="/dev?tab=console">"POST /hub/workflows/publish"</a>
                " → implemented: false."
            </p>
        </div>
    }
}

#[component]
fn DevAuthorPanel() -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (error, set_error) = signal(String::new());
    let (notice, set_notice) = signal(String::new());
    let (wf_id, set_wf_id) = signal(String::new());
    let (package_id, set_package_id) = signal("basic_tool_agent".to_string());
    let (cls_source, set_cls_source) = signal(String::new());
    let (accounting_mode, set_accounting_mode) = signal("action".to_string());

    view! {
        <div class="mx-auto max-w-3xl space-y-4">
            <div class="rounded-lg border border-zinc-800/70 bg-zinc-900/30 p-4">
                <h3 class="text-sm font-medium text-zinc-200">"CCL tool → substrate map"</h3>
                <p class="mt-1 text-[11px] text-zinc-500">"Workflows name substrate tools. ENABLE is on RUN (compile → stage → enable)."</p>
                <table class="mt-3 w-full text-left text-[11px]">
                    <thead class="text-zinc-500">
                        <tr><th class="py-1 pr-2">"CCL"</th><th class="py-1 pr-2">"Surface"</th><th class="py-1">"Note"</th></tr>
                    </thead>
                    <tbody class="text-zinc-300">
                        {TOOL_MAP.iter().map(|(a, b, c)| view! {
                            <tr class="border-t border-zinc-800/50">
                                <td class="py-1.5 pr-2 font-mono text-indigo-300">{*a}</td>
                                <td class="py-1.5 pr-2 font-mono">{*b}</td>
                                <td class="py-1.5 text-zinc-500">{*c}</td>
                            </tr>
                        }).collect_view()}
                    </tbody>
                </table>
            </div>
            <Show when=move || !error.get().is_empty()>
                <p class="rounded-md border border-red-900/40 bg-red-950/30 px-3 py-2 text-xs text-red-300">{move || error.get()}</p>
            </Show>
            <Show when=move || !notice.get().is_empty()>
                <p class="rounded-md border border-emerald-900/40 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200">{move || notice.get()}</p>
            </Show>
            <OpTextField label="Workflow ID".to_string() value=wf_id set_value=set_wf_id placeholder="my-workflow" />
            <OpTextField label="Package ID".to_string() value=package_id set_value=set_package_id placeholder="basic_tool_agent" />
            <fieldset class="space-y-2 rounded-lg border border-zinc-800/70 p-3">
                <legend class="px-1 text-xs font-semibold uppercase tracking-wide text-zinc-500">"Accounting mode"</legend>
                <label class="flex gap-2 text-xs text-zinc-200">
                    <input type="radio" prop:checked=move || accounting_mode.get() == "action" on:change=move |_| set_accounting_mode.set("action".into()) />
                    "action — agents / HITL"
                </label>
                <label class="flex gap-2 text-xs text-zinc-200">
                    <input type="radio" prop:checked=move || accounting_mode.get() == "service_monitoring" on:change=move |_| set_accounting_mode.set("service_monitoring".into()) />
                    "service_monitoring — observe / seal"
                </label>
            </fieldset>
            <label class="block text-xs text-zinc-400">
                "CCL source"
                <textarea
                    class="mt-1 min-h-[160px] w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200"
                    prop:value=move || cls_source.get()
                    on:input=move |ev| set_cls_source.set(event_target_value(&ev))
                    placeholder="contract … { tool memory_write … }"
                />
            </label>
            <div class="flex flex-wrap gap-2">
                <OpButton
                    label="Compile".to_string()
                    variant=OpButtonVariant::Secondary
                    loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let src = cls_source.get_untracked();
                        if src.trim().is_empty() {
                            set_error.set("cls_source empty".into());
                            return;
                        }
                        set_busy.set(true);
                        set_error.set(String::new());
                        spawn_local(async move {
                            match api::post_value("/cls/compile", json!({ "source": src })).await {
                                Ok(v) => {
                                    if let Some(msg) = fail_message(&v) {
                                        set_error.set(msg);
                                    } else {
                                        set_notice.set("Compile ok.".into());
                                    }
                                }
                                Err(e) => set_error.set(e.message),
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <OpButton
                    label="Save workflow (DRAFT)".to_string()
                    variant=OpButtonVariant::Primary
                    loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let id = wf_id.get_untracked().trim().to_string();
                        let pkg = package_id.get_untracked().trim().to_string();
                        let src = cls_source.get_untracked();
                        let mode = accounting_mode.get_untracked();
                        if id.is_empty() || pkg.is_empty() || src.trim().is_empty() {
                            set_error.set("workflow_id, package_id, and cls_source are required".into());
                            return;
                        }
                        set_busy.set(true);
                        set_error.set(String::new());
                        spawn_local(async move {
                            match api::post_value("/workflows", json!({
                                "workflow_id": id,
                                "package_id": pkg,
                                "cls_source": src,
                                "accounting_mode": mode,
                            })).await {
                                Ok(v) => {
                                    if let Some(msg) = fail_message(&v) {
                                        set_error.set(msg);
                                    } else {
                                        set_notice.set("Saved DRAFT — open RUN to compile → stage → enable.".into());
                                    }
                                }
                                Err(e) => set_error.set(e.message),
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <a class="inline-flex items-center text-xs text-indigo-400 hover:underline" href="/run">"Open RUN →"</a>
            </div>
        </div>
    }
}

#[component]
fn DevClsPanel() -> impl IntoView {
    let packages = LocalResource::new(|| api::get_value("/cls/packages"));
    view! {
        <div class="space-y-3">
            <p class="text-sm text-zinc-400">
                "CLS packages from GET /cls/packages. Enable stays on RUN. Install/bind via Console when needed."
            </p>
            <Suspense fallback=move || view! { <OpSpinner /> }>
                {move || Suspend::new(async move {
                    match packages.await {
                        Ok(v) => {
                            let pkgs = v
                                .pointer("/data/packages")
                                .or_else(|| v.get("packages"))
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            if pkgs.is_empty() {
                                view! {
                                    <p class="font-mono text-[11px] text-zinc-500">
                                        "No packages returned (empty ≠ seeded claim)."
                                    </p>
                                }
                                .into_any()
                            } else {
                                view! {
                                    <div class="grid gap-3 sm:grid-cols-2">
                                        {pkgs
                                            .into_iter()
                                            .map(|p| {
                                                let id = p
                                                    .get("id")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("—")
                                                    .to_string();
                                                let name = p
                                                    .get("name")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or(id.as_str())
                                                    .to_string();
                                                let ver = p
                                                    .get("version")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("—")
                                                    .to_string();
                                                let status = p
                                                    .get("status")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("—")
                                                    .to_string();
                                                let install = p
                                                    .get("install_status")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("—")
                                                    .to_string();
                                                let domain = p
                                                    .get("domain")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("")
                                                    .to_string();
                                                let domain_line = if domain.is_empty() {
                                                    None
                                                } else {
                                                    Some(format!("domain={domain}"))
                                                };
                                                view! {
                                                    <div class="space-y-2 rounded-xl border border-zinc-800/70 bg-zinc-900/40 p-4">
                                                        <div class="flex items-start justify-between gap-2">
                                                            <div>
                                                                <p class="text-sm font-medium text-zinc-100">{name}</p>
                                                                <p class="font-mono text-[10px] text-zinc-500">{id.clone()}</p>
                                                            </div>
                                                            <span class="rounded border border-zinc-700 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300">
                                                                {ver}
                                                            </span>
                                                        </div>
                                                        <p class="text-[11px] text-zinc-400">
                                                            {format!("status={status} · install={install}")}
                                                        </p>
                                                        {domain_line.map(|d| {
                                                            view! { <p class="text-[10px] text-zinc-600">{d}</p> }
                                                        })}
                                                        <a
                                                            class="inline-block text-[11px] text-indigo-400 hover:underline"
                                                            href="/run"
                                                        >
                                                            "Enable on RUN →"
                                                        </a>
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                }
                                .into_any()
                            }
                        }
                        Err(e) => view! { <p class="text-xs text-red-300">{e.message}</p> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn DevCatalogPanel() -> impl IntoView {
    let (msg, set_msg) = signal(String::new());
    let (reload, set_reload) = signal(0u32);
    let catalog = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/workflows/catalog").await }
    });
    view! {
        <div class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
                <p class="text-sm text-zinc-400">"GET /workflows/catalog — directory + last sync (not a fake inventory)."</p>
                <OpButton
                    label="Sync catalog".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        set_msg.set("Syncing…".into());
                        spawn_local(async move {
                            match api::post_value("/workflows/catalog/sync", json!({})).await {
                                Ok(v) => {
                                    set_msg.set(
                                        v.get("ok")
                                            .and_then(|x| x.as_bool())
                                            .map(|ok| {
                                                if ok {
                                                    "Sync ok".into()
                                                } else {
                                                    serde_json::to_string(&v).unwrap_or_default()
                                                }
                                            })
                                            .unwrap_or_else(|| {
                                                serde_json::to_string(&v).unwrap_or_default()
                                            }),
                                    );
                                    set_reload.update(|n| *n = n.wrapping_add(1));
                                }
                                Err(e) => set_msg.set(e.message),
                            }
                        });
                    })
                />
            </div>
            <Show when=move || !msg.get().is_empty()>
                <p class="font-mono text-[11px] text-zinc-400">{move || msg.get()}</p>
            </Show>
            <Suspense fallback=move || view! { <OpSpinner /> }>
                {move || Suspend::new(async move {
                    match catalog.await {
                        Ok(v) => {
                            let dir = v
                                .get("catalog_dir")
                                .and_then(|x| x.as_str())
                                .unwrap_or("—")
                                .to_string();
                            let auto = v
                                .get("auto_enable")
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "—".into());
                            let watch = v
                                .get("watch_interval_ms")
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "—".into());
                            let last = v.get("last_sync").cloned().unwrap_or(Value::Null);
                            let last_ok = last.get("ok").and_then(|x| x.as_bool());
                            let last_label = match last_ok {
                                Some(true) => "last_sync ok".to_string(),
                                Some(false) => "last_sync failed".to_string(),
                                None if last.is_null() => "last_sync unavailable".to_string(),
                                None => serde_json::to_string(&last).unwrap_or_default(),
                            };
                            let entries = last
                                .get("entries")
                                .or_else(|| last.get("workflows"))
                                .or_else(|| last.get("items"))
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let entries_view = if entries.is_empty() {
                                None
                            } else {
                                Some(view! {
                                    <div class="grid gap-2 sm:grid-cols-2">
                                        {entries
                                            .into_iter()
                                            .take(24)
                                            .map(|e| {
                                                let id = e
                                                    .get("id")
                                                    .or_else(|| e.get("workflow_id"))
                                                    .or_else(|| e.get("path"))
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("entry")
                                                    .to_string();
                                                let name = e
                                                    .get("name")
                                                    .or_else(|| e.get("title"))
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or(id.as_str())
                                                    .to_string();
                                                view! {
                                                    <div class="rounded-lg border border-zinc-800/60 bg-zinc-950/40 px-3 py-2">
                                                        <p class="text-xs text-zinc-200">{name}</p>
                                                        <p class="font-mono text-[10px] text-zinc-500">{id}</p>
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                })
                            };
                            view! {
                                <div class="space-y-3">
                                    <div class="grid gap-3 sm:grid-cols-3">
                                        <div class="rounded-xl border border-zinc-800/70 bg-zinc-900/40 p-4">
                                            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"catalog_dir"</p>
                                            <p class="mt-1 break-all font-mono text-[11px] text-zinc-200">{dir}</p>
                                        </div>
                                        <div class="rounded-xl border border-zinc-800/70 bg-zinc-900/40 p-4">
                                            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"auto_enable"</p>
                                            <p class="mt-1 font-mono text-[11px] text-zinc-200">{auto}</p>
                                        </div>
                                        <div class="rounded-xl border border-zinc-800/70 bg-zinc-900/40 p-4">
                                            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"watch_interval_ms"</p>
                                            <p class="mt-1 font-mono text-[11px] text-zinc-200">{watch}</p>
                                        </div>
                                    </div>
                                    <p class="font-mono text-[11px] text-zinc-400">{last_label}</p>
                                    {entries_view}
                                </div>
                            }
                            .into_any()
                        }
                        Err(e) => view! { <p class="text-xs text-red-300">{e.message}</p> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn DevSurfacePanel() -> impl IntoView {
    let (wf_id, set_wf_id) = signal(String::new());
    let (body, set_body) = signal(String::new());
    let (msg, set_msg) = signal(String::new());
    view! {
        <div class="mx-auto max-w-2xl space-y-3">
            <p class="text-sm text-zinc-400">"GET/PUT /workflows/:id/surface — operator_surface.v1 (admin/dev)."</p>
            <OpTextField label="Workflow ID".to_string() value=wf_id set_value=set_wf_id placeholder="my-workflow" />
            <div class="flex gap-2">
                <OpButton
                    label="Load".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        let id = wf_id.get_untracked().trim().to_string();
                        if id.is_empty() { set_msg.set("workflow_id required".into()); return; }
                        spawn_local(async move {
                            match api::get_value(&format!("/workflows/{id}/surface")).await {
                                Ok(v) => {
                                    set_body.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                                    set_msg.set("Loaded.".into());
                                }
                                Err(e) => set_msg.set(e.message),
                            }
                        });
                    })
                />
                <OpButton
                    label="PUT surface".to_string()
                    variant=OpButtonVariant::Primary
                    on_click=Arc::new(move |_| {
                        let id = wf_id.get_untracked().trim().to_string();
                        let raw = body.get_untracked();
                        if id.is_empty() { set_msg.set("workflow_id required".into()); return; }
                        let Ok(val) = serde_json::from_str::<Value>(&raw) else {
                            set_msg.set("Body must be JSON".into());
                            return;
                        };
                        spawn_local(async move {
                            match api::put_value(&format!("/workflows/{id}/surface"), val).await {
                                Ok(v) => set_msg.set(format!("Saved: {}", serde_json::to_string(&v).unwrap_or_default())),
                                Err(e) => set_msg.set(e.message),
                            }
                        });
                    })
                />
            </div>
            <Show when=move || !msg.get().is_empty()>
                <p class="font-mono text-[11px] text-zinc-400">{move || msg.get()}</p>
            </Show>
            <textarea
                class="min-h-[220px] w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-200"
                prop:value=move || body.get()
                on:input=move |ev| set_body.set(event_target_value(&ev))
            />
        </div>
    }
}

#[component]
fn DevSdkPanel() -> impl IntoView {
    let (op, set_op) = signal(query_param("op").unwrap_or_else(|| "dal".into()));
    let origin = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_else(|| "http://127.0.0.1:8080".into());

    let ops = [
        ("dal", "DAL / tools"),
        ("talk", "Gateway Talk"),
        ("mcp", "MCP invoke"),
        ("cell", "Cell client"),
        ("agos", "AGOS plugin"),
        ("handshake", "Handshake"),
        ("package", "Package"),
    ];

    view! {
        <div class="grid gap-4 lg:grid-cols-[200px_1fr]">
            <div class="flex flex-col gap-1">
                {ops.into_iter().map(|(id, label)| {
                    view! {
                        <button
                            type="button"
                            class=move || if op.get() == id {
                                "rounded-md bg-zinc-100 px-3 py-2 text-left text-xs font-medium text-zinc-900"
                            } else {
                                "rounded-md px-3 py-2 text-left text-xs text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
                            }
                            on:click=move |_| set_op.set(id.to_string())
                        >{label}</button>
                    }
                }).collect_view()}
            </div>
            <div class="rounded-lg border border-zinc-800/70 bg-zinc-900/30 p-4 space-y-3">
                <p class="text-[11px] text-zinc-500">
                    "This node: "
                    <span class="font-mono text-zinc-300">{origin.clone()}</span>
                    " · Talk does not auto-dispatch tool_calls."
                </p>
                {move || {
                    let o = origin.clone();
                    match op.get().as_str() {
                        "talk" => view! {
                            <SdkOp
                                title="Gateway Talk (/v1)".into()
                                body=format!(
                                    "OPENAI_BASE_URL={o}/v1\n# Completions are governed Talk.\n# tool_calls on messages are NOT executed by /v1.\n# Next: POST /dal/start then POST /dal/:run_id/turn\nor admitted POST /tools/mcp/invoke"
                                )
                                honesty="Auto-dispatch blocked. Stub if CONNECTOR_LLM_STUB.".into()
                            />
                        }.into_any(),
                        "mcp" => view! {
                            <SdkOp
                                title="MCP invoke".into()
                                body=format!(
                                    "curl -sS -X POST {o}/api/v1/tools/mcp/register -H 'Authorization: Bearer $TOKEN' -d '{{…}}'\ncurl -sS -X POST {o}/api/v1/tools/mcp/invoke -H 'Authorization: Bearer $TOKEN' -d '{{…}}'\n# Same ToolDispatch path; identity address is tool:{{id}}"
                                )
                                honesty="Requires identity_stack pillars + PATE Allow (or digest HITL).".into()
                            />
                        }.into_any(),
                        "cell" => view! {
                            <SdkOp
                                title="Cell client".into()
                                body="Copy docs/cell_sdk.py — thin Python, not a pip package.\nthink() → /v1/chat/completions\nNot LangGraph.".into()
                                honesty="No published PyPI AGOS/cell package.".into()
                            />
                        }.into_any(),
                        "agos" => view! {
                            <SdkOp
                                title="AGOS plugin (Rust)".into()
                                body="cargo connector new\n# agos-sdk: handshake::apply_from_env → load_manifest_path → assert_manifest_matches_abi\nconnectorctl plugin verify\n# Contract id: agos.v1 (agos.v2 reserved)".into()
                                honesty="See docs/agos/plugin-authoring.md".into()
                            />
                        }.into_any(),
                        "handshake" => view! {
                            <SdkOp
                                title="Handshake".into()
                                body="CONNECTOR_AGOS_HANDSHAKE / FD — see PLUGIN_CONTRACT.md\nNo-op if env unset.".into()
                                honesty="Kernel → plugin env only.".into()
                            />
                        }.into_any(),
                        "package" => view! {
                            <SdkOp
                                title="Package install".into()
                                body="Use DEV → Packages tab\nPOST /plugins/cpkg/preflight then /install".into()
                                honesty="Unsigned refused when CONNECTOR_CPKG_REQUIRE_SIGNATURE=1".into()
                            />
                        }.into_any(),
                        _ => view! {
                            <SdkOp
                                title="DAL — kernel action loop".into()
                                body=format!(
                                    "curl -sS -X POST {o}/api/v1/dal/start \\\n  -H 'Authorization: Bearer $TOKEN' \\\n  -H 'Content-Type: application/json' \\\n  -d '{{\"agent_vid\":\"agent_…\",\"goal\":\"…\"}}'\n\ncurl -sS -X POST {o}/api/v1/dal/$RUN_ID/turn \\\n  -H 'Authorization: Bearer $TOKEN' \\\n  -d '{{\"tool_calls\":[{{…}}]}}'\n# Ring-1 proposals → PATE → ToolDispatch"
                                )
                                honesty="Empty receipts ≠ success. Same path as RUN Action.".into()
                            />
                        }.into_any(),
                    }
                }}
            </div>
        </div>
    }
}

#[component]
fn SdkOp(title: String, body: String, honesty: String) -> impl IntoView {
    let (copied, set_copied) = signal(false);
    let body_for_copy = body.clone();
    view! {
        <div>
            <div class="flex flex-wrap items-center justify-between gap-2">
                <h3 class="text-sm font-semibold text-zinc-100">{title}</h3>
                <div class="flex items-center gap-2">
                    <Show when=move || copied.get()>
                        <span class="font-mono text-[10px] text-emerald-400/90">"Copied"</span>
                    </Show>
                    <OpButton
                        label="Copy".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| {
                            let text = body_for_copy.clone();
                            if let Some(w) = web_sys::window() {
                                let _ = w.navigator().clipboard().write_text(&text);
                                set_copied.set(true);
                            }
                        })
                    />
                </div>
            </div>
            <pre class="mt-2 overflow-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300">{body}</pre>
            <p class="mt-2 text-[11px] text-amber-200/80">{format!("Honesty: {honesty}")}</p>
        </div>
    }
}

fn fail_message(v: &Value) -> Option<String> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return Some(
            v.get("error")
                .or_else(|| v.get("message"))
                .and_then(|x| x.as_str())
                .unwrap_or("request failed")
                .to_string(),
        );
    }
    if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
        if !err.is_empty() && v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
            return Some(err.to_string());
        }
    }
    None
}

fn event_target_value(ev: &web_sys::Event) -> String {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlTextAreaElement>().ok())
        .map(|el| el.value())
        .or_else(|| {
            ev.target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                .map(|el| el.value())
        })
        .unwrap_or_default()
}
