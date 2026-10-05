//! Agent data workspace. Files stay sources until an explicit ingest.
//! Ingest writes knowledge packets. It does not activate model context.

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::iia_api;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Overview,
    Files,
    Collections,
    Knowledge,
    Memory,
    State,
    Context,
    Behavior,
    Permissions,
    Evidence,
}

impl Pane {
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Files => "Files",
            Self::Collections => "Knowledge folders",
            Self::Knowledge => "Knowledge",
            Self::Memory => "Memory",
            Self::State => "State",
            Self::Context => "Context",
            Self::Behavior => "Behavior",
            Self::Permissions => "Permissions",
            Self::Evidence => "Evidence",
        }
    }

    fn advanced(self) -> &'static str {
        match self {
            Self::Overview => "Principal",
            Self::Files | Self::Collections | Self::Knowledge => "Knowledge",
            Self::Memory => "Memory",
            Self::State => "Situation",
            Self::Context => "Context",
            Self::Behavior => "Purpose",
            Self::Permissions => "Authority",
            Self::Evidence => "Receipts",
        }
    }

    fn all() -> [Self; 10] {
        [
            Self::Overview,
            Self::Files,
            Self::Collections,
            Self::Knowledge,
            Self::Memory,
            Self::State,
            Self::Context,
            Self::Behavior,
            Self::Permissions,
            Self::Evidence,
        ]
    }
}

fn text_at(value: &Value, key: &str) -> String {
    value.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn rows_of(body: &Value, key: &str) -> Vec<Value> {
    body.get(key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn with_extension(name: &str, kind: &str) -> String {
    let trimmed = name.trim();
    if trimmed.contains('.') {
        trimmed.to_string()
    } else if trimmed.is_empty() {
        format!("untitled.{kind}")
    } else {
        format!("{trimmed}.{kind}")
    }
}

#[component]
pub fn AgentDataWorkspace(pid: String) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let deployment = crate::deployment::use_deployment_mode();
    let (pane, set_pane) = signal(Pane::Files);
    let (notice, set_notice) = signal(String::new());
    let (containers, set_containers) = signal(Vec::<Value>::new());
    let (assets, set_assets) = signal(Vec::<Value>::new());
    let (selected_container, set_selected_container) = signal(String::new());
    let (selected, set_selected) = signal(Value::Null);
    let (memory, set_memory) = signal(Value::Null);
    let (stats, set_stats) = signal(Value::Null);
    let (contract, set_contract) = signal(Value::Null);
    let (pressure, set_pressure) = signal(Value::Null);
    let (ceiling, set_ceiling) = signal(Value::Null);
    let (collection_name, set_collection_name) = signal(String::new());
    let (folder_name, set_folder_name) = signal(String::new());
    let (file_name, set_file_name) = signal(String::new());
    let (task_model, set_task_model) = signal(String::new());
    let (task_purpose, set_task_purpose) = signal(String::new());
    let (task_surface, set_task_surface) = signal(String::new());
    let (task_kind, set_task_kind) = signal("workspace".to_string());
    let (task_result, set_task_result) = signal(String::new());
    let (file_kind, set_file_kind) = signal("md".to_string());
    let (file_body, set_file_body) = signal(String::new());
    let (query, set_query) = signal(String::new());
    let (workspace, set_workspace) = signal(Value::Null);
    let (preflight, set_preflight) = signal(Value::Null);
    let (hitl_id, set_hitl_id) = signal(String::new());
    let (journey, set_journey) = signal(String::new());
    let (cease_proof, set_cease_proof) = signal(Value::Null);
    let (explain_id, set_explain_id) = signal(String::new());
    let (explain_body, set_explain_body) = signal(Value::Null);
    let (character_text, set_character_text) = signal(String::new());
    let (directive_name, set_directive_name) = signal(String::new());
    let (directive_text, set_directive_text) = signal(String::new());
    let (alias_name, set_alias_name) = signal(String::new());
    let (alias_target, set_alias_target) = signal(String::new());

    let load_container = move |container_id: String| {
        if container_id.is_empty() {
            set_assets.set(Vec::new());
            return;
        }
        spawn_local(async move {
            match iia_api::get_asset_container(&container_id).await {
                Ok(body) => set_assets.set(rows_of(&body, "assets")),
                Err(err) => set_notice.set(format!("GET /assets/containers/{container_id} — {err}")),
            }
        });
    };

    let reload = move || {
        let pid = pid_sv.get_value();
        let current = selected_container.get_untracked();
        spawn_local(async move {
            match iia_api::list_asset_containers(&pid).await {
                Ok(body) => set_containers.set(rows_of(&body, "containers")),
                Err(err) => set_notice.set(format!("GET /assets/containers — {err}")),
            }
            match iia_api::agent_memory(&pid).await {
                Ok(body) => set_memory.set(body),
                Err(err) => set_notice.set(format!("GET /agents/{pid}/memory — {err}")),
            }
            match iia_api::agent_memory_stats(&pid).await {
                Ok(body) => set_stats.set(body),
                Err(err) => set_notice.set(format!("GET /agents/{pid}/memory/stats — {err}")),
            }
            if let Ok(body) = iia_api::agent_contract(&pid).await {
                set_contract.set(body);
            }
            match iia_api::agent_workspace(&pid).await {
                Ok(body) => set_workspace.set(body),
                Err(err) => set_notice.set(format!("GET /agents/{pid}/workspace — {err}")),
            }
            match iia_api::agent_preflight(&pid).await {
                Ok(body) => set_preflight.set(body),
                Err(err) => set_notice.set(format!("GET /agents/{pid}/preflight — {err}")),
            }
            set_pressure.set(iia_api::context_pressure(&pid).await.unwrap_or(Value::Null));
            set_ceiling.set(iia_api::spend_ceiling(&pid).await.unwrap_or(Value::Null));
            if !current.is_empty() {
                if let Ok(body) = iia_api::get_asset_container(&current).await {
                    set_assets.set(rows_of(&body, "assets"));
                }
            }
        });
    };

    Effect::new(move |_| reload());

    view! {
        <div class="grid gap-3 lg:grid-cols-[11rem_minmax(0,1fr)_16rem]">
            <nav class="flex flex-wrap gap-1 lg:flex-col">
                {Pane::all().into_iter().map(|item| {
                    view! {
                        <button
                            type="button"
                            class=move || if pane.get() == item { "rounded border border-indigo-700/60 bg-indigo-950/40 px-2 py-1 text-left text-[11px] text-indigo-100" } else { "rounded border border-zinc-800 px-2 py-1 text-left text-[11px] text-zinc-400" }
                            on:click=move |_| set_pane.set(item)
                        >
                            <span class="block">{item.label()}</span>
                            <span class="block text-[10px] text-zinc-500">{item.advanced()}</span>
                        </button>
                    }
                }).collect_view()}
            </nav>
            <section class="min-w-0 space-y-3">
                <div>
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Advanced workspace"</p>
                    <p class="text-[11px] text-zinc-500">"A file is stored source. Ingest interprets it as knowledge. Neither step makes it eligible or active. The cards below report present or absent from the workspace."</p>
                </div>
                <p class="min-h-4 text-[11px] text-zinc-300">{move || notice.get()}</p>
                <Show when=move || matches!(pane.get(), Pane::Overview | Pane::Permissions)>
                    <form class="space-y-2 rounded border border-zinc-800 p-2 text-[11px]" on:submit=|ev| ev.prevent_default()>
                        <p class="font-semibold uppercase tracking-wide text-zinc-500">"Configure a task"</p>
                        <p class="text-zinc-500">"This saves the model, purpose, and an ask-only grant. Configured is not executed."</p>
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Model" prop:value=move || task_model.get() on:input=move |ev| set_task_model.set(event_target_value(&ev)) />
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="One specific purpose sentence" prop:value=move || task_purpose.get() on:input=move |ev| set_task_purpose.set(event_target_value(&ev)) />
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Work surface path or sandbox" prop:value=move || task_surface.get() on:input=move |ev| set_task_surface.set(event_target_value(&ev)) />
                        <select class="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" on:change=move |ev| set_task_kind.set(event_target_value(&ev))>
                            <option value="workspace">"Workspace path"</option>
                            <option value="sandbox">"Sandbox"</option>
                            <option value="dedicated">"Dedicated MicroCell"</option>
                        </select>
                        <button type="button" class="rounded border border-indigo-800 px-2 py-1 text-indigo-100" on:click=move |_| {
                            if deployment.get().is_playground() {
                                set_task_result.set("Playground does not configure a product task.".into());
                                return;
                            }
                            let purpose = task_purpose.get_untracked().trim().to_string();
                            let contract_purpose = purpose.clone();
                            let lowered = purpose.to_ascii_lowercase();
                            if purpose.is_empty() || lowered == "general-purpose" || lowered == "general_purpose" || purpose == "GENERAL_PURPOSE" {
                                set_task_result.set("A specific purpose is required.".into());
                                return;
                            }
                            let pid = pid_sv.get_value();
                            let model = task_model.get_untracked().trim().to_string();
                            let surface = task_surface.get_untracked().trim().to_string();
                            let surface_kind = task_kind.get_untracked();
                            spawn_local(async move {
                                let body = serde_json::json!({
                                    "pid": pid,
                                    "model": model,
                                    "purpose": purpose,
                                    "surface": surface,
                                    "surface_kind": surface_kind,
                                    "contract": {"purpose": [contract_purpose], "network_default": "deny"}
                                });
                                match iia_api::post_product_task(body).await {
                                    Ok(result) => {
                                        let stage = result.get("stage").and_then(|v| v.as_str()).unwrap_or("absent");
                                        let executed = result.get("executed").and_then(|v| v.as_bool()).unwrap_or(false);
                                        let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("");
                                        if error.is_empty() {
                                            set_task_result.set(format!("Stage {stage}. Executed: {executed}. An ask grant is not an executed effect."));
                                        } else {
                                            set_task_result.set(format!("{error}. Executed: {executed}."));
                                        }
                                    }
                                    Err(err) => set_task_result.set(err.to_string()),
                                }
                            });
                        }>"Save configuration"</button>
                        <p class="text-zinc-300">{move || task_result.get()}</p>
                    </form>
                </Show>
                <Show when=move || matches!(pane.get(), Pane::Overview)>
                    <div class="grid grid-cols-3 gap-2 text-[11px]">
                        <div class="rounded border border-zinc-800 p-2"><p class="text-zinc-500">"Collections"</p><p class="font-mono text-zinc-100">{move || containers.get().len()}</p></div>
                        <div class="rounded border border-zinc-800 p-2"><p class="text-zinc-500">"Files in view"</p><p class="font-mono text-zinc-100">{move || assets.get().len()}</p></div>
                        <div class="rounded border border-zinc-800 p-2"><p class="text-zinc-500">"Memory records"</p><p class="font-mono text-zinc-100">{move || memory.get().get("total").map(|v| v.to_string()).unwrap_or_else(|| "absent".into())}</p></div>
                    </div>
                    <div class="grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-3">
                        {move || {
                            let body = workspace.get();
                            ["principal", "purpose", "presence", "knowledge", "directives", "authority", "situation"].into_iter().map(|name| {
                                let status = body.pointer(&format!("/dimensions/{name}/status")).and_then(|v| v.as_str()).unwrap_or("absent").to_string();
                                let label = name.to_string();
                                view! {
                                    <div class="rounded border border-zinc-800 p-2">
                                        <p class="capitalize text-zinc-500">{label}</p>
                                        <p class="font-mono text-zinc-100">{status}</p>
                                    </div>
                                }
                            }).collect_view()
                        }}
                    </div>
                    <p class="text-[11px] text-zinc-500">"These states come from GET /agents/:pid/workspace. Absent means the record is not stored."</p>
                    <p class="font-mono text-[11px] text-zinc-300">{move || {
                        let posture = workspace.get().pointer("/integration/posture").and_then(|value| value.as_str()).unwrap_or("absent").to_string();
                        format!("Integration posture: {posture}. A discovered tool stays unauthorized.")
                    }}</p>
                    <p class="font-mono text-[11px] text-zinc-300">{move || {
                        let body = preflight.get();
                        if body.is_null() {
                            return "Preflight: absent".into();
                        }
                        let posture = body.get("posture").and_then(|value| value.as_str()).unwrap_or("absent");
                        let spine = body.get("pate_spine").and_then(|value| value.as_str()).unwrap_or("absent");
                        let runtime = body.get("runtime").and_then(|value| value.as_str()).unwrap_or("absent");
                        let inventory = body.get("inventory_complete").and_then(|value| value.as_bool()).map(|value| value.to_string()).unwrap_or_else(|| "absent".into());
                        let gateway = body.get("agentgateway").and_then(|value| value.as_str()).unwrap_or("absent");
                        format!("Preflight {posture}. Spine {spine}. Runtime {runtime}. HTTP inventory {inventory}. Agentgateway {gateway}. Admits false.")
                    }}</p>
                    <div class="space-y-2 rounded border border-zinc-800 p-2 text-[11px]">
                        <p class="font-semibold uppercase tracking-wide text-zinc-500">"One governed check"</p>
                        <p class="text-zinc-500">"Ask a person, then approve or deny that request. Receipt ids below are the evidence stored for this agent. This screen does not say Connector Ready."</p>
                        <div class="flex flex-wrap gap-2">
                            <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                                let pid = pid_sv.get_value();
                                spawn_local(async move {
                                    match iia_api::hitl_create(&pid, "review_release", "Operator release check").await {
                                        Ok(body) => {
                                            let request_id = body.get("request_id").and_then(|value| value.as_str()).unwrap_or("").to_string();
                                            let task_id = body.get("task_id").and_then(|value| value.as_str()).unwrap_or("absent");
                                            let executed = body.get("executed").and_then(|value| value.as_bool()).map(|value| value.to_string()).unwrap_or_else(|| "absent".into());
                                            let error = body.get("error").and_then(|value| value.as_str()).unwrap_or("");
                                            set_hitl_id.set(request_id.clone());
                                            if error.is_empty() {
                                                set_journey.set(format!("Task {task_id}. Executed {executed}. Request {request_id}. Pending until approve or deny."));
                                            } else {
                                                set_journey.set(format!("{error}. Executed {executed}. Task {task_id}."));
                                            }
                                        }
                                        Err(err) => set_journey.set(format!("POST /agents/{pid}/hitl — {err}")),
                                    }
                                });
                            }>"Ask a person"</button>
                            <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                                let pid = pid_sv.get_value();
                                let request_id = hitl_id.get_untracked();
                                if request_id.is_empty() {
                                    set_journey.set("A pending request id is required before approve.".into());
                                    return;
                                }
                                spawn_local(async move {
                                    match iia_api::hitl_approve(&pid, &request_id).await {
                                        Ok(body) => {
                                            let task_id = body.get("task_id").or_else(|| body.get("pate_task_id")).and_then(|value| value.as_str()).unwrap_or("absent");
                                            let executed = body.get("executed").and_then(|value| value.as_bool()).map(|value| value.to_string()).unwrap_or_else(|| "absent".into());
                                            set_journey.set(format!("Approved {request_id}. Task {task_id}. Executed {executed}."));
                                            reload();
                                        }
                                        Err(err) => set_journey.set(format!("POST /agents/{pid}/hitl/{request_id}/approve — {err}")),
                                    }
                                });
                            }>"Approve"</button>
                            <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                                let pid = pid_sv.get_value();
                                let request_id = hitl_id.get_untracked();
                                if request_id.is_empty() {
                                    set_journey.set("A pending request id is required before deny.".into());
                                    return;
                                }
                                spawn_local(async move {
                                    match iia_api::hitl_deny(&pid, &request_id).await {
                                        Ok(body) => {
                                            let error = body.get("error").and_then(|value| value.as_str()).unwrap_or("");
                                            if error.is_empty() {
                                                set_journey.set(format!("Denied {request_id}. The ask does not execute."));
                                            } else {
                                                set_journey.set(format!("{error}. Request {request_id}."));
                                            }
                                            reload();
                                        }
                                        Err(err) => set_journey.set(format!("POST /agents/{pid}/hitl/{request_id}/deny — {err}")),
                                    }
                                });
                            }>"Deny"</button>
                        </div>
                        <p class="font-mono text-zinc-300">{move || journey.get()}</p>
                        <div class="space-y-1">
                            {move || {
                                let ids = workspace.get().pointer("/evidence/receipt_ids").and_then(|value| value.as_array()).cloned().unwrap_or_default();
                                if ids.is_empty() {
                                    view! { <p class="text-zinc-500">"Receipt ids: absent."</p> }.into_any()
                                } else {
                                    ids.into_iter().map(|id| {
                                        let label = id.as_str().unwrap_or("absent").to_string();
                                        let chosen = label.clone();
                                        view! {
                                            <button type="button" class="block font-mono text-indigo-200" on:click=move |_| {
                                                set_explain_id.set(chosen.clone());
                                                set_pane.set(Pane::Evidence);
                                            }>{label}</button>
                                        }
                                    }).collect_view().into_any()
                                }
                            }}
                        </div>
                    </div>
                </Show>
                <Show when=move || matches!(pane.get(), Pane::Files | Pane::Collections | Pane::Knowledge)>
                    <div class="space-y-2">
                        <div class="flex flex-wrap gap-1">
                            {move || containers.get().into_iter().map(|container| {
                                let id = text_at(&container, "id");
                                let name = text_at(&container, "name");
                                let id_for_class = id.clone();
                                let id_for_click = id.clone();
                                view! {
                                    <button
                                        type="button"
                                        class=move || if selected_container.get() == id_for_class { "rounded border border-indigo-700/60 px-2 py-1 text-[11px] text-indigo-100" } else { "rounded border border-zinc-800 px-2 py-1 text-[11px] text-zinc-300" }
                                        on:click=move |_| {
                                            let id_for_click = id_for_click.clone();
                                            set_selected_container.set(id_for_click.clone());
                                            load_container(id_for_click);
                                        }
                                    >{name}</button>
                                }
                            }).collect_view()}
                        </div>
                        <div class="flex flex-wrap gap-2">
                            <input class="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-100" placeholder="New collection" prop:value=move || collection_name.get() on:input=move |ev| set_collection_name.set(event_target_value(&ev)) />
                            <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200" on:click=move |_| {
                                let name = collection_name.get_untracked().trim().to_string();
                                if name.is_empty() {
                                    set_notice.set("Collection name is required.".into());
                                    return;
                                }
                                spawn_local(async move {
                                    match iia_api::create_asset_container(&name, &pid_sv.get_value()).await {
                                        Ok(body) => {
                                            let id = body.pointer("/container/id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                            set_selected_container.set(id);
                                            set_notice.set("Collection stored. Files in it are not active context.".into());
                                            reload();
                                        }
                                        Err(err) => set_notice.set(format!("POST /assets/containers — {err}")),
                                    }
                                });
                            }>"Create"</button>
                            <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200" on:click=move |_| {
                                let container_id = selected_container.get_untracked();
                                if container_id.is_empty() {
                                    set_notice.set("Choose a collection before ingest.".into());
                                    return;
                                }
                                spawn_local(async move {
                                    match iia_api::ingest_assets(&container_id).await {
                                        Ok(body) => {
                                            let processed = body.get("processed").map(|v| v.to_string()).unwrap_or_else(|| "0".into());
                                            let namespace = text_at(&body, "target_namespace");
                                            set_notice.set(format!("Ingested {processed} pending file(s) into {namespace}. Indexed knowledge is still not active context."));
                                            reload();
                                        }
                                        Err(err) => set_notice.set(format!("POST /assets/ingest — {err}")),
                                    }
                                });
                            }>"Ingest pending"</button>
                        </div>
                        <Show when=move || pane.get() != Pane::Collections>
                            <div class="space-y-2">
                                <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-100" placeholder="Search files" prop:value=move || query.get() on:input=move |ev| set_query.set(event_target_value(&ev)) />
                                <div class="grid gap-2 sm:grid-cols-[8rem_8rem_1fr]">
                                    <input class="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-100" placeholder="Folder" prop:value=move || folder_name.get() on:input=move |ev| set_folder_name.set(event_target_value(&ev)) />
                                    <select class="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-100" on:change=move |ev| set_file_kind.set(event_target_value(&ev))>
                                        <option value="md">"Markdown"</option>
                                        <option value="json">"JSON"</option>
                                        <option value="yaml">"YAML"</option>
                                        <option value="txt">"Text"</option>
                                        <option value="csv">"CSV"</option>
                                    </select>
                                    <input class="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-[11px] text-zinc-100" placeholder="File name" prop:value=move || file_name.get() on:input=move |ev| set_file_name.set(event_target_value(&ev)) />
                                </div>
                                <textarea class="h-24 w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-[11px] text-zinc-100" placeholder="File contents. Saving stores the source only." prop:value=move || file_body.get() on:input=move |ev| set_file_body.set(event_target_value(&ev))></textarea>
                                <button type="button" class="rounded border border-indigo-800 px-2 py-1 text-[11px] text-indigo-100" on:click=move |_| {
                                    let container_id = selected_container.get_untracked();
                                    if container_id.is_empty() {
                                        set_notice.set("Choose a collection before adding a file.".into());
                                        return;
                                    }
                                    let filename = {
                                        let leaf = with_extension(&file_name.get_untracked(), &file_kind.get_untracked());
                                        let folder = folder_name.get_untracked().trim().trim_matches('/').to_string();
                                        if folder.is_empty() { leaf } else { format!("{folder}/{leaf}") }
                                    };
                                    let content = file_body.get_untracked();
                                    if content.trim().is_empty() {
                                        set_notice.set("File content is empty.".into());
                                        return;
                                    }
                                    spawn_local(async move {
                                        match iia_api::upload_asset(&container_id, &filename, &content).await {
                                            Ok(_) => {
                                                set_notice.set(format!("{filename} stored as pending. It is not in model context."));
                                                reload();
                                            }
                                            Err(err) => set_notice.set(format!("POST /assets/containers/{container_id}/upload — {err}")),
                                        }
                                    });
                                }>"Store file"</button>
                                <div class="overflow-hidden rounded border border-zinc-800">
                                    <table class="w-full text-left text-[11px]">
                                        <thead class="bg-zinc-900/70 text-zinc-500"><tr><th class="px-2 py-1">"Name"</th><th>"Type"</th><th>"Status"</th></tr></thead>
                                        <tbody>
                                            {move || {
                                                let q = query.get().to_ascii_lowercase();
                                                let knowledge_only = pane.get() == Pane::Knowledge;
                                                let visible: Vec<Value> = assets.get().into_iter().filter(|asset| {
                                                    let name = text_at(asset, "filename").to_ascii_lowercase();
                                                    (q.is_empty() || name.contains(&q)) && (!knowledge_only || text_at(asset, "status") == "ingested")
                                                }).collect();
                                                if visible.is_empty() {
                                                    view! { <tr><td colspan="3" class="px-2 py-3 text-zinc-500">"No stored file was found in this collection."</td></tr> }.into_any()
                                                } else {
                                                    let mut folders: Vec<(String, Vec<Value>)> = Vec::new();
                                                    for asset in visible {
                                                        let filename = text_at(&asset, "filename");
                                                        let folder = filename.rsplit_once('/').map(|(folder, _)| folder.to_string()).unwrap_or_else(|| "(collection root)".into());
                                                        if let Some((_, rows)) = folders.iter_mut().find(|(name, _)| name == &folder) {
                                                            rows.push(asset);
                                                        } else {
                                                            folders.push((folder, vec![asset]));
                                                        }
                                                    }
                                                    folders.into_iter().flat_map(|(folder, rows)| {
                                                        let mut views = vec![view! {
                                                            <tr class="border-t border-zinc-800 bg-zinc-900/60"><td colspan="3" class="px-2 py-1 text-zinc-500">{folder}</td></tr>
                                                        }.into_any()];
                                                        views.extend(rows.into_iter().map(|asset| {
                                                            let name = text_at(&asset, "filename");
                                                            let kind = text_at(&asset, "file_type");
                                                            let status = text_at(&asset, "status");
                                                            let chosen = asset.clone();
                                                            view! {
                                                                <tr class="cursor-pointer border-t border-zinc-800/80" on:click=move |_| set_selected.set(chosen.clone())>
                                                                    <td class="px-2 py-1 text-zinc-100">{name}</td>
                                                                    <td class="px-2 py-1 text-zinc-400">{kind}</td>
                                                                    <td class="px-2 py-1 text-zinc-300">{status}</td>
                                                                </tr>
                                                            }.into_any()
                                                        }));
                                                        views
                                                    }).collect_view().into_any()
                                                }
                                            }}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </Show>
                    </div>
                </Show>
                <Show when=move || pane.get() == Pane::Memory>
                    <div class="space-y-1">
                        <p class="text-[11px] text-zinc-500">"Learned memory is separate from uploaded files."</p>
                        {move || {
                            let packets = rows_of(&memory.get(), "packets");
                            if packets.is_empty() {
                                view! { <p class="text-[11px] text-zinc-500">"No memory record was found."</p> }.into_any()
                            } else {
                                packets.into_iter().map(|packet| {
                                    let preview = text_at(&packet, "content_preview");
                                    let kind = text_at(&packet, "memory_type");
                                    let chosen = packet.clone();
                                    view! {
                                        <button type="button" class="block w-full rounded border border-zinc-800 px-2 py-1 text-left text-[11px]" on:click=move |_| set_selected.set(chosen.clone())>
                                            <span class="text-zinc-500">{kind}</span>
                                            <span class="mt-1 block text-zinc-200">{preview}</span>
                                        </button>
                                    }
                                }).collect_view().into_any()
                            }
                        }}
                    </div>
                </Show>
                <Show when=move || pane.get() == Pane::State>
                    <div class="space-y-1 text-[11px] text-zinc-400">
                        <p>"SituationV1 is absent. Checkpoints are not memory and they are not active context."</p>
                        <p class="font-mono text-zinc-200">{move || {
                            let detail = workspace.get().pointer("/dimensions/situation/detail").cloned().unwrap_or(Value::Null);
                            let count = detail.get("checkpoint_count").map(|value| value.to_string()).unwrap_or_else(|| "absent".into());
                            let state = detail.get("context_state").and_then(|value| value.as_str()).unwrap_or("absent");
                            format!("Checkpoints {count}. Context state {state}.")
                        }}</p>
                    </div>
                </Show>
                <Show when=move || pane.get() == Pane::Context>
                    <div class="space-y-2 text-[11px]">
                        <p class="text-zinc-500">"Context pressure and spend ceiling are live reads. A missing value stays absent. An activation receipt indexes a stored transfer and does not admit an effect."</p>
                        <p class="font-mono text-zinc-300">{move || {
                            let body = workspace.get();
                            let status = body.pointer("/active_context/status").and_then(|value| value.as_str()).unwrap_or("absent");
                            let id = body.pointer("/active_context/activation_id").and_then(|value| value.as_str()).unwrap_or("absent");
                            format!("Activation {status}. Id {id}. Admits false.")
                        }}</p>
                        <pre class="overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-zinc-300">{move || if pressure.get().is_null() { "absent".into() } else { pressure.get().to_string() }}</pre>
                        <pre class="overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-zinc-300">{move || if ceiling.get().is_null() { "absent".into() } else { ceiling.get().to_string() }}</pre>
                    </div>
                </Show>
                <Show when=move || matches!(pane.get(), Pane::Behavior | Pane::Permissions)>
                    <div class="space-y-2 text-[11px]">
                        <p class="text-zinc-500">"Behavior text does not grant permission. Authority stays on the contract. A knowledge document is not a directive."</p>
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Character text" prop:value=move || character_text.get() on:input=move |ev| set_character_text.set(event_target_value(&ev)) />
                        <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                            let pid = pid_sv.get_value();
                            let text = character_text.get_untracked().trim().to_string();
                            let expected_revision = workspace.get_untracked().pointer("/dimensions/directives/detail/character_revision").and_then(|value| value.as_u64()).unwrap_or(0);
                            if text.is_empty() || text.eq_ignore_ascii_case("general-purpose") {
                                set_notice.set("Character text must be specific. Saving it does not grant authority.".into());
                                return;
                            }
                            spawn_local(async move {
                                match iia_api::put_character(&pid, serde_json::json!({"text": text, "expected_revision": expected_revision})).await {
                                    Ok(body) => set_notice.set(format!("Character revision {}. Admits: false.", body.pointer("/character/revision").map(|v| v.to_string()).unwrap_or_else(|| "absent".into()))),
                                    Err(err) => set_notice.set(format!("PUT /agents/{pid}/character — {err}")),
                                }
                            });
                        }>"Save character draft"</button>
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Directive name" prop:value=move || directive_name.get() on:input=move |ev| set_directive_name.set(event_target_value(&ev)) />
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Directive text" prop:value=move || directive_text.get() on:input=move |ev| set_directive_text.set(event_target_value(&ev)) />
                        <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                            let pid = pid_sv.get_value();
                            let name = directive_name.get_untracked().trim().to_string();
                            let text = directive_text.get_untracked().trim().to_string();
                            spawn_local(async move {
                                match iia_api::post_directive(&pid, serde_json::json!({"name": name, "scope": "agent", "source_kind": "operator", "text": text})).await {
                                    Ok(body) => {
                                        let lifecycle = body.pointer("/directive/lifecycle").and_then(|v| v.as_str()).unwrap_or("absent");
                                        set_notice.set(format!("Directive {lifecycle}. It does not admit an effect."));
                                        reload();
                                    }
                                    Err(err) => set_notice.set(format!("POST /agents/{pid}/directives — {err}")),
                                }
                            });
                        }>"Store inactive directive"</button>
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Alias" prop:value=move || alias_name.get() on:input=move |ev| set_alias_name.set(event_target_value(&ev)) />
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Target principal" prop:value=move || alias_target.get() on:input=move |ev| set_alias_target.set(event_target_value(&ev)) />
                        <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                            let pid = pid_sv.get_value();
                            let alias = alias_name.get_untracked().trim().to_string();
                            let target = alias_target.get_untracked().trim().to_string();
                            spawn_local(async move {
                                match iia_api::post_alias(&pid, serde_json::json!({"namespace": "agent", "alias": alias, "target_principal": target, "valid_until_ms": 4102444800000i64})).await {
                                    Ok(_) => set_notice.set("Alias stored. It selects a principal and does not grant authority.".into()),
                                    Err(err) => set_notice.set(format!("POST /agents/{pid}/aliases — {err}")),
                                }
                            });
                        }>"Store alias"</button>
                        <pre class="overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-zinc-200">{move || {
                            let body = contract.get();
                            let contract_body = body.get("contract").cloned().unwrap_or(body);
                            contract_body.get("purpose").map(|v| v.to_string()).unwrap_or_else(|| "absent".into())
                        }}</pre>
                        <pre class="overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-zinc-200">{move || {
                            let body = contract.get();
                            let contract_body = body.get("contract").cloned().unwrap_or(body);
                            contract_body.get("denied_operations").map(|v| v.to_string()).unwrap_or_else(|| "absent".into())
                        }}</pre>
                    </div>
                </Show>
                <Show when=move || pane.get() == Pane::Evidence>
                    <div class="space-y-2 text-[11px]">
                        <p class="text-zinc-500">"Intelligence receipts are separate from report-center catalog rows. Explain still joins the latest record for this agent and stays PARTIAL."</p>
                        <p class="font-mono text-zinc-300">{move || {
                            let body = workspace.get();
                            let ids = body.pointer("/evidence/receipt_ids").and_then(|v| v.as_array()).map(|items| items.len()).unwrap_or(0);
                            let honesty = body.pointer("/evidence/explain_honesty").and_then(|v| v.as_str()).unwrap_or("PARTIAL");
                            format!("Receipt ids {ids}. Explain {honesty}.")
                        }}</p>
                        <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                            let pid = pid_sv.get_value();
                            spawn_local(async move {
                                match iia_api::runtime_cease_proof(&pid).await {
                                    Ok(body) => set_cease_proof.set(body),
                                    Err(err) => set_notice.set(format!("GET /runtime/cease-proof/{pid} — {err}")),
                                }
                            });
                        }>"Load cease proof"</button>
                        <pre class="overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-zinc-300">{move || if cease_proof.get().is_null() { "absent".into() } else { cease_proof.get().to_string() }}</pre>
                        <input class="w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-zinc-100" placeholder="Receipt id" prop:value=move || explain_id.get() on:input=move |ev| set_explain_id.set(event_target_value(&ev)) />
                        <button type="button" class="rounded border border-zinc-700 px-2 py-1 text-zinc-200" on:click=move |_| {
                            let receipt_id = explain_id.get_untracked().trim().to_string();
                            if receipt_id.is_empty() {
                                set_notice.set("A receipt id is required. Explain does not use the latest agent record from this form.".into());
                                return;
                            }
                            spawn_local(async move {
                                match iia_api::runtime_explain(&receipt_id).await {
                                    Ok(body) => set_explain_body.set(body),
                                    Err(err) => set_notice.set(format!("GET /runtime/explain/{receipt_id} — {err}")),
                                }
                            });
                        }>"Explain this receipt"</button>
                        <pre class="overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-zinc-300">{move || if explain_body.get().is_null() { "absent".into() } else { explain_body.get().to_string() }}</pre>
                    </div>
                </Show>
            </section>
            <aside class="space-y-2 rounded border border-zinc-800 bg-zinc-950/40 p-2 text-[11px]">
                <p class="font-semibold uppercase tracking-wide text-zinc-500">"Inspector"</p>
                {move || {
                    let item = selected.get();
                    if item.is_null() {
                        return view! { <p class="text-zinc-500">"Select a file or memory record."</p> }.into_any();
                    }
                    let name = if text_at(&item, "filename").is_empty() { text_at(&item, "cid") } else { text_at(&item, "filename") };
                    let status = text_at(&item, "status");
                    let activation = if status == "ingested" {
                        "ingested knowledge, not active context"
                    } else if status.is_empty() {
                        "memory record, not a source file"
                    } else {
                        "stored source, not active context"
                    };
                    let digest = ["digest", "content_digest", "sha256"]
                        .iter()
                        .find_map(|key| item.get(*key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
                        .unwrap_or("absent");
                    let stored = if status == "pending" || status == "ingested" { "present" } else { "absent" };
                    let ingested = if status == "ingested" { "present" } else { "absent" };
                    let kind = if text_at(&item, "file_type").is_empty() { text_at(&item, "memory_type") } else { text_at(&item, "file_type") };
                    let namespace = if text_at(&item, "knowledge_namespace").is_empty() { text_at(&item, "namespace") } else { text_at(&item, "knowledge_namespace") };
                    let size = item.get("size_bytes").map(|v| v.to_string()).filter(|s| s != "null").unwrap_or_else(|| "absent".into());
                    view! {
                        <div class="space-y-1">
                            <p class="text-zinc-100">{name}</p>
                            <p class="text-zinc-500">{format!("Type {kind}")}</p>
                            <p class="text-zinc-500">{format!("Size {size}")}</p>
                            <p class="text-zinc-500">{format!("Status {}", if status.is_empty() { "absent".to_string() } else { status })}</p>
                            <p class="text-zinc-500">{format!("Namespace {namespace}")}</p>
                            <p class="text-zinc-500">{format!("Digest {digest}")}</p>
                            <p class="text-zinc-500">{format!("Stored {stored} · Ingested {ingested} · Eligible absent · Active absent")}</p>
                            <p class="text-amber-200/80">{activation}</p>
                            <p class="text-zinc-500">"A knowledge document is not a directive and does not grant authority."</p>
                        </div>
                    }.into_any()
                }}
                <p class="text-zinc-500">{move || format!("Memory stats total: {}", stats.get().get("total").map(|v| v.to_string()).unwrap_or_else(|| "absent".into()))}</p>
            </aside>
        </div>
    }
}
