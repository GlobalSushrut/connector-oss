//! Compact LLM connect — vault key for Talk, used on Setup and Create.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::OpLoadingBlock;
use crate::deployment::use_deployment_mode;

#[derive(Clone, Debug)]
struct CatalogEntry {
    id: String,
    label: String,
    needs_key: bool,
    needs_endpoint: bool,
    default_endpoint: String,
    models: Vec<String>,
}

fn fallback_catalog() -> Vec<CatalogEntry> {
    vec![
        entry("openai", "OpenAI", true, false, "", &["gpt-4o", "gpt-4o-mini", "gpt-4.1", "o4-mini"]),
        entry("anthropic", "Anthropic", true, false, "", &["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"]),
        entry("gemini", "Google Gemini", true, false, "", &["gemini-2.0-flash", "gemini-1.5-pro"]),
        entry("deepseek", "DeepSeek", true, false, "", &["deepseek-chat", "deepseek-reasoner"]),
        entry("groq", "Groq", true, false, "", &["llama-3.3-70b-versatile"]),
        entry("together", "Together", true, false, "", &["meta-llama/Llama-3-70b-chat-hf"]),
        entry("mistral", "Mistral", true, false, "", &["mistral-large-latest", "mistral-small-latest"]),
        entry("cohere", "Cohere", true, false, "", &["command-r-plus"]),
        entry("fireworks", "Fireworks", true, false, "", &["accounts/fireworks/models/llama-v3p1-70b-instruct"]),
        entry("perplexity", "Perplexity", true, false, "", &["sonar"]),
        entry("openrouter", "OpenRouter", true, false, "", &["openai/gpt-4o", "anthropic/claude-3.5-sonnet"]),
        entry("ollama", "Ollama (local)", false, true, "http://127.0.0.1:11434/v1", &["llama3.2", "llama3.1", "mistral"]),
        entry("lmstudio", "LM Studio (local)", false, true, "http://127.0.0.1:1234/v1", &["local-model"]),
        entry("vllm", "vLLM (self-host)", false, true, "http://127.0.0.1:8000/v1", &["local-model"]),
        entry("custom", "Custom OpenAI-compatible API", true, true, "", &[]),
    ]
}

fn entry(
    id: &str,
    label: &str,
    needs_key: bool,
    needs_endpoint: bool,
    default_endpoint: &str,
    models: &[&str],
) -> CatalogEntry {
    CatalogEntry {
        id: id.into(),
        label: label.into(),
        needs_key,
        needs_endpoint,
        default_endpoint: default_endpoint.into(),
        models: models.iter().map(|s| (*s).to_string()).collect(),
    }
}

fn parse_catalog(v: &Value) -> Vec<CatalogEntry> {
    let src = api::resource_object(v);
    let Some(arr) = src.get("catalog").and_then(|x| x.as_array()) else {
        return fallback_catalog();
    };
    let parsed: Vec<CatalogEntry> = arr
        .iter()
        .filter_map(|p| {
            let id = p.get("id").and_then(|x| x.as_str())?.to_string();
            Some(CatalogEntry {
                id,
                label: p
                    .get("label")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                needs_key: p.get("needs_key").and_then(|x| x.as_bool()).unwrap_or(true),
                needs_endpoint: p
                    .get("needs_endpoint")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                default_endpoint: p
                    .get("default_endpoint")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                models: p
                    .get("models")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect();
    if parsed.is_empty() {
        fallback_catalog()
    } else {
        parsed
    }
}

fn apply_provider_defaults(entry: &CatalogEntry, set_model: WriteSignal<String>, set_endpoint: WriteSignal<String>) {
    if let Some(m) = entry.models.first() {
        set_model.set(m.clone());
    } else {
        set_model.set(String::new());
    }
    if !entry.default_endpoint.is_empty() {
        set_endpoint.set(entry.default_endpoint.clone());
    } else if !entry.needs_endpoint {
        set_endpoint.set(String::new());
    }
}

fn without_local_loopback(mut catalog: Vec<CatalogEntry>, playground: bool) -> Vec<CatalogEntry> {
    if playground {
        catalog.retain(|e| !matches!(e.id.as_str(), "ollama" | "lmstudio" | "vllm"));
    }
    catalog
}

#[component]
pub fn OpLlmQuickConnect() -> impl IntoView {
    let mode = use_deployment_mode();
    let (reload, set_reload) = signal(0u32);
    // Playground: never wait on the default 20s API timeout for "Checking LLM…".
    // If the node is wedged, fail fast so Workbench can show connect UI / retry.
    const LLM_STATUS_TIMEOUT_MS: u32 = 5_000;
    let status = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value_timeout("/settings/llms/status", LLM_STATUS_TIMEOUT_MS).await }
    });
    let providers = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value_timeout("/settings/llms/providers", LLM_STATUS_TIMEOUT_MS).await }
    });

    view! {
        <div class="space-y-2">
            <Suspense fallback=move || view! { <OpLoadingBlock message="Checking LLM…".to_string() /> }>
                {move || Suspend::new(async move {
                    let status_v = status.await;
                    let playground = mode.get().is_playground();
                    let catalog = match providers.await {
                        Ok(v) => without_local_loopback(parse_catalog(&v), playground),
                        Err(_) => without_local_loopback(fallback_catalog(), playground),
                    };
                    match status_v {
                        Ok(v) => {
                            let src = api::resource_object(&v);
                            let wired = src.get("router_wired").and_then(|x| x.as_bool()).unwrap_or(false);
                            let proven = src.get("proven").and_then(|x| x.as_bool()).unwrap_or(false);
                            let stub = src.get("stub_mode").and_then(|x| x.as_bool()).unwrap_or(false);
                            let mode = src.get("effective_mode").and_then(|x| x.as_str()).unwrap_or("");
                            let prov = src.get("provider").and_then(|x| x.as_str()).unwrap_or("—");
                            let modl = src.get("model").and_then(|x| x.as_str()).unwrap_or("—");
                            let ep = src.get("endpoint").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            view! {
                                <LlmConnectBody
                                    wired=wired
                                    proven=proven
                                    effective_mode=mode.to_string()
                                    stub=stub
                                    connected_provider=prov.to_string()
                                    connected_model=modl.to_string()
                                    connected_endpoint=ep
                                    catalog=catalog
                                    on_linked=Callback::new(move |_| set_reload.update(|n| *n += 1))
                                />
                            }.into_any()
                        }
                        Err(_) => view! {
                            <LlmConnectBody
                                wired=false
                                proven=false
                                effective_mode="disconnected".into()
                                stub=true
                                connected_provider=String::new()
                                connected_model=String::new()
                                connected_endpoint=String::new()
                                catalog=catalog
                                on_linked=Callback::new(move |_| set_reload.update(|n| *n += 1))
                            />
                        }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn LlmConnectBody(
    wired: bool,
    proven: bool,
    effective_mode: String,
    stub: bool,
    connected_provider: String,
    connected_model: String,
    connected_endpoint: String,
    catalog: Vec<CatalogEntry>,
    on_linked: Callback<()>,
) -> impl IntoView {
    let catalog = RwSignal::new(catalog);
    let first = catalog.get_untracked().first().cloned();
    let (provider, set_provider) = signal(
        if wired && !connected_provider.is_empty() {
            connected_provider.clone()
        } else {
            first
                .as_ref()
                .map(|e| e.id.clone())
                .unwrap_or_else(|| "openai".into())
        },
    );
    let (model, set_model) = signal(
        if wired && !connected_model.is_empty() {
            connected_model.clone()
        } else {
            first
                .and_then(|e| e.models.first().cloned())
                .unwrap_or_else(|| "gpt-4o-mini".into())
        },
    );
    let (api_key, set_api_key) = signal(String::new());
    let (endpoint, set_endpoint) = signal(if wired {
        connected_endpoint.clone()
    } else {
        String::new()
    });
    let (flash, set_flash) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (editing, set_editing) = signal(!wired);
    let key_el = NodeRef::<leptos::html::Input>::new();
    let model_el = NodeRef::<leptos::html::Input>::new();
    let endpoint_el = NodeRef::<leptos::html::Input>::new();

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        ev.stop_propagation();
        if busy.get_untracked() {
            return;
        }
        let p = provider.get_untracked();
        let m_dom = model_el.get().map(|el| el.value()).unwrap_or_default();
        let k_dom = key_el.get().map(|el| el.value()).unwrap_or_default();
        let ep_dom = endpoint_el.get().map(|el| el.value()).unwrap_or_default();
        let m = {
            let from_dom = m_dom.trim().to_string();
            if from_dom.is_empty() {
                model.get_untracked().trim().to_string()
            } else {
                from_dom
            }
        };
        let k = {
            let from_dom = k_dom;
            if from_dom.trim().is_empty() {
                api_key.get_untracked()
            } else {
                from_dom
            }
        };
        let ep = {
            let from_dom = ep_dom.trim().to_string();
            if from_dom.is_empty() {
                endpoint.get_untracked().trim().to_string()
            } else {
                from_dom
            }
        };
        set_model.set(m.clone());
        set_api_key.set(k.clone());
        set_endpoint.set(ep.clone());
        set_flash.set("Connecting…".into());
        let entry = catalog.get_untracked().into_iter().find(|c| c.id == p);
        let needs_key = entry.as_ref().map(|e| e.needs_key).unwrap_or(true);
        let needs_ep = entry.as_ref().map(|e| e.needs_endpoint).unwrap_or(false);
        if m.is_empty() {
            set_flash.set("Model id is required.".into());
            return;
        }
        if needs_ep && ep.is_empty() {
            set_flash.set("This provider needs an API base URL (custom / self-host / local).".into());
            return;
        }
        if needs_key && k.trim().is_empty() && p != "custom" {
            set_flash.set("Paste an API key, or pick Ollama / LM Studio / vLLM / custom.".into());
            return;
        }
        set_busy.set(true);
        let on_linked = on_linked;
        spawn_local(async move {
            let body = json!({
                "provider": p,
                "model": m,
                "api_key": k,
                "endpoint": if ep.is_empty() { Value::Null } else { Value::String(ep) },
                "ping": true,
            });
            match api::post_value_timeout("/settings/llms/link", body, 60_000).await {
                Ok(v) => {
                    let src = api::resource_object(&v);
                    let ok = src.get("ok").and_then(|x| x.as_bool())
                        .or_else(|| v.get("ok").and_then(|x| x.as_bool()))
                        .unwrap_or(false);
                    if ok {
                        let proven_ok = src.get("proven").and_then(|x| x.as_bool())
                            .or_else(|| v.get("proven").and_then(|x| x.as_bool()))
                            .unwrap_or(false);
                        set_api_key.set(String::new());
                        if proven_ok {
                            set_flash.set("LLM linked and proven. Talk is live.".into());
                            set_editing.set(false);
                        } else {
                            set_flash.set(
                                "LLM linked but prove-out did not pass — check key / vendor reachability."
                                    .into(),
                            );
                        }
                        on_linked.run(());
                    } else {
                        let err = src
                            .get("error")
                            .and_then(|x| x.as_str())
                            .or_else(|| v.get("error").and_then(|x| x.as_str()))
                            .map(|s| s.to_string())
                            .or_else(|| api::body_error(&v))
                            .unwrap_or_else(|| "link failed".into());
                        set_flash.set(format!("Could not connect: {err}"));
                    }
                }
                Err(e) => set_flash.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <Show when=move || wired && proven && !editing.get()>
            <div class="space-y-2 rounded-lg border border-emerald-800/50 bg-emerald-950/30 px-3 py-2">
                <p class="text-[12px] text-emerald-100">
                    {format!("LLM proven · {connected_provider} / {connected_model} — Talk is live")}
                </p>
                <button
                    type="button"
                    class="text-[11px] text-emerald-200/80 underline hover:text-emerald-100"
                    on:click=move |_| set_editing.set(true)
                >"Switch provider or model"</button>
            </div>
        </Show>
        <Show when=move || wired && !proven && !editing.get()>
            <div class="space-y-2 rounded-lg border border-amber-800/40 bg-amber-950/20 px-3 py-2">
                <p class="text-[12px] text-amber-100">
                    {format!("LLM linked but not proven ({effective_mode}) · re-link with ping to go live")}
                </p>
                <button
                    type="button"
                    class="text-[11px] text-amber-200/80 underline hover:text-amber-100"
                    on:click=move |_| set_editing.set(true)
                >"Prove provider key"</button>
            </div>
        </Show>
        <Show when=move || editing.get()>
            <form
                class="space-y-2 rounded-lg border border-amber-800/40 bg-amber-950/20 p-3"
                on:submit=submit
                on:click=move |ev| ev.stop_propagation()
            >
                <p class="text-[12px] text-amber-100">
                    {if stub && !wired {
                        "No live LLM yet — pick a known provider or a custom/self-host API."
                    } else {
                        "Connect an LLM. Keys stay in the vault, not the cage. Unknown vendors: Custom + base URL."
                    }}
                </p>
                <Show when=move || !flash.get().is_empty()>
                    <p class="rounded-md border border-amber-700/50 bg-zinc-950/80 px-2 py-1.5 text-[12px] text-amber-100">
                        {move || flash.get()}
                    </p>
                </Show>
                <label class="block text-[10px] uppercase text-zinc-500">
                    "Provider"
                    <select
                        class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100"
                        on:change=move |ev| {
                            let id = event_target_value(&ev);
                            set_provider.set(id.clone());
                            catalog.with(|c| {
                                if let Some(e) = c.iter().find(|c| c.id == id) {
                                    apply_provider_defaults(e, set_model, set_endpoint);
                                }
                            });
                        }
                    >
                        {move || catalog.get().into_iter().map(|e| {
                            let id = e.id.clone();
                            let label = format!("{} ({})", e.label, e.id);
                            let selected = id.clone();
                            view! {
                                <option value=id.clone() selected=move || provider.get() == selected>
                                    {label}
                                </option>
                            }
                        }).collect_view()}
                    </select>
                </label>
                {move || {
                    let p = provider.get();
                    let entry = catalog.get().into_iter().find(|c| c.id == p);
                    let known = entry.as_ref().map(|e| e.models.clone()).unwrap_or_default();
                    let needs_ep = entry.as_ref().map(|e| e.needs_endpoint).unwrap_or(false);
                    let needs_key = entry.as_ref().map(|e| e.needs_key).unwrap_or(true);
                    let known_empty = known.is_empty();
                    let model_label = if known_empty {
                        "Model id (required)"
                    } else {
                        "Model id (override if not in the list)"
                    };
                    let key_label = if needs_key {
                        "API key"
                    } else {
                        "API key (optional for local)"
                    };
                    let key_ph = if needs_key {
                        "sk-…"
                    } else {
                        "leave empty for Ollama / LM Studio / vLLM"
                    };
                    view! {
                        <div class="space-y-2">
                            {if !known_empty {
                                view! {
                                    <label class="block text-[10px] uppercase text-zinc-500">
                                        "Known models"
                                        <select
                                            class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100 font-mono"
                                            on:change=move |ev| set_model.set(event_target_value(&ev))
                                        >
                                            {known.into_iter().map(|m| {
                                                let opt = m.clone();
                                                view! {
                                                    <option value=opt.clone() selected=move || model.get() == opt>
                                                        {m}
                                                    </option>
                                                }
                                            }).collect_view()}
                                        </select>
                                    </label>
                                }.into_any()
                            } else {
                                view! { <span></span> }.into_any()
                            }}
                            <label class="block text-[10px] uppercase text-zinc-500">
                                {model_label}
                                <input
                                    node_ref=model_el
                                    class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100 font-mono"
                                    prop:value=move || model.get()
                                    on:input=move |ev| set_model.set(event_target_value(&ev))
                                    placeholder="model id as the vendor names it"
                                />
                            </label>
                            {if needs_ep {
                                view! {
                                    <label class="block text-[10px] uppercase text-zinc-500">
                                        "API base URL (required for local / custom / self-host)"
                                        <input
                                            node_ref=endpoint_el
                                            class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100 font-mono"
                                            prop:value=move || endpoint.get()
                                            on:input=move |ev| set_endpoint.set(event_target_value(&ev))
                                            placeholder="http://127.0.0.1:11434/v1"
                                        />
                                    </label>
                                }.into_any()
                            } else {
                                view! { <span></span> }.into_any()
                            }}
                            <label class="block text-[10px] uppercase text-zinc-500">
                                {key_label}
                                <input
                                    node_ref=key_el
                                    type="password"
                                    autocomplete="off"
                                    class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100 font-mono"
                                    on:input=move |ev| set_api_key.set(event_target_value(&ev))
                                    on:change=move |ev| set_api_key.set(event_target_value(&ev))
                                    placeholder=key_ph
                                />
                            </label>
                        </div>
                    }.into_any()
                }}
                <button
                    type="submit"
                    class="rounded-lg bg-zinc-100 px-3 py-1.5 text-[12px] font-medium text-zinc-900 disabled:opacity-50"
                    disabled=move || busy.get()
                >{move || if busy.get() { "Connecting…" } else { "Connect LLM" }}</button>
            </form>
        </Show>
    }
}
