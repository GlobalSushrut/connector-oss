//! Bring any agent, including ones Connector has never heard of.
//!
//! The market does not share one agent id, and a brand list cannot cover it.
//! Two directions and three wires are enough:
//! the other software calls Connector as an MCP client, or Connector reads an
//! MCP HTTP server, an A2A agent card (`/.well-known/agent.json`), or an
//! OpenAI-compatible chat URL. A stdio command and a chat window with no
//! address stay unconnected. Reading an address does not grant the remote side.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::iia_api;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// The other software is an MCP client and calls this node.
    Client,
    /// Connector reads an HTTP MCP server the other software already runs.
    Mcp,
    /// Connector reads `/.well-known/agent.json`.
    A2a,
    /// Connector talks to an OpenAI-compatible `/v1` chat endpoint.
    Openai,
}

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Self::Client => "They call Connector",
            Self::Mcp => "MCP server",
            Self::A2a => "A2A agent card",
            Self::Openai => "OpenAI-compatible chat",
        }
    }
    fn hint(self) -> &'static str {
        match self {
            Self::Client => "Any MCP client uses this same address: an editor, a desktop app, a gateway, or a product that does not exist yet. Paste it into that client's MCP config. A stdio command is their transport, not a URL Connector probes. Adding the address does not grant them.",
            Self::Mcp => "Any HTTP MCP server. The product name is irrelevant. A command such as npx or a local stdio serve is not an HTTP address, so it cannot be probed. Discovered tools stay unauthorized.",
            Self::A2a => "Any host that publishes /.well-known/agent.json. Reading the card does not send a task and does not grant the agent.",
            Self::Openai => "Any host that speaks /v1/chat/completions. Hosted APIs need a key. A local runtime may leave the key empty. The link is model-only until a contract, grant, and PATE route exist.",
        }
    }
}

fn mcp_handle() -> String {
    let origin = web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .filter(|origin| !origin.is_empty() && origin != "null")
        .unwrap_or_else(|| "http://127.0.0.1:9091".to_string());
    format!("{origin}/api/v1/protocols/mcp/handle")
}

#[component]
pub fn AgentJourney() -> impl IntoView {
    let shape = RwSignal::new(Shape::Client);
    let url = RwSignal::new(String::new());
    let model = RwSignal::new(String::new());
    let key = RwSignal::new(String::new());
    let pid = RwSignal::new(String::new());
    let purpose = RwSignal::new(String::new());
    let result = RwSignal::new(String::new());
    let preflight = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let read = move |_| {
        let shape = shape.get();
        let url = url.get().trim().to_string();
        let model = model.get().trim().to_string();
        let key = key.get();
        if url.is_empty() {
            result.set("Paste the address the agent already publishes.".into());
            return;
        }
        busy.set(true);
        result.set("Reading the address. Nothing is granted.".into());
        spawn_local(async move {
            let line = match shape {
                Shape::Client => "This software calls Connector. Paste the MCP address into its config. Nothing is probed from here.".into(),
                Shape::Mcp => match api::post_value(
                    "/protocols/mcp/discover",
                    json!({ "server_url": url, "timeout_secs": 10 }),
                )
                .await
                {
                    Ok(value) => mcp_line(&value),
                    Err(error) => error.to_string(),
                },
                Shape::A2a => match api::post_value("/protocols/a2a/card/read", json!({ "url": url })).await {
                    Ok(value) => card_line(&value),
                    Err(error) => error.to_string(),
                },
                Shape::Openai => {
                    if key.trim().is_empty() && !url.contains("127.0.0.1") && !url.contains("localhost") {
                        "A hosted chat endpoint needs a provider key. A local Ollama or vLLM URL can stay empty.".into()
                    } else {
                        match api::post_value(
                            "/settings/llms/link",
                            json!({
                                "provider": "openai",
                                "model": if model.is_empty() { "gpt-4o-mini".into() } else { model },
                                "api_key": key,
                                "endpoint": url,
                                "ping": true,
                            }),
                        )
                        .await
                        {
                            Ok(value) => openai_line(&value),
                            Err(error) => error.to_string(),
                        }
                    }
                }
            };
            result.set(line);
            busy.set(false);
        });
    };

    let save = move |_| {
        let pid = pid.get().trim().to_string();
        let purpose = purpose.get();
        let model = model.get();
        if pid.is_empty() {
            result.set("The outside address is separate from a Connector agent. Paste a Connector agent id only when you want to attach a purpose to one that already exists here.".into());
            return;
        }
        spawn_local(async move {
            let lowered = purpose.to_ascii_lowercase();
            if purpose.trim().is_empty()
                || lowered == "general-purpose"
                || lowered == "general_purpose"
                || purpose == "GENERAL_PURPOSE"
            {
                result.set("A specific purpose is required. Executed: false.".into());
                return;
            }
            let pid_for_flight = pid.clone();
            let body = json!({
                "pid": pid,
                "model": model,
                "purpose": purpose,
                "surface": "bring-agent",
                "surface_kind": "configure",
                "contract": {"purpose": [purpose], "network_default": "deny"}
            });
            match iia_api::post_product_task(body).await {
                Ok(value) => {
                    let stage = value.get("stage").and_then(|item| item.as_str()).unwrap_or("absent");
                    let executed = value.get("executed").and_then(|item| item.as_bool()).unwrap_or(false);
                    let error = value.get("error").and_then(|item| item.as_str()).unwrap_or("");
                    if error.is_empty() {
                        result.set(format!("Purpose saved on {pid_for_flight}. Stage {stage}. Executed: {executed}."));
                    } else {
                        result.set(format!("{error}. Executed: {executed}."));
                    }
                    match iia_api::agent_preflight(&pid_for_flight).await {
                        Ok(flight) => preflight.set(preflight_line(&flight)),
                        Err(flight_error) => preflight.set(format!("GET /agents/{pid_for_flight}/preflight — {flight_error}")),
                    }
                }
                Err(error) => result.set(error.to_string()),
            }
        });
    };

    let shapes = [Shape::Client, Shape::Mcp, Shape::A2a, Shape::Openai];
    let handle = mcp_handle();
    view! {
        <section class="mb-4 rounded-xl border border-zinc-800 bg-zinc-950/40 p-4 space-y-3">
            <p class="text-sm text-zinc-200">"Bring any agent."</p>
            <p class="text-xs leading-relaxed text-zinc-400">
                "Connector does not keep a list of products. Cursor, Windsurf, Copilot, OpenAI, Grok, OpenClaw, and software that does not exist yet all use the same two directions. Either they call this node as an MCP client, or this node reads an MCP server, an A2A card, or an OpenAI-compatible chat URL that they already publish. A chat window with none of those addresses stays unconnected."
            </p>
            <div class="flex flex-wrap gap-2">
                {shapes.into_iter().map(|item| {
                    view! {
                        <button
                            type="button"
                            class=move || if shape.get() == item { "rounded-md border border-indigo-700 bg-indigo-950/40 px-3 py-1 text-sm text-indigo-100" } else { "rounded-md border border-zinc-700 px-3 py-1 text-sm text-zinc-300" }
                            on:click=move |_| shape.set(item)
                        >{item.label()}</button>
                    }
                }).collect_view()}
            </div>
            <p class="text-[11px] leading-relaxed text-zinc-500">{move || shape.get().hint()}</p>
            <Show when=move || shape.get() == Shape::Client>
                <input
                    class="w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-100"
                    readonly=true
                    prop:value=handle.clone()
                />
            </Show>
            <Show when=move || shape.get() != Shape::Client>
                <input class="w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100" placeholder=move || match shape.get() {
                    Shape::Client => "",
                    Shape::Mcp => "https://mcp.example.com",
                    Shape::A2a => "https://agent.example/.well-known/agent.json",
                    Shape::Openai => "https://host/v1",
                } prop:value=move || url.get() on:input=move |event| url.set(event_target_value(&event)) />
            </Show>
            <Show when=move || shape.get() == Shape::Openai>
                <div class="grid gap-2 sm:grid-cols-2">
                    <input class="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100" placeholder="Model name" prop:value=move || model.get() on:input=move |event| model.set(event_target_value(&event)) />
                    <input class="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100" placeholder="Provider key, if the host requires one" prop:value=move || key.get() on:input=move |event| key.set(event_target_value(&event)) />
                </div>
            </Show>
            <Show when=move || shape.get() != Shape::Client>
                <button type="button" class="rounded-md border border-zinc-600 px-3 py-1 text-sm text-zinc-100" prop:disabled=move || busy.get() on:click=read>
                {move || if busy.get() { "Reading…" } else { "Read address" }}
                </button>
            </Show>
            <p class="font-mono text-[11px] text-zinc-300">{move || result.get()}</p>
            <div class="grid gap-2 sm:grid-cols-2">
                <input class="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100" placeholder="Connector agent id, only to attach a purpose" prop:value=move || pid.get() on:input=move |event| pid.set(event_target_value(&event)) />
                <input class="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm text-zinc-100" placeholder="Specific purpose" prop:value=move || purpose.get() on:input=move |event| purpose.set(event_target_value(&event)) />
            </div>
            <button type="button" class="rounded-md border border-zinc-700 px-3 py-1 text-sm text-zinc-300" on:click=save>"Attach purpose"</button>
            <p class="font-mono text-[11px] text-zinc-500">{move || preflight.get()}</p>
        </section>
    }
}

fn mcp_line(value: &Value) -> String {
    if let Some(error) = value.get("error").and_then(|item| item.as_str()) {
        return format!("{error}. Discovered tools stay unauthorized.");
    }
    let names: Vec<String> = value
        .pointer("/tools")
        .or_else(|| value.pointer("/data/tools"))
        .and_then(|item| item.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|tool| {
                    tool.get("name")
                        .and_then(|name| name.as_str())
                        .or_else(|| tool.as_str())
                        .map(|name| name.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    if names.is_empty() {
        "No tool names came back. Nothing was authorized.".into()
    } else {
        format!("MCP tools: {}. Not authorized.", names.join(", "))
    }
}

fn card_line(value: &Value) -> String {
    if let Some(error) = value.get("error").and_then(|item| item.as_str()) {
        return format!("{error}. No task was sent.");
    }
    let name = value.get("name").and_then(|item| item.as_str()).unwrap_or("unnamed");
    let skills = value
        .get("skills")
        .and_then(|item| item.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    if skills.is_empty() {
        format!("A2A card {name}. No task was sent and nothing was granted.")
    } else {
        format!("A2A card {name}. Skills: {skills}. No task was sent and nothing was granted.")
    }
}

fn openai_line(value: &Value) -> String {
    if let Some(error) = value.get("error").and_then(|item| item.as_str()) {
        return format!("{error}. A chat endpoint is model-only.");
    }
    let ok = value.get("ok").and_then(|item| item.as_bool()).unwrap_or(false);
    if ok {
        "Chat endpoint answered a ping. This is model-only until a contract, grant, and PATE route exist.".into()
    } else {
        "The chat endpoint did not confirm. It stays model-only and is not a grant.".into()
    }
}

fn preflight_line(value: &serde_json::Value) -> String {
    let posture = value.get("posture").and_then(|item| item.as_str()).unwrap_or("absent");
    let spine = value.get("pate_spine").and_then(|item| item.as_str()).unwrap_or("absent");
    let runtime = value.get("runtime").and_then(|item| item.as_str()).unwrap_or("absent");
    let inventory = value
        .get("inventory_complete")
        .and_then(|item| item.as_bool())
        .map(|item| item.to_string())
        .unwrap_or_else(|| "absent".into());
    let gateway = value.get("agentgateway").and_then(|item| item.as_str()).unwrap_or("absent");
    format!("Posture {posture}. Spine {spine}. Runtime {runtime}. HTTP inventory {inventory}. Agentgateway {gateway}. Admits false.")
}
