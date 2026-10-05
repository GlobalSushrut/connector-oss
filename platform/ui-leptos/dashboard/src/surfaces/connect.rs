//! `/connect` — Uplink Bay.
//!
//! The one place an operator wires this platform to the outside world without
//! touching a terminal: LLM providers, MCP servers, tool bridges, and the
//! scoped bindings that decide which agent may call what.
//!
//! The MCP path is built as the real workflow rather than a pile of forms:
//!
//! ```text
//!   PROBE  →  discovered tools  →  REGISTER bridge  →  BIND to agent (scoped)
//! ```
//!
//! Probing is read-only and goes through the node egress allowlist, so a URL
//! that the substrate would refuse fails here first — before anything is saved.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::primitives::{OpText, OpTextVariant};
use crate::deployment::use_deployment_mode;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Llm,
    Mcp,
    Bindings,
    Creds,
    Health,
}

impl Tab {
    fn code(self) -> &'static str {
        match self {
            Tab::Llm => "LLM",
            Tab::Mcp => "MCP",
            Tab::Bindings => "BND",
            Tab::Creds => "SEC",
            Tab::Health => "HLT",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Tab::Llm => "Models",
            Tab::Mcp => "Tool servers",
            Tab::Bindings => "Bindings",
            Tab::Creds => "Credentials",
            Tab::Health => "Health",
        }
    }
}

#[component]
pub fn ConnectCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    crate::components::page_title::use_page_title("Uplink Bay");
    let tab = RwSignal::new(Tab::Llm);
    // Tools discovered by a probe, shared into the register form below it.
    let discovered = RwSignal::new(Vec::<String>::new());

    let tabs = [Tab::Llm, Tab::Mcp, Tab::Bindings, Tab::Creds, Tab::Health];

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10 fcs-install">
            <div class="fcs-bezel">
                <div class="fcs-titlebar">
                    <div class="fcs-titlebar-mark">
                        <span class="fcs-win-controls" aria-hidden="true">
                            <span class="fcs-win-btn close"></span>
                            <span class="fcs-win-btn"></span>
                            <span class="fcs-win-btn"></span>
                        </span>
                        <span class="truncate">"CONNECTOR OS  ·  UPLINK BAY"</span>
                    </div>
                    <div class="fcs-lights">
                        <span class="fcs-light pwr"><span class="dot"></span>"EGRESS"</span>
                        <span class="fcs-light pwr"><span class="dot"></span>"BAY"</span>
                    </div>
                </div>

                <div class="fcs-body space-y-4">
                    <div>
                        <OpText text="UPLINK BAY".to_string() variant=OpTextVariant::Title />
                        <p class="mt-1 text-sm text-stone-400 leading-relaxed">
                            "Any agent uses the same wires, whether or not Connector has heard of the product. It calls this node as an MCP client, or this node reads its MCP server, A2A card, or OpenAI-compatible chat URL. The forms below are those wires. A discovered tool is not authorized. A chat URL stays model-only."
                        </p>
                        <div class="mt-3 flex flex-wrap gap-2">
                            <a class="fcs-btn go" href="/setup/uplink">"Connect an existing agent"</a>
                            <a class="fcs-btn" href="/setup">"Build a governed agent"</a>
                        </div>
                        <p class="mt-2 text-xs text-stone-500 leading-relaxed">
                            "Both paths still need a specific purpose, a grant, and a PATE route. Preflight reports absent, model_only, or inventory_unknown. HTTP inventory complete does not install agentgateway and does not admit an effect."
                        </p>
                    </div>

                    <div class="flex flex-wrap items-center gap-2">
                        {tabs.into_iter().map(|t| {
                            let is_active = move || tab.get() == t;
                            view! {
                                <button
                                    type="button"
                                    class=move || if is_active() { "fcs-btn go" } else { "fcs-btn" }
                                    on:click=move |_| tab.set(t)
                                >
                                    {format!("{} · {}", t.code(), t.label())}
                                </button>
                            }
                        }).collect_view()}
                    </div>

                    {move || match tab.get() {
                        Tab::Llm => view! { <LlmTab /> }.into_any(),
                        Tab::Mcp => view! { <McpTab discovered=discovered /> }.into_any(),
                        Tab::Bindings => view! { <BindingsTab /> }.into_any(),
                        Tab::Creds => view! { <CredsTab /> }.into_any(),
                        Tab::Health => view! { <HealthTab /> }.into_any(),
                    }}
                </div>

                <div class="fcs-statusbar">
                    <span>"KEYS GO TO THE VAULT  ·  NEVER THE AGENT CAGE"</span>
                    <span>"UPLINK BAY"</span>
                </div>
            </div>
        </div>
    }
}

// ── LLM ──────────────────────────────────────────────────────────────────────

#[component]
fn LlmTab() -> impl IntoView {
    let mode = use_deployment_mode();
    let (provider, set_provider) = signal("openai".to_string());
    let (model, set_model) = signal("gpt-4o-mini".to_string());
    let (key, set_key) = signal(String::new());
    let (endpoint, set_endpoint) = signal(String::new());
    let (flash, set_flash) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (reload, set_reload) = signal(0u32);

    let status = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value_timeout("/settings/llms/status", 5_000).await }
    });

    let connect = move |_| {
        let (p, m, k, ep) = (provider.get(), model.get(), key.get(), endpoint.get());
        if k.trim().is_empty() && !matches!(p.as_str(), "ollama" | "lmstudio" | "vllm") {
            set_flash.set(if mode.get().is_playground() {
                "Paste an API key. Local Ollama / LM Studio are not reachable from this Fly node.".into()
            } else {
                "Paste an API key, or use provider `ollama` for a local model.".into()
            });
            return;
        }
        if mode.get().is_playground()
            && matches!(p.as_str(), "ollama" | "lmstudio" | "vllm")
        {
            set_flash.set("This hosted trial cannot reach 127.0.0.1 on your laptop. Use a hosted provider.".into());
            return;
        }
        set_busy.set(true);
        set_flash.set("Pinging the provider…".into());
        spawn_local(async move {
            let body = json!({
                "provider": p,
                "model": m,
                "api_key": k,
                "endpoint": if ep.trim().is_empty() { Value::Null } else { json!(ep.trim()) },
                "ping": true,
            });
            match api::post_value("/settings/llms/link", body).await {
                Ok(v) => {
                    if v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
                        set_key.set(String::new());
                        set_flash.set(String::new());
                        set_reload.update(|n| *n += 1);
                    } else {
                        set_flash.set(format!("Provider refused the ping: {v}"));
                    }
                }
                Err(e) => set_flash.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <Suspense fallback=move || view! { <p class="fcs-pad text-xs text-stone-400">"Reading model link…"</p> }>
                {move || Suspend::new(async move {
                    match status.await {
                        Ok(v) => {
                            let wired = v.get("router_wired").and_then(|x| x.as_bool()).unwrap_or(false);
                            let proven = v.get("proven").and_then(|x| x.as_bool()).unwrap_or(false);
                            let stub = v.get("stub_mode").and_then(|x| x.as_bool()).unwrap_or(false);
                            let prov = v.get("provider").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                            let modl = v.get("model").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                            let live = wired && proven;
                            let chip = if live { "fcs-verdict go" } else { "fcs-verdict" };
                            let line = if live {
                                format!("Live · {prov} / {modl}")
                            } else if wired && !proven {
                                format!("Linked, not proven — ping the key before Talk is live · {prov} / {modl}")
                            } else if stub {
                                "Stub mode — replies are canned until a real key is linked and proven.".to_string()
                            } else {
                                "No model linked.".to_string()
                            };
                            view! {
                                <div class="fcs-pad flex items-center gap-2 flex-wrap">
                                    <span class=chip>{if live { "LIVE" } else if wired { "UNPROVEN" } else { "UNWIRED" }}</span>
                                    <span class="text-xs text-stone-200">{line}</span>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! {
                            <p class="fcs-pad text-xs text-rose-300">{e.message}</p>
                        }.into_any(),
                    }
                })}
            </Suspense>

            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"POST /settings/llms/link"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Link a model"</h4>
                <p class="text-[11px] text-stone-400">
                    "The key is pinged, then stored in the vault. Agents receive a secret reference, never the key itself."
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    <FieldInput label="Provider" placeholder="openai · anthropic · azure · bedrock · vertex" value=provider set_value=set_provider />
                    <FieldInput label="Model" placeholder="gpt-4o-mini" value=model set_value=set_model />
                    <FieldInput label="Endpoint (optional)" placeholder="https://api.openai.com/v1" value=endpoint set_value=set_endpoint />
                    <label class="flex flex-col gap-1">
                        <span class="text-[9px] uppercase tracking-wider text-stone-500">"API key"</span>
                        <input
                            type="password"
                            class="fcs-input"
                            placeholder=if mode.get().is_playground() {
                                "sk-…  (required on this hosted trial)"
                            } else {
                                "sk-…  (leave empty for ollama)"
                            }
                            prop:value=move || key.get()
                            on:input=move |ev| set_key.set(event_target_value(&ev))
                        />
                    </label>
                </div>
                <button type="button" class="fcs-btn go" prop:disabled=move || busy.get() on:click=connect>
                    {move || if busy.get() { "PINGING…" } else { "PING + LINK" }}
                </button>
                {move || {
                    let f = flash.get();
                    (!f.is_empty()).then(|| view! { <p class="text-[11px] text-amber-300">{f}</p> })
                }}
            </section>

            <JsonConfigCard
                title="Providers".to_string()
                desc="The provider table the router picks from.".to_string()
                get_path="/settings/llms/providers".to_string()
                post_path="/settings/llms/providers".to_string()
            />
            <JsonConfigCard
                title="Routing rules".to_string()
                desc="Which model serves which class of work.".to_string()
                get_path="/settings/llms/routing-rules".to_string()
                post_path="/settings/llms/routing-rules".to_string()
            />
            <JsonConfigCard
                title="Guardrails".to_string()
                desc="Prompt and output guardrails applied before the model call.".to_string()
                get_path="/settings/llms/guardrails".to_string()
                post_path="/settings/llms/guardrails".to_string()
            />
            <JsonConfigCard
                title="Privacy tags".to_string()
                desc="Data classes that may not leave the node.".to_string()
                get_path="/settings/llms/privacy-tags".to_string()
                post_path="/settings/llms/privacy-tags".to_string()
            />
            <ReadCard
                title="Fallback + cost cap".to_string()
                desc="What happens when the primary model is down or over budget.".to_string()
                path="/settings/llms/fallback-cap".to_string()
            />
        </div>
    }
}

// ── MCP ──────────────────────────────────────────────────────────────────────

#[component]
fn McpTab(discovered: RwSignal<Vec<String>>) -> impl IntoView {
    let (url, set_url) = signal(String::new());
    let (timeout, set_timeout) = signal("10".to_string());
    let (probe_out, set_probe_out) = signal(String::new());
    let (probing, set_probing) = signal(false);

    let (bridge_id, set_bridge_id) = signal(String::new());
    let (agent_pid, set_agent_pid) = signal(String::new());
    let (bridge_url, set_bridge_url) = signal(String::new());
    let (tools_csv, set_tools_csv) = signal(String::new());
    let (reg_out, set_reg_out) = signal(String::new());
    let (registering, set_registering) = signal(false);
    let (reload, set_reload) = signal(0u32);

    let servers = LocalResource::new(move || {
        let _ = reload.get();
        async move {
            (
                api::get_value("/protocols/mcp/servers").await,
                api::get_value("/tools/mcp/bridges").await,
            )
        }
    });

    let probe = move |_| {
        let u = url.get().trim().to_string();
        if u.is_empty() {
            set_probe_out.set("Enter the MCP server URL first.".into());
            return;
        }
        let secs: u64 = timeout.get().trim().parse().unwrap_or(10);
        set_probing.set(true);
        set_probe_out.set(String::new());
        spawn_local(async move {
            let body = json!({ "server_url": u, "timeout_secs": secs });
            match api::post_value("/protocols/mcp/discover", body).await {
                Ok(v) => {
                    let names: Vec<String> = v
                        .pointer("/tools")
                        .or_else(|| v.pointer("/data/tools"))
                        .and_then(|x| x.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|t| {
                                    t.get("name")
                                        .and_then(|n| n.as_str())
                                        .or_else(|| t.as_str())
                                        .map(|s| s.to_string())
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    discovered.set(names.clone());
                    if !names.is_empty() {
                        set_tools_csv.set(names.join(", "));
                    }
                    set_probe_out.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                }
                Err(e) => set_probe_out.set(e.message),
            }
            set_probing.set(false);
        });
    };

    let register = move |_| {
        let (b, a, u) = (bridge_id.get(), agent_pid.get(), bridge_url.get());
        if b.trim().is_empty() || u.trim().is_empty() {
            set_reg_out.set("Bridge id and URL are both required.".into());
            return;
        }
        let tools: Vec<String> = tools_csv
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        set_registering.set(true);
        set_reg_out.set(String::new());
        spawn_local(async move {
            let body = json!({
                "bridge_id": b.trim(),
                "url": u.trim(),
                "agent_pid": if a.trim().is_empty() { json!("mcp-bridge") } else { json!(a.trim()) },
                "tools": tools,
            });
            match api::post_value("/tools/mcp/register", body).await {
                Ok(v) => {
                    if let Some(e) = api::body_error(&v) {
                        set_reg_out.set(e);
                    } else {
                        set_reg_out.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                        set_reload.update(|n| *n += 1);
                    }
                }
                Err(e) => set_reg_out.set(e.message),
            }
            set_registering.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"STEP 1  ·  POST /protocols/mcp/discover"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Probe a tool server"</h4>
                <p class="text-[11px] text-stone-400">
                    "Read-only. Nothing is saved — this asks the server what tools it offers, and confirms the node egress allowlist permits the URL."
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-3 gap-1.5">
                    <div class="sm:col-span-2">
                        <FieldInput label="Server URL" placeholder="https://mcp.example.com" value=url set_value=set_url />
                    </div>
                    <FieldInput label="Timeout (s)" placeholder="10" value=timeout set_value=set_timeout />
                </div>
                <button type="button" class="fcs-btn go" prop:disabled=move || probing.get() on:click=probe>
                    {move || if probing.get() { "PROBING…" } else { "PROBE" }}
                </button>

                {move || {
                    let d = discovered.get();
                    (!d.is_empty()).then(|| {
                        let n = d.len();
                        view! {
                            <div class="space-y-1">
                                <p class="text-[11px] text-emerald-300">
                                    {format!("{n} tool(s) discovered — carried into the register form below.")}
                                </p>
                                <div class="flex flex-wrap gap-1">
                                    {d.into_iter().map(|t| view! {
                                        <span class="fcs-chip">{t}</span>
                                    }).collect_view()}
                                </div>
                            </div>
                        }
                    })
                }}
                {move || {
                    let o = probe_out.get();
                    (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-56 overflow-auto">{o}</pre> })
                }}
            </section>

            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"STEP 2  ·  POST /tools/mcp/register"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Register the bridge"</h4>
                <p class="text-[11px] text-stone-400">
                    "Registration passes the egress allowlist, the agent L7 policy, and the action-binding gate. If governance asks for a human, the response says so."
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    <FieldInput label="Bridge id" placeholder="github-mcp" value=bridge_id set_value=set_bridge_id />
                    <FieldInput label="Owner agent pid" placeholder="mcp-bridge (default)" value=agent_pid set_value=set_agent_pid />
                    <FieldInput label="URL" placeholder="https://mcp.example.com" value=bridge_url set_value=set_bridge_url />
                    <FieldInput label="Tools (comma separated)" placeholder="search, read_file" value=tools_csv set_value=set_tools_csv />
                </div>
                <div class="flex flex-wrap gap-2">
                    <button type="button" class="fcs-btn go" prop:disabled=move || registering.get() on:click=register>
                        {move || if registering.get() { "REGISTERING…" } else { "REGISTER BRIDGE" }}
                    </button>
                    <button
                        type="button"
                        class="fcs-btn"
                        on:click=move |_| set_bridge_url.set(url.get())
                    >
                        "COPY PROBED URL"
                    </button>
                </div>
                {move || {
                    let o = reg_out.get();
                    (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-56 overflow-auto">{o}</pre> })
                }}
            </section>

            <section class="space-y-2">
                <h4 class="fcs-section-label">"Connected"</h4>
                <Suspense fallback=move || view! { <p class="fcs-pad text-xs text-stone-400">"Reading uplinks…"</p> }>
                    {move || Suspend::new(async move {
                        let (srv, brg) = servers.await;
                        let servers_list = srv.ok()
                            .and_then(|v| v.get("servers").or_else(|| v.get("data")).cloned())
                            .and_then(|x| x.as_array().cloned())
                            .unwrap_or_default();
                        let bridges_list = brg.ok()
                            .and_then(|v| v.get("bridges").or_else(|| v.get("data")).cloned())
                            .and_then(|x| x.as_array().cloned())
                            .unwrap_or_default();
                        view! {
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                <div class="fcs-pad space-y-1">
                                    <p class="fcs-pad-id">"GET /protocols/mcp/servers"</p>
                                    {if servers_list.is_empty() {
                                        view! { <p class="text-[11px] text-stone-500">"No MCP servers registered in this session."</p> }.into_any()
                                    } else {
                                        servers_list.into_iter().map(|s| {
                                            let name = s.get("name").or_else(|| s.get("server_url")).and_then(|x| x.as_str()).unwrap_or("server").to_string();
                                            view! { <p class="text-[11px] text-stone-200 truncate">{name}</p> }
                                        }).collect_view().into_any()
                                    }}
                                </div>
                                <div class="fcs-pad space-y-1">
                                    <p class="fcs-pad-id">"GET /tools/mcp/bridges"</p>
                                    {if bridges_list.is_empty() {
                                        view! { <p class="text-[11px] text-stone-500">"No bridges yet."</p> }.into_any()
                                    } else {
                                        bridges_list.into_iter().map(|b| {
                                            let id = b.get("bridge_id").and_then(|x| x.as_str()).unwrap_or("bridge").to_string();
                                            let u = b.get("url").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            let del_id = id.clone();
                                            let drop_bridge = move |_| {
                                                let del_id = del_id.clone();
                                                spawn_local(async move {
                                                    match api::delete_value(&format!("/tools/mcp/bridges/{del_id}")).await {
                                                        Ok(v) => {
                                                            if let Some(e) = api::body_error(&v) {
                                                                set_reg_out.set(e);
                                                            } else {
                                                                set_reg_out.set(format!("Unregistered {del_id}."));
                                                                set_reload.update(|n| *n += 1);
                                                            }
                                                        }
                                                        Err(e) => set_reg_out.set(e.message),
                                                    }
                                                });
                                            };
                                            view! {
                                                <div class="flex items-start justify-between gap-2 text-[11px]">
                                                    <span class="min-w-0">
                                                        <span class="text-stone-200">{id}</span>
                                                        <span class="block truncate text-stone-500">{u}</span>
                                                    </span>
                                                    <button
                                                        type="button"
                                                        class="fcs-btn amber shrink-0"
                                                        on:click=drop_bridge
                                                    >"UNREGISTER"</button>
                                                </div>
                                            }
                                        }).collect_view().into_any()
                                    }}
                                </div>
                            </div>
                        }
                    })}
                </Suspense>
            </section>
        </div>
    }
}

// ── Bindings ─────────────────────────────────────────────────────────────────

#[component]
fn BindingsTab() -> impl IntoView {
    let (agent_pid, set_agent_pid) = signal(String::new());
    let (tool_id, set_tool_id) = signal(String::new());
    let (ops, set_ops) = signal("read".to_string());
    let (paths, set_paths) = signal(String::new());
    let (out, set_out) = signal(String::new());
    let (busy, set_busy) = signal(false);

    let bind = move |_| {
        let (a, t) = (agent_pid.get(), tool_id.get());
        if a.trim().is_empty() || t.trim().is_empty() {
            set_out.set("Agent pid and tool id are both required.".into());
            return;
        }
        let split = |s: String| -> Vec<String> {
            s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
        };
        set_busy.set(true);
        set_out.set(String::new());
        spawn_local(async move {
            let body = json!({
                "agent_pid": a.trim(),
                "tool_id": t.trim(),
                "allowed_operations": split(ops.get()),
                "allowed_paths": split(paths.get()),
            });
            match api::post_value("/tools/bindings/scoped", body).await {
                Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_out.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"POST /tools/bindings/scoped"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Bind a tool to an agent"</h4>
                <p class="text-[11px] text-stone-400">
                    "A binding is the narrowest grant: this agent, this tool, only these operations and paths. The address RULES contract still applies on top — a binding cannot widen what the address denies."
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    <FieldInput label="Agent pid" placeholder="agent-pid" value=agent_pid set_value=set_agent_pid />
                    <FieldInput label="Tool id" placeholder="github.search" value=tool_id set_value=set_tool_id />
                    <FieldInput label="Allowed operations" placeholder="read, list" value=ops set_value=set_ops />
                    <FieldInput label="Allowed paths" placeholder="/repos/**" value=paths set_value=set_paths />
                </div>
                <button type="button" class="fcs-btn go" prop:disabled=move || busy.get() on:click=bind>
                    {move || if busy.get() { "BINDING…" } else { "BIND SCOPED" }}
                </button>
                {move || {
                    let o = out.get();
                    (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-56 overflow-auto">{o}</pre> })
                }}
            </section>

            <ReadCard
                title="Tool name collisions".to_string()
                desc="Two bridges exporting the same tool name is how an alias attack starts.".to_string()
                path="/tools/mcp/collision-check".to_string()
            />
            <ReadCard
                title="Pending tool approvals".to_string()
                desc="Tool calls parked waiting for a human.".to_string()
                path="/tools/approvals/pending".to_string()
            />
            <div class="fcs-pad">
                <p class="text-[11px] text-stone-400">
                    "Per-address allow and block rules live in "
                    <a class="text-amber-300 underline" href="/guard">"Access Control"</a>
                    " — bindings grant, contracts constrain."
                </p>
            </div>
        </div>
    }
}

// ── Credentials ──────────────────────────────────────────────────────────────

/// Vault-backed credentials for third-party tools.
///
/// The important detail an operator needs is the handoff convention: the vault
/// returns an opaque handle, and that handle — not the secret — is what goes
/// into a tool's input. The kernel materialises it in-process at dispatch, so
/// the plaintext never enters the agent's cage or crosses HTTP again.
#[component]
fn CredsTab() -> impl IntoView {
    let (secret_id, set_secret_id) = signal(String::new());
    let (value, set_value) = signal(String::new());
    let (owner, set_owner) = signal(String::new());
    let (desc, set_desc) = signal(String::new());
    let (ttl, set_ttl) = signal(String::new());
    let (kind, set_kind) = signal("llm".to_string());
    let (out, set_out) = signal(String::new());
    let (handle, set_handle) = signal(String::new());
    let (busy, set_busy) = signal(false);

    // Format-check before storing, so a mistyped key fails here rather than at
    // the first tool call.
    let test = move |_| {
        let v = value.get();
        if v.trim().is_empty() {
            set_out.set("Enter the value to test.".into());
            return;
        }
        set_busy.set(true);
        set_out.set(String::new());
        spawn_local(async move {
            let body = json!({ "kind": kind.get(), "value": v });
            match api::post_value("/settings/secrets/test", body).await {
                Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_out.set(e.message),
            }
            set_busy.set(false);
        });
    };

    let store = move |_| {
        let (id, v, o) = (secret_id.get(), value.get(), owner.get());
        if id.trim().is_empty() || v.trim().is_empty() {
            set_out.set("Secret id and value are both required.".into());
            return;
        }
        set_busy.set(true);
        set_out.set(String::new());
        set_handle.set(String::new());
        spawn_local(async move {
            let body = json!({
                "secret_id": id.trim(),
                "value": v.trim(),
                "owner_pid": if o.trim().is_empty() { json!("cnktr:platform") } else { json!(o.trim()) },
                "description": desc.get(),
                "ttl_secs": ttl.get().trim().parse::<u64>().ok(),
            });
            match api::post_value("/infra/vault/secrets", body).await {
                Ok(v) => {
                    if let Some(h) = v.get("handle_id").and_then(|x| x.as_str()) {
                        set_handle.set(h.to_string());
                    }
                    set_value.set(String::new());
                    set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                }
                Err(e) => set_out.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"POST /infra/vault/secrets"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Store a tool credential"</h4>
                <p class="text-[11px] text-stone-400">
                    "The vault returns an opaque handle. Nothing here can read the value back out over HTTP — resolve is restricted to the kernel."
                </p>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    <FieldInput label="Secret id" placeholder="github/api_token" value=secret_id set_value=set_secret_id />
                    <FieldInput label="Owner pid" placeholder="cnktr:platform (default)" value=owner set_value=set_owner />
                    <label class="flex flex-col gap-1">
                        <span class="text-[9px] uppercase tracking-wider text-stone-500">"Value"</span>
                        <input
                            type="password"
                            class="fcs-input"
                            placeholder="the secret"
                            prop:value=move || value.get()
                            on:input=move |ev| set_value.set(event_target_value(&ev))
                        />
                    </label>
                    <FieldInput label="TTL seconds (optional)" placeholder="86400" value=ttl set_value=set_ttl />
                    <FieldInput label="Description" placeholder="what this unlocks" value=desc set_value=set_desc />
                    <FieldInput label="Kind (for format test)" placeholder="llm · stripe" value=kind set_value=set_kind />
                </div>
                <div class="flex flex-wrap gap-2">
                    <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=test>
                        "TEST FORMAT"
                    </button>
                    <button type="button" class="fcs-btn go" prop:disabled=move || busy.get() on:click=store>
                        {move || if busy.get() { "STORING…" } else { "STORE IN VAULT" }}
                    </button>
                </div>

                {move || {
                    let h = handle.get();
                    (!h.is_empty()).then(|| view! {
                        <div class="space-y-1">
                            <p class="text-[11px] text-emerald-300">"Stored. Use this handle in a tool's input:"</p>
                            <pre class="fcs-pre">{format!("vault:handle:{h}")}</pre>
                            <p class="text-[10px] text-stone-500">
                                "Equivalent object form: {\"$vault_handle\": \"" {h} "\"}"
                            </p>
                        </div>
                    })
                }}
                {move || {
                    let o = out.get();
                    (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-56 overflow-auto">{o}</pre> })
                }}
            </section>

            <ReadCard
                title="Secrets overview".to_string()
                desc="Vault contents and the recent secret audit trail.".to_string()
                path="/settings/secrets/overview".to_string()
            />
            <ReadCard
                title="Master key (KEK) mode".to_string()
                desc="Where the key-encrypting key lives — OS keyring, TPM, or cloud KMS.".to_string()
                path="/settings/secrets/master-key".to_string()
            />
            <ReadCard
                title="Vault status".to_string()
                desc="How many secrets and handles this node is holding.".to_string()
                path="/infra/vault/status".to_string()
            />
            <ReadCard
                title="Tool catalog".to_string()
                desc="Registered tool descriptors available to agents.".to_string()
                path="/marketplace/tools".to_string()
            />
            <ReadCard
                title="Egress status".to_string()
                desc="The allowlist every outbound tool call is checked against.".to_string()
                path="/runtime/egress/status".to_string()
            />
        </div>
    }
}

// ── Health ───────────────────────────────────────────────────────────────────

#[component]
fn HealthTab() -> impl IntoView {
    view! {
        <div class="space-y-3">
            <ReadCard
                title="Tool health".to_string()
                desc="Reachability and error rates for every wired tool.".to_string()
                path="/monitor/tools".to_string()
            />
            <ReadCard
                title="MCP tools".to_string()
                desc="Every tool currently exported to agents.".to_string()
                path="/protocols/mcp/tools".to_string()
            />
            <ReadCard
                title="Signal handlers".to_string()
                desc="Registered inbound signal handlers.".to_string()
                path="/tools/signals/handlers".to_string()
            />
            <ReadCard
                title="Gateway status".to_string()
                desc="Which provider and model requests are actually routed to.".to_string()
                path="/gateway/status".to_string()
            />
            <ReadCard
                title="LLM behaviour".to_string()
                desc="Latency, refusal and fallback metrics for the model path.".to_string()
                path="/monitor/llm".to_string()
            />
        </div>
    }
}

// ── Shared pieces ────────────────────────────────────────────────────────────

#[component]
fn FieldInput(
    label: &'static str,
    placeholder: &'static str,
    value: ReadSignal<String>,
    set_value: WriteSignal<String>,
) -> impl IntoView {
    view! {
        <label class="flex flex-col gap-1">
            <span class="text-[9px] uppercase tracking-wider text-stone-500">{label}</span>
            <input
                class="fcs-input"
                placeholder=placeholder
                prop:value=move || value.get()
                on:input=move |ev| set_value.set(event_target_value(&ev))
            />
        </label>
    }
}

/// Read-only endpoint card — fetch on demand, render verbatim.
#[component]
fn ReadCard(title: String, desc: String, path: String) -> impl IntoView {
    let (out, set_out) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let p = path.clone();

    let load = move |_| {
        let p = p.clone();
        set_busy.set(true);
        spawn_local(async move {
            match api::get_value(&p).await {
                Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_out.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <section class="fcs-pad space-y-2">
            <p class="fcs-pad-id">{format!("GET {path}")}</p>
            <h4 class="text-xs font-semibold text-stone-100">{title}</h4>
            <p class="text-[11px] text-stone-400">{desc}</p>
            <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=load>
                {move || if busy.get() { "READING…" } else { "READ" }}
            </button>
            {move || {
                let o = out.get();
                (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-56 overflow-auto">{o}</pre> })
            }}
        </section>
    }
}

/// GET-then-edit-then-POST card for JSON config endpoints.
#[component]
fn JsonConfigCard(
    title: String,
    desc: String,
    get_path: String,
    post_path: String,
) -> impl IntoView {
    let (text, set_text) = signal(String::new());
    let (msg, set_msg) = signal(String::new());
    let (busy, set_busy) = signal(false);

    let gp = get_path.clone();
    let load = move |_| {
        let gp = gp.clone();
        set_busy.set(true);
        set_msg.set(String::new());
        spawn_local(async move {
            match api::get_value(&gp).await {
                Ok(v) => set_text.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_msg.set(e.message),
            }
            set_busy.set(false);
        });
    };

    let pp = post_path.clone();
    let save = move |_| {
        let pp = pp.clone();
        let raw = text.get();
        let parsed: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                set_msg.set(format!("Not valid JSON: {e}"));
                return;
            }
        };
        set_busy.set(true);
        set_msg.set(String::new());
        spawn_local(async move {
            match api::post_value(&pp, parsed).await {
                Ok(v) => {
                    if let Some(e) = api::body_error(&v) {
                        set_msg.set(e);
                    } else {
                        set_msg.set("Saved.".into());
                    }
                }
                Err(e) => set_msg.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <section class="fcs-pad space-y-2">
            <p class="fcs-pad-id">{format!("GET / POST {get_path}")}</p>
            <h4 class="text-xs font-semibold text-stone-100">{title}</h4>
            <p class="text-[11px] text-stone-400">{desc}</p>
            <div class="flex flex-wrap gap-2">
                <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=load>"LOAD"</button>
                <button type="button" class="fcs-btn go" prop:disabled=move || busy.get() on:click=save>"SAVE"</button>
            </div>
            <textarea
                class="fcs-input w-full h-40 font-mono text-[11px]"
                placeholder="Load first, then edit the JSON."
                prop:value=move || text.get()
                on:input=move |ev| set_text.set(event_target_value(&ev))
            ></textarea>
            {move || {
                let m = msg.get();
                (!m.is_empty()).then(|| view! { <p class="text-[11px] text-amber-300">{m}</p> })
            }}
        </section>
    }
}
