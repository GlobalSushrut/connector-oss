//! Owner gateway form — one grant per (agent × CNP address), kernel root passcode.

use leptos::prelude::*;
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpSelect, OpTextField,
};
use crate::deployment::use_deployment_mode;
use crate::iia_api;
use crate::request_store::{bump_reload, use_shared_requests};

#[component]
pub fn OpGatewayGrantForm(#[prop(optional)] agent_pid: Option<String>) -> impl IntoView {
    let shared = use_shared_requests();
    let preset = agent_pid.unwrap_or_default();
    let (agent, set_agent) = signal(preset);
    let (addr_type, set_addr_type) = signal("http_api".to_string());
    let (address, set_address) = signal(String::new());
    let (access, set_access) = signal(String::new());
    let (app_allow, set_app_allow) = signal(String::new());
    let (cone_ask, set_cone_ask) = signal(String::new());
    let (justification, set_justification) = signal(String::new());
    let (params, set_params) = signal(String::new());
    let (layer, set_layer) = signal("cone".to_string());
    let (effect, set_effect) = signal("ask".to_string());
    let (root, set_root) = signal(String::new());
    let (new_root, set_new_root) = signal(String::new());
    let (flash, set_flash) = signal(String::new());
    let (reload, set_reload) = signal(0u32);
    let mode = use_deployment_mode();

    let status = LocalResource::new(move || {
        let _ = reload.get();
        async move { iia_api::gateway_status().await }
    });
    let grants = LocalResource::new(move || {
        let a = agent.get();
        let _ = reload.get();
        async move {
            if a.trim().is_empty() {
                return Ok(json!({"ok": true, "grants": []}));
            }
            iia_api::gateway_list_grants(Some(&a)).await
        }
    });

    view! {
        <section class="space-y-3 rounded-xl border border-amber-900/40 bg-zinc-950/50 p-4">
            <div>
                <p class="text-[10px] font-semibold uppercase tracking-wide text-amber-400/90">"World gateway (owner)"</p>
                <p class="mt-1 text-[12px] text-zinc-300">
                    {move || if mode.get().is_playground() {
                        "Every external target is an address. This trial: your session JWT owns grants for your Demo agent only. Cone Ask is the default. App Allow * is hosted Demo tools only — not a blank cheque. Kernel root is disabled (node-global on the shared volume)."
                    } else {
                        "Every external target is an address. Three layers: (1) Root HITL — human is root. (2) Cone — AI suggests, you approve. (3) App — automation only if you (human + kernel root) justify this agent × this address × these caps. Agents cannot mint App Allow. Isolated NS/FS/ACS per agent."
                    }}
                </p>
                <Show when=move || mode.get().is_playground()>
                    <p class="mt-2 text-[11px] text-cyan-200/90">
                        "This trial: your session JWT is the tenant owner. Cone and justified App grants do not need a kernel root passcode. Demo already has hosted tool grants for Isolate / Govern / Prove."
                    </p>
                </Show>
            </div>
            <Show when=move || !mode.get().is_playground()>
            <Suspense fallback=|| ()>
                {move || Suspend::new(async move {
                    let set = status.await.ok()
                        .and_then(|v| v.get("root_passcode_set").and_then(|x| x.as_bool()))
                        .unwrap_or(false);
                    view! {
                        <p class=if set {
                            "text-[11px] text-emerald-200"
                        } else {
                            "text-[11px] text-amber-200"
                        }>
                            {if set {
                                "Kernel root passcode is set on this node."
                            } else {
                                "No kernel root yet — set one below (admin, min 8 chars) before granting access."
                            }}
                        </p>
                    }.into_any()
                })}
            </Suspense>
            </Show>
            <Show when=move || !mode.get().is_playground()>
            <div class="space-y-2">
            <div class="grid gap-2 sm:grid-cols-2">
                <label class="flex flex-col gap-1">
                    <span class="text-xs font-medium text-zinc-400">"Kernel root passcode"</span>
                    <input
                        type="password"
                        class="h-9 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 text-sm text-zinc-200"
                        placeholder="owner root (not the agent)"
                        prop:value=move || root.get()
                        on:input=move |ev| set_root.set(event_target_value(&ev))
                    />
                </label>
                <OpTextField
                    label="Set / rotate root (admin)".to_string()
                    value=new_root
                    set_value=set_new_root
                    placeholder="leave blank to only verify"
                    password=true
                />
            </div>
            <OpButton
                label="Set or verify root".to_string()
                variant=OpButtonVariant::Ghost
                on_click=Arc::new(move |_| {
                    let r = root.get();
                    let n = new_root.get();
                    spawn_local(async move {
                        match iia_api::gateway_set_root(&r, if n.trim().is_empty() { None } else { Some(&n) }).await {
                            Ok(v) => {
                                set_flash.set(if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                                    "Root ok".into()
                                } else {
                                    format!("{v}")
                                });
                                set_reload.update(|x| *x += 1);
                            }
                            Err(e) => set_flash.set(e.message),
                        }
                    });
                })
            />
            </div>
            </Show>

            <p class="pt-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Grant form — one agent, one address"</p>
            <Suspense fallback=|| ()>
                {move || Suspend::new(async move {
                    let opts = shared.agents.await.ok().map(|v| agent_opts(&v)).unwrap_or_default();
                    let mut o = vec![("".into(), "(pick agent)".into())];
                    o.extend(opts);
                    view! {
                        <OpSelect label="Agent".to_string() value=agent set_value=set_agent options=o />
                    }.into_any()
                })}
            </Suspense>
            <div class="grid gap-2 sm:grid-cols-2">
                <OpSelect
                    label="Address type (~20)"
                    value=addr_type
                    set_value=set_addr_type
                    options=TYPE_OPTS.iter().map(|(a,b)| ((*a).into(), (*b).into())).collect()
                />
                <OpTextField
                    label="Address (CNP / URL / EntityId)".to_string()
                    value=address
                    set_value=set_address
                    placeholder="https://api… or machine:arm-1"
                />
            </div>
            <OpTextField
                label="Access (CNP caps, comma)".to_string()
                value=access
                set_value=set_access
                placeholder="machine.move_axis, actuator.gripper — or * "
            />
            <OpSelect
                label="Layer"
                value=layer
                set_value=set_layer
                options=vec![
                    ("cone".into(), "Cone — AI suggests, human approves (default)".into()),
                    ("root".into(), "Root HITL — human is root, always Ask".into()),
                    ("app".into(), "App — automation (justification required)".into()),
                ]
            />
            <OpTextField
                label="App Allow caps (no HITL — must justify)".to_string()
                value=app_allow
                set_value=set_app_allow
                placeholder="sensor.read — leave blank unless App"
            />
            <OpTextField
                label="Cone Ask caps (always HITL on this address)".to_string()
                value=cone_ask
                set_value=set_cone_ask
                placeholder="actuator.gripper, machine.move_axis"
            />
            <OpTextField
                label="Justification (required for App Allow)".to_string()
                value=justification
                set_value=set_justification
                placeholder="Why agent A may act without HITL at address P…"
            />
            <OpTextField
                label="Root params for this address (optional JSON)".to_string()
                value=params
                set_value=set_params
                placeholder=r#"{"max_speed": 2}"#
            />
            <OpSelect
                label="Effect"
                value=effect
                set_value=set_effect
                options=vec![
                    ("ask".into(), "ask (Cone / HITL)".into()),
                    ("allow".into(), "allow (App — needs justification)".into()),
                    ("block".into(), "block".into()),
                ]
            />
            <OpButton
                label="Save grant (this agent × this address)".to_string()
                variant=OpButtonVariant::Primary
                on_click=Arc::new(move |_| {
                    let pid = agent.get();
                    let ad = address.get();
                    if pid.trim().is_empty() || ad.trim().is_empty() {
                        set_flash.set("Pick an agent and an address.".into());
                        return;
                    }
                    let r = root.get();
                    let ty = addr_type.get();
                    let acc: Vec<String> = access
                        .get()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    let acc2 = acc.clone();
                    let app_a: Vec<String> = app_allow
                        .get()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    let cone_a: Vec<String> = cone_ask
                        .get()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    let just = justification.get();
                    let lyr = layer.get();
                    let ptxt = params.get();
                    let pval = serde_json::from_str(&ptxt).unwrap_or(json!({}));
                    let pval2 = pval.clone();
                    let eff = effect.get();
                    if (lyr == "app" || eff == "allow" || !app_a.is_empty()) && just.trim().len() < 16 {
                        set_flash.set("App Allow needs a justification (≥16 chars) for this agent × this address.".into());
                        return;
                    }
                    spawn_local(async move {
                        let addr_body = json!({
                            "address": ad,
                            "type": ty,
                            "params": pval,
                            "cnp_capabilities": acc,
                            "root_passcode": r,
                        });
                        if let Err(e) = iia_api::gateway_put_address(addr_body.clone()).await {
                            set_flash.set(format!("Address: {}", e.message));
                            return;
                        }
                        let grant = json!({
                            "agent_pid": pid,
                            "address": addr_body["address"],
                            "address_type": ty,
                            "access": acc2,
                            "app_allow": app_a,
                            "cone_ask": cone_a,
                            "layer": lyr,
                            "effect": eff,
                            "justification": just,
                            "params": pval2,
                            "root_passcode": r,
                        });
                        match iia_api::gateway_put_grant(grant).await {
                            Ok(v) => {
                                set_flash.set(if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                                    format!("Granted {} → {}", v.get("agent_pid").and_then(|x| x.as_str()).unwrap_or("?"), v.get("address").and_then(|x| x.as_str()).unwrap_or("?"))
                                } else {
                                    format!("{v}")
                                });
                                bump_reload();
                                set_reload.update(|x| *x += 1);
                            }
                            Err(e) => set_flash.set(e.message),
                        }
                    });
                })
            />
            <p class="text-[11px] text-zinc-400">{move || flash.get()}</p>
            <Suspense fallback=|| ()>
                {move || Suspend::new(async move {
                    match grants.await {
                        Ok(v) => {
                            let rows: Vec<String> = v
                                .get("grants")
                                .and_then(|g| g.as_array())
                                .map(|a| {
                                    a.iter()
                                        .map(|g| {
                                            let ag = g.get("agent_pid").and_then(|x| x.as_str()).unwrap_or("?");
                                            let ad = g.get("address").and_then(|x| x.as_str()).unwrap_or("?");
                                            let ef = g.get("effect").and_then(|x| x.as_str()).unwrap_or("?");
                                            let ly = g.get("layer").and_then(|x| x.as_str()).unwrap_or("cone");
                                            format!("{ag} → {ad} [{ly}/{ef}]")
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            if rows.is_empty() {
                                view! { <p class="text-[11px] text-zinc-600">"No grants yet for this agent."</p> }.into_any()
                            } else {
                                view! {
                                    <ul class="list-disc space-y-0.5 pl-4 font-mono text-[10px] text-zinc-400">
                                        {rows.into_iter().map(|s| view! { <li>{s}</li> }).collect_view()}
                                    </ul>
                                }.into_any()
                            }
                        }
                        Err(_) => ().into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

const TYPE_OPTS: &[(&str, &str)] = &[
    ("http_api", "http_api — REST / URL"),
    ("browser", "browser — governed web explorer origin"),
    ("machine", "machine — robot / CNC"),
    ("device", "device — IoT"),
    ("sensor", "sensor"),
    ("actuator", "actuator"),
    ("service", "service"),
    ("mqtt", "mqtt"),
    ("mcp_tool", "mcp_tool"),
    ("a2a_task", "a2a_task"),
    ("webhook", "webhook"),
    ("cluster_cell", "cluster_cell"),
    ("network_peer", "network_peer"),
    ("robot_hal", "robot_hal"),
    ("iot_endpoint", "iot_endpoint"),
    ("modbus", "modbus"),
    ("composite", "composite"),
    ("cpkg_plugin", "cpkg_plugin"),
    ("knowledge_plane", "knowledge_plane"),
    ("openai_compat", "openai_compat"),
    ("agent", "agent — another pid"),
];

fn agent_opts(v: &serde_json::Value) -> Vec<(String, String)> {
    let arr = v
        .as_array()
        .or_else(|| v.get("agents").and_then(|a| a.as_array()))
        .or_else(|| v.get("items").and_then(|a| a.as_array()));
    let Some(arr) = arr else {
        return vec![];
    };
    arr.iter()
        .filter_map(|a| {
            let pid = a.get("pid").or_else(|| a.get("agent_pid"))?.as_str()?;
            let name = a.get("name").and_then(|x| x.as_str()).unwrap_or(pid);
            Some((pid.to_string(), format!("{name} ({pid})")))
        })
        .collect()
}
