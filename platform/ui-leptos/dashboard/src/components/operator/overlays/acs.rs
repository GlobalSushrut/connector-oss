//! Agentic Character Surface — isolation + NS FS + character at the top of the agent.

use leptos::prelude::*;
use serde_json::Value;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::components::operator::api_state::OpLoadingBlock;
use crate::components::operator::primitives::{OpButton, OpButtonVariant};
use crate::iia_api;

#[component]
pub fn OpAcsStrip(#[prop(into)] pid: String) -> impl IntoView {
    let pid_load = pid.clone();
    let pid_sv = StoredValue::new(pid);
    let (reload, set_reload) = signal(0u32);
    let acs = LocalResource::new(move || {
        let pid = pid_load.clone();
        let _ = reload.get();
        async move { iia_api::agent_acs(&pid).await }
    });
    view! {
        <Suspense fallback=move || view! { <OpLoadingBlock message="Loading ACS…".to_string() /> }>
            {move || Suspend::new(async move {
                match acs.await {
                    Ok(v) => view! { <AcsBody pid=pid_sv.get_value() v=v reload=reload on_reload=set_reload /> }.into_any(),
                    Err(_) => view! {
                        <p class="text-[11px] text-zinc-600">"ACS unavailable — isolation / NS FS still apply at kernel."</p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

#[component]
fn AcsBody(
    pid: String,
    v: Value,
    reload: ReadSignal<u32>,
    on_reload: WriteSignal<u32>,
) -> impl IntoView {
    let class = v
        .pointer("/character/class")
        .and_then(|x| x.as_str())
        .unwrap_or("agent")
        .to_string();
    let name = v
        .pointer("/character/name")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let purpose = v
        .pointer("/character/purpose")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let profile = v
        .pointer("/density/id")
        .and_then(|x| x.as_str())
        .unwrap_or("light_ns")
        .to_string();
    let compute = v
        .pointer("/density/compute")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let tier = v
        .pointer("/isolation/tier")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let ns_root = v
        .pointer("/nsfs/root")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let ns_ok = v.pointer("/nsfs/exists").and_then(|x| x.as_bool()).unwrap_or(false);
    let grants = v
        .pointer("/world/grant_count")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    view! {
        <section class="rounded-xl border border-cyan-900/40 bg-zinc-950/60 p-4 space-y-3">
            <div class="flex flex-wrap items-baseline justify-between gap-2">
                <div>
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-cyan-400/90">"ACS — agentic character surface"</p>
                    <p class="mt-0.5 text-[12px] text-zinc-300">
                        "Top-level: who this intelligence is, how it is isolated, which NS FS it owns."
                    </p>
                </div>
                <span class="rounded-full border border-cyan-800/50 bg-cyan-950/40 px-2 py-0.5 font-mono text-[10px] uppercase text-cyan-100">
                    {profile}
                </span>
            </div>
            <div class="grid gap-3 sm:grid-cols-3">
                <div>
                    <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Character"</p>
                    <p class="font-mono text-[11px] text-zinc-200">{format!("{class}  {name}")}</p>
                    <p class="text-[11px] text-zinc-400">{purpose}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Isolation (density)"</p>
                    <p class="font-mono text-[11px] text-zinc-200">{format!("tier={tier}")}</p>
                    <p class="text-[11px] text-zinc-400">{compute}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase tracking-wide text-zinc-500">"NS FS"</p>
                    <p class="font-mono text-[10px] text-zinc-300">{ns_root}</p>
                    <p class="text-[11px] text-zinc-400">
                        {if ns_ok { format!("trees ready · {grants} world grants") } else { format!("not created yet · {grants} world grants") }}
                    </p>
                    {(!ns_ok).then(|| {
                        let pid = pid.clone();
                        view! {
                            <OpButton
                                label="Create NS FS".to_string()
                                variant=OpButtonVariant::Ghost
                                on_click=Arc::new(move |_| {
                                    let pid = pid.clone();
                                    spawn_local(async move {
                                        match iia_api::agent_nsfs_ensure(&pid).await {
                                            Ok(v) => {
                                                if let Some(e) = crate::api::body_error(&v) {
                                                    web_sys::window().map(|w| {
                                                        let _ = w.alert_with_message(&format!("NS FS ensure failed: {e}"));
                                                    });
                                                }
                                            }
                                            Err(e) => {
                                                web_sys::window().map(|w| {
                                                    let _ = w.alert_with_message(&format!("NS FS ensure failed: {e}"));
                                                });
                                            }
                                        }
                                        on_reload.update(|x| *x += 1);
                                    });
                                })
                            />
                        }
                    })}
                </div>
            </div>
            {(!ns_ok || grants == "0" || grants == "—").then(|| view! {
                <div class="rounded border border-amber-800/50 bg-amber-950/20 px-3 py-2 text-[11px] text-amber-100/90">
                    <p class="font-semibold">"Post-create checklist"</p>
                    <ul class="mt-1 list-disc pl-4 space-y-0.5 text-amber-100/75">
                        <li>"Create NS FS if missing (button above)."</li>
                        <li>"Mint Guard RULES + HITL for tool addresses before Talk tools."</li>
                        <li>"Optional world grant under Manage / Setup WorldConnect."</li>
                        <li>"Download Evidence isolation PDF before production claims."</li>
                    </ul>
                </div>
            })}
            <BrokerSandboxSlotStrip pid=pid.clone() reload=reload />
        </section>
    }
}

#[component]
fn BrokerSandboxSlotStrip(pid: String, reload: ReadSignal<u32>) -> impl IntoView {
    let pid_load = pid.clone();
    let (local_tick, set_local_tick) = signal(0u32);
    let slot = LocalResource::new(move || {
        let pid = pid_load.clone();
        let _ = reload.get();
        let _ = local_tick.get();
        async move { iia_api::agent_isolation_audit(&pid).await.ok() }
    });
    view! {
        <div class="space-y-1">
            <div class="flex justify-end">
                <button
                    type="button"
                    class="text-[10px] text-violet-300/80 hover:underline"
                    on:click=move |_| set_local_tick.update(|n| *n += 1)
                >
                    "Refresh slot"
                </button>
            </div>
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                let Some(v) = slot.await else {
                    return view! { <></> }.into_any();
                };
                let open = v
                    .pointer("/isolation_proofs/4/sandbox_slot/open")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let gen = v
                    .pointer("/isolation_proofs/4/generation")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                let id_hash = v
                    .pointer("/isolation_proofs/4/sandbox_slot/identity_hash")
                    .or_else(|| v.pointer("/isolation_proofs/4/sandbox_slot/sandbox_id"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("—");
                let character = v
                    .pointer("/isolation_proofs/4/sandbox_slot/character_hash")
                    .and_then(|x| x.as_str())
                    .unwrap_or("—");
                let knowledge = v
                    .pointer("/isolation_proofs/4/sandbox_slot/knowledge_hash")
                    .and_then(|x| x.as_str())
                    .unwrap_or("—");
                let trunc = |s: &str| {
                    if s.len() > 12 {
                        format!("{}…", &s[..12])
                    } else {
                        s.to_string()
                    }
                };
                view! {
                    <div class="rounded-lg border border-violet-900/40 bg-violet-950/20 px-3 py-2">
                        <p class="text-[10px] uppercase tracking-wide text-violet-300/90">
                            "Broker sandbox slot · identity · character · knowledge · generation"
                        </p>
                        <p class="mt-1 font-mono text-[10px] text-violet-100/85">
                            {format!(
                                "open={} · gen={} · id={} · char={} · know={}",
                                open,
                                gen,
                                trunc(id_hash),
                                trunc(character),
                                trunc(knowledge)
                            )}
                        </p>
                        <p class="mt-0.5 text-[10px] text-zinc-500">
                            "One shared LLM brain; this slot binds the agent. Cross-slot → 499. Human approve → 200 new epoch."
                        </p>
                    </div>
                }.into_any()
            })}
        </Suspense>
        </div>
    }
}
