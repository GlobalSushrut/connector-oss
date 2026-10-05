//! Live agent status popup — "what is happening, and who stopped it".
//!
//! Opens whenever the operator touches an agent. Polls
//! `GET /kernel/agent-explain` every few seconds and renders, in order:
//!
//! * verdict banner (active / quarantined / paused / blocked / needs human)
//! * the **why chain** — each gate that is holding the agent, named by the
//!   layer that enforced it, with the fix
//! * identity (who it is) and knowledge (what it remembers)
//! * address DAC verdicts, Block seals, pending HITL, recent kernel denials
//!
//! Read-only by design: the backend uses dry-run evaluation, so opening this
//! never writes a Block seal and never mints a HITL request.

use leptos::prelude::*;
use serde_json::Value;
use std::time::Duration;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::iia_api;
use crate::ui_state::use_agent_explain;

const POLL_MS: u64 = 4_000;

fn verdict_chip(verdict: &str) -> &'static str {
    match verdict {
        "active" => "fcs-verdict go",
        "needs_human" => "fcs-verdict ask",
        "unknown" => "fcs-verdict",
        _ => "fcs-verdict",
    }
}

fn severity_chip(sev: &str) -> &'static str {
    match sev {
        "ask" => "fcs-chip warn",
        "warn" => "fcs-chip warn",
        "denial" => "fcs-chip bad",
        _ => "fcs-chip bad",
    }
}

#[component]
pub fn OpAgentExplainHost() -> impl IntoView {
    let explain = use_agent_explain();
    let pid = explain.pid;
    let set_pid = explain.set_pid;

    let (data, set_data) = signal::<Option<Value>>(None);
    let (err, set_err) = signal(String::new());
    let (tick, set_tick) = signal(0u32);

    // Poll while the popup is open so a quarantine lift shows up without a reload.
    Effect::new(move |prev: Option<bool>| {
        if prev.unwrap_or(false) {
            return true;
        }
        let _ = set_interval_with_handle(
            move || set_tick.update(|t| *t = t.wrapping_add(1)),
            Duration::from_millis(POLL_MS),
        );
        true
    });

    Effect::new(move |_| {
        let _ = tick.get();
        let Some(p) = pid.get() else {
            set_data.set(None);
            return;
        };
        spawn_local(async move {
            match api::get_value_q("/kernel/agent-explain", &[("agent_pid", p.as_str())]).await {
                Ok(v) => {
                    set_err.set(String::new());
                    set_data.set(Some(v));
                }
                Err(e) => set_err.set(format!("{e}")),
            }
        });
    });

    view! {
        <div
            class=move || if pid.get().is_some() {
                "fixed inset-0 z-[60] overflow-y-auto fcs-install"
            } else {
                "hidden"
            }
            role="dialog"
            aria-modal="true"
            aria-label="Agent live status"
        >
            <button
                type="button"
                class="fixed inset-0 bg-black/70 backdrop-blur-sm"
                aria-label="Close"
                on:click=move |_| set_pid.set(None)
            ></button>

            <div class="relative flex min-h-full items-start justify-center p-4 sm:p-8">
            <div class="relative w-full max-w-2xl fcs-bezel">
                <div class="fcs-titlebar">
                    <div class="fcs-titlebar-mark">
                        <span class="fcs-win-controls" aria-hidden="true">
                            <span class="fcs-win-btn close"></span>
                            <span class="fcs-win-btn"></span>
                            <span class="fcs-win-btn"></span>
                        </span>
                        <span class="truncate">
                            {move || format!("AGENT MONITOR  ·  {}", pid.get().unwrap_or_default())}
                        </span>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="fcs-light go"><span class="dot"></span>"LIVE"</span>
                        <button
                            type="button"
                            class="fcs-btn"
                            on:click=move |_| set_pid.set(None)
                        >
                            "CLOSE"
                        </button>
                    </div>
                </div>

                <div class="fcs-body space-y-4">
                    {move || {
                        let e = err.get();
                        (!e.is_empty()).then(|| view! {
                            <p class="fcs-pad text-xs text-rose-300">{e}</p>
                        })
                    }}

                    {move || {
                        let Some(v) = data.get() else {
                            return view! {
                                <p class="fcs-pad text-xs text-stone-400">"Reading kernel state…"</p>
                            }.into_any();
                        };

                        let verdict = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
                        let headline = v.get("headline").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        let kstatus = v.get("kernel_status").and_then(|x| x.as_str()).unwrap_or("—").to_string();

                        let why = v.get("why").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        let dac = v.get("address_dac").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        let seals = v.get("block_seals").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        let hitl = v.get("pending_hitl").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        let denials = v.get("recent_denials").and_then(|x| x.as_array()).cloned().unwrap_or_default();

                        let ch_name = v.pointer("/identity/character_name").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let ch_purpose = v.pointer("/identity/character_purpose").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let address = v.pointer("/identity/address").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let addr_type = v.pointer("/identity/address_type").and_then(|x| x.as_str()).unwrap_or("—").to_string();

                        let has_mem = v.pointer("/knowledge/has_last_memory").and_then(|x| x.as_bool()).unwrap_or(false);
                        let mem_cid = v.pointer("/knowledge/last_memory_cid").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let relations = v.pointer("/knowledge/address_relation_count").and_then(|x| x.as_u64());
                        let packets = v.pointer("/knowledge/total_packets").and_then(|x| x.as_u64());
                        let sessions = v.pointer("/knowledge/active_sessions").and_then(|x| x.as_u64());
                        let knowledge_line = format!(
                            "{} packets · {} sessions · {} address relations",
                            packets.map(|n| n.to_string()).unwrap_or_else(|| "—".into()),
                            sessions.map(|n| n.to_string()).unwrap_or_else(|| "—".into()),
                            relations.map(|n| n.to_string()).unwrap_or_else(|| "—".into()),
                        );

                        let quarantined = v.pointer("/control/quarantined").and_then(|x| x.as_bool()).unwrap_or(false);
                        let paused = v.pointer("/control/paused").and_then(|x| x.as_bool()).unwrap_or(false);
                        let isolated = v.pointer("/control/egress_isolated").and_then(|x| x.as_bool()).unwrap_or(false);
                        let agent_pid_action = pid.get().unwrap_or_default();

                        view! {
                            <div class="fcs-pad space-y-1.5">
                                <div class="flex items-center gap-2 flex-wrap">
                                    <span class=verdict_chip(&verdict)>{verdict.to_uppercase()}</span>
                                    <span class="text-sm text-stone-100 font-medium">{headline}</span>
                                </div>
                                <div class="flex items-center gap-2 flex-wrap text-[10px]">
                                    <span class="fcs-chip">{format!("KERNEL {kstatus}")}</span>
                                    {quarantined.then(|| view! { <span class="fcs-chip bad">"QUARANTINED"</span> })}
                                    {paused.then(|| view! { <span class="fcs-chip bad">"PAUSED"</span> })}
                                    {isolated.then(|| view! { <span class="fcs-chip warn">"EGRESS CUT"</span> })}
                                </div>
                                <div class="flex flex-wrap gap-2 pt-2">
                                    <button
                                        type="button"
                                        class="fcs-btn amber"
                                        on:click={
                                            let agent_pid_action = agent_pid_action.clone();
                                            move |_| {
                                                let p = agent_pid_action.clone();
                                                spawn_local(async move {
                                                    let _ = iia_api::approve_unquarantine_hitl(&p, "").await;
                                                    set_tick.update(|t| *t = t.wrapping_add(1));
                                                });
                                            }
                                        }
                                    >
                                        "APPROVE UNQUARANTINE HITL"
                                    </button>
                                    <button
                                        type="button"
                                        class="fcs-btn"
                                        on:click={
                                            let agent_pid_action = agent_pid_action.clone();
                                            move |_| {
                                                let p = agent_pid_action.clone();
                                                spawn_local(async move {
                                                    let _ = iia_api::agent_quarantine(
                                                        &p,
                                                        "operator agent-explain — brain quarantine",
                                                    )
                                                    .await;
                                                    set_tick.update(|t| *t = t.wrapping_add(1));
                                                });
                                            }
                                        }
                                    >
                                        "QUARANTINE"
                                    </button>
                                </div>
                                <p class="text-[10px] text-stone-500">
                                    "Unquarantine clears agent brain / LLM broker quarantine (≠ TraceTramp). Talk resumes on a new epoch (HTTP 200)."
                                </p>
                            </div>

                            {(!why.is_empty()).then(|| view! {
                                <section class="space-y-1.5">
                                    <h4 class="fcs-section-label">"Why  ·  enforcement chain"</h4>
                                    {why.clone().into_iter().map(|w| {
                                        let layer = w.get("layer").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        let sev = w.get("severity").and_then(|x| x.as_str()).unwrap_or("block").to_string();
                                        let title = w.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        let detail = w.get("detail").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        let fix = w.get("fix").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        view! {
                                            <div class="fcs-pad space-y-1">
                                                <div class="flex items-center gap-2 flex-wrap">
                                                    <span class=severity_chip(&sev)>{sev.to_uppercase()}</span>
                                                    <span class="text-xs text-stone-100 font-medium">{title}</span>
                                                </div>
                                                <p class="text-[11px] text-stone-400">{detail}</p>
                                                <p class="text-[10px] text-amber-300/80">{layer}</p>
                                                {(!fix.is_empty()).then(|| view! {
                                                    <p class="text-[10px] text-emerald-300/80">{format!("Fix: {fix}")}</p>
                                                })}
                                            </div>
                                        }
                                    }).collect_view()}
                                </section>
                            })}

                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 items-start">
                                <div class="fcs-pad min-w-0 space-y-1">
                                    <p class="fcs-pad-id">"IDENTITY"</p>
                                    <p class="text-xs text-stone-100 break-words">{ch_name}</p>
                                    <p class="text-[11px] text-stone-400 break-words">{ch_purpose}</p>
                                    <p class="truncate text-[10px] text-stone-500">{format!("{address}  ·  {addr_type}")}</p>
                                </div>
                                <div class="fcs-pad min-w-0 space-y-1">
                                    <p class="fcs-pad-id">"KNOWLEDGE"</p>
                                    <p class="text-xs text-stone-100">
                                        {if has_mem { "Last memory present" } else { "No last memory" }}
                                    </p>
                                    <p class="truncate text-[10px] text-stone-500">{mem_cid}</p>
                                    <p class="text-[10px] text-stone-400">
                                        {knowledge_line}
                                    </p>
                                </div>
                            </div>

                            {(!dac.is_empty()).then(|| view! {
                                <section class="space-y-1">
                                    <h4 class="fcs-section-label">"Address DAC  ·  dry run"</h4>
                                    <div class="fcs-pad space-y-1">
                                        {dac.clone().into_iter().map(|r| {
                                            let tool = r.get("canonical_tool").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                            let vd = r.get("verdict").and_then(|x| x.as_str()).unwrap_or("block").to_string();
                                            let reason = r.get("reason").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            let cls = match vd.as_str() {
                                                "allow" => "fcs-verdict go",
                                                "ask" => "fcs-verdict ask",
                                                _ => "fcs-verdict",
                                            };
                                            view! {
                                                <div class="flex min-w-0 items-start gap-2 text-[11px]">
                                                    <span class=cls>{vd.to_uppercase()}</span>
                                                    <span class="shrink-0 text-stone-200">{tool}</span>
                                                    <span class="min-w-0 flex-1 truncate text-stone-500">{reason}</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </section>
                            })}

                            {(!seals.is_empty()).then(|| view! {
                                <section class="space-y-1">
                                    <h4 class="fcs-section-label">"Block seals  ·  kernel-final"</h4>
                                    <div class="fcs-pad space-y-1">
                                        {seals.clone().into_iter().map(|s| {
                                            let tool = s.get("tool").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                            let reason = s.get("reason").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            let at = s.get("sealed_at").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            view! {
                                                <div class="flex min-w-0 items-start gap-2 text-[11px]">
                                                    <span class="fcs-chip bad">"SEALED"</span>
                                                    <span class="shrink-0 text-stone-200">{tool}</span>
                                                    <span class="min-w-0 flex-1 truncate text-stone-500">{reason}</span>
                                                    <span class="ml-auto shrink-0 text-stone-600">{at}</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                    <p class="text-[10px] text-stone-500">
                                        "HITL approval and LLM output cannot lift these. Unseal from Access Control with the kernel root passcode."
                                    </p>
                                </section>
                            })}

                            {(!hitl.is_empty()).then(|| view! {
                                <section class="space-y-1">
                                    <h4 class="fcs-section-label">"Pending human approvals"</h4>
                                    <div class="fcs-pad space-y-1">
                                        {hitl.clone().into_iter().map(|h| {
                                            let action = h.get("action").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                            let desc = h.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            let bound = h.get("digest_bound").and_then(|x| x.as_bool()).unwrap_or(false);
                                            view! {
                                                <div class="flex items-start gap-2 text-[11px]">
                                                    <span class="fcs-chip warn">"ASK"</span>
                                                    <span class="min-w-0">
                                                        <span class="text-stone-200">{action}</span>
                                                        <span class="block text-stone-500">{desc}</span>
                                                    </span>
                                                    {bound.then(|| view! { <span class="fcs-chip ml-auto">"DIGEST-BOUND"</span> })}
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </section>
                            })}

                            {(!denials.is_empty()).then(|| view! {
                                <section class="space-y-1">
                                    <h4 class="fcs-section-label">"Recent kernel denials"</h4>
                                    <div class="fcs-pad space-y-1">
                                        {denials.clone().into_iter().map(|d| {
                                            let opname = d.get("operation").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                            let reason = d.get("reason").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            let error = d.get("error").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                            let msg = if reason.is_empty() { error } else { reason };
                                            view! {
                                                <div class="flex items-start gap-2 text-[11px]">
                                                    <span class="fcs-chip bad">"DENY"</span>
                                                    <span class="min-w-0">
                                                        <span class="text-stone-200">{opname}</span>
                                                        <span class="block text-stone-500">{msg}</span>
                                                    </span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </section>
                            })}

                            <div class="flex flex-wrap gap-2">
                                <a class="fcs-btn amber" href="/guard">"OPEN ACCESS CONTROL"</a>
                                <a class="fcs-btn" href="/fix">"FIX QUEUE"</a>
                            </div>
                        }.into_any()
                    }}
                </div>

                <div class="fcs-statusbar">
                    <span>"LIVE POLL 4s  ·  READ-ONLY"</span>
                    <span>"NO SEAL WRITTEN BY VIEWING"</span>
                </div>
            </div>
            </div>
        </div>
    }
}
