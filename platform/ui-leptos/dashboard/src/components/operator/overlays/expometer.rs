//! Expometer — live authority + world/LLM exposure for one agent.
//!
//! Shows ceased / quarantined / paused / egress-cut, admit verdict,
//! world grants, and whether Talk is stub / linked / inflight.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::Value;
use std::time::Duration;

use crate::iia_api;

const POLL_MS: u64 = 2_500;

#[component]
pub fn OpExpometer(
    /// Agent API pid.
    pid: String,
    /// Optional external bump (e.g. after Cease) to force refresh.
    #[prop(optional, into)]
    reload: Option<ReadSignal<u32>>,
) -> impl IntoView {
    let pid_sv = StoredValue::new(pid);
    let (snap, set_snap) = signal::<Option<Value>>(None);
    let (err, set_err) = signal(String::new());
    let (tick, set_tick) = signal(0u32);

    let refresh = move || {
        let pid = pid_sv.get_value();
        spawn_local(async move {
            match iia_api::agent_expometer(&pid).await {
                Ok(v) => {
                    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                        set_err.set(
                            v.get("error")
                                .and_then(|x| x.as_str())
                                .unwrap_or("expometer error")
                                .to_string(),
                        );
                        set_snap.set(None);
                    } else {
                        set_err.set(String::new());
                        set_snap.set(Some(v));
                    }
                }
                Err(e) => {
                    set_err.set(format!("{e}"));
                    set_snap.set(None);
                }
            }
        });
    };

    Effect::new(move |_| {
        let _ = tick.get();
        if let Some(r) = reload {
            let _ = r.get();
        }
        refresh();
    });

    // Poll while mounted so Cease / quarantine / LLM link show up without a click.
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

    view! {
        <div class="rounded-lg border border-zinc-700/70 bg-zinc-950/60 px-3 py-2.5 space-y-2">
            <div class="flex items-center justify-between gap-2 flex-wrap">
                <p class="text-[10px] uppercase tracking-wide text-zinc-400">
                    "Expometer — authority · world · LLM"
                </p>
                <button
                    type="button"
                    class="text-[10px] text-zinc-500 hover:text-zinc-300"
                    on:click=move |_| set_tick.update(|n| *n = n.wrapping_add(1))
                >
                    "Refresh"
                </button>
            </div>

            <Show when=move || !err.get().is_empty()>
                <p class="text-[11px] text-rose-400">{move || err.get()}</p>
            </Show>

            {move || {
                let Some(v) = snap.get() else {
                    return view! {
                        <p class="text-[11px] text-zinc-500">"Loading exposure…"</p>
                    }.into_any();
                };

                let verdict = v
                    .get("verdict")
                    .and_then(|x| x.as_str())
                    .unwrap_or("—")
                    .to_string();
                let admit = v
                    .pointer("/authority/admit")
                    .and_then(|x| x.as_str())
                    .unwrap_or("—")
                    .to_string();
                let flags: Vec<String> = v
                    .get("flags")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let gen = v
                    .pointer("/authority/generation_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("—")
                    .to_string();
                let q_reason = v
                    .pointer("/authority/quarantine_reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let grant_n = v
                    .pointer("/world/grant_count")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                let grants: Vec<Value> = v
                    .pointer("/world/grants")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                let llm_mode = v
                    .pointer("/llm/mode")
                    .and_then(|x| x.as_str())
                    .unwrap_or("—")
                    .to_string();
                let inflight = v
                    .pointer("/llm/inflight_count")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                let burn_line = v
                    .get("spend")
                    .filter(|b| !b.is_null())
                    .map(|b| {
                        let rem_usd = b
                            .get("remaining_usd")
                            .and_then(|x| x.as_f64())
                            .unwrap_or(0.0);
                        let rem_tok = b
                            .get("remaining_tokens")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0);
                        let rem_hop = b
                            .get("iterations_remaining")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0);
                        format!("burn rem ${rem_usd:.2} · {rem_tok} tok · {rem_hop} hop")
                    })
                    .or_else(|| {
                        v.get("spend_hint")
                            .and_then(|x| x.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                    })
                    .unwrap_or_default();

                let verdict_class = match verdict.as_str() {
                    "active" => "bg-emerald-900/50 text-emerald-200 border-emerald-700/60",
                    "ceased" | "quarantined" => "bg-rose-950/60 text-rose-200 border-rose-700/60",
                    "paused" | "egress_isolated" => {
                        "bg-amber-950/50 text-amber-200 border-amber-700/50"
                    }
                    _ => "bg-zinc-800 text-zinc-300 border-zinc-600",
                };

                view! {
                    <div class="space-y-2">
                        <div class="flex flex-wrap items-center gap-1.5">
                            <span class=format!(
                                "rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide {verdict_class}"
                            )>
                                {verdict.clone()}
                            </span>
                            <span class="rounded border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-300">
                                {format!("admit · {admit}")}
                            </span>
                            <span class="rounded border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-400">
                                {format!("gen · {gen}")}
                            </span>
                            {flags.into_iter().map(|f| {
                                let bad = matches!(
                                    f.as_str(),
                                    "CEASED" | "QUARANTINED" | "POST_CEASE_RETRY" | "EGRESS_CUT" | "PAUSED"
                                );
                                let cls = if bad {
                                    "rounded border border-rose-800/70 bg-rose-950/40 px-1.5 py-0.5 text-[10px] text-rose-200"
                                } else {
                                    "rounded border border-zinc-700 px-1.5 py-0.5 text-[10px] text-zinc-400"
                                };
                                view! { <span class=cls>{f}</span> }
                            }).collect_view()}
                        </div>

                        {(!q_reason.is_empty()).then(|| view! {
                            <p class="text-[11px] text-rose-300/90">
                                {format!("quarantine: {q_reason}")}
                            </p>
                        })}

                        <div class="grid gap-2 sm:grid-cols-2">
                            <div class="rounded border border-zinc-800/80 bg-zinc-900/40 px-2 py-1.5 space-y-1">
                                <p class="text-[10px] uppercase tracking-wide text-zinc-500">"World exposure"</p>
                                <p class="text-[11px] text-zinc-200">
                                    {if grant_n == 0 {
                                        "No world grants on this agent".to_string()
                                    } else {
                                        format!("{grant_n} grant{}", if grant_n == 1 { "" } else { "s" })
                                    }}
                                </p>
                                <ul class="space-y-0.5 max-h-24 overflow-y-auto">
                                    {grants.into_iter().take(8).map(|g| {
                                        let addr = g.get("address").and_then(|x| x.as_str()).unwrap_or("—");
                                        let effect = g.get("effect").and_then(|x| x.as_str()).unwrap_or("?");
                                        let at = g.get("address_type").and_then(|x| x.as_str()).unwrap_or("");
                                        let line = if at.is_empty() {
                                            format!("{effect} · {addr}")
                                        } else {
                                            format!("{effect} · {at} · {addr}")
                                        };
                                        let title = line.clone();
                                        view! {
                                            <li class="text-[10px] text-zinc-400 truncate" title=title>
                                                {line}
                                            </li>
                                        }
                                    }).collect_view()}
                                </ul>
                            </div>
                            <div class="rounded border border-zinc-800/80 bg-zinc-900/40 px-2 py-1.5 space-y-1">
                                <p class="text-[10px] uppercase tracking-wide text-zinc-500">"LLM behavior"</p>
                                <p class="text-[11px] text-zinc-200">{format!("mode · {llm_mode}")}</p>
                                <p class="text-[10px] text-zinc-400">
                                    {if inflight > 0 {
                                        format!("inflight provider calls · {inflight}")
                                    } else {
                                        "no inflight provider calls".into()
                                    }}
                                </p>
                                {(!burn_line.is_empty()).then(|| view! {
                                    <p class="text-[10px] text-zinc-400">{burn_line.clone()}</p>
                                })}
                            </div>
                        </div>

                        <p class="text-[10px] text-zinc-500 leading-snug">
                            "After Cease/quarantine, new Admit hops refuse for this fence. World grants = addresses this agent may touch. LLM stub = canned until a tenant key is linked."
                        </p>
                    </div>
                }.into_any()
            }}
        </div>
    }
}
