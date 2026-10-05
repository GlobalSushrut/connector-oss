//! Isolation posture panel — Linux bar + broker/tokenize (evidence-bound chips).

use leptos::prelude::*;
use serde_json::Value;
use std::time::Duration;

use crate::components::operator::api_state::OpLoadingBlock;
use crate::iia_api;

fn chip(ok: bool, label: &str, detail: &str) -> impl IntoView {
    let class = if ok {
        "rounded border border-emerald-800/60 bg-emerald-950/30 px-2 py-1"
    } else {
        "rounded border border-amber-800/60 bg-amber-950/30 px-2 py-1"
    };
    let tone = if ok {
        "text-emerald-200"
    } else {
        "text-amber-200"
    };
    let label = label.to_string();
    let detail = detail.to_string();
    view! {
        <div class=class>
            <p class=format!("text-[10px] font-semibold uppercase {tone}")>{label}</p>
            <p class="mt-0.5 font-mono text-[10px] text-zinc-400">{detail}</p>
        </div>
    }
}

fn bool_path(v: &Value, path: &str) -> bool {
    v.pointer(path).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn str_path(v: &Value, path: &str) -> String {
    v.pointer(path)
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string()
}

/// Monitor / Setup: host-evidence chips for unbypassable bar + broker.
#[component]
pub fn OpIsolationPosturePanel() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (tick, set_tick) = signal(0u32);

    Effect::new(move |prev: Option<bool>| {
        if prev.unwrap_or(false) {
            return true;
        }
        let _ = set_interval_with_handle(
            move || set_tick.update(|t| *t = t.wrapping_add(1)),
            Duration::from_secs(12),
        );
        true
    });

    let status = LocalResource::new(move || {
        let _ = reload.get();
        let _ = tick.get();
        async move { iia_api::substrate_status().await }
    });

    view! {
        <section class="rounded-xl border border-zinc-800/70 bg-zinc-950/40 p-4 space-y-3">
            <div class="flex flex-wrap items-start justify-between gap-2">
                <div>
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                        "Isolation posture · host evidence"
                    </p>
                    <p class="mt-1 text-[12px] text-zinc-400">
                        "Green only when API reports positive evidence. Amber = not evidenced (lab/off). Do not claim MILITARY_COURT from amber chips."
                    </p>
                </div>
                <div class="flex flex-wrap gap-2">
                    <button
                        type="button"
                        class="rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-300 hover:border-cyan-700"
                        on:click=move |_| set_reload.update(|n| *n += 1)
                    >
                        "Refresh"
                    </button>
                    <a
                        class="rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-300 hover:border-cyan-700"
                        href="/runtime-enforcement"
                    >
                        "Enforcement"
                    </a>
                </div>
            </div>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading /substrate/status…".to_string() /> }>
                {move || Suspend::new(async move {
                    match status.await {
                        Ok(v) => {
                            let sand = v.get("sandbox_unbypassable").cloned().unwrap_or(Value::Null);
                            let enforced = bool_path(&sand, "/enforced")
                                || bool_path(&v, "/sandbox_unbypassable/enforced");
                            let landlock = bool_path(&sand, "/landlock_fail_closed")
                                && bool_path(&sand, "/fs_allowlists_present");
                            let nft = bool_path(&sand, "/nft");
                            let ipt = bool_path(&sand, "/iptables");
                            let ebpf = bool_path(&sand, "/ebpf_pins");
                            let net_ok = nft || ipt || ebpf;
                            let microvm = bool_path(&sand, "/tools_in_microvm")
                                || bool_path(&sand, "/world_channel_via_microvm");
                            let vsock = bool_path(&sand, "/vsock_ticket_required");
                            let gate = bool_path(&sand, "/gate_ok");
                            // Green only on positive evidence — never "green because bar is off".
                            let vm_ok = microvm && vsock;
                            let gate_ok = gate && enforced;
                            let broker = bool_path(&sand, "/llm_broker_unbypassable")
                                || bool_path(&v, "/llm_broker/unbypassable");
                            let tokenize = bool_path(&v, "/data_tokenization/enforced")
                                || v.pointer("/effect_exclusivity/data_tokenization/enforced")
                                    .and_then(|x| x.as_bool())
                                    .unwrap_or(false)
                                || bool_path(&sand, "/data_tokenization_enforced");
                            view! {
                                <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                                    {chip(landlock, "FS Landlock", &format!(
                                        "fail_closed={} allowlists={}",
                                        bool_path(&sand, "/landlock_fail_closed"),
                                        bool_path(&sand, "/fs_allowlists_present")
                                    ))}
                                    {chip(net_ok, "Net iptables/nft/eBPF", &format!(
                                        "nft={nft} iptables={ipt} ebpf={ebpf}"
                                    ))}
                                    {chip(vm_ok, "VM / vsock", &format!(
                                        "microvm={} vsock_ticket={} enforced={} honesty={}",
                                        microvm,
                                        vsock,
                                        enforced,
                                        str_path(&sand, "/honesty").chars().take(40).collect::<String>()
                                    ))}
                                    {chip(gate_ok, "Sandbox gate", &format!(
                                        "enforced={enforced} gate_ok={gate}"
                                    ))}
                                    {chip(broker, "LLM broker", if broker {
                                        "CONNECTOR_LLM_BROKER_UNBYPASSABLE evidenced"
                                    } else {
                                        "broker soft / not enforced (lab)"
                                    })}
                                    {chip(tokenize, "Tokenization", if tokenize {
                                        "data tokenization enforced"
                                    } else {
                                        "tokenization soft / not evidenced on this payload"
                                    })}
                                </div>
                                <p class="text-[10px] font-mono text-zinc-600">
                                    "GET /substrate/status · poll 12s · HTTP legend: 200 normal · 409 redo · 499 need human approval"
                                </p>
                            }.into_any()
                        }
                        Err(e) => view! {
                            <p class="text-[11px] text-rose-300">{format!("substrate status unavailable: {e}")}</p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}
