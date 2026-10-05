//! Runtime enforcement surface — exclusivity / sandbox refuse (operator cards).

use leptos::prelude::*;
use serde_json::Value;

use crate::api;
use crate::components::operator::api_state::OpLoadingBlock;
use crate::iia_api;
use crate::ui_state::open_agent_drawer;

fn u64_path(v: &Value, path: &str) -> Option<u64> {
    v.pointer(path).and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_i64().map(|n| n as u64))
            .or_else(|| x.as_f64().map(|f| f as u64))
    })
}

fn str_path(v: &Value, path: &str) -> String {
    v.pointer(path)
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string()
}

fn bool_path(v: &Value, path: &str) -> bool {
    v.pointer(path).and_then(|x| x.as_bool()).unwrap_or(false)
}

#[component]
pub fn RuntimeEnforcementCanvas() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let data = LocalResource::new(move || {
        let _ = reload.get();
        async move { iia_api::runtime_enforcement().await }
    });

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10">
            <h1 class="text-lg font-semibold text-zinc-50">"Runtime enforcement"</h1>
            <p class="mt-1 mb-4 max-w-3xl text-sm text-zinc-500">
                "Effect exclusivity and sandbox refuse posture from GET /runtime/enforcement. Not a CPA attestation. Talk 409/499 recovery remains on the agent workbench and Fix queue."
            </p>
            <div class="mb-3 flex flex-wrap gap-2">
                <button
                    type="button"
                    class="btn-secondary w-fit"
                    on:click=move |_| set_reload.update(|n| *n += 1)
                >
                    "Refresh"
                </button>
                <a class="btn-secondary" href="/monitor">"Monitor posture"</a>
                <a class="btn-secondary" href="/fix">"Fix queue"</a>
            </div>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading enforcement…".to_string() /> }>
                {move || Suspend::new(async move {
                    match data.await {
                        Ok(v) => {
                            let root = api::resource_object(&v);
                            let iso = root
                                .get("isolation_summary")
                                .cloned()
                                .or_else(|| root.pointer("/data/isolation_summary").cloned())
                                .unwrap_or(Value::Null);
                            let excl = root
                                .get("effect_exclusivity")
                                .cloned()
                                .or_else(|| root.pointer("/data/effect_exclusivity").cloned())
                                .unwrap_or(Value::Null);
                            let llm = root
                                .get("probabilistic_llm")
                                .cloned()
                                .or_else(|| root.pointer("/data/probabilistic_llm").cloned())
                                .unwrap_or(Value::Null);
                            let agents = root
                                .pointer("/live_agent_lifecycle/agents")
                                .or_else(|| root.pointer("/data/live_agent_lifecycle/agents"))
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let cells = u64_path(&iso, "/active_execution_cells")
                                .or_else(|| u64_path(&iso, "/active_sandboxes"))
                                .unwrap_or(0);
                            let violated = u64_path(&iso, "/violated_execution_cells")
                                .or_else(|| u64_path(&iso, "/violated_sandboxes"))
                                .unwrap_or(0);
                            let denials = u64_path(&iso, "/total_denials").unwrap_or(0);
                            let strict = u64_path(&iso, "/strict_cells").unwrap_or(0);
                            let mode = str_path(&root, "/runtime_mode");
                            let mode = if mode == "—" {
                                str_path(&root, "/data/runtime_mode")
                            } else {
                                mode
                            };
                            let excl_on = bool_path(&excl, "/enforced")
                                || bool_path(&excl, "/effect_exclusivity_enforced");
                            let distrust = bool_path(&llm, "/distrust_enforced")
                                || bool_path(&llm, "/enforced");
                            let raw = serde_json::to_string_pretty(&v).unwrap_or_default();
                            view! {
                                <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-4">
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-950/50 p-3">
                                        <p class="text-[10px] uppercase text-zinc-500">"Runtime mode"</p>
                                        <p class="mt-1 font-mono text-sm text-zinc-100">{mode}</p>
                                    </div>
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-950/50 p-3">
                                        <p class="text-[10px] uppercase text-zinc-500">"Execution cells"</p>
                                        <p class="mt-1 font-mono text-sm text-zinc-100">{format!("{cells} · strict {strict}")}</p>
                                    </div>
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-950/50 p-3">
                                        <p class="text-[10px] uppercase text-zinc-500">"Violations / denials"</p>
                                        <p class=format!(
                                            "mt-1 font-mono text-sm {}",
                                            if violated > 0 || denials > 0 { "text-amber-200" } else { "text-zinc-100" }
                                        )>{format!("{violated} violated · {denials} denials")}</p>
                                    </div>
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-950/50 p-3">
                                        <p class="text-[10px] uppercase text-zinc-500">"Exclusivity / LLM"</p>
                                        <p class="mt-1 font-mono text-[11px] text-zinc-200">
                                            {format!(
                                                "exclusivity={} · distrust={}",
                                                if excl_on { "on" } else { "off" },
                                                if distrust { "on" } else { "off" }
                                            )}
                                        </p>
                                    </div>
                                </div>
                                <section class="mb-4 rounded-xl border border-zinc-800/70 bg-zinc-900/30 p-4">
                                    <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Live agents (open drawer)"</p>
                                    {if agents.is_empty() {
                                        view! { <p class="mt-2 text-[11px] text-zinc-500">"No registered agents in this payload."</p> }.into_any()
                                    } else {
                                        view! {
                                            <ul class="mt-2 space-y-1">
                                                {agents.into_iter().take(24).map(|a| {
                                                    let pid = a.get("agent_pid").or_else(|| a.get("pid")).and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                                    let name = a.get("agent_name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                                    let st = a.get("status").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                                    let pid_open = pid.clone();
                                                    view! {
                                                        <li class="flex flex-wrap items-center gap-2 text-[11px]">
                                                            <button
                                                                type="button"
                                                                class="font-mono text-cyan-300 hover:underline"
                                                                on:click=move |_| open_agent_drawer(pid_open.clone())
                                                            >{pid.clone()}</button>
                                                            <span class="text-zinc-500">{name}</span>
                                                            <span class="rounded bg-zinc-800/80 px-1.5 text-zinc-300">{st}</span>
                                                        </li>
                                                    }
                                                }).collect_view()}
                                            </ul>
                                        }.into_any()
                                    }}
                                </section>
                                <details class="rounded-xl border border-zinc-800 bg-zinc-950/50">
                                    <summary class="cursor-pointer px-4 py-2 text-[10px] uppercase text-zinc-500">
                                        "Raw JSON"
                                    </summary>
                                    <pre class="max-h-[50vh] overflow-auto p-4 text-[11px] font-mono text-zinc-300">{raw}</pre>
                                </details>
                            }.into_any()
                        }
                        Err(e) => view! {
                            <p class="text-sm text-rose-300">{format!("GET /runtime/enforcement failed: {e}")}</p>
                            <p class="mt-2 text-[11px] text-zinc-500">
                                "If the route is not mounted on this build, use Monitor isolation posture and agent Evidence instead."
                            </p>
                        }.into_any(),
                    }
                })}
            </Suspense>
            <section class="mt-6 rounded-xl border border-zinc-800/70 bg-zinc-900/30 p-4">
                <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Env runbook (restart required)"</p>
                <ul class="mt-2 list-disc space-y-1 pl-4 text-[11px] text-zinc-400">
                    <li><code class="text-zinc-300">"CONNECTOR_LLM_BROKER_UNBYPASSABLE=1"</code>" — broker lane + pulls Linux bar"</li>
                    <li><code class="text-zinc-300">"CONNECTOR_SANDBOX_UNBYPASSABLE=1"</code>" — master Landlock/nft/eBPF/cgroup bar"</li>
                    <li><code class="text-zinc-300">"CONNECTOR_KERNEL_ENFORCE=1"</code>" — require kerneld Active + net cut"</li>
                    <li><code class="text-zinc-300">"CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED=1"</code>" — FS path"</li>
                </ul>
            </section>
        </div>
    }
}
