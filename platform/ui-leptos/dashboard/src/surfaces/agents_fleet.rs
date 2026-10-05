//! Fleet agents — quarantine / slot / isolation PDF for 100+ shared-brain agents.

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::OpLoadingBlock;
use crate::components::ui::DownloadButton;
use crate::iia_api;
use crate::ui_state::open_agent_drawer;
use crate::utils::{stamp_download_filename, trigger_download_bytes};

fn agents_array(v: &Value) -> Vec<Value> {
    let root = api::resource_object(v);
    root.get("agents")
        .or_else(|| root.get("items"))
        .and_then(|x| x.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default()
}

fn agent_pid(a: &Value) -> String {
    a.get("agent_pid")
        .or_else(|| a.get("pid"))
        .or_else(|| a.get("id"))
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string()
}

#[component]
pub fn AgentsFleetCanvas() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let list = LocalResource::new(move || {
        let _ = reload.get();
        async move { iia_api::list_agents().await }
    });

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10">
            <h1 class="text-lg font-semibold text-zinc-50">"Agents · fleet"</h1>
            <p class="mt-1 mb-4 max-w-3xl text-sm text-zinc-500">
                "One shared LLM router; many sealed broker sandboxes. Columns show quarantine and isolation evidence. Download per-agent isolation PDF for FS/net/VM/broker proofs."
            </p>
            <div class="mb-3 flex flex-wrap gap-2">
                <button
                    type="button"
                    class="btn-secondary"
                    on:click=move |_| set_reload.update(|n| *n += 1)
                >
                    "Refresh"
                </button>
                <a class="btn-secondary" href="/run">"Back to Run"</a>
            </div>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading agents…".to_string() /> }>
                {move || Suspend::new(async move {
                    match list.await {
                        Ok(v) => {
                            let agents = agents_array(&v);
                            if agents.is_empty() {
                                return view! {
                                    <p class="text-sm text-zinc-500">"No agents registered. Create one from Setup."</p>
                                }.into_any();
                            }
                            view! {
                                <div class="overflow-x-auto rounded-xl border border-zinc-800/70">
                                    <table class="min-w-full text-left text-[11px]">
                                        <thead class="bg-zinc-900/80 text-[10px] uppercase tracking-wide text-zinc-500">
                                            <tr>
                                                <th class="px-3 py-2">"Agent"</th>
                                                <th class="px-3 py-2">"Namespace"</th>
                                                <th class="px-3 py-2">"Status"</th>
                                                <th class="px-3 py-2">"Quarantine"</th>
                                                <th class="px-3 py-2">"Evidence"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {agents.into_iter().map(|a| {
                                                let pid = agent_pid(&a);
                                                let ns = a.get("namespace").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                                let status = a.get("status").and_then(|x| x.as_str())
                                                    .or_else(|| a.get("state").and_then(|x| x.as_str()))
                                                    .unwrap_or("—")
                                                    .to_string();
                                                let q = a.get("quarantined").and_then(|x| x.as_bool()).unwrap_or(false)
                                                    || status.to_ascii_lowercase().contains("quarantine");
                                                let hitl = a.get("quarantine_hitl_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                                let pid_open = pid.clone();
                                                let pid_dl = pid.clone();
                                                view! {
                                                    <tr class="border-t border-zinc-800/60 hover:bg-zinc-900/40">
                                                        <td class="px-3 py-2 font-mono text-zinc-200">
                                                            <button
                                                                type="button"
                                                                class="text-left hover:text-cyan-300"
                                                                on:click=move |_| open_agent_drawer(pid_open.clone())
                                                            >
                                                                {pid.clone()}
                                                            </button>
                                                        </td>
                                                        <td class="px-3 py-2 font-mono text-zinc-400">{ns}</td>
                                                        <td class="px-3 py-2">
                                                            <span class="rounded bg-zinc-800/60 px-1.5 py-0.5 text-zinc-300">{status}</span>
                                                        </td>
                                                        <td class="px-3 py-2">
                                                            {if q {
                                                                view! {
                                                                    <div class="space-y-1">
                                                                        <span class="rounded bg-rose-950/60 px-1.5 py-0.5 text-rose-200">"QUARANTINED"</span>
                                                                        {(!hitl.is_empty()).then(|| view! {
                                                                            <p class="font-mono text-[9px] text-zinc-500">{format!("hitl {hitl}")}</p>
                                                                        })}
                                                                        <a class="block text-[10px] text-cyan-400 hover:underline" href="/fix">"Approve on Fix"</a>
                                                                    </div>
                                                                }.into_any()
                                                            } else {
                                                                view! { <span class="text-zinc-600">"—"</span> }.into_any()
                                                            }}
                                                        </td>
                                                        <td class="px-3 py-2">
                                                            <div class="flex flex-wrap gap-1">
                                                                <DownloadButton
                                                                    path=format!("/agents/{pid}/audit/pdf")
                                                                    filename=format!("connector-agent-isolation-{pid}.pdf")
                                                                    mime="application/pdf".to_string()
                                                                >
                                                                    "PDF"
                                                                </DownloadButton>
                                                                <button
                                                                    type="button"
                                                                    class="rounded border border-zinc-700 px-2 py-0.5 text-[10px] text-zinc-300 hover:border-cyan-700"
                                                                    on:click=move |_| {
                                                                        let pid = pid_dl.clone();
                                                                        spawn_local(async move {
                                                                            if let Ok(v) = iia_api::agent_isolation_audit(&pid).await {
                                                                                if let Ok(bytes) = serde_json::to_vec_pretty(&v) {
                                                                                    let name = stamp_download_filename(
                                                                                        &format!("connector-agent-isolation-{pid}.json"),
                                                                                    );
                                                                                    trigger_download_bytes(
                                                                                        &bytes,
                                                                                        &name,
                                                                                        "application/json",
                                                                                    );
                                                                                }
                                                                            }
                                                                        });
                                                                    }
                                                                >
                                                                    "JSON"
                                                                </button>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view()}
                                        </tbody>
                                    </table>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! {
                            <p class="text-sm text-rose-300">{format!("Failed to list agents: {e}")}</p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}
