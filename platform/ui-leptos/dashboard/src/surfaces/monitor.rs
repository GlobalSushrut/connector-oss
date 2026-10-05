//! Monitor surface — live FinOps / security / network / load canvas.

use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_navigate;
use serde_json::Value;
use std::time::Duration;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::overlays::monitor_panel::OpMonitorPanel;
use crate::components::operator::overlays::isolation_posture::OpIsolationPosturePanel;
use crate::components::toaster::toast;
use crate::components::ui::PdfViewer;
use crate::ui_state::open_agent_explain;
use crate::utils::{stamp_download_filename, trigger_download_bytes};

const CONTEXT_POLL_MS: u64 = 8_000;

/// Live fleet context pressure from `GET /context/status`.
///
/// An agent that runs out of context window stalls or starts dropping history,
/// so this is the one memory signal worth showing before it becomes an
/// incident. Rows are server-ordered worst-first; clicking one opens the agent
/// explain popup.
#[component]
fn ContextPressurePanel() -> impl IntoView {
    let (data, set_data) = signal::<Option<Value>>(None);
    let (err, set_err) = signal(String::new());
    let (tick, set_tick) = signal(0u32);

    Effect::new(move |prev: Option<bool>| {
        if prev.unwrap_or(false) {
            return true;
        }
        let _ = set_interval_with_handle(
            move || set_tick.update(|t| *t = t.wrapping_add(1)),
            Duration::from_millis(CONTEXT_POLL_MS),
        );
        true
    });

    Effect::new(move |_| {
        let _ = tick.get();
        spawn_local(async move {
            match api::get_value("/context/status").await {
                Ok(v) => {
                    set_err.set(String::new());
                    set_data.set(Some(v));
                }
                Err(e) => set_err.set(e.message),
            }
        });
    });

    let agents = move || {
        data.get()
            .and_then(|v| v.get("agents").and_then(|a| a.as_array()).cloned())
            .unwrap_or_default()
    };
    let counts = move || {
        let v = data.get();
        let get = |k: &str| {
            v.as_ref()
                .and_then(|v| v.get(k))
                .and_then(|x| x.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".into())
        };
        (
            get("total_agents"),
            get("critical"),
            get("warning"),
            get("snapshots"),
        )
    };

    view! {
        <section class="rounded-xl border border-zinc-800/70 bg-zinc-950/40 p-3">
            <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div class="min-w-0">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                        "Context pressure · GET /context/status"
                    </p>
                    <p class="mt-0.5 text-[11px] text-zinc-500">
                        "Token window utilisation per tracked agent. Highest pressure first."
                    </p>
                </div>
                {move || {
                    let (total, critical, warning, snapshots) = counts();
                    view! {
                        <div class="flex flex-wrap items-center gap-2 text-[11px]">
                            <span class="rounded-md border border-zinc-800 px-2 py-0.5 text-zinc-400">
                                {format!("{total} tracked")}
                            </span>
                            <span class="rounded-md border border-rose-900/60 px-2 py-0.5 text-rose-300">
                                {format!("{critical} critical")}
                            </span>
                            <span class="rounded-md border border-amber-900/60 px-2 py-0.5 text-amber-300">
                                {format!("{warning} warning")}
                            </span>
                            <span class="rounded-md border border-zinc-800 px-2 py-0.5 text-zinc-400">
                                {format!("{snapshots} snapshots")}
                            </span>
                        </div>
                    }
                }}
            </div>

            <Show when=move || !err.get().is_empty()>
                <p class="rounded-md border border-rose-900/60 bg-rose-950/30 px-2 py-1 text-[11px] text-rose-300">
                    {move || err.get()}
                </p>
            </Show>

            <Show
                when=move || !agents().is_empty()
                fallback=move || {
                    view! {
                        <p class="text-[11px] text-zinc-500">
                            "No agents are tracking context yet. A context is registered on an agent's first memory access or snapshot."
                        </p>
                    }
                }
            >
                <div class="overflow-x-auto">
                    <table class="w-full table-fixed text-left text-[11px]">
                        <colgroup>
                            <col class="w-[32%]" />
                            <col class="w-[28%]" />
                            <col class="w-[18%]" />
                            <col class="w-[12%]" />
                            <col class="w-[10%]" />
                        </colgroup>
                        <thead class="text-[10px] uppercase tracking-wide text-zinc-500">
                            <tr>
                                <th class="py-1 pr-3">"Agent"</th>
                                <th class="py-1 pr-3">"Utilisation"</th>
                                <th class="py-1 pr-3">"Tokens"</th>
                                <th class="py-1 pr-3">"Window"</th>
                                <th class="py-1">"Status"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=agents
                                key=|a| {
                                    a.get("pid")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or_default()
                                        .to_string()
                                }
                                let:agent
                            >
                                {
                                    let pid = agent
                                        .get("pid")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("?")
                                        .to_string();
                                    let session = agent
                                        .get("session_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    let pct = agent.get("utilization_pct").and_then(|v| v.as_f64());
                                    let used = agent.get("tokens_used").and_then(|v| v.as_u64());
                                    let limit = agent.get("tokens_limit").and_then(|v| v.as_u64());
                                    let window = agent.get("window_cids").and_then(|v| v.as_u64());
                                    let status = agent
                                        .get("status")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("—")
                                        .to_string();
                                    let (bar, chip) = match status.as_str() {
                                        "critical" => ("bg-rose-500", "text-rose-300"),
                                        "warning" => ("bg-amber-500", "text-amber-300"),
                                        "ok" => ("bg-emerald-500", "text-emerald-300"),
                                        _ => ("bg-zinc-600", "text-zinc-500"),
                                    };
                                    let width = format!(
                                        "width:{:.1}%",
                                        pct.unwrap_or(0.0).clamp(0.0, 100.0)
                                    );
                                    let pct_label = pct
                                        .map(|n| format!("{n:.1}%"))
                                        .unwrap_or_else(|| "—".into());
                                    let tok_label = match (used, limit) {
                                        (Some(u), Some(l)) => format!("{u} / {l}"),
                                        (Some(u), None) => format!("{u} / —"),
                                        (None, Some(l)) => format!("— / {l}"),
                                        (None, None) => "—".into(),
                                    };
                                    let window_label = window
                                        .map(|n| format!("{n} cids"))
                                        .unwrap_or_else(|| "—".into());
                                    let click_pid = pid.clone();
                                    view! {
                                        <tr
                                            class="cursor-pointer border-t border-zinc-900 hover:bg-zinc-900/40"
                                            on:click=move |_| open_agent_explain(&click_pid)
                                        >
                                            <td class="min-w-0 truncate py-1.5 pr-3">
                                                <span class="font-mono text-zinc-200">{pid}</span>
                                                <Show when={
                                                    let s = session.clone();
                                                    move || !s.is_empty()
                                                }>
                                                    <span class="ml-2 text-zinc-600">{session.clone()}</span>
                                                </Show>
                                            </td>
                                            <td class="py-1.5 pr-3">
                                                <div class="flex items-center gap-2">
                                                    <div class="h-1.5 w-24 overflow-hidden rounded-full bg-zinc-800">
                                                        <div class=format!("h-full {bar}") style=width></div>
                                                    </div>
                                                    <span class="tabular-nums text-zinc-400">
                                                        {pct_label}
                                                    </span>
                                                </div>
                                            </td>
                                            <td class="py-1.5 pr-3 tabular-nums text-zinc-400">
                                                {tok_label}
                                            </td>
                                            <td class="py-1.5 pr-3 tabular-nums text-zinc-500">
                                                {window_label}
                                            </td>
                                            <td class=format!("py-1.5 {chip}")>{status}</td>
                                        </tr>
                                    }
                                }
                            </For>
                        </tbody>
                    </table>
                </div>
            </Show>
        </section>
    }
}

#[component]
pub fn MonitorCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let navigate = use_navigate();
    let pdf_bytes = RwSignal::new(None::<Vec<u8>>);
    let pdf_loading = RwSignal::new(false);
    let pdf_name = RwSignal::new("connector-compliance-brief.pdf".to_string());

    view! {
        <div class="mon-shell">
            <header class="mon-hero">
                <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                        <h1 class="mon-hero__title">"Monitor"</h1>
                        <span class="mon-live-pill">"Live · 8s"</span>
                    </div>
                    <p class="mon-hero__sub">
                        "Live planes from the API: agentic economy, trust & audit, edge/protocol health, and concurrency load. Audit PDFs now include UTC timestamps, LLM broker / tokenization posture, and Linux unbypassable bar — node workpapers, not CPA attestations."
                    </p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    <A href="/plugins/tracetramp" attr:class="btn-secondary">
                        "TraceTramp"
                    </A>
                    <A href="/plugins/witnessctl" attr:class="btn-secondary">
                        "WitnessCtl"
                    </A>
                    <A href="/plugins/devguard" attr:class="btn-secondary">
                        "DevGuard"
                    </A>
                    <button
                        type="button"
                        class="btn-secondary"
                        disabled=move || pdf_loading.get()
                        on:click=move |_| {
                            pdf_loading.set(true);
                            spawn_local(async move {
                                match api::get_bytes("/compliance/brief/pdf").await {
                                    Ok(bytes) if bytes.starts_with(b"%PDF-") => {
                                        let name = stamp_download_filename(
                                            "connector-compliance-brief.pdf",
                                        );
                                        trigger_download_bytes(
                                            &bytes,
                                            &name,
                                            "application/pdf",
                                        );
                                        pdf_name.set(name);
                                        pdf_bytes.set(Some(bytes));
                                    }
                                    Ok(_) => toast::error(
                                        "Brief endpoint did not return a PDF.".to_string(),
                                    ),
                                    Err(e) => toast::error(format!("Brief PDF failed: {}", e.message)),
                                }
                                pdf_loading.set(false);
                            });
                        }
                    >
                        {move || if pdf_loading.get() { "Loading…" } else { "Brief PDF" }}
                    </button>
                    <button
                        type="button"
                        class="btn-secondary"
                        disabled=move || pdf_loading.get()
                        on:click=move |_| {
                            pdf_loading.set(true);
                            spawn_local(async move {
                                match api::get_bytes("/compliance/report/pdf").await {
                                    Ok(bytes) if bytes.starts_with(b"%PDF-") => {
                                        let name = stamp_download_filename(
                                            "connector-compliance-report.pdf",
                                        );
                                        trigger_download_bytes(
                                            &bytes,
                                            &name,
                                            "application/pdf",
                                        );
                                        pdf_name.set(name);
                                        pdf_bytes.set(Some(bytes));
                                    }
                                    Ok(_) => toast::error(
                                        "Report endpoint did not return a PDF.".to_string(),
                                    ),
                                    Err(e) => toast::error(format!("Report PDF failed: {}", e.message)),
                                }
                                pdf_loading.set(false);
                            });
                        }
                    >
                        {move || if pdf_loading.get() { "Loading…" } else { "Report PDF" }}
                    </button>
                    <button
                        type="button"
                        class="btn-primary"
                        on:click=move |_| navigate("/fix", Default::default())
                    >
                        "Open Fix"
                    </button>
                </div>
            </header>
            <div class="mon-body">
                <Show when=move || pdf_bytes.get().is_some() || pdf_loading.get()>
                    <section class="rounded-xl border border-zinc-800/70 bg-zinc-950/40 p-3">
                        <div class="mb-2 flex items-center justify-between gap-2">
                            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                                "Control evidence PDF · UTC-stamped · LLM broker / tokenize / Linux bar · SOC 2 TSC / ISO / NIST / HIPAA · node workpaper, not a CPA attestation"
                            </p>
                            <button
                                type="button"
                                class="text-[11px] text-zinc-500 hover:text-zinc-200"
                                on:click=move |_| pdf_bytes.set(None)
                            >"Close preview"</button>
                        </div>
                        <PdfViewer
                            bytes=pdf_bytes
                            filename=pdf_name
                            is_loading=pdf_loading
                            empty_hint="Click Brief PDF or Report PDF — the file is generated from live control tests on this node.".to_string()
                            height_class="min-h-[420px]".to_string()
                        />
                    </section>
                </Show>
                <ContextPressurePanel />
                <OpIsolationPosturePanel />
                <OpMonitorPanel />
            </div>
        </div>
    }
}
