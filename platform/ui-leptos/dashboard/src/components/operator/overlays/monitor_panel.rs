//! Live Monitor — FinOps, security/audit, network/protocols, load/concurrency.
//! All numbers come from real GET `/monitor/*`, `/operator/*`, `/firewall/*`.

use leptos::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::cards::OpMetricRow;
use crate::components::operator::overlays::forensics::OpForensicsPanel;
use crate::components::operator::overlays::result_sheet::OpResultSheet;
use crate::components::operator::overlays::sparkline::OpSparklineGrid;
use crate::components::operator::primitives::{OpButton, OpButtonVariant};
use crate::request_store::bump_reload;
use crate::ui_state::use_developer_view;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MonitorTab {
    Overview,
    FinOps,
    Security,
    Network,
    Load,
}

impl MonitorTab {
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::FinOps => "Economy",
            Self::Security => "Security · Audit",
            Self::Network => "Network · Protocols",
            Self::Load => "Load · Concurrency",
        }
    }
}

#[component]
pub fn OpMonitorPanel() -> impl IntoView {
    let (dev, _) = use_developer_view();
    let (tab, set_tab) = signal(MonitorTab::Overview);
    let (reload, set_reload) = signal(0u32);
    let (busy, set_busy) = signal(false);
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());
    let (auto, set_auto) = signal(true);
    let (bundle, set_bundle) = signal(None::<Result<MonitorBundle, api::ApiError>>);

    // Live poll every 8s while auto-refresh is on (re-arms after each reload).
    Effect::new(move |_| {
        if !auto.get() {
            return;
        }
        let _ = reload.get();
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(8_000).await;
            if auto.get_untracked() {
                set_reload.update(|n| *n = n.wrapping_add(1));
            }
        });
    });

    // Keep the last successful snapshot on screen. Suspense around LocalResource
    // was collapsing the whole plane to a loading block on every poll.
    Effect::new(move |_| {
        let _ = reload.get();
        set_busy.set(true);
        spawn_local(async move {
            let next = fetch_monitor_bundle().await;
            set_bundle.update(|slot| match next {
                Ok(b) => *slot = Some(Ok(b)),
                Err(e) => {
                    if !matches!(slot.as_ref(), Some(Ok(_))) {
                        *slot = Some(Err(e));
                    }
                }
            });
            set_busy.set(false);
        });
    });

    let tabs = [
        MonitorTab::Overview,
        MonitorTab::FinOps,
        MonitorTab::Security,
        MonitorTab::Network,
        MonitorTab::Load,
    ];

    view! {
        <div class="space-y-4">
            <div class="mon-toolbar">
                <div class="mon-tabs" role="tablist" aria-label="Monitor planes">
                    {tabs.into_iter().map(|t| {
                        view! {
                            <button
                                type="button"
                                role="tab"
                                class=move || {
                                    if tab.get() == t { "mon-tab mon-tab--active" } else { "mon-tab" }
                                }
                                on:click=move |_| set_tab.set(t)
                            >{t.label()}</button>
                        }
                    }).collect_view()}
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    {move || view! {
                        <OpButton
                            label=if auto.get() { "Auto · on".to_string() } else { "Auto · off".to_string() }
                            variant=OpButtonVariant::Ghost
                            on_click=Arc::new(move |_| set_auto.update(|v| *v = !*v))
                        />
                    }}
                    <OpButton
                        label="Refresh now".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            set_reload.update(|n| *n = n.wrapping_add(1));
                            bump_reload();
                        })
                    />
                    <span class=move || {
                        if busy.get() && bundle.get().is_some() {
                            "text-[10px] uppercase tracking-wide text-zinc-500"
                        } else {
                            "invisible text-[10px] uppercase tracking-wide text-zinc-500"
                        }
                    }>"Refreshing"</span>
                </div>
            </div>

            {move || match bundle.get() {
                None => view! { <OpLoadingBlock message="Loading live monitor planes…".to_string() /> }.into_any(),
                Some(Err(e)) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                Some(Ok(b)) => {
                    let current = tab.get();
                    let raw = serde_json::to_string_pretty(&b.raw_sections).unwrap_or_default();
                    let body = match current {
                        MonitorTab::Overview => overview_view(&b),
                        MonitorTab::FinOps => finops_view(&b),
                        MonitorTab::Security => security_view(&b),
                        MonitorTab::Network => network_view(&b),
                        MonitorTab::Load => load_view(&b),
                    };
                    view! {
                        <div class="mon-plane space-y-4">
                            {if b.errors.is_empty() {
                                ().into_any()
                            } else {
                                view! {
                                    <div class="mon-partial text-xs text-amber-100">
                                        <p class="font-semibold">"Partial plane load"</p>
                                        <ul class="mt-1 list-disc space-y-0.5 pl-4 font-mono text-[10px] text-amber-200/80">
                                            {b.errors.iter().map(|e| view! { <li>{e.clone()}</li> }).collect_view()}
                                        </ul>
                                    </div>
                                }.into_any()
                            }}
                            {body}
                            <div class="flex flex-wrap gap-2">
                                <OpButton
                                    label="Create sample SLO".to_string()
                                    variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        set_busy.set(true);
                                        spawn_local(async move {
                                            let body = serde_json::json!({
                                                "name": "operator-ui-availability",
                                                "sli": "availability",
                                                "target": 0.99,
                                                "window": "30d"
                                            });
                                            match api::post_value("/monitor/slos", body).await {
                                                Ok(v) => {
                                                    set_result_title.set("SLO created".into());
                                                    set_result_summary.set(format!(
                                                        "POST /monitor/slos\n{}",
                                                        serde_json::to_string_pretty(&v).unwrap_or_default()
                                                    ));
                                                    set_result_open.set(true);
                                                    set_reload.update(|n| *n = n.wrapping_add(1));
                                                }
                                                Err(e) => {
                                                    set_result_title.set("SLO create failed".into());
                                                    set_result_summary.set(format!("POST /monitor/slos\n{}", e.message));
                                                    set_result_open.set(true);
                                                }
                                            }
                                            set_busy.set(false);
                                        });
                                    })
                                />
                            </div>
                            <Show when=move || dev.get()>
                                <OpDevDisclosure label="Monitor aggregate JSON".to_string() raw=raw.clone() />
                            </Show>
                            <OpResultSheet
                                open=result_open
                                set_open=set_result_open
                                title=result_title
                                summary=result_summary
                            />
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[derive(Clone)]
struct MonitorBundle {
    health: Value,
    cost: Value,
    cost_center: Value,
    trust: Value,
    trust_trend: Value,
    integrity: Value,
    alerts: Value,
    anomalies: Value,
    signals: Value,
    tools: Value,
    llm: Value,
    forecast: Value,
    budget: Value,
    firewall: Value,
    pulse: Value,
    edge: Value,
    runtime: Value,
    protocols: Value,
    books: Value,
    books_costs: Value,
    substrate: Value,
    egress: Value,
    forensics: Value,
    mesh: Value,
    cells: Value,
    ha: Value,
    federation_policy: Value,
    /// DI-3 — intelligence plane posture (principal/cage/lab, not process PID).
    intelligence: Value,
    /// DI-4 — fleet charter digests / drift.
    fleet_charter: Value,
    errors: Vec<String>,
    raw_sections: Vec<(String, Value)>,
}

async fn fetch_monitor_bundle() -> Result<MonitorBundle, api::ApiError> {
            let paths = [
                "/monitor/health",
                "/monitor/cost-dashboard",
                "/monitor/cost-center",
                "/monitor/trust",
                "/monitor/trust-trend",
                "/monitor/integrity",
                "/monitor/alerts",
                "/monitor/anomalies/v2",
                "/monitor/signals",
                "/monitor/tools",
                "/monitor/llm",
                "/monitor/forecast",
                "/monitor/budget-alerts",
                "/firewall/status",
                "/operator/pulse",
                "/operator/edge/plane",
                "/runtime/lifecycle/summary",
                "/protocols/mcp/servers",
                "/books",
                "/books/costs?period=today",
                "/substrate/status",
                "/runtime/egress/status",
                "/forensics/status",
                "/runtime/mesh",
                "/runtime/cells",
                "/runtime/ha-federation",
                "/runtime/federation-policy",
                "/runtime/intelligence-posture",
                "/runtime/fleet/charter",
            ];
    let mut map: HashMap<String, Value> = HashMap::new();
    let mut errors = Vec::new();
    let mut raw_sections = Vec::new();
    for path in paths {
        match api::get_value(path).await {
            Ok(v) => {
                raw_sections.push((path.to_string(), v.clone()));
                map.insert(path.to_string(), v);
            }
            Err(e) => errors.push(format!("{path}: {}", e.message)),
        }
    }
    let get = |p: &str| map.get(p).cloned().unwrap_or(Value::Null);
    Ok(MonitorBundle {
        health: get("/monitor/health"),
        cost: get("/monitor/cost-dashboard"),
        cost_center: get("/monitor/cost-center"),
        trust: get("/monitor/trust"),
        trust_trend: get("/monitor/trust-trend"),
        integrity: get("/monitor/integrity"),
        alerts: get("/monitor/alerts"),
        anomalies: get("/monitor/anomalies/v2"),
        signals: get("/monitor/signals"),
        tools: get("/monitor/tools"),
        llm: get("/monitor/llm"),
        forecast: get("/monitor/forecast"),
        budget: get("/monitor/budget-alerts"),
        firewall: get("/firewall/status"),
        pulse: get("/operator/pulse"),
        edge: get("/operator/edge/plane"),
        runtime: get("/runtime/lifecycle/summary"),
        protocols: get("/protocols/mcp/servers"),
        books: get("/books"),
        books_costs: get("/books/costs?period=today"),
        substrate: get("/substrate/status"),
        egress: get("/runtime/egress/status"),
        forensics: get("/forensics/status"),
        mesh: get("/runtime/mesh"),
        cells: get("/runtime/cells"),
        ha: get("/runtime/ha-federation"),
        federation_policy: get("/runtime/federation-policy"),
        intelligence: get("/runtime/intelligence-posture"),
        fleet_charter: get("/runtime/fleet/charter"),
        errors,
        raw_sections,
    })
}

/// DI-3 — intelligence plane chips (principal/cage/lab), not OS-PID theatre.
fn intelligence_chips(posture: &Value, egress: &Value) -> AnyView {
    let lab = posture
        .get("lab_mode")
        .and_then(|x| x.as_bool())
        .unwrap_or(true);
    let dock = posture.get("docklock").cloned().unwrap_or(Value::Null);
    let ring1 = dock
        .get("ring1_enforce")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let qpr = dock
        .get("qpr_enforce")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let docklock = dock
        .get("docklock_enforce")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let matrix_hw = dock
        .get("matrix_hw_enforce")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let landlock = dock.get("landlock").cloned().unwrap_or(Value::Null);
    let ll_mode = landlock
        .get("mode")
        .and_then(|x| x.as_str())
        .unwrap_or("soft_fail");
    let ll_abi = landlock
        .get("kernel_abi_available")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let ll_label = format!(
        "Landlock {}{}",
        ll_mode,
        if ll_abi { " · abi" } else { " · no-abi" }
    );
    let ll_ok = ll_mode == "fail_closed" && ll_abi;
    let anomaly_on = posture
        .pointer("/anomaly_gate/enabled")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let geo = posture
        .get("geo_id")
        .and_then(|x| x.as_str())
        .unwrap_or("geo:?")
        .to_string();
    let llm = posture
        .get("llm_router_wired")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let llm_label = if llm {
        let p = posture
            .get("llm_provider")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let m = posture
            .get("llm_model")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        format!("LLM {p}/{m}")
    } else {
        "LLM unwired".into()
    };
    let egress_iso = egress
        .pointer("/egress_isolated")
        .or_else(|| egress.get("egress_isolated"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let chip = |label: String, ok: bool| {
        let cls = if ok {
            "rounded border border-emerald-800/50 bg-emerald-950/40 px-2 py-1 text-[10px] text-emerald-100"
        } else {
            "rounded border border-amber-800/50 bg-amber-950/40 px-2 py-1 text-[10px] text-amber-100"
        };
        view! { <span class=cls>{label}</span> }
    };
    view! {
        <section class="mon-panel">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                "Intelligence posture"
            </p>
            <div class="mt-2 flex flex-wrap gap-1.5">
                {chip(if lab { "LAB MODE".into() } else { "prod hardening".into() }, !lab)}
                {chip(format!("Ring-1 {}", if ring1 { "on" } else { "off" }), ring1)}
                {chip(format!("QPR {}", if qpr { "on" } else { "off" }), qpr)}
                {chip(format!("DockLock {}", if docklock { "on" } else { "off" }), docklock)}
                {chip(
                    format!(
                        "matrix_hw {}",
                        if matrix_hw { "enforce" } else { "soft" }
                    ),
                    matrix_hw,
                )}
                {chip(ll_label, ll_ok)}
                {chip(
                    format!(
                        "egress {}",
                        if egress_iso { "isolated" } else { "open" }
                    ),
                    !egress_iso || matrix_hw,
                )}
                {chip(
                    if anomaly_on {
                        "anomaly gate on".into()
                    } else {
                        "anomaly gate off".into()
                    },
                    !anomaly_on,
                )}
                {chip(geo, true)}
                {chip(llm_label, llm)}
            </div>
            <p class="mt-2 font-mono text-[10px] text-zinc-600">
                "GET /runtime/intelligence-posture · enable: POST /runtime/enable-hardening"
            </p>
        </section>
    }
    .into_any()
}

fn overview_view(b: &MonitorBundle) -> AnyView {
    let health = &b.health;
    let score = num(health, &["agent_health_score", "trust_score"]).unwrap_or_else(|| "—".into());
    let agents = num(health, &["agents"]).unwrap_or_else(|| "—".into());
    let packets = num(health, &["packets"])
        .or_else(|| tier_num(health, "packets_used"))
        .unwrap_or_else(|| "—".into());
    let audit = num(health, &["audit_entries"]).unwrap_or_else(|| "—".into());
    let tokens = num(&b.cost, &["total_tokens"]).unwrap_or_else(|| "—".into());
    let llm_calls = num(&b.cost, &["total_llm_calls", "total_requests"]).unwrap_or_else(|| "—".into());
    let trust = str_or(&b.trust, &["trust_grade", "grade"]).unwrap_or_else(|| "—".into());
    let uptime = health
        .get("uptime")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let dims = dimension_spark(health);
    let wf_running = b
        .pulse
        .pointer("/workflows/running")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let wf_idle = b
        .pulse
        .pointer("/workflows/idle")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let recs = health
        .get("recommendations")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    let iia_row = intelligence_chips(&b.intelligence, &b.egress);
    let fleet_row = fleet_charter_section(&b.fleet_charter);
    view! {
        <div class="space-y-4">
            {iia_row}
            {fleet_row}
            <OpMetricRow metrics=vec![
                ("Trust / health".into(), format!("{score} · {trust}")),
                ("Agents live".into(), agents),
                ("Mem packets".into(), packets),
                ("Audit entries".into(), audit),
                ("Tokens".into(), tokens),
                ("LLM calls".into(), llm_calls),
                ("WF running".into(), wf_running.clone()),
                ("Uptime".into(), uptime),
            ] />
            <section class="mon-panel">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Trust dimensions (current level — no history series)"</p>
                <div class="mt-2">
                    <OpSparklineGrid metrics=dims />
                </div>
                <p class="mt-2 font-mono text-[10px] text-zinc-600">"GET /monitor/health · /monitor/trust · /operator/pulse"</p>
            </section>
            <section class="mon-panel">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Workflow concurrency"</p>
                <p class="mt-1 text-sm text-zinc-200">{format!("{wf_running} running · {wf_idle} idle")}</p>
            </section>
            {substrate_durability_section(&b.substrate)}
            {flow_lease_health_section(&b.substrate, &b.egress)}
            {federation_knowledge_badge(&b.federation_policy, &b.substrate)}
            {mesh_topology_section(&b.mesh, &b.cells, &b.ha)}
            {if recs.is_empty() {
                ().into_any()
            } else {
                view! {
                    <section class="mon-partial">
                        <p class="text-[10px] font-semibold uppercase tracking-[0.14em] text-amber-300">"Live recommendations"</p>
                        <ul class="mt-2 list-disc space-y-1 pl-4 text-[11px] text-amber-100/90">
                            {recs.into_iter().take(6).filter_map(|r| r.as_str().map(|s| s.to_string())).map(|s| {
                                view! { <li>{s}</li> }
                            }).collect_view()}
                        </ul>
                    </section>
                }.into_any()
            }}
        </div>
    }.into_any()
}

/// DI-4 — fleet charter digest drift (intelligence plane).
fn fleet_charter_section(fleet: &Value) -> AnyView {
    if fleet.is_null() {
        return ().into_any();
    }
    let n = fleet
        .get("agent_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let drifted = fleet
        .get("charter_drift_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let missing = fleet
        .get("missing_contract_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let broken = fleet
        .get("continuity_broken_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let active = fleet
        .get("active_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let digests = fleet
        .get("distinct_contract_digests")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let mode = fleet
        .get("mode_contract_digest_sha256")
        .and_then(|x| x.as_str())
        .unwrap_or("—");
    let mode_short = if mode.len() > 16 {
        format!("{}…", &mode[..12])
    } else {
        mode.to_string()
    };
    let agents = fleet
        .get("agents")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let rows: Vec<(String, String, String, bool)> = agents
        .into_iter()
        .take(12)
        .map(|row| {
            let pid = row
                .get("agent_pid")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string();
            let mark = row
                .get("intelligence_mark")
                .and_then(|x| x.as_str())
                .unwrap_or("—")
                .to_string();
            let dig = row
                .get("contract_digest_sha256")
                .and_then(|x| x.as_str())
                .map(|s| {
                    if s.len() > 12 {
                        format!("{}…", &s[..10])
                    } else {
                        s.to_string()
                    }
                })
                .unwrap_or_else(|| "missing".into());
            let drift = row
                .get("charter_drift")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
                || !row
                    .get("contract_present")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
            (pid, mark, dig, drift)
        })
        .collect();
    let ok = drifted == 0 && missing == 0;
    view! {
        <section class="mon-panel">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                "Fleet charter drift"
            </p>
            <p class=if ok {
                "mt-1 text-sm text-emerald-200/90"
            } else {
                "mt-1 text-sm text-amber-100/90"
            }>
                {format!(
                    "{n} intelligences · {active} active · {drifted} digest drift · {missing} missing contract · {broken} continuity broken · {digests} distinct digests"
                )}
            </p>
            <p class="mt-1 font-mono text-[10px] text-zinc-500">
                {format!("mode digest {mode_short}")}
            </p>
            {if rows.is_empty() {
                view! { <p class="mt-2 text-[11px] text-zinc-500">"No chartered intelligences yet."</p> }.into_any()
            } else {
                view! {
                    <div class="mt-2 overflow-x-auto">
                        <table class="w-full text-left text-[10px] text-zinc-300">
                            <thead class="text-zinc-500">
                                <tr>
                                    <th class="py-1 pr-2 font-medium">"agent"</th>
                                    <th class="py-1 pr-2 font-medium">"mark"</th>
                                    <th class="py-1 pr-2 font-medium">"digest"</th>
                                    <th class="py-1 font-medium">"drift"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows.into_iter().map(|(pid, mark, dig, drift)| {
                                    let drift_label = if drift { "yes" } else { "—" };
                                    let cls = if drift {
                                        "text-amber-200"
                                    } else {
                                        "text-zinc-400"
                                    };
                                    view! {
                                        <tr class="border-t border-zinc-800/60">
                                            <td class="py-1 pr-2 font-mono">{pid}</td>
                                            <td class="py-1 pr-2 font-mono text-zinc-400">{mark}</td>
                                            <td class="py-1 pr-2 font-mono text-zinc-400">{dig}</td>
                                            <td class=cls>{drift_label}</td>
                                        </tr>
                                    }
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                }.into_any()
            }}
            <p class="mt-2 font-mono text-[10px] text-zinc-600">
                "GET /runtime/fleet/charter"
            </p>
        </section>
    }
    .into_any()
}

fn flow_lease_health_section(substrate: &Value, egress: &Value) -> AnyView {
    let sub = substrate
        .get("data")
        .cloned()
        .unwrap_or_else(|| substrate.clone());
    let eg = egress.get("data").cloned().unwrap_or_else(|| egress.clone());
    let fl = sub
        .get("flow_lease")
        .cloned()
        .or_else(|| eg.get("flow_lease").cloned())
        .unwrap_or(Value::Null);
    let enforce = fl
        .get("enforce")
        .and_then(|x| x.as_str())
        .or_else(|| eg.get("flow_lease_enforce").and_then(|x| x.as_str()))
        .unwrap_or("off")
        .to_string();
    let reason = fl
        .get("reason")
        .and_then(|x| x.as_str())
        .unwrap_or("unavailable")
        .to_string();
    let active = fl
        .get("active_leases")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let env = fl
        .get("enforce_env")
        .and_then(|x| x.as_str())
        .unwrap_or("CONNECTOR_FLOW_LEASE_ENFORCE")
        .to_string();
    view! {
        <section class="mon-panel">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Flow lease · egress"</p>
            <OpMetricRow metrics=vec![
                ("Enforce".into(), enforce.clone()),
                ("Active leases".into(), active),
                ("Flag".into(), env),
            ] />
            <p class="mt-1 text-[11px] text-zinc-400">{reason}</p>
            <p class="mt-1 font-mono text-[10px] text-zinc-600">
                "GET /substrate/status · /runtime/egress/status — enforce on/off honesty"
            </p>
        </section>
    }.into_any()
}

fn federation_knowledge_badge(fed: &Value, substrate: &Value) -> AnyView {
    let deny = fed
        .get("deny_overrides")
        .and_then(|x| x.as_str())
        .unwrap_or("local_only")
        .to_string();
    let wired = fed
        .get("aapi_federation_wired")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let mesh_fab = fed
        .get("mesh_fabric")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let sub = substrate
        .get("data")
        .cloned()
        .unwrap_or_else(|| substrate.clone());
    let knowledge_mesh = sub
        .pointer("/knowledge/mesh_fabric")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let badge = if mesh_fab && deny != "local_only" {
        "replicated"
    } else {
        "local_only"
    };
    let tone = if badge == "local_only" {
        "bg-zinc-900 text-zinc-400 border-zinc-700/60"
    } else {
        "bg-emerald-950/50 text-emerald-200 border-emerald-800/40"
    };
    view! {
        <section class="mon-panel">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Knowledge / policy federation"</p>
            <div class="mt-2 flex flex-wrap items-center gap-2">
                <span class=format!("inline-flex rounded px-2 py-0.5 font-mono text-[11px] border {tone}")>
                    {format!("mesh · {badge}")}
                </span>
                <span class="font-mono text-[10px] text-zinc-500">
                    {format!("deny_overrides={deny}")}
                </span>
            </div>
            <p class="mt-1 text-[11px] text-zinc-400">
                {format!(
                    "aapi_federation_wired={wired} · policy mesh_fabric={mesh_fab} · substrate knowledge.mesh_fabric={knowledge_mesh}"
                )}
            </p>
            <p class="mt-1 font-mono text-[10px] text-zinc-600">
                "GET /runtime/federation-policy — local_only until FederatedPolicyEngine soak"
            </p>
        </section>
    }.into_any()
}

fn mesh_topology_section(mesh: &Value, cells: &Value, ha: &Value) -> AnyView {
    let geo_id = mesh
        .get("geo_id")
        .or_else(|| cells.get("geo_id"))
        .and_then(|x| x.as_str())
        .unwrap_or("geo:local")
        .to_string();
    let region = mesh
        .pointer("/local_placement/region")
        .and_then(|x| x.as_str())
        .unwrap_or("local")
        .to_string();
    let cell_id = mesh
        .pointer("/local_placement/cell_id")
        .and_then(|x| x.as_str())
        .unwrap_or("local")
        .to_string();
    let placement_schema = mesh
        .pointer("/local_placement/schema")
        .or_else(|| cells.pointer("/cells/0/placement/schema"))
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let caps = mesh
        .pointer("/local_placement/capabilities")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .take(4)
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "—".into());
    let endpoints = mesh
        .pointer("/local_placement/endpoints")
        .and_then(|x| x.as_array())
        .map(|a| a.len().to_string())
        .unwrap_or_else(|| "—".into());
    let edge_id = mesh
        .pointer("/intelligence_edge_example/identity_id")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let cell_count = cells
        .get("cells")
        .or_else(|| mesh.get("cells"))
        .and_then(|x| x.as_array())
        .map(|a| a.len().to_string())
        .unwrap_or_else(|| "—".into());
    // P8.4 — live peer list from mesh.peers ∪ ha.env.peer_urls (show empty honestly).
    let mut peer_set: Vec<String> = Vec::new();
    for src in [
        mesh.get("peers"),
        ha.pointer("/env/peer_urls"),
        ha.get("peers"),
    ] {
        if let Some(arr) = src.and_then(|x| x.as_array()) {
            for p in arr {
                if let Some(s) = p.as_str() {
                    let t = s.trim();
                    if !t.is_empty() && !peer_set.iter().any(|e| e == t) {
                        peer_set.push(t.to_string());
                    }
                }
            }
        }
    }
    let peer_lines = peer_set;
    let peer_tls = mesh
        .get("peer_tls")
        .or_else(|| ha.get("peer_tls"))
        .and_then(|x| x.as_str())
        .unwrap_or("fail_closed")
        .to_string();
    let channel_note = mesh
        .get("product_sot")
        .and_then(|x| x.as_str())
        .unwrap_or("single_node")
        .to_string();
    let role = ha
        .pointer("/env/role")
        .and_then(|x| x.as_str())
        .unwrap_or("standalone")
        .to_string();
    let mtls_required = ha
        .pointer("/env/mtls_required")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let automatic_failover = ha
        .get("automatic_failover")
        .or_else(|| mesh.get("automatic_failover"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let peers_seen = mesh
        .get("peers_seen")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "1".into());
    let membership_algo = mesh
        .get("membership_algorithm")
        .and_then(|x| x.as_str())
        .unwrap_or("vac_cluster_crdt")
        .to_string();
    let spiffe_id = mesh
        .get("spiffe_id")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let hw_v2 = placement_schema == "hardware_placement.v2";
    let peer_count = peer_lines.len().to_string();
    let mtls_label = mtls_required.to_string();
    let failover_label = automatic_failover.to_string();

    view! {
        <section class="mon-panel">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Mesh / topology"</p>
            <p class="mt-1 text-[11px] text-zinc-400">
                "Identities × geo × hardware — cluster badge only after soak. mesh_fabric=false · product_sot=single_node."
            </p>
            <OpMetricRow metrics=vec![
                ("Geo".into(), geo_id),
                ("Cell".into(), cell_id),
                ("Region".into(), region),
                ("Placement".into(), placement_schema.clone()),
                ("Cells".into(), cell_count),
                ("Endpoints".into(), endpoints),
                ("Caps".into(), caps),
                ("Edge example".into(), edge_id),
                ("Peers".into(), peer_count.clone()),
                ("Peer TLS".into(), peer_tls.clone()),
                ("Membership".into(), membership_algo),
                ("peers_seen".into(), peers_seen),
            ] />
            {if hw_v2 {
                view! {
                    <p class="mt-1 text-[11px] text-emerald-300/80">
                        "HardwarePlacementV2 on GET /runtime/cells · /runtime/mesh (local single-node vocabulary; not a live multi-cell schedule)."
                    </p>
                }.into_any()
            } else {
                view! {
                    <p class="mt-1 text-[11px] text-amber-200/80">
                        "Placement schema not hardware_placement.v2 — inspect GET /runtime/cells."
                    </p>
                }.into_any()
            }}
            <p class="mt-1 font-mono text-[10px] text-zinc-500 truncate" title=spiffe_id.clone()>
                {format!("spiffe_id={spiffe_id}")}
            </p>
            // P8.5 — HA panel matches API: peers, role, mTLS required, automatic_failover.
            <p class="mt-3 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"HA"</p>
            <OpMetricRow metrics=vec![
                ("Role".into(), role),
                ("Peers".into(), peer_count),
                ("mTLS required".into(), mtls_label),
                ("automatic_failover".into(), failover_label),
                ("Peer TLS".into(), peer_tls),
            ] />
            <p class="mt-1 text-[11px] text-amber-200/90">
                "automatic_failover=false until two-node soak — matches GET /runtime/ha-federation."
            </p>
            <p class="mt-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Live peers"</p>
            <p class="text-[10px] text-zinc-600">
                {format!("Channel posture product_sot={channel_note} · membership CRDT local heartbeat · empty peer list is honest.")}
            </p>
            {if peer_lines.is_empty() {
                view! {
                    <p class="mt-1 rounded border border-dashed border-zinc-800/80 px-2 py-1.5 text-[11px] text-zinc-500">
                        "peers: [] — set CONNECTOR_HA_PEER_URLS / CONNECTOR_FEDERATION_PEERS (Settings → Network → Mesh)."
                    </p>
                }.into_any()
            } else {
                view! {
                    <ul class="mt-1 space-y-0.5 font-mono text-[10px] text-zinc-400">
                        {peer_lines.into_iter().take(12).map(|u| view! { <li class="truncate">{u}</li> }).collect_view()}
                    </ul>
                }.into_any()
            }}
            <p class="mt-1 font-mono text-[10px] text-zinc-600">"GET /runtime/mesh · /runtime/cells · /runtime/ha-federation"</p>
        </section>
    }.into_any()
}

fn substrate_durability_section(substrate: &Value) -> AnyView {
    let root = substrate
        .get("data")
        .cloned()
        .unwrap_or_else(|| substrate.clone());
    let dur = root.get("durability").cloned().unwrap_or(Value::Null);
    let last_flush = dur
        .get("last_flush_ms")
        .and_then(|x| x.as_i64())
        .map(|ms| {
            if ms <= 0 {
                "unavailable".into()
            } else {
                format!("{ms} ms epoch")
            }
        })
        .unwrap_or_else(|| "unavailable".into());
    let wal = dur
        .get("wal_status")
        .and_then(|x| x.as_str())
        .unwrap_or("unavailable")
        .to_string();
    let write_through = dur
        .get("memwrite_write_through")
        .and_then(|x| x.as_bool())
        .map(|b| b.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let knot = dur
        .get("knot_node_count")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let iso = root
        .pointer("/isolation/declared_runtime")
        .and_then(|x| x.as_str())
        .unwrap_or("unavailable")
        .to_string();
    let dns = root
        .pointer("/dns/mode")
        .and_then(|x| x.as_str())
        .unwrap_or("unavailable")
        .to_string();
    let note = dur
        .get("honesty_note")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let glue = root
        .pointer("/glue/honesty")
        .and_then(|x| x.as_str())
        .unwrap_or("Glue posture unavailable")
        .to_string();
    view! {
        <section class="mon-panel">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Durability · isolation · DNS"</p>
            <OpMetricRow metrics=vec![
                ("Last durable flush".into(), last_flush),
                ("WAL / write-through".into(), format!("{wal} · wt={write_through}")),
                ("Knot nodes".into(), knot),
                ("Isolation grade".into(), iso),
                ("Cage DNS".into(), dns),
            ] />
            {if note.is_empty() {
                ().into_any()
            } else {
                view! { <p class="mt-1 text-[11px] text-amber-200/80">{note}</p> }.into_any()
            }}
            <p class="mt-2 text-[11px] text-zinc-400">{glue}</p>
            <p class="mt-1 font-mono text-[10px] text-zinc-600">"GET /substrate/status — dns.mode=in_process · glue.stub · unavailable ≠ 0"</p>
        </section>
    }.into_any()
}

fn finops_view(b: &MonitorBundle) -> AnyView {
    let cost = &b.cost;
    let center = &b.cost_center;
    let budget = &b.budget;
    let books = &b.books;
    let books_costs = &b.books_costs;
    // A missing meter is "—", never "0": zero is a measurement, absence is not.
    let tokens = num(cost, &["total_tokens"]).unwrap_or_else(|| "—".into());
    let packets = num(cost, &["total_packets"]).unwrap_or_else(|| "—".into());
    let llm_calls = num(cost, &["total_llm_calls", "total_requests"]).unwrap_or_else(|| "—".into());
    let sessions = num(cost, &["total_sessions"]).unwrap_or_else(|| "—".into());
    let billing_events = num(cost, &["billing_events"]).unwrap_or_else(|| "—".into());
    let tok_hr = center
        .get("tokens_per_hour")
        .and_then(|x| x.as_f64())
        .map(|n| format!("{n:.1}"))
        .unwrap_or_else(|| "—".into());
    let daily_tok = center
        .get("projected_daily_tokens")
        .and_then(|x| x.as_f64())
        .map(|n| format!("{n:.0}"))
        .unwrap_or_else(|| "—".into());
    let budget_tok = num(budget, &["global_budget_tokens"]).unwrap_or_else(|| "—".into());
    let warn = num(budget, &["warning_count"]).unwrap_or_else(|| "—".into());
    let exceeded = num(budget, &["exceeded_count"]).unwrap_or_else(|| "—".into());
    let denied = cost
        .pointer("/operations/denied_ops")
        .or_else(|| center.pointer("/operations/denied_ops"))
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let tools = cost
        .pointer("/operations/tool_dispatches")
        .or_else(|| center.pointer("/operations/tool_dispatches"))
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let audit = cost
        .pointer("/operations/total_audit_entries")
        .or_else(|| center.pointer("/operations/total_audit_entries"))
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let honesty = cost
        .get("honesty_note")
        .and_then(|x| x.as_str())
        .or_else(|| books_costs.pointer("/meta/honesty_note").and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();
    let books_tokens = books
        .pointer("/data/cost/today_tokens")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let books_agents = books
        .pointer("/data/resources/running_agents")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let books_sessions = books
        .pointer("/data/resources/active_sessions")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let chain_len = books
        .pointer("/data/integrity/chain_length")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let by_agent = cost
        .get("by_agent")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let by_model = cost
        .get("by_model")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let tok_n = tokens.parse::<f64>().unwrap_or(0.0);
    let spark = vec![
        ("Tokens".into(), tokens.clone(), spark_from_f64(tok_n, 10)),
        (
            "Tokens/hr".into(),
            tok_hr.clone(),
            spark_from_f64(tok_hr.parse().unwrap_or(0.0), 10),
        ),
        (
            "Daily tok proj".into(),
            daily_tok.clone(),
            spark_from_f64(daily_tok.parse().unwrap_or(0.0), 10),
        ),
        (
            "Tool ops".into(),
            tools.clone(),
            spark_from_f64(tools.parse().unwrap_or(0.0), 10),
        ),
    ];

    view! {
        <div class="space-y-4">
            <div class="mon-panel mon-panel--economy">
                <p class="text-[10px] font-semibold uppercase tracking-[0.14em] text-emerald-300">"Agentic economy · usage-first"</p>
                <p class="mt-1 text-[11px] text-zinc-300">
                    "Machine-recorded meters only: tokens, mem packets, LLM calls, sessions, tool dispatches, denials, audit chain. USD is not primary FinOps — a machine cannot independently know invoice spend."
                </p>
                <p class="mt-1 font-mono text-[10px] text-zinc-600">
                    {format!(
                        "mode={} · {}",
                        cost.get("economy_mode").and_then(|x| x.as_str()).unwrap_or("usage_first"),
                        cost.get("cost_basis").and_then(|x| x.as_str()).unwrap_or("tokens/packets/ops"),
                    )}
                </p>
                {if honesty.is_empty() {
                    ().into_any()
                } else {
                    view! { <p class="mt-2 text-[11px] text-amber-200/90">{honesty}</p> }.into_any()
                }}
            </div>
            <OpMetricRow metrics=vec![
                ("Tokens".into(), tokens),
                ("Mem packets".into(), packets),
                ("LLM calls".into(), llm_calls),
                ("Sessions".into(), sessions),
                ("Billing events".into(), billing_events),
                ("Tokens/hr".into(), tok_hr),
                ("Daily tok proj".into(), daily_tok),
                ("Budget tokens".into(), budget_tok),
            ] />
            <OpSparklineGrid metrics=spark />
            <OpMetricRow metrics=vec![
                ("Audit entries".into(), audit),
                ("Tool dispatches".into(), tools),
                ("Denied ops".into(), denied),
                ("Budget warnings".into(), warn),
                ("Budget exceeded".into(), exceeded),
                ("Books today tok".into(), books_tokens),
                ("Books agents".into(), books_agents),
                ("Books sessions".into(), books_sessions),
            ] />
            <section class="mon-panel">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Books ledger (GET /books)"</p>
                <p class="mt-1 text-xs text-zinc-300">{format!("Audit chain length {chain_len} · resources from SystemPosition")}</p>
                <p class="mt-1 font-mono text-[10px] text-zinc-600">
                    {books_costs.pointer("/meta/reconciliation_status").and_then(|x| x.as_str()).unwrap_or("—").to_string()}
                    " · GET /books/costs?period=today"
                </p>
            </section>
            <UsageBreakdown title="By agent" path="GET /monitor/cost-dashboard → by_agent" rows=usage_rows(&by_agent, &["pid", "name"], &["tokens"], &["packets"]) />
            <UsageBreakdown title="By model" path="GET /monitor/cost-dashboard → by_model" rows=usage_rows(&by_model, &["model", "name"], &["tokens"], &[]) />
            <p class="font-mono text-[10px] text-zinc-600">
                "GET /monitor/cost-dashboard · /monitor/cost-center · /monitor/budget-alerts · /books · /books/costs"
            </p>
        </div>
    }.into_any()
}

fn security_view(b: &MonitorBundle) -> AnyView {
    let trust = &b.trust;
    let integrity = &b.integrity;
    let firewall = &b.firewall;
    let llm = &b.llm;
    let alerts = &b.alerts;
    let anomalies = &b.anomalies;
    let signals = &b.signals;
    let health = &b.health;
    let score = num(trust, &["score", "agent_health_score"]).unwrap_or_else(|| "—".into());
    let grade = str_or(trust, &["trust_grade", "grade"]).unwrap_or_else(|| "—".into());
    let denied = num(trust, &["denied_total"]).unwrap_or_else(|| "—".into());
    let failed = num(trust, &["failed_total"]).unwrap_or_else(|| "—".into());
    let ops = num(trust, &["operations_analyzed"]).unwrap_or_else(|| "—".into());
    let integ = bool_or(integrity, &["integrity"]).unwrap_or_else(|| "—".into());
    let packets_checked = num(integrity, &["packets_checked"]).unwrap_or_else(|| "—".into());
    let audit_checked = num(integrity, &["audit_entries_checked"]).unwrap_or_else(|| "—".into());
    let fw_on = bool_or(firewall, &["enabled"]).unwrap_or_else(|| "—".into());
    let open_br = num(firewall, &["breakers_open"]).unwrap_or_else(|| "—".into());
    let half = num(firewall, &["breakers_half_open"]).unwrap_or_else(|| "—".into());
    let rules = num(firewall, &["dynamic_rules_loaded"]).unwrap_or_else(|| "—".into());
    let blocks = llm
        .pointer("/guardrails/guardrail_blocks")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let block_pct = llm
        .pointer("/guardrails/block_rate_pct")
        .and_then(|x| x.as_f64())
        .map(|n| format!("{n:.2}"))
        .unwrap_or_else(|| "—".into());
    let alert_n = num(alerts, &["count"]).unwrap_or_else(|| "—".into());
    let anom = num(anomalies, &["anomaly_count"]).unwrap_or_else(|| "—".into());
    let sig_n = num(signals, &["signal_count"]).unwrap_or_else(|| "—".into());
    let packets = num(health, &["packets"])
        .or_else(|| tier_num(health, "packets_used"))
        .unwrap_or_else(|| "—".into());
    let plan = b
        .trust_trend
        .get("improvement_plan")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let dims = dimension_spark(trust);

    view! {
        <div class="space-y-4">
            <OpMetricRow metrics=vec![
                ("Trust score".into(), format!("{score} · {grade}")),
                ("Integrity".into(), integ),
                ("Mem packets".into(), packets),
                ("Packets verified".into(), packets_checked),
                ("Audit checked".into(), audit_checked),
                ("Denied".into(), denied),
                ("Failed".into(), failed),
                ("Ops analyzed".into(), ops),
            ] />
            <OpSparklineGrid metrics=dims />
            <OpMetricRow metrics=vec![
                ("Firewall".into(), fw_on),
                ("Breakers open".into(), open_br),
                ("Half-open".into(), half),
                ("FW rules".into(), rules),
                ("Guard blocks".into(), blocks),
                ("Block rate %".into(), block_pct),
                ("Alerts".into(), alert_n),
                ("Anomalies".into(), anom),
            ] />
            <section class="mon-panel mon-panel--security">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Guardrails · LLM security"</p>
                <dl class="mt-2 space-y-1 text-xs">
                    <Kv k="hallucination_filter" v=llm.pointer("/guardrails/hallucination_filter").and_then(|x| x.as_str()).unwrap_or("—").to_string() />
                    <Kv k="injection_protection" v=llm.pointer("/guardrails/injection_protection").and_then(|x| x.as_str()).unwrap_or("—").to_string() />
                    <Kv k="pii_scrub" v=llm.pointer("/guardrails/pii_scrub").and_then(|x| x.as_str()).unwrap_or("—").to_string() />
                    <Kv k="signals" v=sig_n />
                </dl>
            </section>
            <section class="mon-panel">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Trust improvement plan (live)"</p>
                {if plan.is_empty() {
                    view! { <p class="mt-1 text-xs text-zinc-600">"No improvement actions from /monitor/trust-trend."</p> }.into_any()
                } else {
                    plan.into_iter().take(8).map(|p| {
                        let dim = p.get("dimension").and_then(|x| x.as_str()).unwrap_or("dim").to_string();
                        let action = p.get("action").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let cur = p.get("current").and_then(|x| x.as_u64()).unwrap_or(0);
                        let tgt = p.get("target").and_then(|x| x.as_u64()).unwrap_or(0);
                        view! {
                            <div class="mt-2 border-t border-zinc-800/50 pt-2 text-[11px]">
                                <p class="font-mono text-zinc-300">{format!("{dim} · {cur}→{tgt}")}</p>
                                <p class="text-zinc-500">{action}</p>
                            </div>
                        }
                    }).collect_view().into_any()
                }}
            </section>
            <section class="mon-panel">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Forensics timeline"</p>
                <p class="mt-1 text-[11px] text-zinc-400">
                    "Aggregate from GET /forensics/status — fni_moment_join; verified only after recompute (never fake green)."
                </p>
                <OpForensicsPanel load_status=true />
                {if b.forensics.is_null() {
                    view! { <p class="mt-1 text-[10px] text-zinc-600">"forensics/status unavailable this poll"</p> }.into_any()
                } else {
                    ().into_any()
                }}
            </section>
            <p class="font-mono text-[10px] text-zinc-600">
                "GET /monitor/trust · trust-trend · integrity · alerts · anomalies/v2 · llm · /firewall/status · /forensics/status"
            </p>
        </div>
    }.into_any()
}

fn network_view(b: &MonitorBundle) -> AnyView {
    let edge = &b.edge;
    let protocols = &b.protocols;
    let tools = &b.tools;
    let dns = edge
        .get("internal_dns")
        .or_else(|| edge.get("endpoints"))
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let healthy = dns
        .iter()
        .filter(|d| d.get("healthy").and_then(|x| x.as_bool()) == Some(true))
        .count();
    let stale = dns
        .iter()
        .filter(|d| d.get("stale").and_then(|x| x.as_bool()) == Some(true))
        .count();
    let mcp_n = num(protocols, &["count"]).unwrap_or_else(|| "—".into());
    let bridges = num(tools, &["bridge_count"]).unwrap_or_else(|| "—".into());
    let tool_status = str_or(tools, &["overall_status"]).unwrap_or_else(|| "—".into());
    let tool_ops = num(tools, &["total_tool_ops"]).unwrap_or_else(|| "—".into());
    let cage = edge
        .get("cage_tld")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();

    view! {
        <div class="space-y-4">
            <OpMetricRow metrics=vec![
                ("Edge endpoints".into(), dns.len().to_string()),
                ("Healthy".into(), healthy.to_string()),
                ("Stale".into(), stale.to_string()),
                ("Cage TLD".into(), cage),
                ("MCP servers".into(), mcp_n),
                ("Tool bridges".into(), bridges),
                ("Tool status".into(), tool_status),
                ("Tool ops".into(), tool_ops),
            ] />
            <section class="mon-panel mon-panel--network">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Protocol / edge plane (live)"</p>
                <p class="mt-1 text-[11px] text-amber-200/90">
                    "CNP peer mTLS: fail-closed without CONNECTOR_CNP_ALLOW_MTLS_STUB=1 — mutual_auth not productized (see GET /cnp/overview → data.mtls)."
                </p>
                <p class="mt-1 font-mono text-[10px] text-zinc-600">"GET /operator/edge/plane · /protocols/mcp/servers · /cnp/overview · /monitor/tools"</p>
                <div class="mt-2 max-h-72 space-y-1 overflow-auto">
                    {if dns.is_empty() {
                        view! { <p class="text-xs text-zinc-600">"No edge DNS entries."</p> }.into_any()
                    } else {
                        dns.into_iter().map(|d| {
                            let name = d.get("name").and_then(|x| x.as_str()).unwrap_or("endpoint").to_string();
                            let addr = d.get("addr").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                            let desc = d.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let ok = d.get("healthy").and_then(|x| x.as_bool());
                            let (label, class) = match ok {
                                Some(true) => ("up", "shrink-0 text-emerald-400"),
                                Some(false) => ("down", "shrink-0 text-amber-400"),
                                None => ("—", "shrink-0 text-zinc-500"),
                            };
                            let tags = d.get("tags").and_then(|x| x.as_array()).map(|a| {
                                a.iter().filter_map(|t| t.as_str()).collect::<Vec<_>>().join(",")
                            }).unwrap_or_default();
                            view! {
                                <div class="flex items-start justify-between gap-2 border-b border-zinc-800/40 py-1.5 text-[11px]">
                                    <div class="min-w-0">
                                        <p class="truncate font-mono text-zinc-200">{name}</p>
                                        <p class="truncate text-zinc-500">{format!("{addr} · {desc}")}</p>
                                        <p class="truncate font-mono text-[10px] text-zinc-600">{tags}</p>
                                    </div>
                                    <span class=class>
                                        {label}
                                    </span>
                                </div>
                            }
                        }).collect_view().into_any()
                    }}
                </div>
            </section>
            <p class="text-[11px] text-zinc-500">
                "Latency histograms are recorded when agents generate traffic; empty numbers mean no load yet — not a stub."
            </p>
            <p class="text-[11px] text-zinc-500">
                "Peer mesh TLS is L5 / single_node until soak (fail_closed by default; see GET /runtime/mesh)."
            </p>
        </div>
    }.into_any()
}

fn load_view(b: &MonitorBundle) -> AnyView {
    let health = &b.health;
    let runtime = &b.runtime;
    let forecast = &b.forecast;
    let pulse = &b.pulse;
    // Tier numbers drive both a label and a sparkline. The label must show "—"
    // when the meter is absent; only the bar geometry falls back to zero.
    let pct_label = |v: Option<f64>| v.map(|n| format!("{n:.1}%")).unwrap_or_else(|| "—".into());
    let agents = num(health, &["agents"]).unwrap_or_else(|| "—".into());
    let limit = health
        .pointer("/tier_usage/agents_limit")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let agents_pct = health
        .pointer("/tier_usage/agents_pct")
        .and_then(|x| x.as_f64());
    let packets_used = health
        .pointer("/tier_usage/packets_used")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let packets_limit = health
        .pointer("/tier_usage/packets_limit")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let packets_pct = health
        .pointer("/tier_usage/packets_pct")
        .and_then(|x| x.as_f64());
    let isolation = b
        .substrate
        .pointer("/data/isolation/declared_runtime")
        .or_else(|| b.substrate.pointer("/isolation/declared_runtime"))
        .or_else(|| health.pointer("/tier_usage/isolation_runtime"))
        .or_else(|| runtime.get("isolation_declared"))
        .and_then(|x| x.as_str())
        .unwrap_or("unavailable")
        .to_string();
    let iso_ok = b
        .substrate
        .pointer("/data/cage_security/isolation_grade_ok")
        .or_else(|| b.substrate.pointer("/cage_security/isolation_grade_ok"))
        .and_then(|x| x.as_bool());
    let isolation_badge = match iso_ok {
        Some(true) => format!("{isolation} · grade_ok"),
        Some(false) => format!("{isolation} · grade_fail"),
        None => isolation.clone(),
    };
    let mode = health
        .pointer("/tier_usage/runtime_mode")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let wf_run = pulse
        .pointer("/workflows/running")
        .and_then(|x| x.as_u64());
    let wf_idle = pulse
        .pointer("/workflows/idle")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let wf_run_disp = wf_run
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".to_string());
    let plugins = runtime
        .get("plugins")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let running_plugins = plugins
        .iter()
        .filter(|p| p.get("lifecycle").and_then(|x| x.as_str()) == Some("running"))
        .count();
    let ops_dir = forecast
        .pointer("/ops_trend/direction")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let ops_daily = forecast
        .pointer("/ops_trend/projected_daily_ops")
        .and_then(|x| x.as_u64());
    let ops_daily_disp = ops_daily
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".to_string());
    let slope = forecast
        .pointer("/ops_trend/slope_per_day")
        .and_then(|x| x.as_f64())
        .map(|n| format!("{n:.3}"))
        .unwrap_or_else(|| "—".into());
    let load_spark = vec![
        (
            "Agent util %".into(),
            pct_label(agents_pct),
            spark_from_f64(agents_pct.unwrap_or(0.0), 10),
        ),
        (
            "Packet util %".into(),
            pct_label(packets_pct),
            spark_from_f64(packets_pct.unwrap_or(0.0), 10),
        ),
        (
            "WF running".into(),
            wf_run_disp.clone(),
            spark_from_f64(wf_run.unwrap_or(0) as f64, 10),
        ),
        (
            "Ops/day proj".into(),
            ops_daily_disp.clone(),
            spark_from_f64(ops_daily.unwrap_or(0) as f64, 10),
        ),
    ];

    view! {
        <div class="space-y-4">
            <OpMetricRow metrics=vec![
                ("Agents".into(), format!("{agents}/{limit}")),
                ("Agent util".into(), pct_label(agents_pct)),
                ("Packets".into(), format!("{packets_used}/{packets_limit}")),
                ("Packet util".into(), pct_label(packets_pct)),
                ("Isolation".into(), isolation_badge),
                ("Runtime mode".into(), mode),
                ("Plugins running".into(), running_plugins.to_string()),
                ("Ops trend".into(), ops_dir),
            ] />
            <OpSparklineGrid metrics=load_spark />
            {substrate_durability_section(&b.substrate)}
            <section class="mon-panel mon-panel--load">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Distributed / parallel concurrency"</p>
                <p class="mt-1 text-sm text-zinc-200">{format!("{wf_run_disp} workflows running · {wf_idle} idle")}</p>
                <p class="mt-1 text-[11px] text-zinc-500">{format!("Projected daily ops {ops_daily_disp} · slope/day {slope}")}</p>
                <p class="mt-2 font-mono text-[10px] text-zinc-600">"GET /operator/pulse · /runtime/lifecycle/summary · /monitor/forecast"</p>
            </section>
            <section class="mon-panel">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Plugin lifecycle (parallel plane)"</p>
                {if plugins.is_empty() {
                    view! { <p class="mt-1 text-xs text-zinc-600">"No plugin lifecycle rows."</p> }.into_any()
                } else {
                    plugins.into_iter().map(|p| {
                        let id = p.get("id").and_then(|x| x.as_str()).unwrap_or("plugin").to_string();
                        let life = p.get("lifecycle").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let ver = p.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        let en = p.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
                        view! {
                            <div class="mt-1 flex justify-between gap-2 border-b border-zinc-800/40 py-1 text-[11px]">
                                <span class="font-mono text-zinc-300">{format!("{id} {ver}")}</span>
                                <span class="text-zinc-500">{format!("{} · {}", life, if en { "enabled" } else { "off" })}</span>
                            </div>
                        }
                    }).collect_view().into_any()
                }}
            </section>
        </div>
    }.into_any()
}

#[component]
fn UsageBreakdown(
    title: &'static str,
    path: &'static str,
    rows: Vec<(String, String, String)>,
) -> impl IntoView {
    view! {
        <section class="mon-panel">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">{title}</p>
            <p class="mt-0.5 font-mono text-[10px] text-zinc-600">{path}</p>
            {if rows.is_empty() {
                view! { <p class="mt-2 text-xs text-zinc-600">"No rows yet — meters appear when agents run (tokens/packets)."</p> }.into_any()
            } else {
                rows.into_iter().map(|(name, tokens, packets)| {
                    view! {
                        <div class="mt-1 flex justify-between gap-2 border-b border-zinc-800/40 py-1 text-[11px]">
                            <span class="truncate font-mono text-zinc-300">{name}</span>
                            <span class="shrink-0 text-zinc-400">
                                {if packets.is_empty() || packets == "—" {
                                    format!("{tokens} tok")
                                } else {
                                    format!("{tokens} tok · {packets} pkt")
                                }}
                            </span>
                        </div>
                    }
                }).collect_view().into_any()
            }}
        </section>
    }
}

#[component]
fn Kv(k: &'static str, v: String) -> impl IntoView {
    view! {
        <div class="flex justify-between gap-2">
            <dt class="text-zinc-500">{k}</dt>
            <dd class="font-mono text-zinc-200">{v}</dd>
        </div>
    }
}

fn usage_rows(
    arr: &[Value],
    name_keys: &[&str],
    tok_keys: &[&str],
    packet_keys: &[&str],
) -> Vec<(String, String, String)> {
    arr.iter()
        .take(12)
        .map(|r| {
            let name = name_keys
                .iter()
                .find_map(|k| r.get(*k).and_then(|x| x.as_str()))
                .unwrap_or("row")
                .to_string();
            let tok = tok_keys
                .iter()
                .find_map(|k| r.get(*k).and_then(|x| x.as_u64()))
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".into());
            let packets = if packet_keys.is_empty() {
                String::new()
            } else {
                packet_keys
                    .iter()
                    .find_map(|k| r.get(*k).and_then(|x| x.as_u64()))
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "—".into())
            };
            (name, tok, packets)
        })
        .collect()
}

fn dimension_spark(v: &Value) -> Vec<(String, String, Vec<f64>)> {
    let dims = v.get("dimensions").cloned().unwrap_or(Value::Null);
    let keys = [
        "audit_completeness",
        "authorization_coverage",
        "decision_provenance",
        "memory_integrity",
        "operational_health",
    ];
    keys.into_iter()
        .filter_map(|k| {
            let n = dims.get(k)?.as_f64().or_else(|| dims.get(k)?.as_u64().map(|u| u as f64))?;
            Some((k.replace('_', " "), format!("{n:.0}"), spark_from_f64(n, 10)))
        })
        .collect()
}

/// Flat series at the current reading.
///
/// No backend time series feeds these cards, so the bars show the present level
/// only. An earlier version added a sine "wobble" so the card looked like a
/// graph, which drew history the backend never reported.
fn spark_from_f64(n: f64, len: usize) -> Vec<f64> {
    vec![n.max(0.0); len]
}

fn num(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        v.get(*k)
            .and_then(|x| x.as_u64())
            .map(|n| n.to_string())
            .or_else(|| v.get(*k).and_then(|x| x.as_f64()).map(|n| format!("{n}")))
    })
}

fn fnum(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_f64()).map(|n| format!("{n:.4}")))
}

fn str_or(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_str()).map(str::to_string))
}

fn bool_or(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_bool()).map(|b| b.to_string()))
}

fn tier_num(v: &Value, key: &str) -> Option<String> {
    v.pointer(&format!("/tier_usage/{key}"))
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
}
