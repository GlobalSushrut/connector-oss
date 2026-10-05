use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_location};
use serde_json::Value;

use crate::api;
use crate::auth::{AuthState, logout};
use crate::components::icons;
use crate::components::capacity_meters::CapacityMetersCompact;
use crate::components::countdown_pill::CountdownPill;
use crate::components::live_dot_pill::LiveDotPill;
use crate::components::status_banner::{live_state_from_monitor_status, LiveState};
use crate::utils::{time_ago_str, truncate};

// `NavItem` + `NavSection` definitions and the sidebar registry now live in
// `crate::routes` (Phase 1.3). Sidebar rendering reads `nav_sections()`,
// which delegates to the central registry — no hand-edited duplication.
use crate::routes::{nav_sections_for_mode, NavSection};
use crate::deployment::{use_deployment, use_deployment_mode, DeploymentMode};
use gloo_storage::{LocalStorage, Storage};

fn nav_sections(mode: DeploymentMode) -> Vec<NavSection> {
    nav_sections_for_mode(mode)
}

/// Apps sidebar: respects `enabled_in_deployment` from `GET /api/v1/plugins/status`.
/// Groups Dev Apps (AI tool integration) and Server Apps separately.
/// Apps sub-section in the sidebar.
///
/// Phase 2.3: surfaces **all 9** marketed plugins (was 3). Pulls the
/// labels + icons + `default_enabled` from the central product catalog
/// (`platform/products/catalog.json`); overlays per-plugin enablement
/// from `GET /api/v1/plugins/status` once the response arrives. Falls
/// back to the catalog's `default_enabled` for plugins the server
/// doesn't know about — keeps the sidebar honest on a fresh node.
#[component]
fn PluginsNavSection(
    collapsed: ReadSignal<bool>,
    pathname: Memo<String>,
    auth: ReadSignal<AuthState>,
) -> impl IntoView {
    let status = LocalResource::new(move || {
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(api::ApiError {
                    status: 0,
                    code: None,
                    message: "not authenticated".into(),
                    detail: None,
                    hints: vec![],
                    docs: None,
                });
            }
            api::get_value("/plugins/status").await
        }
    });
    let (developer_view, _) = crate::ui_state::use_developer_view();

    view! {
        <div class="mb-4">
            <Show when=move || !collapsed.get()>
                <p class="px-3 mb-2 text-[10px] font-semibold text-zinc-600 uppercase tracking-wider">"Apps"</p>
            </Show>
            <div class="space-y-0.5">
                <SidebarPluginNavItem
                    path="/apps"
                    label="Apps Hub"
                    icon_key="marketplace"
                    exact=true
                    collapsed=collapsed
                    pathname=pathname.clone()
                    enabled=true
                />
                <SidebarPluginNavItem
                    path="/plugins"
                    label="All Plugins"
                    icon_key="tools"
                    exact=true
                    collapsed=collapsed
                    pathname=pathname.clone()
                    enabled=true
                />
            </div>
            <Suspense fallback=move || view! {
                <div class="space-y-1 px-1 mt-2">
                    <div class="h-9 rounded-xl bg-zinc-800/40 animate-pulse"></div>
                    <div class="h-9 rounded-xl bg-zinc-800/30 animate-pulse"></div>
                    <div class="h-9 rounded-xl bg-zinc-800/25 animate-pulse"></div>
                </div>
            }>
                {move || Suspend::new(async move {
                    let body = status.await;
                    let server_plugins = body
                        .as_ref()
                        .ok()
                        .and_then(|v| v.get("plugins").cloned())
                        .unwrap_or(serde_json::Value::Null);
                    let plugin_enabled = move |slug: &str, fallback: bool| -> bool {
                        server_plugins
                            .get(slug)
                            .and_then(|x| x.get("enabled_in_deployment"))
                            .and_then(|b| b.as_bool())
                            .unwrap_or(fallback)
                    };

                    view! {
                        <div class="space-y-0.5 mt-2">
                            {crate::catalog::plugins().iter().filter(|plugin| {
                                developer_view.get()
                                    || matches!(
                                        plugin.slug.as_str(),
                                        "tracetramp" | "witnessctl" | "devguard"
                                    )
                            }).map(|plugin| {
                                let enabled = plugin_enabled(&plugin.slug, plugin.default_enabled);
                                let deferred = !matches!(
                                    plugin.slug.as_str(),
                                    "tracetramp" | "witnessctl" | "devguard"
                                );
                                let label = if deferred {
                                    format!("{} · deferred", plugin.name)
                                } else {
                                    plugin.name.clone()
                                };
                                view! {
                                    <SidebarPluginNavItem
                                        path=crate::catalog::plugin_path(&plugin.slug)
                                        label=label
                                        icon_key=plugin.icon_key.clone()
                                        exact=false
                                        collapsed=collapsed
                                        pathname=pathname.clone()
                                        enabled=enabled
                                    />
                                }
                            }).collect::<Vec<_>>()}
                        </div>
                    }.into_any()
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn SidebarPluginNavItem(
    #[prop(into)] path: String,
    #[prop(into)] label: String,
    #[prop(into)] icon_key: String,
    exact: bool,
    collapsed: ReadSignal<bool>,
    pathname: Memo<String>,
    enabled: bool,
) -> impl IntoView {
    let path_for_active = path.clone();
    let is_active = Memo::new(move |_| {
        if !enabled {
            return false;
        }
        let cur = pathname.get();
        let p = path_for_active.as_str();
        if p == "/" {
            return cur == "/";
        }
        if exact {
            return cur == p;
        }
        cur.starts_with(p)
            && (cur.len() == p.len() || cur.as_bytes().get(p.len()) == Some(&b'/'))
    });
    let icon_svg = icons::get_icon(&icon_key);

    // Pre-clone strings used in both Show branches so each branch's
    // closure can be Fn (Leptos requires Fn for both `when` and
    // `fallback` body closures).
    let fallback_label = label.clone();
    let main_label = label;
    let main_path = path;

    view! {
        <Show
            when=move || enabled
            fallback={
                let fallback_label = fallback_label.clone();
                move || {
                    let label = fallback_label.clone();
                    view! {
                        <div
                            class=move || {
                                let base = "nav-item flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm text-zinc-600 border border-transparent opacity-55 cursor-default";
                                let col = if collapsed.get() { "justify-center px-2.5" } else { "" };
                                format!("{base} {col}")
                            }
                            title="Not enabled in this deployment. Set CONNECTOR_PLUGINS_ENABLED on the platform (or open All plugins for status)."
                        >
                            <span class="shrink-0 w-5 h-5 flex items-center justify-center text-zinc-600" inner_html=icon_svg />
                            <Show when=move || !collapsed.get()>
                                <span class="truncate text-[13px] font-medium">{label.clone()}</span>
                            </Show>
                        </div>
                    }
                }
            }
        >
            {
                let main_label = main_label.clone();
                let main_path = main_path.clone();
                let preload_path = main_path.clone();
                view! {
                    <A href=main_path
                        attr:class=move || {
                            let base = "nav-item group flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all duration-200";
                            let state = if is_active.get() {
                                "nav-item-active bg-gradient-to-r from-indigo-500/20 to-purple-500/10 text-white font-medium border border-indigo-500/30 shadow-lg shadow-indigo-500/10"
                            } else {
                                "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-100 border border-transparent hover:border-zinc-700/50 hover:shadow-md"
                            };
                            let col = if collapsed.get() { "justify-center px-2.5" } else { "" };
                            format!("{base} {state} {col}")
                        }
                        attr:aria-current=move || if is_active.get() { "page" } else { "" }
                        on:mouseenter=move |_| {
                            #[cfg(feature = "full-pages")]
                            crate::routing::lazy_preload::preload_on_hover(&preload_path);
                        }
                    >
                        <span
                            class=move || {
                                let base = "shrink-0 w-5 h-5 flex items-center justify-center transition-transform duration-200 group-hover:scale-110";
                                if is_active.get() { format!("{base} text-indigo-400") } else { format!("{base} text-zinc-500 group-hover:text-zinc-300") }
                            }
                            inner_html=icon_svg
                        />
                        <Show when=move || !collapsed.get()>
                            <span class="truncate text-[13px] font-medium">{main_label.clone()}</span>
                        </Show>
                    </A>
                }
            }
        </Show>
    }
}

fn notif_row_kind(severity: &str, status: &str) -> &'static str {
    let sev = severity.to_ascii_uppercase();
    if matches!(sev.as_str(), "CRITICAL" | "PAGED")
        || (sev == "WARNING"
            && !status.eq_ignore_ascii_case("ACKNOWLEDGED")
            && !status.eq_ignore_ascii_case("CANCELLED"))
    {
        "alert"
    } else if sev == "WARNING" {
        "warning"
    } else if status.eq_ignore_ascii_case("DELIVERED") {
        "success"
    } else {
        "info"
    }
}

fn notif_row_icon_class(ntype: &str, muted: bool) -> &'static str {
    match (ntype, muted) {
        ("alert",   false) => "notif-icon-alert",
        ("alert",   true)  => "notif-icon-alert-dim",
        ("warning", false) => "notif-icon-warning",
        ("warning", true)  => "notif-icon-warning-dim",
        ("success", false) => "notif-icon-success",
        ("success", true)  => "notif-icon-success-dim",
        (_,         false) => "notif-icon-info",
        (_,         true)  => "notif-icon-info-dim",
    }
}

fn notif_row_icon_svg(ntype: &str) -> &'static str {
    match ntype {
        "alert" | "warning" => icons::ICON_ALERT,
        "success" => icons::ICON_CHECK,
        _ => icons::ICON_INFO,
    }
}

fn partition_header_notifications(items: Vec<Value>) -> (Vec<Value>, Vec<Value>) {
    let mut urgent = Vec::new();
    let mut rest = Vec::new();
    for v in items {
        let sev = v.get("severity").and_then(|x| x.as_str()).unwrap_or("");
        let st = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
        let is_urgent = matches!(sev.to_ascii_uppercase().as_str(), "CRITICAL" | "PAGED")
            || (sev.eq_ignore_ascii_case("WARNING")
                && !st.eq_ignore_ascii_case("ACKNOWLEDGED")
                && !st.eq_ignore_ascii_case("CANCELLED"));
        if is_urgent {
            urgent.push(v);
        } else {
            rest.push(v);
        }
    }
    urgent.sort_by(|a, b| {
        let sa = a.get("severity").and_then(|x| x.as_str()).unwrap_or("");
        let sb = b.get("severity").and_then(|x| x.as_str()).unwrap_or("");
        severity_sort_key(sa).cmp(&severity_sort_key(sb))
    });
    urgent.truncate(8);
    rest.truncate(8);
    (urgent, rest)
}

fn notif_row_time_label(v: &Value) -> (String, String) {
    let iso = v
        .get("created_at")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("due_at_iso").and_then(|x| x.as_str()))
        .unwrap_or("");
    if iso.is_empty() {
        return ("—".into(), String::new());
    }
    let rel = time_ago_str(iso);
    let abs = if iso.len() > 24 {
        format!("{}…", &iso[..23])
    } else {
        iso.to_string()
    };
    if rel.is_empty() {
        (abs.clone(), abs)
    } else {
        (rel, abs)
    }
}

fn severity_sort_key(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "PAGED" => 0,
        "CRITICAL" => 1,
        "WARNING" => 2,
        "INFO" => 3,
        _ => 4,
    }
}

fn notif_severity_rail_class(sev: &str) -> &'static str {
    match sev.to_ascii_uppercase().as_str() {
        "PAGED"    => "notif-rail-paged",
        "CRITICAL" => "notif-rail-critical",
        "WARNING"  => "notif-rail-warning",
        "INFO"     => "notif-rail-info",
        _          => "notif-rail-default",
    }
}

fn notif_severity_pill_class(sev: &str) -> &'static str {
    match sev.to_ascii_uppercase().as_str() {
        "PAGED"    => "notif-pill-paged",
        "CRITICAL" => "notif-pill-critical",
        "WARNING"  => "notif-pill-warning",
        "INFO"     => "notif-pill-info",
        _          => "notif-pill-default",
    }
}

fn notif_status_pill_class(st: &str) -> &'static str {
    match st.to_ascii_uppercase().as_str() {
        "PENDING"      => "notif-status-pending",
        "DELIVERED"    => "notif-status-delivered",
        "ACKNOWLEDGED" => "notif-status-acknowledged",
        "SNOOZED"      => "notif-status-snoozed",
        "ESCALATED"    => "notif-status-escalated",
        "CANCELLED"    => "notif-status-cancelled",
        _              => "notif-status-default",
    }
}

#[allow(dead_code)] // re-used by SystemHealthCard on /monitor in Phase 6.
fn build_health_detail_chips(v: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let score = v
        .get("agent_health_score")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("agent_health_score").and_then(|x| x.as_i64()).map(|n| n as u64))
        .or_else(|| {
            v.get("agent_health_score")
                .and_then(|x| x.as_f64())
                .map(|f| f as u64)
        });
    if let (Some(grade), Some(sc)) = (v.get("trust_grade").and_then(|x| x.as_str()), score) {
        out.push(("Trust".into(), format!("{grade} · {sc}")));
    } else if let Some(grade) = v.get("trust_grade").and_then(|x| x.as_str()) {
        out.push(("Trust".into(), grade.into()));
    } else if let Some(sc) = score {
        out.push(("Score".into(), sc.to_string()));
    }
    if let Some(i) = v.get("integrity").and_then(|x| x.as_bool()) {
        out.push((
            "Audit".into(),
            if i {
                "chain OK".into()
            } else {
                "chain FAIL".into()
            },
        ));
    }
    if let Some(n) = v.get("agents").and_then(|x| x.as_u64()) {
        out.push(("Agents".into(), n.to_string()));
    }
    if let Some(g) = v.get("governance").and_then(|x| x.as_object()) {
        let ready = g.get("governance_ready").and_then(|x| x.as_bool()).unwrap_or(false);
        let llm = g.get("llm_router_wired").and_then(|x| x.as_bool()).unwrap_or(false);
        let broker = g
            .get("llm_broker_unbypassable")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let sand = g
            .get("sandbox_unbypassable_enforced")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let guard = g
            .get("guard_pipeline_active")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        // Ready without Linux/broker bar is still "partial" for honest operator chrome.
        let label = if ready && (broker || sand) {
            "ready"
        } else if ready {
            "partial"
        } else {
            "partial"
        };
        out.push((
            "Gov".into(),
            format!(
                "{} · llm {} · broker {} · bar {} · guard {}",
                label,
                if llm { "on" } else { "off" },
                if broker { "strict" } else { "soft" },
                if sand { "on" } else { "off" },
                if guard { "on" } else { "off" }
            ),
        ));
    }
    if let Some(ds) = v.get("deploy_safe").and_then(|x| x.as_bool()) {
        out.push((
            "Deploy".into(),
            if ds {
                "gate ok".into()
            } else {
                "hold".into()
            },
        ));
    }
    out.truncate(6);
    out
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // re-used by /monitor in Phase 6.
enum SubsystemStripTier {
    Ok,
    Warn,
    Bad,
    Unknown,
}

#[allow(dead_code)] // re-used by /monitor in Phase 6.
fn strip_tier_dot_class(t: SubsystemStripTier) -> &'static str {
    match t {
        SubsystemStripTier::Ok => {
            "w-2 h-2 rounded-full bg-emerald-500 shadow-sm shadow-emerald-500/50"
        }
        SubsystemStripTier::Warn => {
            "w-2 h-2 rounded-full bg-amber-400 shadow-sm shadow-amber-400/45 animate-pulse"
        }
        SubsystemStripTier::Bad => {
            "w-2 h-2 rounded-full bg-rose-500 shadow-sm shadow-rose-500/45"
        }
        SubsystemStripTier::Unknown => {
            "w-2 h-2 rounded-full bg-zinc-600 shadow-sm shadow-zinc-600/35"
        }
    }
}

#[allow(dead_code)] // re-used by /monitor in Phase 6.
fn json_dim_u64(v: &Value, dim: &str) -> Option<u64> {
    v.get("dimensions")
        .and_then(|d| d.get(dim))
        .and_then(|x| {
            x.as_u64()
                .or_else(|| x.as_i64().map(|n| n as u64))
                .or_else(|| x.as_f64().map(|f| f.round() as u64))
        })
}

#[allow(dead_code)] // re-used by /monitor in Phase 6.
fn memory_strip_tier(v: &Value) -> SubsystemStripTier {
    match json_dim_u64(v, "memory_integrity") {
        None => SubsystemStripTier::Unknown,
        Some(x) if x >= 80 => SubsystemStripTier::Ok,
        Some(x) if x >= 55 => SubsystemStripTier::Warn,
        Some(_) => SubsystemStripTier::Bad,
    }
}

#[allow(dead_code)] // re-used by /monitor in Phase 6.
fn ledger_strip_tier(v: &Value) -> SubsystemStripTier {
    match v.get("integrity").and_then(|x| x.as_bool()) {
        Some(true) => SubsystemStripTier::Ok,
        Some(false) => SubsystemStripTier::Bad,
        None => SubsystemStripTier::Unknown,
    }
}

#[allow(dead_code)] // re-used by /monitor in Phase 6.
fn packet_pressure_tier(v: &Value) -> Option<SubsystemStripTier> {
    let pct = v
        .get("tier_usage")
        .and_then(|t| t.get("packets_pct"))
        .and_then(|x| x.as_f64())?;
    if pct >= 92.0 {
        Some(SubsystemStripTier::Bad)
    } else if pct >= 78.0 {
        Some(SubsystemStripTier::Warn)
    } else {
        None
    }
}

/// Derive the third header dot: prefer packet pressure, else memory integrity tier.
#[allow(dead_code)] // re-used by /monitor in Phase 6.
fn store_or_cache_tier(v: &Value) -> SubsystemStripTier {
    if let Some(t) = packet_pressure_tier(v) {
        return t;
    }
    memory_strip_tier(v)
}

#[allow(dead_code)] // re-used by /monitor in Phase 6 to render an inline subsystem strip.
#[component]
fn HeaderSubsystemStrip(health: LocalResource<Result<Value, api::ApiError>>) -> impl IntoView {
    view! {
        <div class="hidden lg:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-zinc-900/50 border border-zinc-800/50">
            <Suspense fallback=move || view! {
                <div class="flex items-center gap-3">
                    <div class="flex items-center gap-1.5 text-xs" title="Loading monitor health">
                        <span class="w-2 h-2 rounded-full bg-zinc-600 animate-pulse"></span>
                        <span class="text-zinc-500">"API"</span>
                    </div>
                    <div class="w-px h-3 bg-zinc-700"></div>
                    <div class="flex items-center gap-1.5 text-xs" title="Loading monitor health">
                        <span class="w-2 h-2 rounded-full bg-zinc-600 animate-pulse"></span>
                        <span class="text-zinc-500">"Ledger"</span>
                    </div>
                    <div class="w-px h-3 bg-zinc-700"></div>
                    <div class="flex items-center gap-1.5 text-xs" title="Loading monitor health">
                        <span class="w-2 h-2 rounded-full bg-zinc-600 animate-pulse"></span>
                        <span class="text-zinc-500">"Mem"</span>
                    </div>
                </div>
            }>
                {move || Suspend::new(async move {
                    let r = health.await;
                    match r {
                        Err(e) => {
                            let msg = truncate(&e.message, 120);
                            let t_api = format!(
                                "Monitor request failed ({}) — not a live platform signal.",
                                e.status
                            );
                            view! {
                                <div class="flex items-center gap-3">
                                    <div class="flex items-center gap-1.5 text-xs" title=t_api>
                                        <span class=strip_tier_dot_class(SubsystemStripTier::Bad)></span>
                                        <span class="text-zinc-400">"API"</span>
                                    </div>
                                    <div class="w-px h-3 bg-zinc-700"></div>
                                    <div class="flex items-center gap-1.5 text-xs" title=format!("No health body: {}", msg)>
                                        <span class=strip_tier_dot_class(SubsystemStripTier::Unknown)></span>
                                        <span class="text-zinc-400">"Ledger"</span>
                                    </div>
                                    <div class="w-px h-3 bg-zinc-700"></div>
                                    <div class="flex items-center gap-1.5 text-xs" title=format!("No health body: {}", msg)>
                                        <span class=strip_tier_dot_class(SubsystemStripTier::Unknown)></span>
                                        <span class="text-zinc-400">"Mem"</span>
                                    </div>
                                </div>
                            }.into_any()
                        }
                        Ok(v) => {
                            let status = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
                            let api_tier = match status {
                                s if s.eq_ignore_ascii_case("critical") => SubsystemStripTier::Bad,
                                s if s.eq_ignore_ascii_case("degraded") => SubsystemStripTier::Warn,
                                "" => SubsystemStripTier::Unknown,
                                _ => SubsystemStripTier::Ok,
                            };
                            let led = ledger_strip_tier(&v);
                            let mem = store_or_cache_tier(&v);
                            let api_title = format!(
                                "Platform status: {} — from GET /api/v1/monitor/health",
                                if status.is_empty() { "unknown" } else { status }
                            );
                            let led_title = match v.get("integrity").and_then(|x| x.as_bool()) {
                                Some(true) => "Kernel audit chain verification succeeded (ledger OK).",
                                Some(false) => "Audit chain verification FAILED — treat as incident.",
                                None => "Integrity field missing on health payload.",
                            };
                            let mem_title = if packet_pressure_tier(&v).is_some() {
                                let pct = v
                                    .get("tier_usage")
                                    .and_then(|t| t.get("packets_pct"))
                                    .and_then(|x| x.as_f64())
                                    .unwrap_or(0.0);
                                format!(
                                    "Memory / tier pressure: packets at {:.0}% of licensed limit (hot path).",
                                    pct
                                )
                            } else {
                                let n = json_dim_u64(&v, "memory_integrity").map(|n| n.to_string()).unwrap_or_else(|| "—".into());
                                format!("Trust dimension memory_integrity: {} (higher is better).", n)
                            };
                            let api_dot = strip_tier_dot_class(api_tier);
                            let led_dot = strip_tier_dot_class(led);
                            let mem_dot = strip_tier_dot_class(mem);
                            view! {
                                <div class="flex items-center gap-3">
                                    <div class="flex items-center gap-1.5 text-xs" title=api_title>
                                        <span class=api_dot></span>
                                        <span class="text-zinc-400">"API"</span>
                                    </div>
                                    <div class="w-px h-3 bg-zinc-700"></div>
                                    <div class="flex items-center gap-1.5 text-xs" title=led_title>
                                        <span class=led_dot></span>
                                        <span class="text-zinc-400">"Ledger"</span>
                                    </div>
                                    <div class="w-px h-3 bg-zinc-700"></div>
                                    <div class="flex items-center gap-1.5 text-xs" title=mem_title>
                                        <span class=mem_dot></span>
                                        <span class="text-zinc-400">"Mem"</span>
                                    </div>
                                </div>
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn NotificationPreviewRow(record: Value, dimmed: bool) -> impl IntoView {
    let title = record
        .get("title")
        .and_then(|x| x.as_str())
        .unwrap_or("Untitled")
        .to_string();
    let raw_msg = record
        .get("message")
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string();
    let desc = truncate(&raw_msg, 240);
    let sev = record
        .get("severity")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let st = record
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let nt = record
        .get("notification_type")
        .and_then(|x| x.as_str())
        .unwrap_or("CUSTOM")
        .to_string();
    let nt_label = truncate(&nt.replace('_', " "), 32);
    let nkind = notif_row_kind(&sev, &st);
    let rail = notif_severity_rail_class(&sev);
    let ic = notif_row_icon_class(nkind, dimmed);
    let icon = notif_row_icon_svg(nkind);
    let sev_cls = notif_severity_pill_class(&sev);
    let st_cls = notif_status_pill_class(&st);
    let (time_rel, time_abs) = notif_row_time_label(&record);
    let time_abs_title = time_abs.clone();
    let webhook = record
        .get("webhook_delivered")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let attempts = record
        .get("delivery_attempts")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let esc = record
        .get("escalation_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let next_es = record
        .get("next_escalation")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let finding = record
        .get("finding_ref")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let fw = record
        .get("framework")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let subj = record
        .get("subject_pid")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let row_opacity = if dimmed {
        "opacity-[0.88]"
    } else {
        ""
    };

    view! {
        <div class=format!("notification-item {}", row_opacity)>
            <div class=format!("w-1 shrink-0 self-stretch min-h-[3rem] {}", rail)></div>
            <div class="flex flex-1 gap-2.5 p-3 pl-2 min-w-0">
                <div class=format!("{} shrink-0", ic)>
                    <span inner_html=icon />
                </div>
                <div class="flex-1 min-w-0 space-y-1.5">
                    <div class="flex flex-wrap items-center gap-1">
                        <span class=sev_cls>{sev.clone()}</span>
                        <span class=st_cls>{st.clone()}</span>
                        <span class="rounded border border-zinc-600/45 bg-zinc-900/60 px-1.5 py-0.5 text-[9px] font-mono text-zinc-400 uppercase tracking-tight">
                            {nt_label}
                        </span>
                        {webhook.then(|| view! {
                            <span class="rounded border border-emerald-600/25 bg-emerald-950/20 px-1.5 py-0.5 text-[9px] font-mono text-emerald-300/90">"webhook"</span>
                        })}
                        {(attempts > 0).then(|| view! {
                            <span class="rounded border border-zinc-600/40 bg-black/30 px-1.5 py-0.5 text-[9px] font-mono text-zinc-500">
                                "attempts " {attempts}
                            </span>
                        })}
                        {(esc > 0).then(|| view! {
                            <span class="rounded border border-orange-600/25 bg-orange-950/15 px-1.5 py-0.5 text-[9px] font-mono text-orange-200/80">
                                "esc " {esc}
                            </span>
                        })}
                    </div>
                    <p class="text-sm font-medium text-zinc-100 leading-snug break-words">{title}</p>
                    <p class="text-[11px] text-zinc-400 leading-relaxed line-clamp-3 whitespace-pre-wrap">{desc}</p>
                    <div class="flex flex-wrap gap-x-3 gap-y-0.5 text-[9px] text-zinc-500 font-mono">
                        {finding.clone().map(|f| view! { <span>"finding " <span class="text-zinc-400">{f}</span></span> })}
                        {fw.clone().map(|x| view! { <span>"fw " <span class="text-zinc-400">{x}</span></span> })}
                        {subj.clone().map(|p| view! { <span>"pid " <span class="text-zinc-400">{p}</span></span> })}
                        {next_es.clone().map(|n| view! { <span>"next " <span class="text-amber-500/80">{n}</span></span> })}
                    </div>
                    <div class="flex flex-wrap items-baseline justify-between gap-2 pt-0.5">
                        <span class="text-[10px] text-zinc-400">{time_rel}</span>
                        {(!time_abs.is_empty()).then(|| view! {
                            <span class="text-[9px] text-zinc-600 truncate max-w-[14rem]" title=time_abs_title.clone()>{time_abs}</span>
                        })}
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn Sidebar(
    collapsed: ReadSignal<bool>,
    set_collapsed: WriteSignal<bool>,
    auth: ReadSignal<AuthState>,
    set_auth: WriteSignal<AuthState>,
) -> impl IntoView {
    let location = use_location();
    let pathname = location.pathname;

    // Phase 7.3 — mobile drawer state. On `md:` and below the
    // sidebar is positioned `fixed` and slides off-canvas; on `md:`
    // and above it sits inline with the layout as before.
    let (drawer_open, set_drawer_open) = crate::ui_state::use_mobile_drawer();

    // Auto-close the mobile drawer whenever the route changes so a
    // click on a sidebar item also dismisses the overlay.
    Effect::new(move |last_path: Option<String>| {
        let current = pathname.get();
        if let Some(prev) = last_path.as_ref() {
            if prev != &current {
                set_drawer_open.set(false);
            }
        }
        current
    });

    view! {
        <aside
            aria-label="Primary navigation"
            class=move || {
                let base = "flex flex-col border-r border-zinc-800/60 bg-zinc-950/95 backdrop-blur-xl transition-all duration-300 shrink-0";
                // Width.
                let width = if collapsed.get() { "w-16" } else { "w-60" };
                // Off-canvas at ≤ md. On md+ we revert to the in-flow
                // layout (`md:static md:translate-x-0`).
                let drawer = if drawer_open.get() {
                    "fixed inset-y-0 left-0 z-30 translate-x-0 md:static md:translate-x-0"
                } else {
                    "fixed inset-y-0 left-0 z-30 -translate-x-full md:static md:translate-x-0"
                };
                format!("{base} {width} {drawer}")
            }
        >
            // Logo header
            <div class="flex h-14 items-center gap-2 border-b border-zinc-800/60 px-3 shrink-0 bg-zinc-900/30">
                <a href="/" class="flex min-w-0 items-center" aria-label="cnktros home">
                    <Show
                        when=move || !collapsed.get()
                        fallback=move || view! {
                            <img src="/favicon.png" alt="cnktros" class="h-8 w-8 object-contain" />
                        }
                    >
                        <img src="/logo.png" alt="cnktros" class="h-8 w-auto max-w-[8.5rem]" />
                    </Show>
                </a>
                <button
                    on:click=move |_| set_collapsed.update(|v| *v = !*v)
                    class="ml-auto text-zinc-500 hover:text-zinc-300 transition-colors p-1.5 rounded-lg hover:bg-zinc-800/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50"
                    aria-label=move || if collapsed.get() { "Expand sidebar".to_string() } else { "Collapse sidebar".to_string() }
                    aria-expanded=move || (!collapsed.get()).to_string()
                    aria-controls="primary-sidebar-nav"
                >
                    {move || if collapsed.get() { "»" } else { "«" }}
                </button>
            </div>

            // Navigation sections — 4-section IA + collapsible "More"
            // (Phase 2.2). The Apps section also renders the
            // PluginsNavSection (Phase 2.3 wires it to the catalog).
            // Sections are filtered against the runtime DeploymentMode
            // (Phase 2.4) so Playground hides admin surfaces.
            <nav id="primary-sidebar-nav" aria-label="Primary" class="flex-1 overflow-y-auto py-3 px-2">
                // Phase 7.8 — operator personalisation (Pinned + Recent)
                // sits above the static IA so frequently-used pages
                // surface first. Hidden when both lists are empty so
                // the sidebar looks clean on first login.
                <crate::components::sidebar_personal::SidebarPersonalSection collapsed=collapsed />
                {
                    let mode_memo = use_deployment_mode();
                    move || {
                        let mode = mode_memo.get();
                        let pathname = pathname.clone();
                        nav_sections(mode).into_iter().map(|section| {
                            let pathname = pathname.clone();
                            if section.collapsible {
                                render_collapsible_section(section, collapsed, pathname).into_any()
                            } else {
                                render_section(section, collapsed, pathname).into_any()
                            }
                        }).collect::<Vec<_>>()
                    }
                }
                <PluginsNavSection collapsed=collapsed pathname=pathname.clone() auth=auth />
            </nav>

            // User footer
            <div class="border-t border-zinc-800/60 p-3 shrink-0 bg-zinc-900/30">
                <Show when=move || auth.get().user.is_some() && !collapsed.get()>
                    {move || auth.get().user.map(|u| view! {
                        <div class="mb-2 px-1">
                            <p class="text-xs text-zinc-300 truncate font-medium">{u.name.clone()}</p>
                            <p class="text-[10px] text-zinc-500 truncate">{u.email}</p>
                        </div>
                    })}
                </Show>
                // Edition pill (Phase 2.4) — communicates the active
                // distribution + version. Hidden in the collapsed
                // sidebar to keep the icon strip clean. Phase 7.5
                // tacks on a tier-aware Upgrade pill alongside it
                // when the operator is below the top tier.
                <Show when=move || !collapsed.get()>
                    <EditionPill />
                    <SidebarUpgradeRow />
                </Show>
                <button
                    on:click=move |_| logout(set_auth)
                    class=move || {
                        let base = "flex items-center gap-2 w-full rounded-lg text-xs text-zinc-500 hover:text-red-400 hover:bg-red-500/10 transition-all";
                        if collapsed.get() { format!("{base} justify-center p-2") } else { format!("{base} px-3 py-2") }
                    }
                >
                    <span class="text-sm">"⏻"</span>
                    <Show when=move || !collapsed.get()>
                        <span>"Sign out"</span>
                    </Show>
                </button>
            </div>
        </aside>
    }
}

/// Render a normal (always-expanded) nav section. Phase 2.2.
fn render_section(
    section: NavSection,
    collapsed: ReadSignal<bool>,
    pathname: Memo<String>,
) -> impl IntoView {
    let title = section.title;
    view! {
        <div class="mb-4">
            <Show when=move || !collapsed.get()>
                <p class="px-3 mb-2 text-[10px] font-semibold text-zinc-600 uppercase tracking-wider">
                    {title}
                </p>
            </Show>
            <div class="space-y-1">
                {section.items.into_iter().map(|item| {
                    view! {
                        <SidebarItem
                            path=item.path
                            label=item.label
                            icon_key=item.icon_key
                            exact=item.exact
                            collapsed=collapsed
                            pathname=pathname.clone()
                        />
                    }
                }).collect::<Vec<_>>()}
            </div>
        </div>
    }
}

/// Render a collapsible nav section (the long-tail "More…" group).
/// State is persisted to `localStorage["sidebar:<title>:expanded"]` so
/// the operator's preference survives page reloads.
fn render_collapsible_section(
    section: NavSection,
    collapsed: ReadSignal<bool>,
    pathname: Memo<String>,
) -> impl IntoView {
    let title = section.title;
    let storage_key = format!("sidebar:{}:expanded", title.to_ascii_lowercase());
    let initial: bool = LocalStorage::get(&storage_key).unwrap_or(false);
    let (expanded, set_expanded) = signal(initial);


    // Highlight the disclosure if any nested route matches — gives a
    // visual cue that the active page lives inside the collapsed group.
    // Wrapped in a Memo so the resulting derived signal is `Copy`-able
    // and can be invoked from any number of child closures.
    let items_for_active = section.items.clone();
    let has_active = Memo::new(move |_| {
        let cur = pathname.get();
        items_for_active.iter().any(|item| {
            if item.path == "/" {
                cur == "/"
            } else if item.exact {
                cur == item.path
            } else {
                cur.starts_with(item.path)
                    && (cur.len() == item.path.len()
                        || cur.as_bytes().get(item.path.len()) == Some(&b'/'))
            }
        })
    });

    view! {
        <div class="mb-4">
            <Show when=move || !collapsed.get()>
                <button
                    type="button"
                    class="px-3 mb-2 w-full flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider transition-colors hover:text-zinc-300"
                    style=move || {
                        if has_active.get() {
                            "color: rgb(165 180 252)".to_string()
                        } else {
                            "color: rgb(82 82 91)".to_string()
                        }
                    }
                    aria-expanded=move || if expanded.get() { "true" } else { "false" }
                    on:click={
                        let storage_key = storage_key.clone();
                        move |_| {
                            let next = !expanded.get_untracked();
                            set_expanded.set(next);
                            let _ = LocalStorage::set(&storage_key, next);
                        }
                    }
                >
                    <span>{title}</span>
                    <span
                        class="transition-transform duration-200"
                        style=move || {
                            if expanded.get() {
                                "transform: rotate(90deg)".to_string()
                            } else {
                                "transform: rotate(0deg)".to_string()
                            }
                        }
                    >
                        "▸"
                    </span>
                </button>
            </Show>
            <Show when=move || expanded.get() || collapsed.get()>
                <div class="space-y-1">
                    {section.items.iter().cloned().map(|item| {
                        view! {
                            <SidebarItem
                                path=item.path
                                label=item.label
                                icon_key=item.icon_key
                                exact=item.exact
                                collapsed=collapsed
                                pathname=pathname.clone()
                            />
                        }
                    }).collect::<Vec<_>>()}
                </div>
            </Show>
        </div>
    }
}

/// Sidebar footer pill — distribution + edition + version.
///
/// Examples (Phase 2.4):
///
/// - **Self-hosted Community**: `Community · v0.5.2`
/// - **Self-hosted Enterprise**: `Enterprise · v0.5.2`
/// - **Playground**: `Try Me · 47m left` (countdown driven by
///   `DeploymentInfo.session_expires_at`; Phase 4.6 will own the
///   real-time tick).
/// - **Unknown** (boot fetch in flight): `Detecting…` (neutral)
/// Phase 7.5 — tier-aware "Upgrade" CTA shown beneath the edition
/// pill in the sidebar footer. Hidden when the operator is already on
/// the top tier (Enterprise) or when the deployment fetch hasn't
/// landed yet (`Tier::Unknown`).
#[component]
fn SidebarUpgradeRow() -> impl IntoView {
    use crate::entitlements::{use_entitlements, Tier};
    let ent = use_entitlements();

    let label = move || match ent.get() {
        Tier::Trial => "Install on your own node",
        Tier::Community => "Upgrade · Team",
        Tier::Team => "Upgrade · Enterprise",
        Tier::Enterprise | Tier::Unknown => "",
    };
    let href = move || ent.get().upgrade_path().to_string();
    let aria = move || match ent.get() {
        Tier::Trial => "Switch from the hosted trial to a self-deploy node",
        Tier::Community => "Upgrade to the Team tier",
        Tier::Team => "Upgrade to the Enterprise tier",
        Tier::Enterprise | Tier::Unknown => "",
    };

    view! {
        <Show when=move || ent.get().can_upgrade()>
            <a
                href=href
                aria-label=aria
                class="mt-1 mb-2 flex items-center justify-center gap-1.5 rounded-md border border-brand/40 bg-brand-10 px-2 py-1 text-[10px] font-semibold text-brand hover:bg-brand-20 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 no-underline"
            >
                <span aria-hidden="true">"↑"</span>
                <span>{label}</span>
            </a>
        </Show>
    }
}

#[component]
fn EditionPill() -> impl IntoView {
    let info = use_deployment();
    let mode = use_deployment_mode();

    let pill_class = move || {
        let base = "block w-full text-center text-[10px] font-medium uppercase tracking-wider rounded-md px-2 py-1 mb-2 border";
        match mode.get() {
            DeploymentMode::Playground => format!(
                "{base} border-amber-500/40 bg-amber-500/10 text-amber-200"
            ),
            DeploymentMode::SelfHosted => format!(
                "{base} border-zinc-700/60 bg-zinc-900/40 text-zinc-400"
            ),
            DeploymentMode::Unknown => format!(
                "{base} border-zinc-800/40 bg-zinc-900/20 text-zinc-500"
            ),
        }
    };

    let pill_text = move || {
        let v = info.get();
        let version = if v.version.is_empty() { String::new() } else { format!("v{}", v.version) };
        match mode.get() {
            DeploymentMode::Playground => {
                let countdown = playground_session_countdown(v.session_expires_at);
                match countdown {
                    Some(label) => format!("Try Me · {label}"),
                    None => "Try Me".to_string(),
                }
            }
            DeploymentMode::SelfHosted => {
                let edition = if v.edition.is_empty() {
                    "Community".to_string()
                } else {
                    let mut s = v.edition.clone();
                    if let Some(c) = s.get_mut(0..1) {
                        c.make_ascii_uppercase();
                    }
                    s
                };
                if version.is_empty() { edition } else { format!("{edition} · {version}") }
            }
            DeploymentMode::Unknown => "Detecting…".to_string(),
        }
    };

    view! {
        <div
            class=pill_class
            title=move || {
                let v = info.get();
                format!(
                    "Edition: {} · Mode: {:?} · Version: {} · Public URL: {}",
                    v.edition, v.mode, v.version, v.public_url,
                )
            }
        >
            {pill_text}
        </div>
    }
}

/// "47m left" / "1h 23m left" / "expired" — coarse human countdown.
/// Returns `None` when no expiry is known. Recomputed on every render
/// (per signal tick); precise enough for sidebar UX.
fn playground_session_countdown(expires_at: Option<i64>) -> Option<String> {
    let expires_at = expires_at?;
    let now = (js_sys::Date::now() / 1000.0) as i64;
    let remaining = expires_at - now;
    if remaining <= 0 {
        return Some("expired".into());
    }
    let minutes = remaining / 60;
    if minutes < 60 {
        Some(format!("{minutes}m left"))
    } else {
        let hours = minutes / 60;
        let mins = minutes % 60;
        Some(format!("{hours}h {mins}m left"))
    }
}

#[component]
fn SidebarItem(
    path: &'static str,
    label: &'static str,
    icon_key: &'static str,
    exact: bool,
    collapsed: ReadSignal<bool>,
    pathname: Memo<String>,
) -> impl IntoView {
    let is_active = move || {
        let cur = pathname.get();
        if path == "/" {
            return cur == "/";
        }
        if exact {
            return cur == path;
        }
        cur.starts_with(path)
            && (cur.len() == path.len() || cur.as_bytes().get(path.len()) == Some(&b'/'))
    };
    let icon_svg = icons::get_icon(icon_key);

    view! {
        <A href=path
            attr:class=move || {
                let base = "nav-item group flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all duration-200";
                let state = if is_active() { 
                    "nav-item-active bg-gradient-to-r from-indigo-500/20 to-purple-500/10 text-white font-medium border border-indigo-500/30 shadow-lg shadow-indigo-500/10" 
                } else { 
                    "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-100 border border-transparent hover:border-zinc-700/50 hover:shadow-md" 
                };
                let col = if collapsed.get() { "justify-center px-2.5" } else { "" };
                format!("{base} {state} {col}")
            }
            attr:aria-current=move || if is_active() { "page" } else { "" }
            on:mouseenter=move |_| {
                #[cfg(feature = "full-pages")]
                crate::routing::lazy_preload::preload_on_hover(path);
            }
        >
            <span 
                class=move || {
                    let base = "shrink-0 w-5 h-5 flex items-center justify-center transition-transform duration-200 group-hover:scale-110";
                    if is_active() { format!("{base} text-indigo-400") } else { format!("{base} text-zinc-500 group-hover:text-zinc-300") }
                }
                inner_html=icon_svg
            />
            <Show when=move || !collapsed.get()>
                <span class="truncate text-[13px] font-medium">{label}</span>
            </Show>
        </A>
    }
}

#[component]
pub fn Header(#[prop(into)] title: String, auth: ReadSignal<AuthState>) -> impl IntoView {
    // Phase 7 / P2-12 — every Header call site already passes a
    // human-readable title. Setting `document.title` here means every
    // page automatically picks up "{title} · Connector" without
    // each page authoring an explicit `use_page_title` call.
    crate::components::page_title::use_page_title(title.clone());

    let (show_profile, set_show_profile) = signal(false);
    // Phase 2.7 — global ⌘K palette state lives in App context now, so
    // any page or hotkey can open it. The search button just delegates
    // to the same WriteSignal.
    let search_overlay = crate::ui_state::use_search_overlay();
    let show_search = search_overlay.open;
    let set_show_search = search_overlay.set_open;
    let (show_notifications, set_show_notifications) = signal(false);
    // Sign-Out wiring: pull the auth WriteSignal from context (provided in
    // `main::App`). When `logout` clears the signal, `main::App`'s `<Show
    // fallback=Redirect>` automatically routes back to `/login`.
    let set_auth_ctx = expect_context::<WriteSignal<AuthState>>();
    let shared = crate::request_store::use_shared_requests();
    let health = shared.health;
    let notif_preview = shared.notifications;

    // Phase 7.3 — hamburger button toggles the off-canvas sidebar on
    // small screens. Hidden on md+ where the sidebar is always in flow.
    let (_drawer_open, set_drawer_open) = crate::ui_state::use_mobile_drawer();

    view! {
        <header role="banner" class="header-bar flex h-14 items-center justify-between border-b border-zinc-800/40 px-3 sm:px-6 shrink-0 bg-zinc-950/90 backdrop-blur-xl sticky top-0 z-20">
            <div class="flex items-center gap-3 sm:gap-4">
                <button
                    type="button"
                    on:click=move |_| set_drawer_open.update(|v| *v = !*v)
                    class="md:hidden header-icon-btn"
                    aria-label="Open navigation"
                >
                    <span aria-hidden="true" inner_html=icons::ICON_MENU />
                </button>
                <h1 class="text-base sm:text-lg font-semibold text-zinc-100 tracking-tight">{title}</h1>
                // Phase 7.8 — Star toggle for the current path so
                // operators can pin the page they're on to the sidebar.
                // The button hides itself if the path isn't in the
                // route registry.
                {
                    let location = use_location();
                    let star_path = location.pathname.get_untracked();
                    view! {
                        <span class="hidden sm:inline-flex">
                            <crate::components::sidebar_personal::StarPinButton path=star_path />
                        </span>
                    }
                }
                {
                    // Phase 5.1 — Playground bundles swap the live-dot
                    // pill for a session countdown. Self-deploy keeps
                    // the kernel-health pill (which links to /monitor).
                    // Phase 5.7 — Playground also surfaces a compact
                    // capacity badge next to the countdown when any
                    // meter is ≥ 80 %.
                    let header_mode = use_deployment_mode();
                    move || if header_mode.get() == DeploymentMode::Playground {
                        view! {
                            <span class="hidden sm:inline-flex">
                                <CountdownPill />
                            </span>
                            <span class="hidden md:inline-flex">
                                <CapacityMetersCompact />
                            </span>
                        }.into_any()
                    } else {
                        view! {
                            <Suspense fallback=|| view! {
                                <LiveDotPill
                                    state=LiveState::Checking
                                    message="Fetching /monitor/health…"
                                    last_updated=""
                                    provenance="monitor/health"
                                />
                            }>
                                {move || Suspend::new(async move {
                                    let r = health.await;
                                    let v = r.as_ref().ok().cloned().unwrap_or_default();
                                    let state = live_state_from_monitor_status(
                                        v.get("status").and_then(|x| x.as_str()),
                                    );
                                    let message = v["summary"]
                                        .as_str()
                                        .or_else(|| {
                                            v.get("recommendations")
                                                .and_then(|a| a.as_array())
                                                .and_then(|a| a.first())
                                                .and_then(|x| x.as_str())
                                        })
                                        .unwrap_or("Live monitor feed")
                                        .to_string();
                                    let provenance = v["source"]
                                        .as_str()
                                        .unwrap_or("monitor/health")
                                        .to_string();
                                    let updated = v["timestamp"]
                                        .as_str()
                                        .or_else(|| v["checked_at"].as_str())
                                        .or_else(|| v.get("uptime").and_then(|x| x.as_str()))
                                        .map(|s| time_ago_str(s))
                                        .unwrap_or_default();
                                    view! {
                                        <LiveDotPill
                                            state=state
                                            message=message
                                            last_updated=updated
                                            provenance=provenance
                                        />
                                    }
                                })}
                            </Suspense>
                        }.into_any()
                    }
                }
            </div>

            <div class="flex items-center gap-3">
                // Search button
                <button
                    on:click=move |_| set_show_search.update(|v| *v = !*v)
                    class="header-icon-btn"
                    title="Search"
                    aria-label="Open search palette"
                    aria-keyshortcuts="Control+K"
                >
                    <span aria-hidden="true" inner_html=icons::ICON_SEARCH />
                </button>

                // Notifications
                <div class="relative">
                    <button
                        class="header-icon-btn relative"
                        title="Notifications (live from API when permitted)"
                        aria-label="Open notifications"
                        aria-haspopup="dialog"
                        aria-expanded=move || show_notifications.get().to_string()
                        on:click=move |_| set_show_notifications.update(|v| *v = !*v)
                    >
                        <span aria-hidden="true" inner_html=icons::ICON_NOTIFICATIONS />
                    </button>

                    // Notifications popup — data from GET /api/v1/notifications (operator+), not placeholder copy.
                    <Show when=move || show_notifications.get()>
                        <div class="notifications-popup absolute right-0 top-full mt-2 w-[min(100vw-2rem,28rem)] max-h-[min(100vh-6rem,36rem)] rounded-2xl border border-zinc-800/60 bg-zinc-900/98 backdrop-blur-xl shadow-2xl shadow-black/50 overflow-hidden z-50">
                            <div class="flex items-center justify-between p-4 border-b border-zinc-800/60 bg-zinc-900/50">
                                <div class="flex items-center gap-3">
                                    <div class="w-8 h-8 rounded-lg bg-indigo-500/20 flex items-center justify-center">
                                        <span class="text-indigo-400" inner_html=icons::ICON_NOTIFICATIONS />
                                    </div>
                                    <div title="Source: GET /api/v1/notifications">
                                        <h3 class="text-sm font-semibold text-zinc-100">"Notifications"</h3>
                                        <p class="text-[10px] text-zinc-500">"Live preview"</p>
                                    </div>
                                </div>
                                <span class="text-[10px] text-zinc-600 text-right max-w-[11rem] leading-tight">"Acknowledge / snooze on the full Notifications page"</span>
                            </div>

                            <Suspense fallback=|| view! {
                                <div class="p-6 text-center text-xs text-zinc-500">"Loading notifications…"</div>
                            }>
                                {move || Suspend::new(async move {
                                    let r = notif_preview.await;
                                    match r {
                                        Err(e) => {
                                            let msg = e.message.clone();
                                            let hint = if e.status == 403 {
                                                "Operator role or higher is required for this API."
                                            } else {
                                                "Sign in and ensure the platform API is reachable."
                                            };
                                            view! {
                                                <div class="p-4 space-y-2">
                                                    <p class="text-xs text-rose-300/90 font-medium">"Could not load notification preview"</p>
                                                    <p class="text-[11px] text-zinc-500 font-mono break-words">{msg}</p>
                                                    <p class="text-[10px] text-zinc-600">{hint}</p>
                                                    <a href="/notifications" class="block text-center text-xs text-indigo-400 hover:underline pt-2">"Open Notifications page →"</a>
                                                </div>
                                            }.into_any()
                                        }
                                        Ok(body) => {
                                            let list: Vec<Value> = body
                                                .get("notifications")
                                                .and_then(|a| a.as_array())
                                                .cloned()
                                                .unwrap_or_default();
                                            let pending = body.get("pending").and_then(|x| x.as_u64()).unwrap_or(0);
                                            let critical = body.get("critical").and_then(|x| x.as_u64()).unwrap_or(0);
                                            let total = body.get("total").and_then(|x| x.as_u64()).unwrap_or(0);
                                            let (urgent, recent) = partition_header_notifications(list);
                                            if urgent.is_empty() && recent.is_empty() {
                                                return view! {
                                                    <div class="p-6 space-y-2 text-center">
                                                        <p class="text-sm text-zinc-400">"No active notifications"</p>
                                                        <p class="text-[10px] text-zinc-600" title="Trigger a scan via POST /api/v1/notifications/scan or schedule one in the Notifications page.">"Run a scan or schedule one to populate this list."</p>
                                                        <p class="text-[10px] text-zinc-600">"Total " {total} " · Pending " {pending} " · Critical/paged " {critical}</p>
                                                        <a href="/notifications" class="inline-block text-xs text-indigo-400 hover:underline pt-2">"Notifications →"</a>
                                                    </div>
                                                }.into_any();
                                            }
                                            view! {
                                                <div class="border-b border-zinc-800/60">
                                                    <div class="px-4 py-2 bg-red-500/5 flex flex-wrap justify-between items-center gap-x-2 gap-y-1">
                                                        <p class="text-[10px] font-semibold text-red-400 uppercase tracking-wider">"Needs attention"</p>
                                                        <p class="text-[10px] text-zinc-600 font-mono">"Σ " {total}" · pend " {pending}" · crit " {critical}</p>
                                                    </div>
                                                    <div class="divide-y divide-zinc-800/40 max-h-52 overflow-y-auto">
                                                        {if urgent.is_empty() {
                                                            view! { <p class="p-4 text-xs text-zinc-600">"No high-urgency rows in the current list."</p> }.into_any()
                                                        } else {
                                                            urgent
                                                                .into_iter()
                                                                .map(|row| view! { <NotificationPreviewRow record=row dimmed=false /> })
                                                                .collect::<Vec<_>>()
                                                                .into_any()
                                                        }}
                                                    </div>
                                                </div>
                                                <div>
                                                    <div class="px-4 py-2 bg-zinc-800/30">
                                                        <p class="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider">"Other"</p>
                                                    </div>
                                                    <div class="divide-y divide-zinc-800/40 max-h-48 overflow-y-auto">
                                                        {if recent.is_empty() {
                                                            view! { <p class="p-4 text-xs text-zinc-600">"No additional rows in preview window."</p> }.into_any()
                                                        } else {
                                                            recent
                                                                .into_iter()
                                                                .map(|row| view! { <NotificationPreviewRow record=row dimmed=true /> })
                                                                .collect::<Vec<_>>()
                                                                .into_any()
                                                        }}
                                                    </div>
                                                </div>
                                                <div class="p-3 border-t border-zinc-800/60 bg-zinc-900/50">
                                                    <a href="/notifications" class="flex items-center justify-center gap-2 w-full py-2 rounded-lg text-xs font-medium text-indigo-400 hover:bg-indigo-500/10 transition-colors">
                                                        "View all notifications"
                                                        <span inner_html=icons::ICON_CHEVRON_RIGHT />
                                                    </a>
                                                </div>
                                            }.into_any()
                                        }
                                    }
                                })}
                            </Suspense>
                        </div>
                    </Show>
                </div>

                <div class="w-px h-6 bg-zinc-800/60 hidden md:block"></div>

                // Profile dropdown
                {move || {
                    let user = auth.get().user;
                    user.map(|u| {
                        let name = u.name.clone();
                        let name2 = u.name.clone();
                        let email = u.email.clone();
                        let role = u.role.clone();
                        let role2 = u.role.clone();
                        let initial = name.chars().next().unwrap_or('?').to_string();
                        let initial2 = initial.clone();
                        view! {
                            <div class="relative">
                                <button
                                    on:click=move |_| set_show_profile.update(|v| *v = !*v)
                                    class="profile-trigger flex items-center gap-3 px-2 py-1.5 rounded-xl hover:bg-zinc-800/50 transition-all duration-200 border border-transparent hover:border-zinc-700/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50"
                                    aria-label="Open account menu"
                                    aria-haspopup="menu"
                                    aria-expanded=move || show_profile.get().to_string()
                                >
                                    <div class="hidden sm:flex flex-col items-end">
                                        <span class="text-sm text-zinc-200 font-medium">{name.clone()}</span>
                                        <span class="text-[10px] text-zinc-500 uppercase tracking-wider">{role.clone()}</span>
                                    </div>
                                    <div class="profile-avatar flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white text-sm font-bold shadow-lg shadow-indigo-500/20 ring-2 ring-indigo-500/20">
                                        {initial.clone()}
                                    </div>
                                    <span class="hidden sm:block text-zinc-500" inner_html=icons::ICON_CHEVRON_DOWN />
                                </button>

                                // Dropdown menu
                                <Show when=move || show_profile.get()>
                                    <div class="profile-dropdown absolute right-0 top-full mt-2 w-72 rounded-2xl border border-zinc-800/60 bg-zinc-900/95 backdrop-blur-xl shadow-2xl shadow-black/50 overflow-hidden z-50">
                                        // Profile header
                                        <div class="p-4 border-b border-zinc-800/60 bg-gradient-to-br from-indigo-500/10 to-purple-500/5">
                                            <div class="flex items-center gap-3">
                                                <div class="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white text-lg font-bold shadow-lg">
                                                    {initial2.clone()}
                                                </div>
                                                <div class="flex-1 min-w-0">
                                                    <p class="text-sm font-semibold text-zinc-100 truncate">{name2.clone()}</p>
                                                    <p class="text-xs text-zinc-500 truncate">{email.clone()}</p>
                                                    <span class="inline-flex mt-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">{role2.clone()}</span>
                                                </div>
                                            </div>
                                        </div>
                                        // Menu items
                                        <div class="p-2">
                                            <a href="/settings" class="dropdown-item">
                                                <span inner_html=icons::ICON_USER />
                                                <span>"Profile Settings"</span>
                                            </a>
                                            <a href="/billing" class="dropdown-item">
                                                <span inner_html=icons::ICON_BILLING />
                                                <span>"Billing & Usage"</span>
                                            </a>
                                            <a href="/license" class="dropdown-item">
                                                <span inner_html=icons::ICON_LICENSE />
                                                <span>"License"</span>
                                            </a>
                                            <div class="my-2 border-t border-zinc-800/60"></div>
                                            <button
                                                type="button"
                                                class="dropdown-item text-red-400 hover:bg-red-500/10 w-full"
                                                on:click=move |_| {
                                                    set_show_profile.set(false);
                                                    logout(set_auth_ctx);
                                                }
                                            >
                                                <span inner_html=icons::ICON_LOGOUT />
                                                <span>"Sign Out"</span>
                                            </button>
                                        </div>
                                    </div>
                                </Show>
                            </div>
                        }
                    })
                }}
            </div>
        </header>

        // Search modal
        <Show when=move || show_search.get()>
            <SearchModal set_show=set_show_search />
        </Show>
    }
}

#[component]
fn SearchModal(set_show: WriteSignal<bool>) -> impl IntoView {
    let (query, set_query) = signal(String::new());

    // ── Static page rows ──────────────────────────────────────────
    // Pages come from the central route registry, mode-filtered so
    // Playground searches don't surface `/billing` etc. Live agents
    // and plugins are layered on top via dedicated resources below.
    let mode = use_deployment_mode();
    let pages_for_mode = move || -> Vec<(String, String, String, String)> {
        crate::routes::search_items_for_mode(mode.get())
            .into_iter()
            .map(|(t, l, d, p)| (t.to_string(), l.to_string(), d.to_string(), p.to_string()))
            .collect()
    };

    // ── Static "action" rows ──────────────────────────────────────
    // Operator shortcuts — not routes, hand-curated. We keep them
    // alongside pages so ⌘K → "create agent" works without anyone
    // remembering the URL.
    let action_rows: Vec<(String, String, String, String)> = vec![
        ("action", "Create Agent", "Register a new AI agent", "/agents"),
        ("action", "Pause Agent", "Pause an active agent", "/agents"),
        ("action", "Resume Agent", "Resume a paused agent", "/agents"),
        ("action", "View Metrics", "Open monitoring dashboard", "/monitor"),
        ("action", "Run Experiment", "Start a new experiment", "/experiments"),
        ("action", "Generate Report", "Create compliance report", "/compliance"),
        ("action", "Add Webhook", "Register a new webhook", "/webhooks"),
        ("action", "Deploy Agent", "Deploy agent to production", "/agents"),
    ]
    .into_iter()
    .map(|(a, b, c, d)| (a.to_string(), b.to_string(), c.to_string(), d.to_string()))
    .collect();

    // Saleable catalog: TraceTramp / WitnessCtl / DevGuard only unless developer view.
    let (developer_view, _) = crate::ui_state::use_developer_view();
    let plugin_rows = move || -> Vec<(String, String, String, String)> {
        crate::catalog::plugins()
            .iter()
            .filter(|p| {
                developer_view.get()
                    || matches!(
                        p.slug.as_str(),
                        "tracetramp" | "witnessctl" | "devguard"
                    )
            })
            .map(|p| {
                (
                    "plugin".to_string(),
                    p.name.clone(),
                    p.short_desc.clone(),
                    crate::catalog::plugin_path(&p.slug),
                )
            })
            .collect()
    };

    // ── Reference workflow rows ───────────────────────────────────
    let workflow_rows: Vec<(String, String, String, String)> = crate::catalog::reference_workflows()
        .iter()
        .map(|w| {
            (
                "workflow".to_string(),
                w.name.clone(),
                w.short_desc.clone(),
                "/workflows".to_string(),
            )
        })
        .collect();

    // Live agent rows — shared cache from request_store (no duplicate fetch).
    let shared = crate::request_store::use_shared_requests();
    let agents = shared.agents;

    let filtered_items = move || -> Vec<(String, String, String, String)> {
        let q = query.get().to_lowercase();
        let agent_rows: Vec<(String, String, String, String)> = match agents
            .get()
            .as_ref()
            .and_then(|v| v.as_ref().ok())
        {
            Some(v) => api::resource_array(v, "agents")
                .into_iter()
                .filter_map(|entry| {
                    let name = entry
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("agent")
                        .to_string();
                    let pid = entry
                        .get("pid")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    if name.is_empty() {
                        return None;
                    }
                    let desc = if pid.is_empty() {
                        "Live agent".to_string()
                    } else {
                        format!("Live agent · {pid}")
                    };
                    Some((
                        "agent".to_string(),
                        name,
                        desc,
                        "/agents".to_string(),
                    ))
                })
                .collect(),
            None => Vec::new(),
        };

        let mut all: Vec<(String, String, String, String)> = pages_for_mode();
        all.extend(plugin_rows());
        all.extend(workflow_rows.iter().cloned());
        all.extend(agent_rows);
        all.extend(action_rows.iter().cloned());

        if q.is_empty() {
            all.into_iter().take(8).collect()
        } else {
            all.into_iter()
                .filter(|(_, name, desc, _)| {
                    name.to_lowercase().contains(&q) || desc.to_lowercase().contains(&q)
                })
                .take(20)
                .collect()
        }
    };

    view! {
        <div
            class="search-overlay fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center pt-20"
            on:click=move |_| set_show.set(false)
            role="presentation"
        >
            <div
                class="search-modal w-full max-w-2xl mx-4 rounded-2xl border border-zinc-800/60 bg-zinc-900/98 backdrop-blur-xl shadow-2xl overflow-hidden"
                on:click=move |e| e.stop_propagation()
                role="dialog"
                aria-modal="true"
                aria-label="Search palette"
            >
                // Search input
                <div class="flex items-center gap-3 p-4 border-b border-zinc-800/60">
                    <span aria-hidden="true" class="text-zinc-500" inner_html=icons::ICON_SEARCH />
                    <input
                        type="text"
                        placeholder="Search pages, actions, agents..."
                        aria-label="Search pages, actions, agents"
                        class="flex-1 bg-transparent text-zinc-100 placeholder-zinc-500 outline-none text-base"
                        prop:value=move || query.get()
                        on:input=move |e| set_query.set(event_target_value(&e))
                        on:keydown=move |e| {
                            if e.key() == "Escape" {
                                set_show.set(false);
                            }
                        }
                        autofocus
                    />
                    <kbd class="px-2 py-1 rounded-lg bg-zinc-800 text-zinc-500 text-xs font-mono">"ESC"</kbd>
                </div>
                
                // Results
                <div class="max-h-96 overflow-y-auto p-2">
                    {move || {
                        let items = filtered_items();
                        if items.is_empty() {
                            view! {
                                <div class="p-8 text-center">
                                    <p class="text-zinc-500 text-sm">"No results found"</p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="space-y-1">
                                    {items.into_iter().map(|(item_type, name, desc, path)| {
                                        let icon = match item_type.as_str() {
                                            "action"   => icons::ICON_ZAPP,
                                            "plugin"   => icons::get_icon("tools"),
                                            "agent"    => icons::get_icon("agents"),
                                            "workflow" => icons::get_icon("orchestrator"),
                                            _          => icons::get_icon(&name.to_lowercase().replace(' ', "")),
                                        };
                                        let badge_class = match item_type.as_str() {
                                            "action"   => "px-1.5 py-0.5 rounded text-[10px] font-medium border bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
                                            "plugin"   => "px-1.5 py-0.5 rounded text-[10px] font-medium border bg-violet-500/20 text-violet-300 border-violet-500/30",
                                            "agent"    => "px-1.5 py-0.5 rounded text-[10px] font-medium border bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
                                            "workflow" => "px-1.5 py-0.5 rounded text-[10px] font-medium border bg-sky-500/20 text-sky-300 border-sky-500/30",
                                            _          => "px-1.5 py-0.5 rounded text-[10px] font-medium border bg-zinc-700/50 text-zinc-400 border-zinc-600/30",
                                        };
                                        let badge_text = match item_type.as_str() {
                                            "action"   => "Action",
                                            "plugin"   => "Plugin",
                                            "agent"    => "Agent",
                                            "workflow" => "Workflow",
                                            _          => "Page",
                                        };
                                        view! {
                                            <a
                                                href=path
                                                class="flex items-center gap-3 p-3 rounded-xl hover:bg-zinc-800/50 transition-all group"
                                                on:click=move |_| set_show.set(false)
                                            >
                                                <div class="w-10 h-10 rounded-xl bg-zinc-800/80 flex items-center justify-center text-zinc-400 group-hover:text-zinc-200 group-hover:bg-zinc-700/80 transition-colors">
                                                    <span inner_html=icon />
                                                </div>
                                                <div class="flex-1 min-w-0">
                                                    <div class="flex items-center gap-2">
                                                        <p class="text-sm font-medium text-zinc-200 group-hover:text-white truncate">{name}</p>
                                                        <span class=badge_class>{badge_text}</span>
                                                    </div>
                                                    <p class="text-xs text-zinc-500 truncate mt-0.5">{desc}</p>
                                                </div>
                                                <span class="text-zinc-600 group-hover:text-zinc-400 transition-colors" inner_html=icons::ICON_CHEVRON_RIGHT />
                                            </a>
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                            }.into_any()
                        }
                    }}
                </div>
                
                // Footer with keyboard hints
                <div class="flex items-center justify-between p-3 border-t border-zinc-800/60 bg-zinc-900/50 text-xs text-zinc-600">
                    <div class="flex items-center gap-4">
                        <span class="flex items-center gap-1.5">
                            <kbd class="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-500 font-mono">"↑↓"</kbd>
                            "Navigate"
                        </span>
                        <span class="flex items-center gap-1.5">
                            <kbd class="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-500 font-mono">"↵"</kbd>
                            "Select"
                        </span>
                    </div>
                    <span class="flex items-center gap-1.5">
                        <kbd class="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-500 font-mono">"⌘K"</kbd>
                        "to open anytime"
                    </span>
                </div>
            </div>
        </div>
    }
}
