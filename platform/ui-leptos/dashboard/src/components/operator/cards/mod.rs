use leptos::prelude::*;

use super::primitives::{
    OpButton, OpButtonVariant, OpDecisionPill, OpInstitutionChip, OpProgress, OpSignal,
    OpStatePill, OpText, OpTextVariant, OpTimeAgo, OpTruncMono,
};
use super::primitives::controls::OpClick;

fn noop_click() -> OpClick {
    std::sync::Arc::new(|_| ())
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum OpCardAccent {
    #[default]
    Idle,
    Running,
    Attention,
    Denied,
}

impl OpCardAccent {
    fn rail_class(self) -> &'static str {
        match self {
            Self::Running => "bg-emerald-500 op-glow-running",
            Self::Attention => "bg-amber-500 op-glow-attention",
            Self::Denied => "bg-red-500",
            Self::Idle => "bg-zinc-600",
        }
    }
}

#[component]
pub fn OpCard(
    title: String,
    #[prop(optional, into, default = String::new())] subtitle: String,
    accent: OpCardAccent,
    #[prop(optional, into, default = String::new())] primary_label: String,
    #[prop(optional)] on_primary: Option<OpClick>,
    #[prop(optional)] on_click: Option<OpClick>,
    #[prop(optional, into, default = String::new())] secondary_label: String,
    #[prop(optional)] on_secondary: Option<OpClick>,
    #[prop(optional, into, default = String::new())] tertiary_label: String,
    #[prop(optional)] on_tertiary: Option<OpClick>,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    let clickable = on_click.is_some();
    let card_click = on_click.unwrap_or_else(noop_click);
    let primary_click = on_primary.unwrap_or_else(noop_click);
    let secondary_click = on_secondary.unwrap_or_else(noop_click);
    let tertiary_click = on_tertiary.unwrap_or_else(noop_click);
    let has_primary = !primary_label.is_empty();
    let has_secondary = !secondary_label.is_empty();
    let has_tertiary = !tertiary_label.is_empty();
    view! {
        <article
            class=move || {
                let base = "op-card relative flex min-h-[140px] flex-col overflow-visible rounded-xl border border-zinc-800/70 bg-zinc-900/35 backdrop-blur-sm";
                if clickable {
                    format!("{base} cursor-pointer hover:border-zinc-700/80 transition-colors")
                } else {
                    base.to_string()
                }
            }
            on:click=move |ev| card_click(ev)
        >
            <div class=format!("absolute left-0 top-0 bottom-0 w-[3px] {}", accent.rail_class()) aria-hidden="true"></div>
            <div class="flex flex-1 flex-col gap-3 p-4 pl-5">
                <div class="flex items-start justify-between gap-2">
                    <div class="min-w-0">
                        <h3 class="truncate text-sm font-semibold text-zinc-100">{title.clone()}</h3>
                        {(!subtitle.is_empty()).then(|| view! {
                            <p class="mt-0.5 truncate text-xs text-zinc-500">{subtitle.clone()}</p>
                        })}
                    </div>
                </div>
                {children.map(|c| view! {
                    <div class="flex flex-wrap gap-1.5">{c()}</div>
                })}
                <div class="mt-auto flex items-center gap-2 pt-1" on:click=move |ev| ev.stop_propagation()>
                    {has_primary.then(|| {
                        let label = primary_label.clone();
                        let click = primary_click.clone();
                        view! {
                            <OpButton
                                label=label
                                variant=if accent == OpCardAccent::Attention {
                                    OpButtonVariant::Primary
                                } else {
                                    OpButtonVariant::Secondary
                                }
                                on_click=click
                            />
                        }
                    })}
                    {has_tertiary.then(|| {
                        let label = tertiary_label.clone();
                        let click = tertiary_click.clone();
                        view! {
                            <OpButton
                                label=label
                                variant=OpButtonVariant::Ghost
                                on_click=click
                            />
                        }
                    })}
                    {has_secondary.then(|| {
                        let label = secondary_label.clone();
                        let click = secondary_click.clone();
                        view! {
                            <OpButton
                                label=label
                                variant=OpButtonVariant::Danger
                                on_click=click
                            />
                        }
                    })}
                </div>
            </div>
        </article>
    }
}

#[component]
pub fn OpCardFooterActions(
    primary_label: String,
    #[prop(optional)] secondary_label: Option<String>,
    #[prop(optional)] on_primary: Option<OpClick>,
    #[prop(optional)] on_secondary: Option<OpClick>,
) -> impl IntoView {
    let primary = on_primary.unwrap_or_else(noop_click);
    let secondary = on_secondary.unwrap_or_else(noop_click);
    view! {
        <div class="mt-auto flex items-center gap-2 pt-1">
            <OpButton label=primary_label variant=OpButtonVariant::Primary on_click=primary />
            {secondary_label.map(|label| {
                let click = secondary.clone();
                view! {
                    <OpButton label=label variant=OpButtonVariant::Ghost on_click=click />
                }
            })}
        </div>
    }
}

#[component]
pub fn OpDropdownMenu(
    #[prop(optional)] on_dry_run: Option<OpClick>,
    #[prop(optional)] on_pause: Option<OpClick>,
    #[prop(optional)] on_enable: Option<OpClick>,
    #[prop(optional)] on_archive: Option<OpClick>,
    /// Current workflow state — used to label Activate vs Resume.
    #[prop(optional, into)] state: String,
) -> impl IntoView {
    let (open, set_open) = signal(false);
    let dry = on_dry_run.unwrap_or_else(noop_click);
    let pause = on_pause.unwrap_or_else(noop_click);
    let enable = on_enable.unwrap_or_else(noop_click);
    let archive = on_archive.unwrap_or_else(noop_click);
    let st = state.to_ascii_uppercase();
    let enable_label = if st == "PAUSED" {
        "Resume (enable)".to_string()
    } else if st == "DRAFT" || st == "COMPILED" || st == "STAGED" {
        "Activate (compile→stage→enable)".to_string()
    } else {
        "Activate (enable)".to_string()
    };
    let can_pause = st == "ENABLED";
    let can_enable = st != "ENABLED" && st != "ARCHIVED";
    let can_archive = st != "ARCHIVED";
    view! {
        <div class="relative">
            <button
                type="button"
                class="inline-flex h-7 w-7 items-center justify-center rounded-md text-zinc-500 hover:bg-zinc-800 hover:text-zinc-300"
                aria-label="More actions"
                on:click=move |ev| {
                    ev.stop_propagation();
                    set_open.update(|v| *v = !*v);
                }
            >
                "⋮"
            </button>
            <div
                class=move || {
                    if open.get() {
                        "absolute right-0 top-full z-30 mt-1 min-w-[11rem] rounded-lg border border-zinc-800 bg-zinc-900 py-1 shadow-xl"
                    } else {
                        "hidden"
                    }
                }
            >
                <button
                    type="button"
                    class="block w-full px-3 py-1.5 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                    on:click={
                        let dry = dry.clone();
                        move |ev| { ev.stop_propagation(); set_open.set(false); dry(ev); }
                    }
                >"Dry-run"</button>
                <button
                    type="button"
                    class=if can_enable {
                        "block w-full px-3 py-1.5 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                    } else {
                        "block w-full px-3 py-1.5 text-left text-xs text-zinc-600 cursor-not-allowed"
                    }
                    disabled=can_enable == false
                    on:click={
                        let enable = enable.clone();
                        move |ev| {
                            ev.stop_propagation();
                            if can_enable {
                                set_open.set(false);
                                enable(ev);
                            }
                        }
                    }
                >{enable_label}</button>
                <button
                    type="button"
                    class=if can_pause {
                        "block w-full px-3 py-1.5 text-left text-xs text-zinc-300 hover:bg-zinc-800"
                    } else {
                        "block w-full px-3 py-1.5 text-left text-xs text-zinc-600 cursor-not-allowed"
                    }
                    disabled=can_pause == false
                    title="Pause only when workflow is ENABLED"
                    on:click={
                        let pause = pause.clone();
                        move |ev| {
                            ev.stop_propagation();
                            if can_pause {
                                set_open.set(false);
                                pause(ev);
                            }
                        }
                    }
                >"Pause"</button>
                <button
                    type="button"
                    class=if can_archive {
                        "block w-full px-3 py-1.5 text-left text-xs text-red-300 hover:bg-zinc-800"
                    } else {
                        "block w-full px-3 py-1.5 text-left text-xs text-zinc-600 cursor-not-allowed"
                    }
                    disabled=can_archive == false
                    on:click={
                        let archive = archive.clone();
                        move |ev| {
                            ev.stop_propagation();
                            if can_archive {
                                set_open.set(false);
                                archive(ev);
                            }
                        }
                    }
                >"Archive"</button>
                <p class="border-t border-zinc-800/80 px-3 py-1.5 text-[10px] leading-snug text-zinc-600">
                    "Revoke / quarantine are agent & TraceTramp actions — not workflow lifecycle."
                </p>
            </div>
        </div>
    }
}

#[component]
pub fn OpWorkflowCard(
    workflow_id: String,
    title: String,
    subtitle: String,
    state: String,
    accent: OpCardAccent,
    #[prop(optional, into, default = String::new())] accounting_mode: String,
    #[prop(optional)] on_open: Option<OpClick>,
) -> impl IntoView {
    use serde_json::json;
    use wasm_bindgen_futures::spawn_local;
    use crate::api;
    use crate::components::operator::overlays::result_sheet::OpResultSheet;
    use crate::components::operator::workflow_actions::{
        activate_workflow, archive_workflow, pause_workflow,
    };
    use crate::request_store::bump_reload;
    use crate::ui_state::open_workflow_drawer;

    let open = on_open.unwrap_or_else(noop_click);
    let primary = open.clone();
    let wf = workflow_id.clone();
    let wf_dry = workflow_id.clone();
    let wf_pause = workflow_id.clone();
    let wf_enable = workflow_id.clone();
    let wf_archive = workflow_id.clone();
    let state_for_menu = state.clone();
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());

    view! {
        <OpCard
            title=title
            subtitle=subtitle
            accent=accent
            primary_label=if accent == OpCardAccent::Attention {
                "FIX".to_string()
            } else {
                "Open".to_string()
            }
            on_click=open
            on_primary=primary
        >
            <OpStatePill state=state />
            {(!accounting_mode.is_empty()).then(|| {
                let label = if accounting_mode == "service_monitoring" {
                    "service"
                } else {
                    "action"
                };
                let title = if accounting_mode == "service_monitoring" {
                    "Accounting: service_monitoring"
                } else {
                    "Accounting: action"
                };
                view! {
                    <span
                        class="rounded border border-zinc-700/70 bg-zinc-950/50 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-zinc-400"
                        title=title
                    >{label}</span>
                }
            })}
            <OpSignal label="wf".to_string() value=wf />
            <OpDropdownMenu
                state=state_for_menu
                on_dry_run=std::sync::Arc::new(move |_| {
                    let id = wf_dry.clone();
                    spawn_local(async move {
                        match api::post_value(&format!("/workflows/{id}/dry-run"), json!({})).await {
                            Ok(v) => {
                                let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(true);
                                set_result_title.set(id.clone());
                                set_result_summary.set(if ok {
                                    format!(
                                        "Dry-run completed.\nAPI: POST /workflows/{id}/dry-run\n{}",
                                        serde_json::to_string_pretty(&v).unwrap_or_default()
                                    )
                                } else {
                                    format!(
                                        "{}\nAPI: POST /workflows/{id}/dry-run",
                                        v.get("error").and_then(|x| x.as_str()).unwrap_or("Dry-run failed")
                                    )
                                });
                                set_result_open.set(true);
                                bump_reload();
                                open_workflow_drawer(id);
                            }
                            Err(e) => {
                                set_result_title.set("Dry-run failed".into());
                                set_result_summary.set(format!(
                                    "API: POST /workflows/{id}/dry-run\n{}",
                                    e.message
                                ));
                                set_result_open.set(true);
                            }
                        }
                    });
                })
                on_pause=std::sync::Arc::new(move |_| {
                    let id = wf_pause.clone();
                    spawn_local(async move {
                        match pause_workflow(&id).await {
                            Ok(msg) => {
                                set_result_title.set(id.clone());
                                set_result_summary.set(format!(
                                    "{msg}\nAPI: POST /workflows/{id}/lifecycle {{\"state\":\"PAUSED\"}}"
                                ));
                                set_result_open.set(true);
                                bump_reload();
                            }
                            Err(e) => {
                                set_result_title.set("Pause failed".into());
                                set_result_summary.set(format!(
                                    "{e}\nAPI: POST /workflows/{id}/lifecycle — Pause only when ENABLED."
                                ));
                                set_result_open.set(true);
                            }
                        }
                    });
                })
                on_enable=std::sync::Arc::new(move |_| {
                    let id = wf_enable.clone();
                    spawn_local(async move {
                        match activate_workflow(&id).await {
                            Ok(msg) => {
                                set_result_title.set(id.clone());
                                set_result_summary.set(format!(
                                    "{msg}\nAPI: POST /workflows/{id}/lifecycle (compile→stage→enable as needed)"
                                ));
                                set_result_open.set(true);
                                bump_reload();
                            }
                            Err(e) => {
                                set_result_title.set("Enable failed".into());
                                set_result_summary.set(format!(
                                    "{e}\n\nAPI: POST /workflows/{id}/lifecycle\nLifecycle: DRAFT → COMPILED → STAGED → ENABLED ⇄ PAUSED → ARCHIVED"
                                ));
                                set_result_open.set(true);
                            }
                        }
                    });
                })
                on_archive=std::sync::Arc::new(move |_| {
                    let id = wf_archive.clone();
                    spawn_local(async move {
                        match archive_workflow(&id).await {
                            Ok(msg) => {
                                set_result_title.set(id);
                                set_result_summary.set(msg);
                                set_result_open.set(true);
                                bump_reload();
                            }
                            Err(e) => {
                                set_result_title.set("Archive failed".into());
                                set_result_summary.set(e);
                                set_result_open.set(true);
                            }
                        }
                    });
                })
            />
            <OpResultSheet
                open=result_open
                set_open=set_result_open
                title=result_title
                summary=result_summary
            />
        </OpCard>
    }
}

#[component]
pub fn OpIssueCard(
    title: String,
    detail: String,
    #[prop(optional, into, default = "medium".to_string())] severity: String,
    #[prop(optional, into, default = "Fix now".to_string())] primary_label: String,
    #[prop(optional)] on_fix: Option<OpClick>,
    #[prop(optional)] on_open: Option<OpClick>,
    #[prop(optional, into, default = String::new())] secondary_label: String,
    #[prop(optional)] on_secondary: Option<OpClick>,
) -> impl IntoView {
    let fix = on_fix.unwrap_or_else(noop_click);
    let open = on_open.unwrap_or_else(|| fix.clone());
    let secondary = on_secondary.unwrap_or_else(noop_click);
    let pill = match severity.to_ascii_lowercase().as_str() {
        "high" | "critical" => "deny",
        "low" => "allow",
        _ => "info",
    };
    view! {
        <OpCard
            title=title
            subtitle=detail
            accent=OpCardAccent::Attention
            primary_label=primary_label
            on_primary=fix
            on_click=open
            secondary_label=secondary_label
            on_secondary=secondary
        >
            <OpDecisionPill decision=pill />
            <span class="font-mono text-[10px] uppercase text-zinc-500">{severity}</span>
        </OpCard>
    }
}

#[component]
pub fn OpEventRow(
    time: String,
    decision: &'static str,
    agent: String,
    action: String,
    resource: String,
) -> impl IntoView {
    view! {
        <div class="grid grid-cols-[5rem_4rem_1fr_1fr_1fr] gap-2 border-b border-zinc-800/50 px-4 py-2 text-xs hover:bg-zinc-900/40">
            <span class="text-zinc-500 font-mono">{time}</span>
            <OpDecisionPill decision=decision />
            <span class="truncate font-mono text-zinc-400">{agent}</span>
            <span class="truncate text-zinc-300">{action}</span>
            <span class="truncate font-mono text-zinc-500">{resource}</span>
        </div>
    }
}

#[component]
pub fn OpAgentCard(
    name: String,
    pid: String,
    state: String,
    #[prop(optional)] on_open: Option<OpClick>,
    #[prop(optional)] on_view: Option<OpClick>,
    #[prop(optional)] on_delete: Option<OpClick>,
    #[prop(optional)] primary_label: Option<String>,
) -> impl IntoView {
    let open = on_open.unwrap_or_else(noop_click);
    let open_primary = open.clone();
    let has_view = on_view.is_some();
    let has_delete = on_delete.is_some();
    let view_click = on_view.unwrap_or_else(noop_click);
    let delete_click = on_delete.unwrap_or_else(noop_click);
    let primary_label = primary_label.unwrap_or_else(|| "Run".into());
    view! {
        <OpCard
            title=name
            subtitle="Active agent".to_string()
            accent=OpCardAccent::Running
            primary_label=primary_label
            on_primary=open_primary
            on_click=open
            tertiary_label=if has_view { "View".to_string() } else { String::new() }
            on_tertiary=view_click
            secondary_label=if has_delete { "Delete".to_string() } else { String::new() }
            on_secondary=delete_click
        >
            <OpTruncMono text=pid />
            <OpStatePill state=state />
        </OpCard>
    }
}

#[component]
pub fn OpMetricCard(
    label: String,
    value: String,
    #[prop(default = vec![])] sparkline: Vec<f64>,
) -> impl IntoView {
    let value_title = value.clone();
    view! {
        <div class="mon-metric-card">
            <OpText text=label variant=OpTextVariant::Caption />
            <p class="mon-metric-card__value" title=value_title>{value}</p>
            {(!sparkline.is_empty()).then(|| view! {
                <OpMiniSparkline values=sparkline />
            })}
        </div>
    }
}

#[component]
pub fn OpMetricRow(metrics: Vec<(String, String)>) -> impl IntoView {
    view! {
        <div class="mon-metric-grid">
            {metrics.into_iter().map(|(label, value)| view! {
                <OpMetricCard label=label value=value />
            }).collect_view()}
        </div>
    }
}

#[component]
pub fn OpInstitutionCard(
    code: &'static str,
    name: String,
    healthy: bool,
    installed: bool,
    #[prop(optional)] on_install: Option<OpClick>,
    #[prop(optional)] on_click: Option<OpClick>,
) -> impl IntoView {
    let accent = if !installed {
        OpCardAccent::Idle
    } else if healthy {
        OpCardAccent::Running
    } else {
        OpCardAccent::Attention
    };
    let install = on_install.unwrap_or_else(noop_click);
    let open = on_click.unwrap_or_else(|| install.clone());
    view! {
        <OpCard
            title=name
            subtitle=if installed { "Installed" } else { "Not installed" }.to_string()
            accent=accent
            primary_label=if installed { "Open console" } else { "Install" }.to_string()
            on_primary=install
            on_click=open
        >
            <OpInstitutionChip code=code healthy=healthy installed=installed />
        </OpCard>
    }
}

#[component]
pub fn OpObjectTile(
    label: String,
    count: Option<u64>,
    #[prop(optional)] on_click: Option<OpClick>,
) -> impl IntoView {
    let display = count.map(|n| n.to_string()).unwrap_or_else(|| "—".to_string());
    let click = on_click.unwrap_or_else(noop_click);
    view! {
        <button
            type="button"
            class="flex flex-col items-start gap-1 rounded-lg border border-zinc-800/70 bg-zinc-900/40 p-3 text-left hover:border-zinc-700"
            on:click=move |ev| click(ev)
        >
            <span class="text-[10px] font-medium uppercase tracking-wide text-zinc-500">{label}</span>
            <span class="text-xl font-semibold tabular-nums text-zinc-100">{display}</span>
        </button>
    }
}

#[component]
pub fn OpReceiptCard(
    receipt_id: String,
    summary: String,
    time: String,
    #[prop(optional)] on_click: Option<OpClick>,
) -> impl IntoView {
    let click = on_click.unwrap_or_else(noop_click);
    view! {
        <button
            type="button"
            class="flex w-full items-center justify-between gap-3 rounded-lg border border-zinc-800/70 bg-zinc-900/35 px-4 py-3 text-left hover:border-zinc-700"
            on:click=move |ev| click(ev)
        >
            <div class="min-w-0">
                <OpTruncMono text=receipt_id />
                <p class="mt-0.5 truncate text-xs text-zinc-400">{summary}</p>
            </div>
            <OpTimeAgo label=time />
        </button>
    }
}

#[component]
pub fn OpUsageMeter(
    label: String,
    used: u8,
    cap: u8,
) -> impl IntoView {
    let pct = if cap == 0 {
        0
    } else {
        ((used as u16 * 100) / cap as u16).min(100) as u8
    };
    view! {
        <div class="space-y-1.5">
            <div class="flex items-center justify-between text-xs">
                <span class="text-zinc-400">{label}</span>
                <span class="tabular-nums text-zinc-500">{format!("{used}/{cap}")}</span>
            </div>
            <OpProgress percent=pct />
        </div>
    }
}

#[component]
fn OpMiniSparkline(values: Vec<f64>) -> impl IntoView {
    let max = values.iter().cloned().fold(0.0_f64, f64::max).max(1.0);
    let points: String = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = (i as f64 / (values.len().saturating_sub(1).max(1) as f64)) * 64.0;
            let y = 16.0 - (v / max) * 14.0;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    view! {
        <svg class="mt-2 h-4 w-full text-emerald-500/70" viewBox="0 0 64 16" preserveAspectRatio="none" aria-hidden="true">
            <polyline fill="none" stroke="currentColor" stroke-width="1.5" points=points />
        </svg>
    }
}
