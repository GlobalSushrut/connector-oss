//! Capacity meters (Phase 5.7).
//!
//! Renders `Agents 2 / 5 · Tokens 12k / 100k · Workflows 1 / 3` from
//! the `DeploymentCaps` block on `DeploymentInfo`. Two variants:
//!
//! * [`CapacityMeters`] — full row used on the Overview page,
//!   visible whenever any cap exists.
//! * [`CapacityMetersCompact`] — single-line summary mounted in the
//!   header (next to the countdown pill) only when *any* meter is at
//!   or above 80 %.

use leptos::prelude::*;

use crate::deployment::use_deployment;

/// Threshold above which the compact header version reveals itself.
const HEADER_THRESHOLD_PCT: f32 = 80.0;

#[component]
pub fn CapacityMeters() -> impl IntoView {
    let deployment = use_deployment();
    view! {
        {move || {
            let info = deployment.get();
            match info.caps {
                None => view! { <span></span> }.into_any(),
                Some(caps) => view! {
                    <section class="rounded-2xl border border-zinc-800/60 bg-zinc-900/40 px-4 py-3 space-y-2 mb-4">
                        <div class="flex items-center justify-between gap-2">
                            <p class="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold">"Session capacity"</p>
                            {match caps.agents_max + caps.workflows_max + caps.tokens_max as u32 {
                                0 => view! { <span></span> }.into_any(),
                                _ => view! {
                                    <p class="text-[11px] text-zinc-500">"Resets when this playground session ends."</p>
                                }.into_any(),
                            }}
                        </div>
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <Meter label="Agents" used=caps.agents_used as u64 max=caps.agents_max as u64 />
                            <Meter label="Workflows" used=caps.workflows_used as u64 max=caps.workflows_max as u64 />
                            <Meter label="Tokens" used=caps.tokens_used max=caps.tokens_max />
                        </div>
                    </section>
                }.into_any(),
            }
        }}
    }
}

#[component]
pub fn CapacityMetersCompact() -> impl IntoView {
    let deployment = use_deployment();
    view! {
        {move || {
            let info = deployment.get();
            let Some(caps) = info.caps.clone() else {
                return view! { <span></span> }.into_any();
            };
            // Show only when at least one meter is over the threshold.
            let any_high = pct(caps.agents_used as u64, caps.agents_max as u64) >= HEADER_THRESHOLD_PCT
                || pct(caps.tokens_used, caps.tokens_max) >= HEADER_THRESHOLD_PCT
                || pct(caps.workflows_used as u64, caps.workflows_max as u64) >= HEADER_THRESHOLD_PCT;
            if !any_high {
                return view! { <span></span> }.into_any();
            }
            let agents = format_meter("Agents", caps.agents_used as u64, caps.agents_max as u64);
            let workflows = format_meter("Workflows", caps.workflows_used as u64, caps.workflows_max as u64);
            let tokens = format_meter_si("Tokens", caps.tokens_used, caps.tokens_max);
            view! {
                <span
                    class="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[11px] font-medium text-amber-300"
                    title="Some session resource is near its cap. Open Overview for full meters."
                >
                    {agents}{" · "}{workflows}{" · "}{tokens}
                </span>
            }.into_any()
        }}
    }
}

#[component]
fn Meter(label: &'static str, used: u64, max: u64) -> impl IntoView {
    let p = pct(used, max);
    let (track_class, fill_class) = bar_classes(p);
    view! {
        <div class="space-y-1">
            <div class="flex items-center justify-between gap-2 text-xs">
                <span class="text-zinc-400">{label}</span>
                <span class="font-mono text-zinc-200">{format_used_max(label, used, max)}</span>
            </div>
            <div class=format!("h-1.5 rounded-full overflow-hidden {track_class}")>
                <div
                    class=format!("h-full {fill_class}")
                    style=format!("width: {:.1}%", p.clamp(0.0, 100.0))
                ></div>
            </div>
        </div>
    }
}

fn pct(used: u64, max: u64) -> f32 {
    if max == 0 {
        return 0.0;
    }
    (used as f32 / max as f32) * 100.0
}

fn bar_classes(p: f32) -> (&'static str, &'static str) {
    if p >= 95.0 {
        ("bg-red-500/20", "bg-red-500")
    } else if p >= 80.0 {
        ("bg-amber-500/20", "bg-amber-500")
    } else if p >= 50.0 {
        ("bg-indigo-500/20", "bg-indigo-500")
    } else {
        ("bg-zinc-700/60", "bg-emerald-400")
    }
}

fn format_used_max(label: &str, used: u64, max: u64) -> String {
    if label == "Tokens" {
        return format!("{} / {}", short_si(used), short_si(max));
    }
    format!("{} / {}", used, max)
}

fn format_meter(label: &str, used: u64, max: u64) -> String {
    format!("{label} {used}/{max}")
}

fn format_meter_si(label: &str, used: u64, max: u64) -> String {
    format!("{label} {}/{}", short_si(used), short_si(max))
}

fn short_si(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
