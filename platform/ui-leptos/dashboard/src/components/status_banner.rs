use leptos::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    /// First fetch in flight or response not yet observed. Neutral colour —
    /// must never flash red on cold start.
    Checking,
    Live,
    Degraded,
    Unavailable,
}

/// Map `GET /api/v1/monitor/health` `status` field to header feed state.
/// The platform uses `healthy`, `production_ready`, `degraded`, `critical` — not only `ok`/`live`.
/// An empty / missing status is **Checking** (neutral), not Unavailable.
pub fn live_state_from_monitor_status(status: Option<&str>) -> LiveState {
    let s = status.unwrap_or("").trim();
    if s.is_empty() {
        return LiveState::Checking;
    }
    let lower = s.to_ascii_lowercase();
    match lower.as_str() {
        "live" | "ok" | "healthy" | "operational" | "production_ready" => LiveState::Live,
        "degraded" | "degrading" | "critical" | "warning" => LiveState::Degraded,
        _ if lower.contains("degrad") => LiveState::Degraded,
        _ => LiveState::Unavailable,
    }
}

impl LiveState {
    pub fn label(&self) -> &'static str {
        match self {
            LiveState::Checking => "Checking",
            LiveState::Live => "Live",
            LiveState::Degraded => "Degraded",
            LiveState::Unavailable => "Unavailable",
        }
    }

    /// `(badge_classes, dot_classes)`.
    pub fn classes(&self) -> (&'static str, &'static str) {
        match self {
            LiveState::Checking => (
                "bg-zinc-800/50 text-zinc-400 border-zinc-700/50",
                "bg-zinc-500",
            ),
            LiveState::Live => (
                "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
                "bg-emerald-500",
            ),
            LiveState::Degraded => (
                "bg-amber-500/15 text-amber-200 border-amber-500/30",
                "bg-amber-400",
            ),
            LiveState::Unavailable => (
                "bg-red-500/15 text-red-200 border-red-500/30",
                "bg-red-400",
            ),
        }
    }

    /// Strong left rail so the strip reads severity at a glance.
    fn left_accent(&self) -> &'static str {
        match self {
            LiveState::Checking => "border-l-[3px] border-l-zinc-600/70",
            LiveState::Live => "border-l-[3px] border-l-emerald-400/80",
            LiveState::Degraded => "border-l-[3px] border-l-amber-400/90",
            LiveState::Unavailable => "border-l-[3px] border-l-red-400/90",
        }
    }

    pub fn dot_pulse(&self) -> bool {
        matches!(
            self,
            LiveState::Checking | LiveState::Degraded | LiveState::Unavailable
        )
    }
}

#[allow(dead_code)] // first consumer lands in Phase 6 (Monitor / Overview rewrites use SystemHealthCard).
#[component]
pub fn StatusBanner(
    state: LiveState,
    #[prop(into)] provenance: String,
    #[prop(into)] message: String,
    #[prop(into)] last_updated: String,
    /// Small key/value flags (e.g. trust grade, audit chain, agent count) shown under the headline.
    #[prop(default = Vec::new())] detail_chips: Vec<(String, String)>,
) -> impl IntoView {
    let (badge_cls, dot_cls) = state.classes();
    let info = if message.trim().is_empty() {
        "Live monitor feed".into()
    } else {
        message
    };
    let updated = if last_updated.trim().is_empty() {
        "Just now".into()
    } else {
        last_updated
    };
    let chips = detail_chips.clone();
    let left = state.left_accent();
    let pulse_dot = state.dot_pulse();
    let dot_extra = if pulse_dot { " animate-pulse" } else { "" };

    view! {
        <div class=format!(
            "status-banner flex items-start gap-3 rounded-xl border px-3 py-2 text-xs {badge_cls} {left}"
        )>
            <span class=format!("w-2 h-2 rounded-full shrink-0 mt-1 {dot_cls}{dot_extra}")></span>
            <div class="flex flex-col min-w-0 flex-1 gap-1">
                <div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                    <span class="font-semibold tracking-wide uppercase shrink-0">{state.label()}</span>
                    <span class="text-[10px] text-zinc-400 font-mono truncate">{provenance}</span>
                </div>
                <div class="text-zinc-200 text-[11px] leading-snug line-clamp-2">{info}</div>
                <div class="text-[10px] text-zinc-500">{format!("Updated {}", updated)}</div>
                {(!chips.is_empty()).then(|| view! {
                    <div class="flex flex-wrap gap-1 pt-0.5">
                        {chips.iter().map(|(k, val)| {
                            let k = k.clone();
                            let val = val.clone();
                            view! {
                                <span class="inline-flex items-baseline gap-1 rounded-md border border-zinc-700/60 bg-black/25 px-1.5 py-0.5 text-[9px] leading-none">
                                    <span class="text-zinc-500 uppercase tracking-tight">{k}</span>
                                    <span class="font-mono text-zinc-300">{val}</span>
                                </span>
                            }
                        }).collect::<Vec<_>>()}
                    </div>
                })}
            </div>
        </div>
    }
}
