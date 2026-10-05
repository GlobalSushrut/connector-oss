use leptos::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum OpHealthState {
    #[default]
    Unknown,
    Ok,
    Degraded,
    Down,
}

impl OpHealthState {
    pub fn from_api(s: &str) -> Self {
        // `critical` from /monitor/health means trust/deploy gates failed — the
        // HTTP node is still up. Reserve Down for unreachable / hard failure.
        match s.to_ascii_lowercase().as_str() {
            "ok" | "healthy" => Self::Ok,
            "degraded" | "warn" | "warning" | "critical" => Self::Degraded,
            "down" | "error" | "unreachable" | "offline" => Self::Down,
            _ => Self::Unknown,
        }
    }

    fn dot_class(self) -> &'static str {
        match self {
            Self::Ok => "bg-emerald-400 shadow-emerald-400/50",
            Self::Degraded => "bg-amber-400 shadow-amber-400/50",
            Self::Down => "bg-red-500 shadow-red-500/50",
            Self::Unknown => "bg-zinc-600",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ok => "healthy",
            Self::Degraded => "degraded",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

#[component]
pub fn OpHealthDot(
    state: OpHealthState,
    #[prop(default = false)] show_label: bool,
    /// Override label text (e.g. API `status: critical` while state is Degraded).
    #[prop(optional, into)] label: Option<String>,
) -> impl IntoView {
    let text = label.unwrap_or_else(|| state.label().to_string());
    let title = text.clone();
    view! {
        <span class="inline-flex items-center gap-1.5" title=title>
            <span
                class=format!("h-2 w-2 rounded-full shadow-sm {}", state.dot_class())
                aria-hidden="true"
            ></span>
            {show_label.then(|| view! {
                <span class="text-xs text-zinc-400 capitalize">{text.clone()}</span>
            })}
        </span>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpStatVariant {
    Running,
    NeedsYou,
    Idle,
}

#[component]
pub fn OpStatChip(
    variant: OpStatVariant,
    count: Option<u64>,
) -> impl IntoView {
    let (color, label) = match variant {
        OpStatVariant::Running => ("text-emerald-400", "running"),
        OpStatVariant::NeedsYou => ("text-amber-400", "needs you"),
        OpStatVariant::Idle => ("text-zinc-400", "idle"),
    };
    let display = count.map(|n| n.to_string()).unwrap_or_else(|| "—".to_string());
    view! {
        <span class=format!("inline-flex items-center gap-1.5 text-xs font-medium {color}")>
            <span class="font-mono tabular-nums">{display}</span>
            <span class="text-zinc-500">{label}</span>
        </span>
    }
}

#[component]
pub fn OpStatePill(#[prop(into)] state: String) -> impl IntoView {
    let lower = state.to_ascii_lowercase();
    let class = if lower.contains("run") || lower.contains("active") || lower.contains("enabled") {
        "bg-emerald-500/15 text-emerald-400 border-emerald-500/25"
    } else if lower.contains("pause") || lower.contains("wait") {
        "bg-amber-500/15 text-amber-400 border-amber-500/25"
    } else {
        "bg-zinc-800 text-zinc-400 border-zinc-700"
    };
    view! {
        <span class=format!("inline-flex rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide {class}")>
            {state}
        </span>
    }
}

#[component]
pub fn OpDecisionPill(decision: &'static str) -> impl IntoView {
    let class = match decision {
        "allow" => "bg-emerald-500/15 text-emerald-400",
        "deny" => "bg-red-500/15 text-red-400",
        _ => "bg-sky-500/15 text-sky-400",
    };
    view! {
        <span class=format!("inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase {class}")>
            {decision}
        </span>
    }
}

#[component]
pub fn OpSignal(#[prop(into)] label: String, #[prop(into)] value: String) -> impl IntoView {
    view! {
        <span class="inline-flex items-center gap-1 rounded-md bg-zinc-800/80 px-2 py-0.5 text-xs text-zinc-400">
            <span class="text-zinc-500">{label}</span>
            <span class="text-zinc-200">{value}</span>
        </span>
    }
}

#[component]
pub fn OpInstitutionChip(
    code: &'static str,
    healthy: bool,
    installed: bool,
) -> impl IntoView {
    let dot = if !installed {
        "bg-zinc-600"
    } else if healthy {
        "bg-emerald-400"
    } else {
        "bg-amber-400"
    };
    view! {
        <span class="inline-flex items-center gap-1 rounded-md border border-zinc-800 bg-zinc-900/60 px-2 py-0.5 text-[10px] font-semibold text-zinc-300">
            <span class=format!("h-1.5 w-1.5 rounded-full {dot}")></span>
            {code}
        </span>
    }
}

#[component]
pub fn OpLiveDot() -> impl IntoView {
    view! {
        <span class="relative flex h-2 w-2" aria-label="live">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-40"></span>
            <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"></span>
        </span>
    }
}

#[component]
pub fn OpPulseWave() -> impl IntoView {
    view! {
        <svg class="h-4 w-16 text-emerald-500/70" viewBox="0 0 64 16" fill="none" aria-hidden="true">
            <path
                d="M0 8 L8 8 L12 2 L16 14 L20 8 L28 8 L32 4 L36 12 L40 8 L64 8"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
    }
}

#[component]
pub fn OpEnvBadge(#[prop(into)] name: String) -> impl IntoView {
    view! {
        <span class="inline-flex items-center rounded-md border border-zinc-700/80 bg-zinc-900/80 px-2 py-0.5 text-xs font-mono text-zinc-400">
            {name}
        </span>
    }
}
