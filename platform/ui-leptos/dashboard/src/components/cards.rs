#![allow(dead_code)] // Leptos #[component] props are referenced in view!; rustc may flag them on generated props structs.

use leptos::prelude::*;
use crate::api::ApiError;
use crate::utils::{trust_color, trust_grade};

#[component]
pub fn MetricCard(
    label: &'static str,
    #[prop(into)] value: String,
    #[prop(optional, into)] trend: Option<String>,
    #[prop(optional, into)] color: Option<String>,
    icon_svg: &'static str,
) -> impl IntoView {
    let color_class = color.unwrap_or_else(|| "text-zinc-50".into());
    view! {
        <div class="card flex items-start justify-between">
            <div>
                <p class="text-xs text-zinc-500 uppercase tracking-wider">{label}</p>
                <p class=format!("mt-1 text-2xl font-bold font-mono {color_class}")>{value}</p>
                {trend.map(|t| view! { <p class="mt-1 text-xs text-zinc-500">{t}</p> })}
            </div>
            <div class="rounded-lg bg-zinc-800 p-2">
                <span class="text-zinc-400 w-5 h-5 block" inner_html=icon_svg />
            </div>
        </div>
    }
}

#[component]
pub fn TrustGauge(
    score: f64,
    #[prop(default = 100)] size: u32,
) -> impl IntoView {
    let color = trust_color(score);
    let grade = trust_grade(score);
    let r = (size - 12) / 2;
    let circumference = 2.0 * std::f64::consts::PI * r as f64;
    let offset = circumference - (score / 100.0) * circumference;
    view! {
        <div class="relative inline-flex items-center justify-center"
             style=format!("width:{size}px;height:{size}px")>
            <svg width=size height=size class="-rotate-90">
                <circle cx=size/2 cy=size/2 r=r fill="none" stroke="#27272a" stroke-width="8" />
                <circle cx=size/2 cy=size/2 r=r fill="none"
                    stroke=color stroke-width="8" stroke-linecap="round"
                    stroke-dasharray=format!("{circumference:.2}")
                    stroke-dashoffset=format!("{offset:.2}")
                    style="transition:stroke-dashoffset 0.7s ease" />
            </svg>
            <div class="absolute flex flex-col items-center">
                <span class="text-2xl font-bold font-mono" style=format!("color:{color}")>
                    {format!("{:.0}", score)}
                </span>
                <span class="text-xs font-medium" style=format!("color:{color}")>{grade}</span>
            </div>
        </div>
    }
}

#[component]
pub fn StatPill(
    label: &'static str,
    #[prop(into)] value: String,
    #[prop(optional, into)] accent: Option<String>,
) -> impl IntoView {
    let cls = accent.unwrap_or_else(|| "text-zinc-200".into());
    view! {
        <div class="stat-pill">
            <span class="stat-pill-label">{label}</span>
            <span class=format!("font-mono text-sm font-medium {cls}")>{value}</span>
        </div>
    }
}

#[component]
pub fn JsonBox(#[prop(into)] data: String) -> impl IntoView {
    view! { <pre class="json-box">{data}</pre> }
}

#[component]
pub fn FlashMsg(msg: ReadSignal<Option<(String, bool)>>) -> impl IntoView {
    view! {
        {move || msg.get().map(|(text, ok)| {
            let cls = if ok { "flash-ok" } else { "flash-err" };
            view! { <div class=cls>{text}</div> }
        })}
    }
}

#[component]
pub fn StatusDot(ok: bool) -> impl IntoView {
    let cls = if ok { "h-2 w-2 rounded-full bg-green-500" } else { "h-2 w-2 rounded-full bg-red-500" };
    view! { <span class=cls /> }
}

#[component]
pub fn AgentStatusBadge(#[prop(into)] status: String) -> impl IntoView {
    let cls = match status.as_str() {
        "Active" | "healthy" => "badge badge-green",
        "Paused"             => "badge badge-amber",
        "Terminated"         => "badge badge-red",
        "Registered"         => "badge badge-blue",
        _                    => "badge badge-zinc",
    };
    view! { <span class=cls>{status}</span> }
}

#[component]
pub fn RagBadge(#[prop(into)] rag: String) -> impl IntoView {
    let cls = match rag.as_str() {
        "GREEN" => "badge badge-green",
        "AMBER" => "badge badge-amber",
        "RED"   => "badge badge-red",
        _       => "badge badge-zinc",
    };
    view! { <span class=cls>{rag}</span> }
}

#[component]
pub fn RiskBadge(#[prop(into)] rating: String) -> impl IntoView {
    let cls = match rating.as_str() {
        "CRITICAL"      => "badge bg-red-500/20 text-red-400",
        "HIGH"          => "badge bg-orange-500/20 text-orange-400",
        "MEDIUM"        => "badge bg-yellow-500/20 text-yellow-400",
        "LOW"           => "badge badge-green",
        "INFORMATIONAL" => "badge badge-zinc",
        _               => "badge badge-zinc",
    };
    view! { <span class=cls>{rating}</span> }
}

/// Shown when the API returns **403** (e.g. operator/admin-only routes).
#[component]
pub fn ElevatedRoleBanner(
    #[prop(into)] summary: String,
    #[prop(optional)] detail: Option<String>,
) -> impl IntoView {
    view! {
        <div class="rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3">
            <p class="text-sm font-medium text-amber-100">{summary}</p>
            {detail.map(|d| view! { <p class="text-xs text-amber-100/85 mt-2 leading-relaxed">{d}</p> })}
        </div>
    }
}

/// Non-fatal API failure (401, 403, 5xx, network). Use 403 styling for permission errors.
#[component]
pub fn ApiErrorBanner(#[prop(into)] err: ApiError) -> impl IntoView {
    let status = err.status;
    let msg = err.message.clone();
    let detail = err.detail.clone().unwrap_or_default();
    let code = err.code.clone().map(|c| format!("code={c} ")).unwrap_or_default();
    let is_403 = status == 403;
    let border = if is_403 {
        "rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3"
    } else {
        "rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3"
    };
    let title = if is_403 {
        "Permission denied"
    } else {
        "Request failed"
    };
    view! {
        <div class=border>
            <p class=if is_403 { "text-sm font-medium text-amber-100" } else { "text-sm font-medium text-red-100" }>
                {title}" — HTTP " {status}
            </p>
            <p class=if is_403 { "text-xs text-amber-100/90 mt-1" } else { "text-xs text-red-100/90 mt-1" }>{code}{msg}</p>
            {(!detail.is_empty()).then(|| view! { <p class="text-xs text-zinc-400 mt-2 leading-relaxed">{detail}</p> })}
        </div>
    }
}

#[component]
pub fn PageLoading() -> impl IntoView {
    // Phase 7 / P2-5 — single loading treatment. Used as the
    // `<Suspense fallback>` on every page so users see the same
    // spinner + label everywhere. Tokenised: the spinner picks up the
    // brand colour from the 6-token palette so re-theming the app
    // doesn't leave the loader stuck on indigo. `role="status"` +
    // `aria-live="polite"` let assistive tech announce it.
    view! {
        <div
            class="flex items-center gap-2 text-muted text-sm"
            role="status"
            aria-live="polite"
            aria-busy="true"
        >
            <svg
                aria-hidden="true"
                class="animate-spin h-4 w-4 text-brand"
                xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"
            >
                <circle class="opacity-25" cx="12" cy="12" r="10"
                        stroke="currentColor" stroke-width="4"/>
                <path class="opacity-75" fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            <span class="sr-only">"Loading content"</span>
            <span aria-hidden="true">"Loading…"</span>
        </div>
    }
}

#[component]
pub fn PageEmpty(msg: &'static str) -> impl IntoView {
    // Phase 7 / P2-17 — `PageEmpty` was an unadorned `<p>` used in
    // ~30 call sites. Re-route to the opinionated `EmptyState`
    // component (with `role="status"` + dashed border) so all those
    // pages pick up the same a11y + visual rhythm without each one
    // having to migrate explicitly.
    view! {
        <crate::components::empty_state::EmptyState
            headline=msg.to_string()
        />
    }
}

#[component]
pub fn GateCard(#[prop(into)] gate: String) -> impl IntoView {
    let pass = gate == "PASS";
    let cls = if pass {
        "flex items-center gap-2 rounded-lg px-4 py-3 border text-sm font-medium bg-green-500/10 border-green-500/30 text-green-400"
    } else {
        "flex items-center gap-2 rounded-lg px-4 py-3 border text-sm font-medium bg-red-500/10 border-red-500/30 text-red-400"
    };
    let label = format!("Deployment Gate: {gate}");
    view! {
        <div class=cls>
            {if pass {
                view! { <span>"OK"</span> }
            } else {
                view! { <span>"FAIL"</span> }
            }}
            {label}
        </div>
    }
}
