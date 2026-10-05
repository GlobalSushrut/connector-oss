//! Compact health indicator used in the global header.
//!
//! Replaces the multi-row `StatusBanner` that used to live next to the page
//! title. Renders as a single-line pill: dot + state + last-updated. Hover
//! exposes provenance and message via the native `title=` tooltip. Click
//! navigates to the `/monitor` page where the full detail lives in a
//! `SystemHealthCard`.
//!
//! Never flashes red during a cold fetch — first-paint state is `Checking`
//! (zinc / neutral), set by `live_state_from_monitor_status` when the
//! response is empty.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::components::status_banner::LiveState;

#[component]
pub fn LiveDotPill(
    state: LiveState,
    /// One-line message; surfaced in the native tooltip only.
    #[prop(into, default = String::new())]
    message: String,
    /// e.g. `"12s ago"` / `"Just now"` / ISO timestamp.
    #[prop(into, default = String::new())]
    last_updated: String,
    /// `monitor/health` or similar API origin; surfaced in the tooltip.
    #[prop(into, default = String::new())]
    provenance: String,
) -> impl IntoView {
    let (badge_cls, dot_cls) = state.classes();
    let label = state.label();
    let pulse = state.dot_pulse();

    let updated_display = if last_updated.trim().is_empty() {
        String::new()
    } else {
        format!(" · {last_updated}")
    };

    let tooltip = {
        let mut parts: Vec<String> = vec![label.to_string()];
        if !message.trim().is_empty() {
            parts.push(message.trim().to_string());
        }
        if !last_updated.trim().is_empty() {
            parts.push(format!("Updated {}", last_updated.trim()));
        }
        if !provenance.trim().is_empty() {
            parts.push(format!("Source: {}", provenance.trim()));
        }
        parts.push("Open Monitor for full health detail".to_string());
        parts.join(" · ")
    };

    let dot_extra = if pulse { " animate-pulse" } else { "" };

    view! {
        <A
            href="/monitor"
            attr:class=move || format!(
                "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 {badge_cls}"
            )
            attr:title=tooltip.clone()
            attr:aria-label=format!("System status: {label}. Open Monitor.")
            attr:role="status"
            attr:aria-live="polite"
        >
            <span
                aria-hidden="true"
                class=format!("w-1.5 h-1.5 rounded-full {dot_cls}{dot_extra}")
            ></span>
            <span class="tracking-tight">{label}{updated_display}</span>
        </A>
    }
}
