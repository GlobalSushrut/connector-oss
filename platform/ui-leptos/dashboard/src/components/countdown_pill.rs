//! Countdown pill — replaces `LiveDotPill` in Playground mode.
//!
//! Reads `session_expires_at` (Unix seconds, server-side authoritative)
//! from `DeploymentInfo`. Ticks every second locally. Colors:
//!
//! * ≥ 10 m left → emerald (live)
//! * 2 m – 10 m  → amber  (warning)
//! * < 2 m       → red    (critical)
//! * ≤ 0         → "session ended" terminal state
//!
//! Auto-opens the session-end modal once when the remaining time
//! drops below 60 s; the modal is owned by `App` (via `ui_state`).

use leptos::prelude::*;
use std::time::Duration;

use crate::deployment::use_deployment;
use crate::ui_state::use_session_end_modal;

const TICK_MS: u32 = 1_000;
const AUTO_OPEN_MODAL_AT_SECS: i64 = 60;

#[component]
pub fn CountdownPill() -> impl IntoView {
    let deployment = use_deployment();
    let session_end_modal = use_session_end_modal();

    // Recompute every second so the pill ticks down. We piggy-back on
    // a small RwSignal that's bumped from a setInterval callback below.
    let (tick, set_tick) = signal(0u64);

    // Install the 1 Hz tick once on mount.
    Effect::new(move |has_run: Option<bool>| {
        if has_run.unwrap_or(false) {
            return true;
        }
        let handle = set_interval_with_handle(
            move || set_tick.update(|t| *t = t.wrapping_add(1)),
            Duration::from_millis(TICK_MS as u64),
        );
        // Drop the handle — the interval should live for the lifetime
        // of the dashboard tab. `IntervalHandle` is `Copy` so this is
        // effectively a no-op, but it documents intent.
        if let Ok(h) = handle {
            let _ = h;
        }
        true
    });

    // Auto-open the modal once when we cross the T-60 s threshold.
    Effect::new(move |last_opened: Option<bool>| {
        let _ = tick.get();
        if last_opened.unwrap_or(false) {
            return true;
        }
        let info = deployment.get();
        if let Some(expires_at) = info.session_expires_at {
            let now = now_unix_secs();
            let remaining = expires_at - now;
            if (1..=AUTO_OPEN_MODAL_AT_SECS).contains(&remaining) {
                session_end_modal.1.set(true);
                return true;
            }
        }
        false
    });

    let click_to_open = move |_| {
        session_end_modal.1.set(true);
    };

    view! {
        {move || {
            let _ = tick.get();
            let info = deployment.get();
            let expires_at = info.session_expires_at;
            let remaining = expires_at.map(|exp| exp - now_unix_secs()).unwrap_or(0);

            let (border, bg, dot_class, label) = pill_classes(remaining, expires_at.is_some());
            let rendered = format_remaining(remaining);
            let aria_label_text = format!(
                "Playground session: {label}, {rendered}. Open session options."
            );

            view! {
                <button
                    type="button"
                    class=format!(
                        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors hover:brightness-110 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 {border} {bg}"
                    )
                    title=format!("Playground session · click for end / extend / download options")
                    aria-label=aria_label_text
                    role="status"
                    aria-live="polite"
                    on:click=click_to_open
                >
                    <span aria-hidden="true" class=format!("w-1.5 h-1.5 rounded-full {dot_class}")></span>
                    <span class="tracking-tight">{label}{" · "}{rendered}</span>
                </button>
            }
        }}
    }
}

fn pill_classes(remaining_secs: i64, has_expiry: bool) -> (&'static str, &'static str, &'static str, &'static str) {
    if !has_expiry {
        return (
            "border-zinc-700/60",
            "text-zinc-400 bg-zinc-900/40",
            "bg-zinc-500",
            "Playground",
        );
    }
    if remaining_secs <= 0 {
        return (
            "border-red-500/40",
            "text-red-300 bg-red-500/10",
            "bg-red-500",
            "Session ended",
        );
    }
    if remaining_secs < 120 {
        return (
            "border-red-500/40",
            "text-red-300 bg-red-500/10",
            "bg-red-500 animate-pulse",
            "Live",
        );
    }
    if remaining_secs < 600 {
        return (
            "border-amber-500/40",
            "text-amber-300 bg-amber-500/10",
            "bg-amber-400 animate-pulse",
            "Live",
        );
    }
    (
        "border-emerald-500/30",
        "text-emerald-300 bg-emerald-500/5",
        "bg-emerald-400",
        "Live",
    )
}

fn format_remaining(secs: i64) -> String {
    if secs <= 0 {
        return "expired".into();
    }
    let mins = secs / 60;
    let s = secs % 60;
    if mins == 0 {
        format!("expires in {s}s")
    } else if mins < 60 {
        format!("expires in {mins}m {:02}s", s)
    } else {
        let h = mins / 60;
        let m = mins % 60;
        format!("expires in {h}h {m:02}m")
    }
}

fn now_unix_secs() -> i64 {
    web_sys::js_sys::Date::now() as i64 / 1000
}
