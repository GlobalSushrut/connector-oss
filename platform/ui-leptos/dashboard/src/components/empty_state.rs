//! One opinionated empty-state pattern (Phase 1.5).
//!
//! Every page that can be "empty" (no agents, no workflows, no
//! notifications, no incidents…) should use this component instead of
//! growing its own bespoke prose paragraph. Goals:
//!
//! - Predictable visual rhythm — operators recognise the shape and the
//!   meaning ("there's nothing to look at; here's the one thing to do").
//! - Single primary action — the empty state always advertises *the
//!   next click*. No paragraph of choices.
//! - Optional icon + sub-line for context. Both default to nothing.
//!
//! Adoption rollout: Phase 1.5 wires one consumer (the Workflows page).
//! Later phases adopt as they touch each page.

use leptos::prelude::*;

use crate::components::icons;

#[component]
pub fn EmptyState(
    /// Icon key from `components::icons::get_icon`. When empty, no icon
    /// is rendered.
    #[prop(into, default = String::new())] icon_key: String,
    /// Bold one-line headline. Required.
    #[prop(into)] headline: String,
    /// Optional sub-line giving 1 sentence of context.
    #[prop(into, default = String::new())] sub: String,
    /// Optional action element — a `<button>` / `<A href=…>` produced by
    /// the caller. Renders below the sub-line, centred. Pass `().into_any()`
    /// (the default) to omit.
    #[prop(into, default = ().into_any())] action: AnyView,
    /// Optional auxiliary line rendered below the action. Use for "or"
    /// secondary affordances, doc links, etc.
    #[prop(into, default = ().into_any())] aux: AnyView,
    /// Optional class hook on the outer wrapper for layout tweaks.
    #[prop(into, default = String::new())] class: String,
) -> impl IntoView {
    let wrapper_class = format!(
        "empty-state flex flex-col items-center text-center gap-3 px-6 py-10 rounded-2xl border border-dashed border-zinc-800/60 bg-zinc-950/30 {class}"
    );
    let icon_svg = if icon_key.trim().is_empty() {
        None
    } else {
        Some(icons::get_icon(&icon_key))
    };

    view! {
        // Phase 7 / P2-17 — announce empty states to assistive tech.
        // `role="status"` + a polite live region means screen readers
        // pick up "No agents yet — Create your first agent" right after
        // the empty list loads, instead of silently rendering an
        // unstructured paragraph.
        <div class=wrapper_class role="status" aria-live="polite">
            {icon_svg.map(|svg| view! {
                <div
                    aria-hidden="true"
                    class="w-10 h-10 rounded-xl bg-zinc-900/60 border border-zinc-800/60 flex items-center justify-center text-zinc-400"
                >
                    <span inner_html=svg />
                </div>
            })}
            <p class="text-sm font-semibold text-zinc-200">{headline}</p>
            {(!sub.trim().is_empty()).then(|| view! {
                <p class="text-xs text-zinc-500 max-w-md leading-relaxed">{sub}</p>
            })}
            <div class="pt-1">{action}</div>
            <div class="text-[11px] text-zinc-600">{aux}</div>
        </div>
    }
}
