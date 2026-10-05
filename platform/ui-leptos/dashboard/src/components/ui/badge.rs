//! Badge — small inline status label.
//!
//! Replaces the eight ad-hoc `.badge-*` classes (`badge-green`,
//! `badge-amber`, …) with a typed `BadgeVariant` enum so the call
//! site can't pick an inconsistent colour. The old CSS classes still
//! exist for backwards compatibility but new code should use this
//! primitive.

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BadgeVariant {
    /// Brand / neutral-positive — use for "Active", "Connected".
    Brand,
    /// Healthy / completed / online.
    Success,
    /// Pending / degraded / amber.
    Warning,
    /// Failed / denied / over-cap.
    Danger,
    /// Informational neutral.
    Info,
    /// Tertiary / paused / muted.
    #[default]
    Neutral,
}

impl BadgeVariant {
    fn class(self) -> &'static str {
        match self {
            BadgeVariant::Brand => "bg-brand-10 text-brand border border-brand/30",
            BadgeVariant::Success => "bg-success-10 text-success border border-success/30",
            BadgeVariant::Warning => "bg-warn-10 text-warn border border-warn/30",
            BadgeVariant::Danger => "bg-danger-10 text-danger border border-danger/30",
            BadgeVariant::Info => "bg-info/10 text-info border border-info/30",
            BadgeVariant::Neutral => "bg-zinc-800/60 text-zinc-400 border border-zinc-700/50",
        }
    }
}

const BASE: &str = "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium whitespace-nowrap";

/// Small inline status label. Accepts arbitrary children so callers
/// can prepend a dot, icon, or count.
///
/// ```ignore
/// view! {
///     <Badge variant=BadgeVariant::Success>"Active"</Badge>
/// }
/// ```
#[component]
pub fn Badge(
    #[prop(optional, into)] variant: Signal<BadgeVariant>,
    /// When true, prepends a 6px coloured dot — matches the
    /// "live" pattern used across status pages.
    #[prop(optional, into)]
    dot: Signal<bool>,
    /// Optional explicit `aria-label` for cases where the visible
    /// text is too terse for a screen reader (e.g. just "3").
    #[prop(optional, into)]
    aria_label: MaybeProp<String>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("{BASE} {} {extra}", variant.get().class())
    };
    let aria = move || aria_label.get();
    let dot_cls = move || match variant.get() {
        BadgeVariant::Brand => "bg-brand",
        BadgeVariant::Success => "bg-success",
        BadgeVariant::Warning => "bg-warn",
        BadgeVariant::Danger => "bg-danger",
        BadgeVariant::Info => "bg-info",
        BadgeVariant::Neutral => "bg-zinc-500",
    };
    view! {
        <span class=cls aria-label=aria>
            <Show when=move || dot.get()>
                <span class=move || format!("h-1.5 w-1.5 rounded-full {}", dot_cls()) aria-hidden="true"></span>
            </Show>
            {children()}
        </span>
    }
}
