//! Alert + Banner — inline and top-of-page feedback surfaces.
//!
//! An **Alert** is an inline coloured panel that lives in flow with
//! the rest of the page content. Use it to surface a non-fatal
//! warning, an informational tip, or a success acknowledgment that
//! the user should read but not be interrupted by.
//!
//! A **Banner** is a slimmer, full-width strip that lives at the
//! top of a page (or above a section). Use it for system-state
//! announcements: maintenance windows, expired licences, "you're in
//! a degraded mode" notices.
//!
//! Toasts (`crate::components::toaster`) are the third feedback
//! channel — those are for transient confirmations that don't need
//! to stay on screen.

use leptos::ev::MouseEvent;
use leptos::prelude::*;
use std::sync::Arc;

use super::button::OnClick;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlertVariant {
    #[default]
    Info,
    Success,
    Warning,
    Danger,
    Neutral,
}

impl AlertVariant {
    fn shell_class(self) -> &'static str {
        match self {
            AlertVariant::Info => "alert-shell alert-info",
            AlertVariant::Success => "alert-shell alert-success",
            AlertVariant::Warning => "alert-shell alert-warning",
            AlertVariant::Danger => "alert-shell alert-danger",
            AlertVariant::Neutral => "alert-shell alert-neutral",
        }
    }

    fn aria_role(self) -> &'static str {
        // Danger and Warning are "alert" — interrupt assistive tech.
        // Info / Success / Neutral are "status" — announced politely.
        match self {
            AlertVariant::Danger | AlertVariant::Warning => "alert",
            _ => "status",
        }
    }

    fn icon_path(self) -> &'static str {
        // Minimal Lucide-style line icons. Matches the rest of the app.
        match self {
            AlertVariant::Info => "M12 8v4m0 4h.01M12 22a10 10 0 100-20 10 10 0 000 20z",
            AlertVariant::Success => "M22 11.08V12a10 10 0 11-5.93-9.14M22 4L12 14.01l-3-3",
            AlertVariant::Warning => "M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01",
            AlertVariant::Danger => "M12 9v4M12 17h.01M22 12a10 10 0 11-20 0 10 10 0 0120 0z",
            AlertVariant::Neutral => "M12 8v4l3 2M22 12a10 10 0 11-20 0 10 10 0 0120 0z",
        }
    }
}

/// Inline alert panel. Renders as a coloured card-shaped surface
/// flowing in line with surrounding page content.
///
/// ```ignore
/// view! {
///     <Alert
///         variant=AlertVariant::Warning
///         title="Token expires soon"
///     >
///         "Renew within 7 days to avoid service interruption."
///     </Alert>
/// }
/// ```
#[component]
pub fn Alert(
    #[prop(optional, into)] variant: Signal<AlertVariant>,
    /// Optional bold heading at the top of the alert. Plain text only.
    #[prop(optional, into)]
    title: MaybeProp<String>,
    /// Optional dismiss handler. When set, renders a close button.
    #[prop(optional, into)]
    on_dismiss: Option<OnClick>,
    /// Optional extra utility classes.
    #[prop(optional, into)]
    class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("{} {extra}", variant.get().shell_class())
    };
    let role = move || variant.get().aria_role();
    let icon = move || variant.get().icon_path();
    let dismiss_btn = on_dismiss.map(|cb| {
        let on_click = move |ev: MouseEvent| cb(ev);
        view! {
            <button
                type="button"
                class="ml-auto -my-1 -mr-1 rounded-md p-1 text-current opacity-60 hover:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-current/40"
                aria-label="Dismiss alert"
                on:click=on_click
            >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
            </button>
        }
    });
    view! {
        <div class=cls role=role>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="shrink-0 mt-0.5">
                <path d=icon></path>
            </svg>
            <div class="min-w-0 flex-1">
                {move || title.get().filter(|s| !s.is_empty()).map(|t| {
                    view! { <p class="font-semibold mb-0.5">{t}</p> }
                })}
                <div class="text-current/90">{children()}</div>
            </div>
            {dismiss_btn}
        </div>
    }
}

/// Top-of-page banner — slim, full-width, system-state announcement.
///
/// Compose immediately under the topbar or above a `<PageHeader>`.
/// For an alert that lives inside a section, use [`Alert`] instead.
#[component]
pub fn Banner(
    #[prop(optional, into)] variant: Signal<AlertVariant>,
    /// Optional dismiss handler. When set, renders a close button on
    /// the right.
    #[prop(optional, into)]
    on_dismiss: Option<OnClick>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let base = "banner-shell";
        let v = match variant.get() {
            AlertVariant::Info => "bg-info/10 border-info-30 text-info",
            AlertVariant::Success => "bg-success-10 border-success-30 text-success",
            AlertVariant::Warning => "bg-warn-10 border-warn-30 text-warn",
            AlertVariant::Danger => "bg-danger-10 border-danger-30 text-danger",
            AlertVariant::Neutral => "bg-zinc-900/60 border-zinc-700/60 text-zinc-200",
        };
        let extra = class.get().unwrap_or_default();
        format!("{base} {v} {extra}")
    };
    let role = move || variant.get().aria_role();
    let dismiss = on_dismiss.map(|cb| {
        let on_click = move |ev: MouseEvent| cb(ev);
        view! {
            <button
                type="button"
                aria-label="Dismiss banner"
                class="ml-auto rounded-md p-1 text-current opacity-60 hover:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-current/40"
                on:click=on_click
            >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
            </button>
        }
    });
    let _ = std::marker::PhantomData::<Arc<()>>; // placeholder marker; keeps `Arc` in scope for the close handler conversion.
    view! {
        <div class=cls role=role>
            <div class="flex-1 min-w-0">{children()}</div>
            {dismiss}
        </div>
    }
}
