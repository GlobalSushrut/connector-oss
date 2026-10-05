//! Page title helper (Phase 1.5).
//!
//! Every page should call [`use_page_title`] in its component body (any
//! position — it just creates an Effect). The helper sets
//! `document.title` to `"{title} · Connector"` on mount and any time the
//! input title changes. Browser tabs then show distinct titles instead
//! of all reading "Connector Platform".
//!
//! Rollout: Phase 1 ships the helper. Each page picks it up in the
//! phase that rewrites that page.

use leptos::prelude::*;

const SUFFIX: &str = " · Connector";

/// Set `document.title` to `"{title} · Connector"`. Reactive: re-runs
/// every time the closure result changes.
///
/// Usage:
///
/// ```ignore
/// #[component]
/// pub fn MyPage() -> impl IntoView {
///     crate::components::page_title::use_page_title("Agents");
///     view! { /* … */ }
/// }
/// ```
pub fn use_page_title(title: impl Into<String>) {
    let title: String = title.into();
    Effect::new(move |_| {
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            doc.set_title(&format!("{title}{SUFFIX}"));
        }
    });
}

/// Reactive variant — accepts a closure for title computation. Use when
/// the page title depends on a signal (e.g. an entity name pulled from
/// an API response).
#[allow(dead_code)]
pub fn use_dynamic_page_title<F>(make_title: F)
where
    F: Fn() -> String + 'static,
{
    Effect::new(move |_| {
        let title = make_title();
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            doc.set_title(&format!("{title}{SUFFIX}"));
        }
    });
}

/// Reset the document title to the bare app name. Call from auth
/// landing pages (`/login`, `/connect`, `/trial`) where the page-title
/// rhythm doesn't apply.
#[allow(dead_code)]
pub fn reset_page_title() {
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        doc.set_title("Connector");
    }
}
