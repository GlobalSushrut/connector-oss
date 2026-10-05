//! Spinner — standalone loading indicator with sizes + accessible label.
//!
//! For inline "this button is working" spinners, use the loading prop
//! on [`Button`](super::Button) — it embeds the same SVG. Use this
//! component for full-surface loads (Suspense fallbacks where a
//! skeleton would be overkill).

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpinnerSize {
    Xs,
    Sm,
    #[default]
    Md,
    Lg,
}

impl SpinnerSize {
    fn class(self) -> &'static str {
        match self {
            SpinnerSize::Xs => "h-3 w-3",
            SpinnerSize::Sm => "h-4 w-4",
            SpinnerSize::Md => "h-5 w-5",
            SpinnerSize::Lg => "h-8 w-8",
        }
    }
}

#[component]
pub fn Spinner(
    #[prop(optional, into)] size: Signal<SpinnerSize>,
    /// Accessible label. Required so a screen reader announces what
    /// the spinner is for. Defaults to "Loading".
    #[prop(optional, into, default = "Loading".to_string().into())]
    label: Signal<String>,
    #[prop(optional, into)] class: MaybeProp<String>,
) -> impl IntoView {
    let svg_cls = move || {
        let extra = class.get().unwrap_or_default();
        let sz = size.get().class();
        format!("animate-spin {sz} text-brand {extra}")
    };
    view! {
        <span class="inline-flex items-center" role="status">
            <svg
                class=svg_cls
                xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"
                aria-hidden="true"
            >
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
            </svg>
            <span class="sr-only">{move || label.get()}</span>
        </span>
    }
}
