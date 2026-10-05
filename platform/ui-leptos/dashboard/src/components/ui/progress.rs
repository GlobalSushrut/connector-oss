//! Progress — determinate / indeterminate progress bar.
//!
//! Determinate: pass a `value` between 0 and 100; the fill animates
//! to that width using the `--ease-snap` token. Indeterminate: omit
//! `value` (or pass `None`) and the bar slides a 1/3-wide chip
//! across the track — same recipe as Vercel / Linear.
//!
//! Always pair with an `aria-label` describing what's progressing,
//! and a `value`-relative announcement (the `aria-valuenow` is
//! managed for you).

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgressSize {
    Sm,
    #[default]
    Md,
    Lg,
}

impl ProgressSize {
    fn track_class(self) -> &'static str {
        match self {
            ProgressSize::Sm => "h-1",
            ProgressSize::Md => "h-1.5",
            ProgressSize::Lg => "h-2",
        }
    }
}

#[component]
pub fn Progress(
    /// 0–100. When `None`, the bar renders as indeterminate.
    #[prop(optional, into)]
    value: MaybeProp<f32>,
    #[prop(optional, into)] size: Signal<ProgressSize>,
    /// Accessible label — what's progressing. Required for screen
    /// readers because the visual fill alone has no semantic meaning.
    #[prop(into)]
    label: String,
    #[prop(optional, into)] class: MaybeProp<String>,
) -> impl IntoView {
    let track_cls = move || {
        let extra = class.get().unwrap_or_default();
        let h = size.get().track_class();
        let indeterminate = if value.get().is_none() {
            "progress-indeterminate"
        } else {
            ""
        };
        format!("progress-track {h} {indeterminate} {extra}")
    };
    let fill_style = move || match value.get() {
        Some(v) => format!("width: {:.1}%", v.clamp(0.0, 100.0)),
        None => "width: 0".to_string(),
    };
    let label_for_aria = label.clone();
    view! {
        <div
            class=track_cls
            role="progressbar"
            aria-label=label_for_aria
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow=move || value.get().map(|v| format!("{:.0}", v.clamp(0.0, 100.0)))
        >
            <Show when=move || value.get().is_some()>
                <span class="progress-fill" style=fill_style></span>
            </Show>
        </div>
    }
}
