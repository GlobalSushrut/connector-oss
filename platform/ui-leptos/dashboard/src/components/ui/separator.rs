//! Separator — semantic divider.
//!
//! Replaces ad-hoc `<hr class="border-zinc-800">` and `<div class="h-px bg-zinc-800">`.
//! When `decorative=true` (the default) it sets `role="none"` so
//! screen readers skip it. Set `decorative=false` for a divider that
//! actually changes the document outline (e.g. between two semantic
//! sections in a long page).

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeparatorOrientation {
    #[default]
    Horizontal,
    Vertical,
}

#[component]
pub fn Separator(
    #[prop(optional, into)] orientation: Signal<SeparatorOrientation>,
    /// When true (default) the separator is purely visual and
    /// announced as `role="none"`. Set false to keep it in the
    /// accessibility tree as a `role="separator"`.
    #[prop(optional, into)]
    decorative: Signal<bool>,
    #[prop(optional, into)] class: MaybeProp<String>,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        let dims = match orientation.get() {
            SeparatorOrientation::Horizontal => "w-full h-px",
            SeparatorOrientation::Vertical => "h-full w-px",
        };
        format!("{dims} bg-zinc-800/60 {extra}")
    };
    let role = move || if decorative.get() { "none" } else { "separator" };
    let aria_orient = move || match orientation.get() {
        SeparatorOrientation::Horizontal => "horizontal",
        SeparatorOrientation::Vertical => "vertical",
    };
    view! {
        <div class=cls role=role aria-orientation=aria_orient></div>
    }
}
