//! Kbd — keyboard shortcut chip.
//!
//! Renders a `<kbd>` with a chip-shaped visual that matches the
//! command-palette aesthetic used across the dashboard. The platform
//! convention is to wrap each key in its own `<Kbd>` and join with a
//! `+` if the call site wants multi-key combos (e.g. `<Kbd>"⌘"</Kbd>
//! "+" <Kbd>"K"</Kbd>`).

use leptos::prelude::*;

#[component]
pub fn Kbd(
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!(
            "inline-flex items-center justify-center min-w-[1.5em] h-5 px-1.5 rounded border border-zinc-700 bg-zinc-800 text-[10px] font-mono font-medium text-zinc-300 shadow-[inset_0_-1px_0_rgba(255,255,255,0.05)] {extra}"
        )
    };
    view! { <kbd class=cls>{children()}</kbd> }
}
