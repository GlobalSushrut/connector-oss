//! AppShell — the single layout container that prevents component overlap.
//!
//! Every page in the dashboard lives inside this shell. It enforces
//! the three slots an enterprise app needs:
//!
//! ```text
//! ┌─────────────┬─────────────────────────────────────────────────┐
//! │             │  ┌─ topbar (sticky-topbar, z-sticky) ────────┐  │
//! │  sidebar    │  ├──────────────────────────────────────────┤  │
//! │ (z-drawer)  │  │ banner slot (optional)                    │  │
//! │             │  ├──────────────────────────────────────────┤  │
//! │             │  │ main content                              │  │
//! │             │  │ (scrolls independently of sidebar +       │  │
//! │             │  │  topbar — never overlapped)               │  │
//! │             │  │                                           │  │
//! │             │  └──────────────────────────────────────────┘  │
//! └─────────────┴─────────────────────────────────────────────────┘
//! ```
//!
//! Why this matters: a flex column with a sticky child can collapse
//! the rest of the layout under the sticky element if `min-height: 0`
//! is missing on the scroll container. We bake that fix into the
//! shell so it's impossible to mis-author.
//!
//! ## Slots
//!
//! * `sidebar` — fixed-width column on the left. Hidden on mobile
//!   (the responsibility of the sidebar component itself).
//! * `topbar` — sticky header inside the content column. Already
//!   carries `position: sticky; top: 0; z-sticky;` via `sticky-topbar`.
//! * `banner` — optional pinned banner between topbar and content.
//!   Use for system-state announcements (`<Banner />`).
//! * `children` — the routed page body. Lives in a scroll container
//!   with `min-h-0` so the sidebar never gets pushed off screen.
//!
//! Pages don't render the shell themselves — `main.rs` mounts it
//! once around `<Outlet />`. They just render their `<PageHeader>` +
//! content; the shell handles the chrome.

use leptos::prelude::*;

#[component]
pub fn AppShell(
    /// Sidebar slot. Typically `<Sidebar />`.
    sidebar: Children,
    /// Optional top-bar slot. The shell applies `sticky-topbar` so
    /// authors don't have to remember the z-index + backdrop combo.
    #[prop(optional)]
    topbar: Option<Children>,
    /// Optional banner slot pinned under the topbar. Use for
    /// announcements that should always be visible while a page is
    /// open (e.g. "trial ends in 12 min").
    #[prop(optional)]
    banner: Option<Children>,
    /// Page content slot — usually `<Outlet />`.
    children: Children,
) -> impl IntoView {
    view! {
        <div class="flex min-h-dvh bg-zinc-950 text-zinc-200">
            <aside class="z-drawer">{sidebar()}</aside>
            <div class="flex-1 min-w-0 flex flex-col min-h-dvh">
                {topbar.map(|f| view! { <header class="sticky-topbar">{f()}</header> })}
                {banner.map(|f| view! { <div class="z-raised">{f()}</div> })}
                <main
                    id="main-content"
                    tabindex="-1"
                    aria-label="Main content"
                    class="flex-1 min-w-0"
                >
                    {children()}
                </main>
            </div>
        </div>
    }
}
