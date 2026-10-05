//! Typed skeleton loaders.
//!
//! React/Next-grade apps render content-shaped placeholders while data
//! is in flight, not lone spinners. The base `.skeleton` class in
//! `input.css` is a single animated rectangle; this module composes it
//! into purpose-built skeletons (`SkeletonRow`, `SkeletonCard`,
//! `SkeletonTable`, `SkeletonPage`) the rest of the app uses as
//! `<Suspense fallback>` and as inline placeholders.
//!
//! All skeletons set `aria-hidden="true"` so assistive tech doesn't
//! announce them; the surrounding `<Suspense>` / `<Show>` is expected
//! to provide a `role="status"` parent or a `PageLoading` sibling for
//! the screen-reader announcement.

#![allow(dead_code)] // Some skeletons are entry-points called per page; rustc may flag them on the bin target.

use leptos::prelude::*;

/// Single thin pulse row — defaults to 75% width, full width when
/// `full=true`.
#[component]
pub fn SkeletonText(#[prop(optional)] full: bool) -> impl IntoView {
    let w = if full { "w-full" } else { "w-3/4" };
    view! { <div class=format!("skeleton-text {w}") aria-hidden="true"></div> }
}

/// Heading-height pulse, ~66% width — used at the top of card
/// skeletons to mimic a `<h2>` while loading.
#[component]
pub fn SkeletonHeading() -> impl IntoView {
    view! { <div class="skeleton-heading" aria-hidden="true"></div> }
}

/// Circular pulse, e.g. avatar / icon placeholder. `size` is px.
#[component]
pub fn SkeletonCircle(#[prop(default = 32)] size: u32) -> impl IntoView {
    let style = format!("width:{size}px;height:{size}px");
    view! { <div class="skeleton-circle" style=style aria-hidden="true"></div> }
}

/// Card skeleton — heading + N text rows. Drop in wherever a real
/// `.card` would render content the user is waiting for.
#[component]
pub fn SkeletonCard(#[prop(default = 3)] rows: u8) -> impl IntoView {
    view! {
        <div class="skeleton-card" aria-hidden="true">
            <SkeletonHeading />
            {(0..rows).map(|i| {
                let full = i % 2 == 1;
                view! { <SkeletonText full=full /> }
            }).collect_view()}
        </div>
    }
}

/// Inline list row — avatar circle + two stacked text lines. Use for
/// agent / workflow / plugin list skeletons.
#[component]
pub fn SkeletonRow(#[prop(default = true)] with_avatar: bool) -> impl IntoView {
    view! {
        <div class="skeleton-row" aria-hidden="true">
            <Show when=move || with_avatar>
                <SkeletonCircle size=32 />
            </Show>
            <div class="flex-1 space-y-2">
                <div class="skeleton-text w-1/3"></div>
                <div class="skeleton-text w-2/3"></div>
            </div>
        </div>
    }
}

/// Table skeleton — header bar + N row skeletons. `cols` is how many
/// cells per row.
#[component]
pub fn SkeletonTable(
    #[prop(default = 6)] rows: u8,
    #[prop(default = 4)] cols: u8,
) -> impl IntoView {
    view! {
        <div class="table-wrapper" aria-hidden="true">
            <table class="table">
                <thead>
                    <tr>
                        {(0..cols).map(|_| view! {
                            <th><div class="skeleton-text w-2/3"></div></th>
                        }).collect_view()}
                    </tr>
                </thead>
                <tbody>
                    {(0..rows).map(|_| view! {
                        <tr>
                            {(0..cols).map(|_| view! {
                                <td><div class="skeleton-text"></div></td>
                            }).collect_view()}
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }
}

/// Full-page skeleton — title row + 3 card skeletons. Use as the
/// `<Suspense fallback>` on heavy pages (Overview, Workflows, Apps,
/// Plugins) so the layout doesn't collapse to a spinner.
///
/// Pair with a sibling `<PageLoading />` (in `components/cards.rs`)
/// for the screen-reader announcement — `SkeletonPage` itself is
/// `aria-hidden` so it stays silent.
#[component]
pub fn SkeletonPage() -> impl IntoView {
    view! {
        <div class="page-content space-y-6" aria-hidden="true">
            <div class="space-y-2">
                <div class="skeleton-heading w-1/3"></div>
                <div class="skeleton-text"></div>
            </div>
            <div class="metric-grid-3">
                <SkeletonCard rows=2 />
                <SkeletonCard rows=2 />
                <SkeletonCard rows=2 />
            </div>
            <SkeletonCard rows=4 />
        </div>
    }
}
