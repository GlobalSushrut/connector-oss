//! Layout primitives — the structural foundation that prevents overlap.
//!
//! Every page in an enterprise dashboard ends up composing the same
//! four shapes:
//!
//! * A **Stack** of things flowing vertically with consistent spacing.
//! * An **Inline** cluster of things flowing horizontally.
//! * A **Cluster** that wraps when it runs out of room (badges, tag
//!   lists).
//! * A **Grid** for tile layouts (metric cards, dashboards).
//!
//! Plus the supporting cast — `Container` (max-width + padding),
//! `Center` (vertical / horizontal centering), `Spacer` (flexible
//! filler).
//!
//! Why introduce these instead of letting authors write Tailwind
//! flex/grid by hand? Two reasons:
//!
//! 1. **Spacing rhythm.** Authors mix `gap-2`, `gap-3`, `space-y-4`
//!    almost at random; the page ends up with three different rhythms
//!    in one layout. The `Space` enum here exposes nine named tiers on
//!    an 8 px grid. Every nested Stack lands on the same baseline.
//! 2. **Overlap safety.** A `Stack` is `display: flex; flex-direction:
//!    column; min-height: 0;` — that `min-height: 0` is the single
//!    fix that prevents flex children from collapsing under a sticky
//!    sibling. Doing it once here is cheaper than chasing the bug
//!    page-by-page.
//!
//! ## Spacing scale
//!
//! Nine tiers on the 8 px grid: `3xs (2)`, `2xs (4)`, `xs (8)`,
//! `sm (12)`, `md (16, default)`, `lg (24)`, `xl (32)`, `2xl (48)`,
//! `3xl (64)`.
//!
//! ## Alignment
//!
//! `Align::{Start, Center, End, Stretch, Baseline}` — covers every
//! practical layout. `Justify::{Start, Center, End, Between, Around,
//! Evenly}` matches the underlying flexbox vocabulary.

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Space {
    Z3xs,
    Z2xs,
    Xs,
    Sm,
    #[default]
    Md,
    Lg,
    Xl,
    Z2xl,
    Z3xl,
}

impl Space {
    fn gap_class(self) -> &'static str {
        match self {
            Space::Z3xs => "gap-0.5",
            Space::Z2xs => "gap-1",
            Space::Xs => "gap-2",
            Space::Sm => "gap-3",
            Space::Md => "gap-4",
            Space::Lg => "gap-6",
            Space::Xl => "gap-8",
            Space::Z2xl => "gap-12",
            Space::Z3xl => "gap-16",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Align {
    Start,
    Center,
    End,
    #[default]
    Stretch,
    Baseline,
}

impl Align {
    fn class(self) -> &'static str {
        match self {
            Align::Start => "items-start",
            Align::Center => "items-center",
            Align::End => "items-end",
            Align::Stretch => "items-stretch",
            Align::Baseline => "items-baseline",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Justify {
    #[default]
    Start,
    Center,
    End,
    Between,
    Around,
    Evenly,
}

impl Justify {
    fn class(self) -> &'static str {
        match self {
            Justify::Start => "justify-start",
            Justify::Center => "justify-center",
            Justify::End => "justify-end",
            Justify::Between => "justify-between",
            Justify::Around => "justify-around",
            Justify::Evenly => "justify-evenly",
        }
    }
}

/// Vertical stack.
///
/// Children flow top-to-bottom with consistent spacing. `min-height: 0`
/// is applied so this can sit inside a flex parent without collapsing
/// — the canonical fix for the "my content gets hidden by a sticky
/// header" bug.
#[component]
pub fn Stack(
    #[prop(optional, into)] space: Signal<Space>,
    #[prop(optional, into)] align: Signal<Align>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!(
            "flex flex-col min-h-0 {gap} {align} {extra}",
            gap = space.get().gap_class(),
            align = align.get().class(),
        )
    };
    view! { <div class=cls>{children()}</div> }
}

/// Horizontal cluster that does NOT wrap.
///
/// For wrapping clusters (tag pills, badge lists) use [`Cluster`].
#[component]
pub fn Inline(
    #[prop(optional, into)] space: Signal<Space>,
    #[prop(optional, into)] align: Signal<Align>,
    #[prop(optional, into)] justify: Signal<Justify>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!(
            "flex flex-row {gap} {align} {justify} {extra}",
            gap = space.get().gap_class(),
            align = align.get().class(),
            justify = justify.get().class(),
        )
    };
    view! { <div class=cls>{children()}</div> }
}

/// Horizontal cluster that wraps when it overflows.
///
/// Same vocabulary as [`Inline`] but with `flex-wrap`. Use for tag
/// lists, badge groups, filter chips — anything where the count is
/// variable and the row should reflow on narrow screens.
#[component]
pub fn Cluster(
    #[prop(optional, into)] space: Signal<Space>,
    #[prop(optional, into)] align: Signal<Align>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!(
            "flex flex-row flex-wrap {gap} {align} {extra}",
            gap = space.get().gap_class(),
            align = align.get().class(),
        )
    };
    view! { <div class=cls>{children()}</div> }
}

/// Responsive grid with a column count per breakpoint.
///
/// Authors specify a default column count (mobile) and an override
/// for sm/md/lg/xl. Anything not specified inherits from the previous
/// breakpoint.
#[component]
pub fn Grid(
    /// Base (mobile) column count.
    #[prop(optional, into, default = 1.into())]
    cols: Signal<u8>,
    /// Columns from the `sm` breakpoint (≥ 640px).
    #[prop(optional, into)]
    cols_sm: MaybeProp<u8>,
    /// Columns from the `md` breakpoint (≥ 768px).
    #[prop(optional, into)]
    cols_md: MaybeProp<u8>,
    /// Columns from the `lg` breakpoint (≥ 1024px).
    #[prop(optional, into)]
    cols_lg: MaybeProp<u8>,
    /// Columns from the `xl` breakpoint (≥ 1280px).
    #[prop(optional, into)]
    cols_xl: MaybeProp<u8>,
    #[prop(optional, into)] space: Signal<Space>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        let base = format!("grid grid-cols-{}", cols.get().min(12));
        let sm = cols_sm
            .get()
            .map(|n| format!("sm:grid-cols-{}", n.min(12)))
            .unwrap_or_default();
        let md = cols_md
            .get()
            .map(|n| format!("md:grid-cols-{}", n.min(12)))
            .unwrap_or_default();
        let lg = cols_lg
            .get()
            .map(|n| format!("lg:grid-cols-{}", n.min(12)))
            .unwrap_or_default();
        let xl = cols_xl
            .get()
            .map(|n| format!("xl:grid-cols-{}", n.min(12)))
            .unwrap_or_default();
        format!(
            "{base} {sm} {md} {lg} {xl} {gap} {extra}",
            gap = space.get().gap_class(),
        )
    };
    view! { <div class=cls>{children()}</div> }
}

/// Center children horizontally and vertically with a sensible
/// minimum height. Use for empty states, login screens, 404 panels.
#[component]
pub fn Center(
    /// Minimum height — defaults to `min-h-[40vh]` so the content
    /// doesn't hug the topbar. Pass a Tailwind utility to override.
    #[prop(optional, into, default = "min-h-[40vh]".to_string().into())]
    min_height: Signal<String>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        let mh = min_height.get();
        format!("flex flex-col items-center justify-center text-center {mh} {extra}")
    };
    view! { <div class=cls>{children()}</div> }
}

/// Flexible filler that pushes siblings apart in a flex parent.
/// Equivalent to `flex: 1 1 auto;`.
#[component]
pub fn Spacer() -> impl IntoView {
    view! { <div class="flex-1"></div> }
}

/// Bounded container with consistent horizontal padding.
///
/// The three sizes match `container-page` (default 80rem), `narrow`
/// (48rem — for forms/long-form), and `wide` (96rem — for dense
/// dashboards). Padding scales with the viewport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerSize {
    Narrow,
    #[default]
    Page,
    Wide,
    Full,
}

impl ContainerSize {
    fn class(self) -> &'static str {
        match self {
            ContainerSize::Narrow => "container-narrow",
            ContainerSize::Page => "container-page",
            ContainerSize::Wide => "container-wide",
            ContainerSize::Full => "w-full px-6",
        }
    }
}

#[component]
pub fn Container(
    #[prop(optional, into)] size: Signal<ContainerSize>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("{} {extra}", size.get().class())
    };
    view! { <div class=cls>{children()}</div> }
}
