//! Page primitives — the same header / section / breadcrumb rhythm
//! on every route.
//!
//! Enterprise dashboards converge on this layout language:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ Home › Agents › Sales Bot     (breadcrumb — small, top)         │
//! │ AGENTS                         (eyebrow — uppercase, tiny)      │
//! │ Sales Bot                      (title — display-grade)          │
//! │ A short explanation of what    (description — body, max-w-2xl)  │
//! │ this view shows.                                                │
//! │                                       [Secondary] [Primary]     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │ <PageSection title="Overview">                                  │
//! │   ...content...                                                 │
//! │ </PageSection>                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Why mandate this shape? Three reasons:
//!
//! 1. **Predictability.** An operator who learns one page learns
//!    every page — title always lives in the same scroll position
//!    relative to the topbar.
//! 2. **Accessibility.** A single `<h1>` per page, in a known
//!    location, makes screen-reader navigation actually work.
//! 3. **Spacing rhythm.** The header + sections share the same 8 px
//!    grid as the layout primitives, so a page composed entirely of
//!    primitives has no surprises.

use leptos::prelude::*;

/// Top-of-page header — eyebrow + title + description + actions slot,
/// with an optional breadcrumb trail above.
///
/// ```ignore
/// view! {
///     <PageHeader
///         eyebrow="Agents"
///         title="Sales Bot"
///         description="Production agent owned by Sales Ops."
///         breadcrumbs=vec![
///             ("Home", "/"),
///             ("Agents", "/agents"),
///         ]
///         actions=Some(Children::new(move || view! {
///             <Button variant=ButtonVariant::Secondary>"Duplicate"</Button>
///             <Button variant=ButtonVariant::Primary>"Save"</Button>
///         }.into_any()))
///     />
/// }
/// ```
#[component]
pub fn PageHeader(
    #[prop(into)] title: String,
    /// Optional uppercase eyebrow label above the title. Use for the
    /// page category (e.g. "AGENTS" on `/agents/:id`).
    #[prop(optional, into)]
    eyebrow: MaybeProp<String>,
    /// Optional body-sized description below the title. Cap at one
    /// sentence — anything longer belongs in a section.
    #[prop(optional, into)]
    description: MaybeProp<String>,
    /// Optional breadcrumb trail as `(label, href)` pairs. The final
    /// item is rendered as plain text (current page).
    #[prop(optional)]
    breadcrumbs: Option<Vec<(&'static str, &'static str)>>,
    /// Optional actions slot — typically one or two `<Button>`s, right
    /// aligned. Use the trailing position for the primary action so
    /// the eye lands there.
    #[prop(optional)]
    actions: Option<Children>,
) -> impl IntoView {
    view! {
        <header class="page-header">
            {breadcrumbs.map(|crumbs| view! { <Breadcrumbs items=crumbs /> })}
            <div class="page-header-row">
                <div class="min-w-0 max-w-2xl">
                    {move || eyebrow.get().filter(|s| !s.is_empty()).map(|e| {
                        view! { <p class="text-eyebrow text-muted">{e}</p> }
                    })}
                    <h1 class="text-h1 text-zinc-100 mt-1">{title.clone()}</h1>
                    {move || description.get().filter(|s| !s.is_empty()).map(|d| {
                        view! { <p class="text-body text-muted mt-2">{d}</p> }
                    })}
                </div>
                {actions.map(|f| view! { <div class="page-header-actions">{f()}</div> })}
            </div>
        </header>
    }
}

/// Breadcrumb trail — small `›`-separated path of links above the
/// page title. The last item is plain text (current page).
#[component]
pub fn Breadcrumbs(items: Vec<(&'static str, &'static str)>) -> impl IntoView {
    let last = items.len().saturating_sub(1);
    view! {
        <nav aria-label="Breadcrumb">
            <ol class="breadcrumb">
                {items.into_iter().enumerate().map(|(i, (label, href))| {
                    let is_last = i == last;
                    view! {
                        <li class="flex items-center gap-1.5">
                            {if is_last {
                                view! {
                                    <span class="text-zinc-300" aria-current="page">{label}</span>
                                }.into_any()
                            } else {
                                view! {
                                    <a href=href class="hover:text-zinc-300">{label}</a>
                                    <span class="text-zinc-600" aria-hidden="true">"›"</span>
                                }.into_any()
                            }}
                        </li>
                    }
                }).collect_view()}
            </ol>
        </nav>
    }
}

/// Sub-section header inside a page. Smaller than `<PageHeader>` but
/// uses the same vocabulary so authors don't have to mentally switch.
///
/// ```ignore
/// view! {
///     <PageSection
///         title="Recent runs"
///         description="The last 50 executions across all agents."
///         actions=Some(Children::new(move || view! {
///             <Button variant=ButtonVariant::Ghost size=ButtonSize::Sm>"Export"</Button>
///         }.into_any()))
///     >
///         <RecentRunsTable />
///     </PageSection>
/// }
/// ```
#[component]
pub fn PageSection(
    #[prop(into)] title: String,
    #[prop(optional, into)] description: MaybeProp<String>,
    #[prop(optional)] actions: Option<Children>,
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("space-y-3 {extra}")
    };
    view! {
        <section class=cls>
            <div class="flex items-start justify-between gap-4 flex-wrap">
                <div class="min-w-0">
                    <h2 class="text-h3 text-zinc-100">{title.clone()}</h2>
                    {move || description.get().filter(|s| !s.is_empty()).map(|d| {
                        view! { <p class="text-body-sm text-muted mt-1">{d}</p> }
                    })}
                </div>
                {actions.map(|f| view! { <div class="flex items-center gap-2 shrink-0">{f()}</div> })}
            </div>
            <div>{children()}</div>
        </section>
    }
}
