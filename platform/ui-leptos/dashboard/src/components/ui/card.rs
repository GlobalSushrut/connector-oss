//! Card — composable surface primitives.
//!
//! Replaces the `.card` / `.card-3d` / `.card-glass` ad-hoc usage
//! pattern with shadcn-style composables:
//!
//! ```ignore
//! view! {
//!     <Card>
//!         <CardHeader>
//!             <CardTitle>"Active agents"</CardTitle>
//!             <CardDescription>"Across all tenants"</CardDescription>
//!         </CardHeader>
//!         <CardContent>{42}</CardContent>
//!         <CardFooter>
//!             <a href="/agents" class="text-xs text-muted">"Open agents →"</a>
//!         </CardFooter>
//!     </Card>
//! }
//! ```
//!
//! These are intentionally thin wrappers — the visual treatment lives
//! in `input.css` under `.card`, `.card-header`, etc. The point is
//! getting the spacing rhythm + semantic structure right at every
//! call site.

use leptos::prelude::*;

#[component]
pub fn Card(
    /// Optional extra utility classes.
    #[prop(optional, into)]
    class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("card flex flex-col gap-4 {extra}")
    };
    view! { <div class=cls>{children()}</div> }
}

#[component]
pub fn CardHeader(
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("flex flex-col gap-1 {extra}")
    };
    view! { <div class=cls>{children()}</div> }
}

#[component]
pub fn CardTitle(
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("text-base font-semibold text-zinc-100 leading-tight {extra}")
    };
    view! { <h3 class=cls>{children()}</h3> }
}

#[component]
pub fn CardDescription(
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("text-sm text-muted {extra}")
    };
    view! { <p class=cls>{children()}</p> }
}

#[component]
pub fn CardContent(
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("text-sm text-zinc-300 {extra}")
    };
    view! { <div class=cls>{children()}</div> }
}

#[component]
pub fn CardFooter(
    #[prop(optional, into)] class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("flex items-center justify-between gap-2 pt-2 border-t border-zinc-800/60 {extra}")
    };
    view! { <div class=cls>{children()}</div> }
}
