//! EmptyState — illustrated empty surface with a clear next action.
//!
//! The single most common UX failure in enterprise dashboards is the
//! empty state that says "No data." and then drops the operator at
//! an interactionless wall. This primitive forces the better shape:
//!
//! 1. **Icon or illustration** — a visual anchor so the eye knows
//!    where to start.
//! 2. **Headline** — what's missing (e.g. "No agents yet").
//! 3. **Description** — one short sentence explaining what to do.
//! 4. **Primary action** — the CTA that resolves the empty state.
//! 5. **Secondary action** (optional) — usually "Read docs" or
//!    "Run sample".
//!
//! Compose with the rest of the primitives:
//!
//! ```ignore
//! view! {
//!     <EmptyState
//!         title="No workflows yet"
//!         description="Workflows orchestrate your agents. Install a reference workflow or build your own."
//!         actions=Some(Children::new(move || view! {
//!             <Button variant=ButtonVariant::Primary>"Install reference"</Button>
//!             <Button variant=ButtonVariant::Ghost>"Read the guide"</Button>
//!         }.into_any()))
//!     >
//!         <WorkflowIcon />
//!     </EmptyState>
//! }
//! ```
//!
//! Children render inside the icon slot. Pass an `<svg>` (any 24-32
//! sized line icon) or an `<img>` for a fuller illustration.

use leptos::prelude::*;

#[component]
pub fn EmptyState(
    #[prop(into)] title: String,
    #[prop(optional, into)] description: MaybeProp<String>,
    /// Optional actions row — typically one primary + one secondary
    /// `<Button>`.
    #[prop(optional)]
    actions: Option<Children>,
    #[prop(optional, into)] class: MaybeProp<String>,
    /// Icon / illustration. Rendered inside a 56 px rounded chip.
    children: Children,
) -> impl IntoView {
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("empty-shell {extra}")
    };
    view! {
        <div class=cls>
            <div class="empty-icon" aria-hidden="true">
                {children()}
            </div>
            <div class="space-y-1.5 max-w-sm">
                <h2 class="text-h4 text-zinc-100">{title.clone()}</h2>
                {move || description.get().filter(|s| !s.is_empty()).map(|d| {
                    view! { <p class="text-body-sm text-muted">{d}</p> }
                })}
            </div>
            {actions.map(|f| view! {
                <div class="flex items-center justify-center gap-2 pt-2">{f()}</div>
            })}
        </div>
    }
}
