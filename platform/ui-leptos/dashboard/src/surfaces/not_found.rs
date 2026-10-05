use leptos::prelude::*;

use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpEmptyState};

#[component]
pub fn NotFoundSurface() -> impl IntoView {
    view! {
        <div class="flex w-full items-center justify-center px-6 py-16">
            <OpEmptyState
                title="Page not found"
                description="That route isn't part of the operator shell. Use ⌘K or return to RUN."
            >
                <div class="flex gap-2">
                    <a href="/run"><OpButton label="Go to RUN".to_string() /></a>
                    <a href="/setup"><OpButton label="SETUP".to_string() variant=OpButtonVariant::Ghost /></a>
                </div>
            </OpEmptyState>
        </div>
    }
}
