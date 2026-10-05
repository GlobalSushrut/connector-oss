use leptos::prelude::*;
use std::sync::Arc;

use crate::components::operator::primitives::OpIconButton;

/// O11 — bottom sheet (mobile-friendly).
#[component]
pub fn OpSheet(
    open: ReadSignal<bool>,
    set_open: WriteSignal<bool>,
    title: String,
    children: Children,
) -> impl IntoView {
    let body = children();
    view! {
        <div
            class=move || {
                if open.get() {
                    "fixed inset-0 z-50 flex items-end"
                } else {
                    "hidden"
                }
            }
            role="dialog"
            aria-modal="true"
        >
            <button
                type="button"
                class="absolute inset-0 bg-black/50"
                aria-label="Close sheet"
                on:click=move |_| set_open.set(false)
            ></button>
            <div class="relative max-h-[80vh] w-full overflow-auto rounded-t-2xl border border-zinc-800 bg-zinc-950 p-4 shadow-2xl">
                <div class="mb-3 flex items-center justify-between">
                    <h2 class="text-sm font-semibold text-zinc-100">{title}</h2>
                    <OpIconButton label="Close".to_string() on_click=Arc::new(move |_| set_open.set(false))>
                        <span>"×"</span>
                    </OpIconButton>
                </div>
                {body}
            </div>
        </div>
    }
}
