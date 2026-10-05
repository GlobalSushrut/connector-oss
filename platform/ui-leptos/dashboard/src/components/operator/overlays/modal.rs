use leptos::prelude::*;
use std::sync::Arc;

use crate::components::operator::primitives::OpIconButton;

#[component]
pub fn OpModal(
    open: ReadSignal<bool>,
    set_open: WriteSignal<bool>,
    title: String,
    children: Children,
) -> impl IntoView {
    // Render children once (Children is FnOnce); toggle visibility with class.
    let body = children();
    view! {
        <div
            class=move || {
                if open.get() {
                    "fixed inset-0 z-50 flex items-center justify-center p-4"
                } else {
                    "hidden"
                }
            }
            role="dialog"
            aria-modal="true"
            aria-hidden=move || (!open.get()).to_string()
        >
            <button
                type="button"
                class="absolute inset-0 bg-black/60 backdrop-blur-sm"
                aria-label="Close modal"
                on:click=move |_| set_open.set(false)
            ></button>
            <div class="relative w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-950 p-5 shadow-2xl">
                <div class="mb-4 flex items-center justify-between gap-2">
                    <h2 class="text-base font-semibold text-zinc-100">{title}</h2>
                    <OpIconButton
                        label="Close".to_string()
                        on_click=Arc::new(move |_| set_open.set(false))
                    >
                        <span>"×"</span>
                    </OpIconButton>
                </div>
                {body}
            </div>
        </div>
    }
}
