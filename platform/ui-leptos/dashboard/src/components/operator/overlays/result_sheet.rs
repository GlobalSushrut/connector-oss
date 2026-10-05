use leptos::prelude::*;
use std::sync::Arc;

use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpIconButton};

/// O07 — post dry-run human summary sheet.
#[component]
pub fn OpResultSheet(
    open: ReadSignal<bool>,
    set_open: WriteSignal<bool>,
    title: ReadSignal<String>,
    summary: ReadSignal<String>,
    #[prop(optional, default = "Action result")]
    eyebrow: &'static str,
    #[prop(optional, default = false)]
    danger: bool,
) -> impl IntoView {
    let eyebrow_class = if danger {
        "text-[10px] font-semibold uppercase tracking-wide text-rose-400"
    } else {
        "text-[10px] font-semibold uppercase tracking-wide text-emerald-400"
    };
    view! {
        <div
            class=move || {
                if open.get() {
                    "fixed inset-0 z-50 overflow-y-auto"
                } else {
                    "hidden"
                }
            }
            role="dialog"
            aria-modal="true"
        >
            <button
                type="button"
                class="fixed inset-0 bg-black/50 backdrop-blur-sm"
                aria-label="Close result"
                on:click=move |_| set_open.set(false)
            ></button>
            <div class="relative flex min-h-full items-start justify-center p-4 sm:items-center">
            <div class=move || {
                if danger {
                    "relative w-full max-w-lg rounded-xl border border-rose-900/50 bg-zinc-950 p-5 shadow-2xl"
                } else {
                    "relative w-full max-w-lg rounded-xl border border-zinc-800 bg-zinc-950 p-5 shadow-2xl"
                }
            }>
                <div class="mb-3 flex items-start justify-between gap-2">
                    <div>
                        <p class=eyebrow_class>{eyebrow}</p>
                        <h2 class="mt-1 text-base font-semibold text-zinc-100">{move || title.get()}</h2>
                    </div>
                    <OpIconButton label="Close".to_string() on_click=Arc::new(move |_| set_open.set(false))>
                        <span>"×"</span>
                    </OpIconButton>
                </div>
                <p class="text-sm text-zinc-300 whitespace-pre-wrap">{move || summary.get()}</p>
                <div class="mt-4 flex justify-end">
                    <OpButton
                        label="Done".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| set_open.set(false))
                    />
                </div>
            </div>
            </div>
        </div>
    }
}
