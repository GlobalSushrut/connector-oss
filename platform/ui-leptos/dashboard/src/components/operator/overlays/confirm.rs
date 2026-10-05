use leptos::prelude::*;
use std::sync::Arc;

use crate::components::operator::primitives::{OpButton, OpButtonVariant};

#[component]
pub fn OpConfirm(
    open: ReadSignal<bool>,
    set_open: WriteSignal<bool>,
    title: String,
    message: String,
    #[prop(default = "Confirm")] confirm_label: &'static str,
    on_confirm: impl Fn() + 'static + Clone + Send + Sync,
) -> impl IntoView {
    let confirm = on_confirm.clone();
    view! {
        <Show when=move || open.get()>
            <div class="fixed inset-0 z-50 flex items-center justify-center p-4" role="alertdialog" aria-modal="true">
                <button
                    type="button"
                    class="absolute inset-0 bg-black/60 backdrop-blur-sm"
                    aria-label="Cancel"
                    on:click=move |_| set_open.set(false)
                ></button>
                <div class="relative w-full max-w-sm rounded-xl border border-red-900/40 bg-zinc-950 p-5 shadow-2xl">
                    <h2 class="text-base font-semibold text-zinc-100">{title.clone()}</h2>
                    <p class="mt-2 text-sm text-zinc-400">{message.clone()}</p>
                    <div class="mt-5 flex justify-end gap-2">
                        <OpButton
                            label="Cancel".to_string()
                            variant=OpButtonVariant::Ghost
                            on_click=Arc::new(move |_| set_open.set(false))
                        />
                        <OpButton
                            label=confirm_label.to_string()
                            variant=OpButtonVariant::Danger
                            on_click={
                                let confirm = confirm.clone();
                                Arc::new(move |_| {
                                    confirm();
                                    set_open.set(false);
                                })
                            }
                        />
                    </div>
                </div>
            </div>
        </Show>
    }
}
