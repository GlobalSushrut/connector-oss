use leptos::prelude::*;

use crate::components::operator::primitives::{OpButton, OpButtonVariant};

#[component]
pub fn OpErrorHero(
    title: String,
    detail: String,
    #[prop(default = false)] show_fix: bool,
) -> impl IntoView {
    view! {
        <div class="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4">
            <p class="text-xs font-semibold uppercase tracking-wide text-amber-400">"What's wrong"</p>
            <h3 class="mt-1 text-sm font-semibold text-zinc-100">{title}</h3>
            <p class="mt-1 text-xs text-zinc-400">{detail}</p>
            {show_fix.then(|| view! {
                <div class="mt-3">
                    <OpButton label="Fix now".to_string() variant=OpButtonVariant::Primary />
                </div>
            })}
        </div>
    }
}
