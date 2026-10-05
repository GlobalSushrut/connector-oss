//! Uniform loading / empty / error / unavailable states for operator surfaces.

use leptos::prelude::*;
use std::sync::Arc;

use crate::api::ApiError;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpEmptyState, OpSkeleton, OpSpinner,
};

#[component]
pub fn OpLoadingBlock(
    #[prop(optional, into, default = "Loading…".to_string())] message: String,
) -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center gap-3 py-12" role="status" aria-busy="true">
            <OpSpinner />
            <p class="text-xs text-zinc-500">{message}</p>
        </div>
    }
}

#[component]
pub fn OpSkeletonCards(#[prop(default = 3usize)] count: usize) -> impl IntoView {
    view! {
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {(0..count).map(|_| view! { <OpSkeleton class="h-36 w-full rounded-xl" /> }).collect_view()}
        </div>
    }
}

#[component]
pub fn OpApiErrorBanner(
    error: ApiError,
    #[prop(optional)] on_retry: Option<Arc<dyn Fn() + Send + Sync>>,
) -> impl IntoView {
    let status = error.status;
    let message = error.message.clone();
    let retry = on_retry;
    view! {
        <div
            class="rounded-lg border border-red-900/50 bg-red-950/40 px-4 py-3 text-sm text-red-200"
            role="alert"
        >
            <p class="font-medium">
                {if message.contains("admission_denied") || message.contains("Admission") {
                    "Denied by admission".to_string()
                } else if status == 401 || status == 403 {
                    "Not authorized for this data.".to_string()
                } else if status == 0 {
                    "Unavailable.".to_string()
                } else {
                    format!("Request failed ({status})")
                }}
            </p>
            <p class="mt-1 text-xs text-red-300/80">{message}</p>
            {retry.map(|cb| {
                view! {
                    <div class="mt-3">
                        <OpButton
                            label="Retry".to_string()
                            variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| cb())
                        />
                    </div>
                }
            })}
        </div>
    }
}

#[component]
pub fn OpUnavailable(
    #[prop(default = "Unavailable")] title: &'static str,
    #[prop(default = "This capability is not available on this node.")] detail: &'static str,
) -> impl IntoView {
    view! {
        <OpEmptyState title=title description=detail />
    }
}

#[component]
pub fn OpDevDisclosure(
    #[prop(into)] label: String,
    #[prop(into)] raw: String,
) -> impl IntoView {
    view! {
        <details class="rounded-lg border border-zinc-800/60 bg-zinc-950/40 p-3 text-xs">
            <summary class="cursor-pointer select-none text-zinc-500 hover:text-zinc-300">
                {label}
            </summary>
            <pre class="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px] text-zinc-400">
                {raw}
            </pre>
        </details>
    }
}
