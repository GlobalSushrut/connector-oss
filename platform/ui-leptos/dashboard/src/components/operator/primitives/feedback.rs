use leptos::prelude::*;

#[component]
pub fn OpSpinner(#[prop(default = "md")] size: &'static str) -> impl IntoView {
    let dim = match size {
        "sm" => "h-4 w-4 border",
        "lg" => "h-8 w-8 border-2",
        _ => "h-6 w-6 border-2",
    };
    view! {
        <div
            class=format!("{dim} border-zinc-700 border-t-indigo-500 rounded-full animate-spin")
            role="status"
            aria-label="Loading"
        ></div>
    }
}

#[component]
pub fn OpSkeleton(#[prop(default = "h-4 w-3/4")] class: &'static str) -> impl IntoView {
    view! {
        <div class=format!("animate-pulse rounded-md bg-zinc-800/60 {class}") aria-hidden="true"></div>
    }
}

#[component]
pub fn OpEmptyState(
    title: &'static str,
    description: &'static str,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <div class="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <p class="text-sm font-medium text-zinc-300">{title}</p>
            <p class="text-xs text-zinc-500 max-w-sm">{description}</p>
            {children.map(|c| view! { <div class="mt-2">{c()}</div> })}
        </div>
    }
}

#[component]
pub fn OpProgress(#[prop(default = 0)] percent: u8) -> impl IntoView {
    let pct = percent.min(100);
    view! {
        <div class="h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden" role="progressbar" aria-valuenow=pct aria-valuemin="0" aria-valuemax="100">
            <div class="h-full bg-indigo-500 transition-all duration-300" style=format!("width: {pct}%")></div>
        </div>
    }
}
