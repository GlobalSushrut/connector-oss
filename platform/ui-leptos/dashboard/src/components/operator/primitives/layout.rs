use leptos::prelude::*;

#[component]
pub fn OpSurface(
    #[prop(default = "")] class: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("op-surface rounded-xl border border-zinc-800/60 bg-zinc-900/40 backdrop-blur-sm {class}")>
            {children()}
        </div>
    }
}

#[component]
pub fn OpStack(
    #[prop(default = "vertical")] direction: &'static str,
    #[prop(default = "gap-3")] gap: &'static str,
    children: Children,
) -> impl IntoView {
    let flex = if direction == "horizontal" {
        "flex flex-row items-center"
    } else {
        "flex flex-col"
    };
    view! {
        <div class=format!("{flex} {gap}")>{children()}</div>
    }
}

#[component]
pub fn OpGrid(
    #[prop(default = "grid-cols-1 md:grid-cols-2 xl:grid-cols-3")] cols: &'static str,
    #[prop(default = "gap-4")] gap: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("grid {cols} {gap}")>{children()}</div>
    }
}

#[component]
pub fn OpScrollArea(
    #[prop(default = "")] class: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <div class=format!("overflow-auto min-h-0 {class}")>{children()}</div>
    }
}

#[component]
pub fn OpDivider(#[prop(default = "horizontal")] direction: &'static str) -> impl IntoView {
    if direction == "vertical" {
        view! { <div class="w-px self-stretch bg-zinc-800/80" aria-hidden="true"></div> }.into_any()
    } else {
        view! { <div class="h-px w-full bg-zinc-800/80" aria-hidden="true"></div> }.into_any()
    }
}
