use leptos::prelude::*;

use super::controls::OpClick;

#[component]
pub fn OpAlertBar(
    #[prop(into)] message: String,
    #[prop(default = "info")] variant: &'static str,
    #[prop(optional)] on_dismiss: Option<OpClick>,
) -> impl IntoView {
    let border = match variant {
        "warn" => "border-amber-500/40 bg-amber-500/10 text-amber-200",
        "danger" => "border-red-500/40 bg-red-500/10 text-red-200",
        _ => "border-sky-500/40 bg-sky-500/10 text-sky-200",
    };
    view! {
        <div class=format!("flex shrink-0 items-center gap-3 border-b px-4 py-2 text-xs {border}") role="status">
            <span class="flex-1">{message}</span>
            {on_dismiss.map(|h| {
                let handler = h.clone();
                view! {
                    <button
                        type="button"
                        class="rounded px-2 py-0.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
                        aria-label="Dismiss alert"
                        on:click=move |ev| handler(ev)
                    >
                        "×"
                    </button>
                }
            })}
        </div>
    }
}

#[component]
pub fn OpNotifyBell(
    unread: Option<u64>,
    #[prop(optional)] on_click: Option<OpClick>,
) -> impl IntoView {
    let count = unread.unwrap_or(0);
    let aria = if count > 0 {
        format!("{count} unread notifications")
    } else {
        "Notifications".to_string()
    };
    let handler = on_click.clone();
    view! {
        <button
            type="button"
            class="relative inline-flex h-8 w-8 items-center justify-center rounded-lg text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
            aria-label=aria
            on:click=move |ev| {
                if let Some(ref h) = handler {
                    h(ev);
                }
            }
        >
            <span aria-hidden="true">"🔔"</span>
            {(count > 0).then(|| view! {
                <span class="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-indigo-500 px-1 text-[9px] font-bold text-white">
                    {count.min(99).to_string()}
                </span>
            })}
        </button>
    }
}

#[component]
pub fn OpModeButton(
    href: &'static str,
    icon: &'static str,
    label: &'static str,
    #[prop(into)] active: Signal<bool>,
    #[prop(default = 0)] badge: u64,
) -> impl IntoView {
    view! {
        <a
            href=href
            class=move || {
                if active.get() {
                    "relative op-mode-btn op-mode-btn-active flex w-full flex-col items-center gap-0.5 rounded-xl px-1.5 py-2 text-[10px] font-semibold no-underline"
                } else {
                    "relative op-mode-btn flex w-full flex-col items-center gap-0.5 rounded-xl px-1.5 py-2 text-[10px] font-semibold text-zinc-500 hover:text-zinc-200 no-underline"
                }
            }
        >
            <span class="text-base leading-none">{icon}</span>
            <span class="leading-tight">{label}</span>
            {(badge > 0).then(|| view! {
                <span class="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-amber-500 px-1 text-[9px] font-bold text-zinc-950">
                    {badge.to_string()}
                </span>
            })}
        </a>
    }
}
