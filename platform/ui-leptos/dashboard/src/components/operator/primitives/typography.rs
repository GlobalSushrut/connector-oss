use leptos::prelude::*;

use crate::components::operator::honesty::fmt_unknown_str;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum OpTextVariant {
    #[default]
    Body,
    Title,
    Subtitle,
    Caption,
    Mono,
}

#[component]
pub fn OpText(
    #[prop(into)] text: String,
    #[prop(default = OpTextVariant::Body)] variant: OpTextVariant,
    #[prop(default = "")] class: &'static str,
) -> impl IntoView {
    let base = match variant {
        OpTextVariant::Title => "text-base font-semibold text-zinc-100",
        OpTextVariant::Subtitle => "text-sm text-zinc-400",
        OpTextVariant::Caption => "text-xs text-zinc-500",
        OpTextVariant::Mono => "text-xs font-mono text-zinc-300",
        OpTextVariant::Body => "text-sm text-zinc-200",
    };
    view! { <span class=format!("{base} {class}")>{text}</span> }
}

#[component]
pub fn OpFmtUnknown(#[prop(into)] value: Option<String>) -> impl IntoView {
    view! { <span class="text-zinc-300">{fmt_unknown_str(value.as_deref())}</span> }
}

#[component]
pub fn OpVerifiedBadge(
    verified: bool,
    #[prop(default = false)] pending: bool,
) -> impl IntoView {
    let (label, class) = if verified {
        ("Verified", "bg-emerald-500/15 text-emerald-400 border-emerald-500/30")
    } else if pending {
        ("Pending", "bg-amber-500/15 text-amber-400 border-amber-500/30")
    } else {
        ("Unverified", "bg-zinc-800 text-zinc-500 border-zinc-700")
    };
    view! {
        <span class=format!("inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide {class}")>
            {label}
        </span>
    }
}

#[component]
pub fn OpTimeAgo(#[prop(into)] label: String) -> impl IntoView {
    view! { <span class="text-xs text-zinc-500" title="absolute time on hover">{label}</span> }
}

#[component]
pub fn OpTruncMono(#[prop(into)] text: String) -> impl IntoView {
    let title = text.clone();
    view! {
        <span class="font-mono text-xs text-zinc-400 truncate max-w-[12rem] inline-block align-bottom" title=title>
            {text}
        </span>
    }
}
