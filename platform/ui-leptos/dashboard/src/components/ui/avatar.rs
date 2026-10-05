//! Avatar — image with initials fallback.
//!
//! Industry standard: a circular avatar with an `<img>` if one is
//! available, falling back to coloured initials so empty states never
//! show a broken-image icon. The colour is deterministic per-name so
//! the same user always gets the same chip.

use leptos::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AvatarSize {
    Xs,
    Sm,
    #[default]
    Md,
    Lg,
    Xl,
}

impl AvatarSize {
    fn class(self) -> &'static str {
        match self {
            AvatarSize::Xs => "h-6 w-6 text-[10px]",
            AvatarSize::Sm => "h-8 w-8 text-xs",
            AvatarSize::Md => "h-10 w-10 text-sm",
            AvatarSize::Lg => "h-12 w-12 text-base",
            AvatarSize::Xl => "h-16 w-16 text-lg",
        }
    }
}

const PALETTE: &[&str] = &[
    "bg-brand/20 text-brand",
    "bg-success/20 text-success",
    "bg-warn/20 text-warn",
    "bg-info/20 text-info",
    "bg-purple-500/20 text-purple-300",
    "bg-pink-500/20 text-pink-300",
    "bg-cyan-500/20 text-cyan-300",
];

fn initials(name: &str) -> String {
    let mut chars = String::new();
    for part in name.split_whitespace().take(2) {
        if let Some(c) = part.chars().next() {
            chars.push(c.to_ascii_uppercase());
        }
    }
    if chars.is_empty() {
        chars.push('?');
    }
    chars
}

fn palette_class(name: &str) -> &'static str {
    let h: u32 = name.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
    PALETTE[(h as usize) % PALETTE.len()]
}

/// Avatar with image + initials fallback.
///
/// ```ignore
/// view! {
///     <Avatar name="Alice Operator" src=None size=AvatarSize::Sm />
/// }
/// ```
#[component]
pub fn Avatar(
    /// Name used for both `alt` text and the initials fallback.
    #[prop(into)]
    name: String,
    /// Optional image URL. When `None` or empty, initials are shown.
    #[prop(optional, into)]
    src: MaybeProp<String>,
    #[prop(optional, into)] size: Signal<AvatarSize>,
    #[prop(optional, into)] class: MaybeProp<String>,
) -> impl IntoView {
    let name_for_initials = name.clone();
    let name_for_palette = name.clone();
    let alt = name.clone();
    let cls = move || {
        let extra = class.get().unwrap_or_default();
        let size_cls = size.get().class();
        format!(
            "inline-flex items-center justify-center rounded-full overflow-hidden font-semibold select-none ring-1 ring-inset ring-white/5 {size_cls} {extra}"
        )
    };
    // Both the palette colour and the initials are derived from
    // `name`, which is fixed for the lifetime of the component, so we
    // compute the final class string once instead of each render.
    let palette_cls = palette_class(&name_for_palette).to_string();
    let has_src = move || src.get().map(|s| !s.is_empty()).unwrap_or(false);

    let init = initials(&name_for_initials);
    let fallback_span_cls = format!(
        "flex h-full w-full items-center justify-center {palette_cls}"
    );
    let init_for_text = init.clone();
    let name_for_sr = name_for_initials.clone();
    view! {
        <span class=cls>
            <Show
                when=has_src
                fallback=move || {
                    let init_text = init_for_text.clone();
                    let sr_text = name_for_sr.clone();
                    let span_cls = fallback_span_cls.clone();
                    view! {
                        <span class=span_cls aria-hidden="true">
                            {init_text}
                        </span>
                        <span class="sr-only">{sr_text}</span>
                    }
                }
            >
                <img
                    src=move || src.get().unwrap_or_default()
                    alt=alt.clone()
                    class="h-full w-full object-cover"
                    loading="lazy"
                    decoding="async"
                />
            </Show>
        </span>
    }
}
