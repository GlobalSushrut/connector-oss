//! Button — the workhorse primitive.
//!
//! Variants follow the standard product-design taxonomy used by
//! Stripe, Linear, Vercel: `Primary` (one per surface, conversion-grade),
//! `Secondary` (the most common neutral action), `Ghost` (toolbar /
//! tertiary), `Danger` (destructive, requires explicit colour),
//! `Outline` (border-only neutral), and `Link` (looks like a hyperlink,
//! behaves like a button).
//!
//! Sizes follow the t-shirt scale. `Md` (default) is the keyboard-
//! optimal target (≥40 px tall on mobile via the `pointer: coarse`
//! rule in `input.css`). `Sm` keeps tight UI dense, `Lg` is reserved
//! for hero / landing CTAs.
//!
//! ## Accessibility
//!
//! - Renders a real `<button type=...>` so it's keyboard-reachable and
//!   form-submit aware by default.
//! - Focus ring is brand-coloured via the global `:focus-visible`
//!   rule in `input.css`.
//! - When `loading` is true, the button sets `aria-busy="true"` and
//!   disables interaction, but stays mounted so layout doesn't shift.
//! - `aria-label` is forwarded when the visible label isn't an
//!   accessible name (icon-only buttons must pass it).
//!
//! ## Composition
//!
//! - Icon slot before/after the label via the `leading` / `trailing`
//!   props (any view).
//! - When the button is acting as a link, prefer the `<a>` tag with
//!   `class="btn-primary"` for now — a polymorphic `as` prop is
//!   tracked but not yet implemented to keep the type story simple.

use leptos::ev::MouseEvent;
use leptos::prelude::*;
use std::sync::Arc;

/// Handler type used by all primitives. `Arc<dyn Fn>` is `Clone`,
/// which is what makes the primitives compose inside `<Show>` /
/// `ChildrenFn` boundaries (the children closure may run more than
/// once, so we must be able to clone the handler).
pub type OnClick = Arc<dyn Fn(MouseEvent) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ButtonVariant {
    #[default]
    Primary,
    Secondary,
    Outline,
    Ghost,
    Danger,
    Link,
}

impl ButtonVariant {
    fn class(self) -> &'static str {
        match self {
            ButtonVariant::Primary => {
                "bg-brand text-white hover:brightness-110 active:brightness-95 shadow-lg shadow-brand/20"
            }
            ButtonVariant::Secondary => {
                "bg-zinc-800 text-zinc-100 hover:bg-zinc-700 border border-zinc-700"
            }
            ButtonVariant::Outline => {
                "bg-transparent text-zinc-200 border border-zinc-700 hover:bg-zinc-800/60 hover:border-zinc-600"
            }
            ButtonVariant::Ghost => {
                "bg-transparent text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-100"
            }
            ButtonVariant::Danger => {
                "bg-danger text-white hover:brightness-110 active:brightness-95 shadow-lg shadow-danger/20"
            }
            ButtonVariant::Link => {
                "bg-transparent text-brand hover:underline underline-offset-4 px-0 py-0"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ButtonSize {
    Sm,
    #[default]
    Md,
    Lg,
    /// Square icon-only button — must pair with an `aria-label`.
    Icon,
}

impl ButtonSize {
    fn class(self) -> &'static str {
        match self {
            ButtonSize::Sm => "h-8 px-3 text-xs rounded-md gap-1.5",
            ButtonSize::Md => "h-10 px-4 text-sm rounded-lg gap-2",
            ButtonSize::Lg => "h-12 px-6 text-base rounded-xl gap-2.5",
            ButtonSize::Icon => "h-10 w-10 p-0 rounded-lg",
        }
    }
}

const BASE: &str =
    "inline-flex items-center justify-center font-medium select-none transition-[background,color,box-shadow,filter] disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950";

/// Inline spinner used during the `loading=true` state.
#[component]
fn ButtonSpinner() -> impl IntoView {
    view! {
        <svg
            aria-hidden="true"
            class="animate-spin h-4 w-4"
            xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"
        >
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
    }
}

/// The `Button` primitive.
///
/// ```ignore
/// view! {
///     <Button variant=ButtonVariant::Primary on:click=on_save>
///         "Save changes"
///     </Button>
/// }
/// ```
#[component]
pub fn Button(
    /// Visual variant. Defaults to `Primary`.
    #[prop(optional, into)]
    variant: Signal<ButtonVariant>,
    /// Visual size. Defaults to `Md`.
    #[prop(optional, into)]
    size: Signal<ButtonSize>,
    /// HTML `type=` attribute. Defaults to `"button"` so a button inside
    /// a form doesn't accidentally submit. Pass `"submit"` for the
    /// primary form CTA.
    #[prop(optional, into)]
    button_type: MaybeProp<String>,
    /// Disable interaction. Drives both `disabled` and `aria-disabled`.
    #[prop(optional, into)]
    disabled: Signal<bool>,
    /// Show an inline spinner and set `aria-busy`. Use during async
    /// operations triggered by the button.
    #[prop(optional, into)]
    loading: Signal<bool>,
    /// Accessible label for icon-only buttons. Required when `children`
    /// is purely visual; ignored otherwise.
    #[prop(optional, into)]
    aria_label: MaybeProp<String>,
    /// Optional leading slot (icon, badge).
    #[prop(optional)]
    leading: Option<Children>,
    /// Optional trailing slot.
    #[prop(optional)]
    trailing: Option<Children>,
    /// Click handler. Wrapped in `Arc` so the same handler can be
    /// reused across re-renders inside `<Show>` / `ChildrenFn`
    /// boundaries without rebuilding closures per mount.
    #[prop(optional, into)]
    on_click: Option<OnClick>,
    /// Extra utility classes appended after the variant + size classes.
    #[prop(optional, into)]
    class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let ty = move || button_type.get().unwrap_or_else(|| "button".to_string());
    let extra = move || class.get().unwrap_or_default();
    let cls = move || {
        format!(
            "{BASE} {v} {s} {extra}",
            v = variant.get().class(),
            s = size.get().class(),
            extra = extra(),
        )
    };
    let aria = move || aria_label.get();
    let on_click_handler = move |ev: MouseEvent| {
        if disabled.get() || loading.get() {
            ev.prevent_default();
            return;
        }
        if let Some(cb) = on_click.as_ref() {
            cb(ev);
        }
    };

    view! {
        <button
            type=ty
            class=cls
            disabled=move || disabled.get() || loading.get()
            aria-disabled=move || (disabled.get() || loading.get()).then_some("true")
            aria-busy=move || loading.get().then_some("true")
            aria-label=aria
            on:click=on_click_handler
        >
            {move || loading.get().then(|| view! { <ButtonSpinner /> })}
            {leading.map(|f| f())}
            <span>{children()}</span>
            {trailing.map(|f| f())}
        </button>
    }
}
