//! TextField — labelled, validated input.
//!
//! Replaces inline `<input class="input" />` with a composed control
//! that always renders the label, helper text, and error text together
//! as one block. Tying them with `aria-describedby` + `aria-invalid`
//! is what makes screen-reader announcements correct without each call
//! site having to remember.
//!
//! Industry baselines this primitive enforces:
//!
//! 1. Every input has a visible `<label>` linked by `for=`. Placeholder
//!    is *not* a label — that's a WCAG 2.1 §3.3.2 violation and a
//!    constant source of usability bugs.
//! 2. Error messages are rendered in a `<p role="alert">` so they
//!    announce when validation fails.
//! 3. Helper text always lives in a `<p>` linked by `aria-describedby`
//!    so it's read in the same breath as the field's name.
//! 4. Required fields show a `*` with `aria-hidden="true"` and an
//!    invisible "required" text alternative for screen readers.

use leptos::ev::{Event, FocusEvent};
use leptos::prelude::*;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextFieldKind {
    #[default]
    Text,
    Email,
    Password,
    Number,
    Search,
    Url,
    Tel,
}

impl TextFieldKind {
    fn as_str(self) -> &'static str {
        match self {
            TextFieldKind::Text => "text",
            TextFieldKind::Email => "email",
            TextFieldKind::Password => "password",
            TextFieldKind::Number => "number",
            TextFieldKind::Search => "search",
            TextFieldKind::Url => "url",
            TextFieldKind::Tel => "tel",
        }
    }
}

fn next_id() -> String {
    use std::cell::Cell;
    thread_local! {
        static SEQ: Cell<u64> = const { Cell::new(0) };
    }
    SEQ.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        format!("tf-{v}")
    })
}

/// Labelled input with helper text, error text, optional leading
/// icon, and validation states wired into ARIA.
///
/// ```ignore
/// let (email, set_email) = signal(String::new());
/// view! {
///     <TextField
///         label="Email"
///         value=email
///         on_input=Box::new(move |v| set_email.set(v))
///         placeholder="you@example.com"
///         kind=TextFieldKind::Email
///         required=true
///     />
/// }
/// ```
#[component]
pub fn TextField(
    #[prop(into)] label: String,
    #[prop(optional, into)] value: Signal<String>,
    #[prop(optional)] on_input: Option<Box<dyn Fn(String) + Send + Sync>>,
    #[prop(optional)] on_blur: Option<Box<dyn Fn(FocusEvent) + Send + Sync>>,
    #[prop(optional, into)] placeholder: MaybeProp<String>,
    #[prop(optional, into)] helper: MaybeProp<String>,
    /// Error message. When `Some(non-empty)`, the field renders in
    /// the error state and the message is announced via `role=alert`.
    #[prop(optional, into)]
    error: MaybeProp<String>,
    #[prop(optional, into)] kind: Signal<TextFieldKind>,
    #[prop(optional, into)] required: Signal<bool>,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional, into)] readonly: Signal<bool>,
    #[prop(optional, into)] autocomplete: MaybeProp<String>,
    /// Optional inline leading icon (e.g. a magnifier in a search box).
    #[prop(optional)]
    leading_icon: Option<Children>,
    /// Optional inline trailing slot (e.g. a "show password" toggle).
    #[prop(optional)]
    trailing: Option<Children>,
    /// Extra utility classes on the outer wrapper.
    #[prop(optional, into)]
    class: MaybeProp<String>,
) -> impl IntoView {
    let id = next_id();
    let helper_id = format!("{id}-helper");
    let error_id = format!("{id}-error");

    let has_error = move || error.get().map(|s| !s.is_empty()).unwrap_or(false);
    let describedby = {
        let helper_id = helper_id.clone();
        let error_id = error_id.clone();
        move || {
            let mut parts = Vec::new();
            if helper.get().map(|s| !s.is_empty()).unwrap_or(false) {
                parts.push(helper_id.clone());
            }
            if has_error() {
                parts.push(error_id.clone());
            }
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(" "))
            }
        }
    };

    let on_input = on_input.map(Arc::new);
    let on_input_handler = move |ev: Event| {
        let v = event_target_value(&ev);
        if let Some(cb) = on_input.as_ref() {
            cb(v);
        }
    };
    let on_blur = on_blur.map(Arc::new);
    let on_blur_handler = move |ev: FocusEvent| {
        if let Some(cb) = on_blur.as_ref() {
            cb(ev);
        }
    };

    let has_leading = leading_icon.is_some();
    let has_trailing = trailing.is_some();
    let wrapper_cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("space-y-1.5 {extra}")
    };
    let input_cls = move || {
        let base = "w-full h-10 rounded-lg bg-zinc-900/80 px-3 text-sm text-zinc-100 placeholder-zinc-500 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950 disabled:opacity-50 disabled:cursor-not-allowed";
        let border = if has_error() {
            "border border-danger/60 focus-visible:ring-danger/60"
        } else {
            "border border-zinc-700/80 focus-visible:ring-brand/60 focus-visible:border-brand/60"
        };
        let lp = if has_leading { "pl-9" } else { "" };
        let tp = if has_trailing { "pr-10" } else { "" };
        format!("{base} {border} {lp} {tp}")
    };

    let id_for_label = id.clone();
    let id_for_input = id.clone();

    view! {
        <div class=wrapper_cls>
            <label
                for=id_for_label
                class="flex items-baseline justify-between text-sm font-medium text-zinc-300"
            >
                <span>
                    {label}
                    <Show when=move || required.get()>
                        <span class="text-danger ml-0.5" aria-hidden="true">"*"</span>
                        <span class="sr-only">" (required)"</span>
                    </Show>
                </span>
            </label>
            <div class="relative">
                {leading_icon.map(|f| view! {
                    <span class="pointer-events-none absolute inset-y-0 left-0 flex items-center justify-center w-9 text-zinc-500" aria-hidden="true">
                        {f()}
                    </span>
                })}
                <input
                    id=id_for_input
                    type=move || kind.get().as_str()
                    class=input_cls
                    prop:value=move || value.get()
                    placeholder=move || placeholder.get().unwrap_or_default()
                    required=move || required.get()
                    disabled=move || disabled.get()
                    readonly=move || readonly.get()
                    aria-invalid=move || has_error().then_some("true")
                    aria-describedby=describedby
                    autocomplete=move || autocomplete.get().unwrap_or_default()
                    on:input=on_input_handler
                    on:blur=on_blur_handler
                />
                {trailing.map(|f| view! {
                    <span class="absolute inset-y-0 right-0 flex items-center pr-2">
                        {f()}
                    </span>
                })}
            </div>
            {move || helper.get().filter(|s| !s.is_empty()).map(|h| {
                view! { <p id=helper_id.clone() class="text-xs text-muted">{h}</p> }
            })}
            {move || error.get().filter(|s| !s.is_empty()).map(|e| {
                view! { <p id=error_id.clone() role="alert" class="text-xs text-danger">{e}</p> }
            })}
        </div>
    }
}
