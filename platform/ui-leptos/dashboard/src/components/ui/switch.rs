//! Switch — accessible on/off toggle.
//!
//! Renders a real `<button role="switch">` with `aria-checked`, the
//! pattern the WAI-ARIA Authoring Practices recommend (and Radix,
//! shadcn, Headless UI all implement). Keyboard support: `Space` and
//! `Enter` toggle, Tab moves on. The visible label and the optional
//! description below it both wire to the switch via `aria-labelledby`
//! and `aria-describedby` so screen readers announce the whole row.

use leptos::ev::MouseEvent;
use leptos::prelude::*;
use std::sync::Arc;

fn next_id() -> String {
    use std::cell::Cell;
    thread_local! {
        static SEQ: Cell<u64> = const { Cell::new(0) };
    }
    SEQ.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        format!("sw-{v}")
    })
}

/// Accessible toggle switch with optional label + description.
///
/// ```ignore
/// let (enabled, set_enabled) = signal(false);
/// view! {
///     <Switch
///         label="Email me when a workflow fails"
///         description="Sent at most every 5 minutes."
///         checked=enabled
///         on_change=Box::new(move |v| set_enabled.set(v))
///     />
/// }
/// ```
#[component]
pub fn Switch(
    /// Visible label for the switch. Always rendered — placeholder
    /// labels and `aria-label` are not acceptable substitutes.
    #[prop(into)]
    label: String,
    #[prop(optional, into)] description: MaybeProp<String>,
    #[prop(optional, into)] checked: Signal<bool>,
    #[prop(optional)] on_change: Option<Box<dyn Fn(bool) + Send + Sync>>,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional, into)] class: MaybeProp<String>,
) -> impl IntoView {
    let id = next_id();
    let label_id = format!("{id}-label");
    let desc_id = format!("{id}-desc");

    let on_change = on_change.map(Arc::new);
    let on_click = move |ev: MouseEvent| {
        ev.prevent_default();
        if disabled.get() {
            return;
        }
        let next = !checked.get();
        if let Some(cb) = on_change.as_ref() {
            cb(next);
        }
    };

    let wrapper_cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("flex items-start gap-3 {extra}")
    };
    let track_cls = move || {
        let base = "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950 disabled:opacity-50 disabled:cursor-not-allowed";
        let state = if checked.get() {
            "bg-brand"
        } else {
            "bg-zinc-700"
        };
        format!("{base} {state}")
    };
    let knob_cls = move || {
        let base = "pointer-events-none absolute top-1 left-1 inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform";
        let state = if checked.get() { "translate-x-5" } else { "translate-x-0" };
        format!("{base} {state}")
    };

    let has_desc = move || description.get().map(|s| !s.is_empty()).unwrap_or(false);
    let describedby = {
        let desc_id = desc_id.clone();
        move || has_desc().then(|| desc_id.clone())
    };

    let id_for_button = id.clone();
    let id_for_label = id.clone();
    let label_id_for_button = label_id.clone();
    let label_id_for_label = label_id.clone();
    view! {
        <div class=wrapper_cls>
            <button
                type="button"
                role="switch"
                id=id_for_button
                class=track_cls
                aria-checked=move || if checked.get() { "true" } else { "false" }
                aria-labelledby=label_id_for_button
                aria-describedby=describedby
                disabled=move || disabled.get()
                on:click=on_click
            >
                <span class=knob_cls></span>
            </button>
            <div class="space-y-0.5 leading-tight">
                <label id=label_id_for_label for=id_for_label class="text-sm text-zinc-200 cursor-pointer select-none">
                    {label}
                </label>
                {move || description.get().filter(|s| !s.is_empty()).map(|d| {
                    view! { <p id=desc_id.clone() class="text-xs text-muted">{d}</p> }
                })}
            </div>
        </div>
    }
}
