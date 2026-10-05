//! Tooltip — hover + focus + keyboard accessible.
//!
//! WAI-ARIA tooltip pattern: the trigger references the tip via
//! `aria-describedby`, the tip has `role="tooltip"`, and the tip
//! appears on both `pointerover` and `focus`. Escape dismisses while
//! keyboard focus is on the trigger.
//!
//! This is a CSS-positioned tooltip (no Floating UI / Popper port —
//! that's overkill for a single direction). Pages that need
//! collision-aware positioning should opt for a popover library when
//! we land one; for now, default placement is top with sensible
//! padding.

use leptos::ev::{FocusEvent, KeyboardEvent, PointerEvent};
use leptos::prelude::*;
use std::cell::Cell;
use std::rc::Rc;

fn next_id() -> String {
    thread_local! {
        static SEQ: Cell<u64> = const { Cell::new(0) };
    }
    SEQ.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        format!("tt-{v}")
    })
}

/// Wraps a single trigger child with an accessible tooltip.
///
/// ```ignore
/// view! {
///     <Tooltip content="Open the search palette">
///         <button class="btn-ghost">"⌘K"</button>
///     </Tooltip>
/// }
/// ```
#[component]
pub fn Tooltip(
    /// Text shown inside the tooltip. Plain string only — anything
    /// richer wants a Popover, not a tooltip.
    #[prop(into)]
    content: String,
    /// Trigger element. Should be a single focusable child (button or
    /// anchor); otherwise focus/keyboard accessibility breaks.
    children: Children,
    /// Optional class on the outer span wrapper.
    #[prop(optional, into)]
    class: MaybeProp<String>,
) -> impl IntoView {
    let id = next_id();
    let open = RwSignal::new(false);
    let trigger_open = Rc::new(move || open.set(true));
    let trigger_close = Rc::new(move || open.set(false));

    let on_enter = {
        let t = trigger_open.clone();
        move |_: PointerEvent| t()
    };
    let on_leave = {
        let t = trigger_close.clone();
        move |_: PointerEvent| t()
    };
    let on_focus = {
        let t = trigger_open.clone();
        move |_: FocusEvent| t()
    };
    let on_blur = {
        let t = trigger_close.clone();
        move |_: FocusEvent| t()
    };
    let on_keydown = {
        let t = trigger_close.clone();
        move |ev: KeyboardEvent| {
            if ev.key() == "Escape" {
                t();
            }
        }
    };

    let wrapper_cls = move || {
        let extra = class.get().unwrap_or_default();
        format!("relative inline-flex {extra}")
    };
    let tip_cls = move || {
        let base = "pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 rounded-md text-[11px] font-medium text-zinc-100 bg-zinc-800 border border-zinc-700/60 shadow-lg whitespace-nowrap z-50 transition-opacity duration-100";
        let state = if open.get() { "opacity-100" } else { "opacity-0" };
        format!("{base} {state}")
    };
    let tip_id = id.clone();

    view! {
        <span
            class=wrapper_cls
            on:pointerover=on_enter
            on:pointerleave=on_leave
            on:focusin=on_focus
            on:focusout=on_blur
            on:keydown=on_keydown
            aria-describedby=tip_id.clone()
        >
            {children()}
            <span
                id=id
                role="tooltip"
                class=tip_cls
                aria-hidden=move || (!open.get()).then_some("true")
            >
                {content}
            </span>
        </span>
    }
}
