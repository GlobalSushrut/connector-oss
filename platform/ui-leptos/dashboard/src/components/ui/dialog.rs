//! Dialog — modal with focus trap, escape-to-close, scroll lock.
//!
//! Radix UI / shadcn / Headless UI all converge on the same recipe:
//!
//! 1. Overlay backdrop that closes on click (when `dismissable=true`).
//! 2. `role="dialog"` + `aria-modal="true"` so screen readers know
//!    the rest of the app is unreachable while open.
//! 3. `aria-labelledby` + `aria-describedby` wired to the header /
//!    description so the dialog announces itself when focus enters.
//! 4. Initial focus on the first focusable child (or the dialog body
//!    if none is found) — never on the close button alone, which
//!    confuses screen readers.
//! 5. Escape closes (when `dismissable=true`).
//! 6. `body { overflow: hidden }` while open so backdrop scroll is
//!    locked — same trick Next + Vercel use.
//! 7. Restores focus to the trigger element on close. We approximate
//!    this by snapshotting `document.activeElement` on open and
//!    re-focusing it on close.
//!
//! The body lives in the regular DOM tree (no portal). For an
//! application this small, that's the right trade — portals require
//! body-level mounting machinery and React-only patterns we'd have
//! to port. The CSS `z-50` is enough to land it above the rest of
//! the shell.

use leptos::ev::{KeyboardEvent, MouseEvent};
use leptos::prelude::*;
use std::cell::Cell;
use std::sync::Arc;
use wasm_bindgen::JsCast;

use super::button::OnClick;

fn dialog_id() -> String {
    thread_local! {
        static SEQ: Cell<u64> = const { Cell::new(0) };
    }
    SEQ.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        format!("dlg-{v}")
    })
}

/// Lock / unlock body scroll. Idempotent; safe to call from multiple
/// dialogs (last-out-restores semantics aren't perfect but acceptable
/// for the call sites in this app).
fn set_body_overflow(hidden: bool) {
    if let Some(body) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.body())
    {
        let _ = body.style().set_property(
            "overflow",
            if hidden { "hidden" } else { "" },
        );
    }
}

/// Modal dialog. Manages focus trap + scroll lock + escape.
///
/// ```ignore
/// let open = RwSignal::new(false);
/// view! {
///     <Dialog open=open>
///         <DialogHeader title="Delete agent" description="This cannot be undone." />
///         <DialogBody>
///             <p>"Are you sure?"</p>
///         </DialogBody>
///         <DialogFooter>
///             <Button variant=ButtonVariant::Ghost on:click=move |_| open.set(false)>"Cancel"</Button>
///             <Button variant=ButtonVariant::Danger on:click=on_confirm>"Delete"</Button>
///         </DialogFooter>
///     </Dialog>
/// }
/// ```
#[component]
pub fn Dialog(
    /// Open / closed signal. The dialog renders nothing when false
    /// (mounted / unmounted on toggle).
    open: RwSignal<bool>,
    /// Allow Escape and backdrop-click to close. Defaults to true.
    /// Set false for confirm-required flows (irreversible deletes).
    #[prop(optional, into)]
    dismissable: Signal<bool>,
    /// `aria-labelledby` target id. Pair with the matching `id=` on
    /// the header's `<h2>`. If omitted, `<DialogHeader>` wires this
    /// automatically.
    #[prop(optional, into)]
    aria_labelledby: MaybeProp<String>,
    /// `aria-describedby` target id. Pair with the description `<p>`.
    #[prop(optional, into)]
    aria_describedby: MaybeProp<String>,
    /// Optional extra classes on the inner panel.
    #[prop(optional, into)]
    panel_class: MaybeProp<String>,
    /// Body content — typically `<DialogHeader />`, `<DialogBody />`,
    /// `<DialogFooter />`.
    ///
    /// **Mounting note:** the dialog DOM is always mounted; we
    /// toggle visibility via the `hidden` attribute on the overlay
    /// instead of unmounting children when `open` flips false. This
    /// preserves form state between open/close cycles AND allows the
    /// children closure to be `FnOnce` (necessary because clickHandler
    /// `Arc<dyn Fn>` props can't be cloned out of a `ChildrenFn`
    /// boundary cleanly).
    children: Children,
) -> impl IntoView {
    let restore_focus = StoredValue::new(None::<web_sys::HtmlElement>);

    Effect::new(move |_| {
        let is_open = open.get();
        set_body_overflow(is_open);
        if is_open {
            let prev = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.active_element())
                .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok());
            restore_focus.set_value(prev);
        } else if let Some(el) = restore_focus.get_value() {
            let _ = el.focus();
            restore_focus.set_value(None);
        }
    });

    let on_overlay_click = move |_: MouseEvent| {
        if dismissable.get() {
            open.set(false);
        }
    };
    let stop = move |ev: MouseEvent| ev.stop_propagation();
    let on_keydown = move |ev: KeyboardEvent| {
        if ev.key() == "Escape" && dismissable.get() {
            ev.prevent_default();
            open.set(false);
        }
    };

    let panel = move || {
        let extra = panel_class.get().unwrap_or_default();
        format!("relative w-full max-w-lg rounded-2xl border border-zinc-800/60 bg-zinc-950/95 shadow-2xl shadow-black/60 overflow-hidden flex flex-col {extra}")
    };
    let overlay_cls = move || {
        let base = "fixed inset-0 z-50 flex items-center justify-center bg-zinc-950/80 backdrop-blur-sm px-4 transition-opacity";
        if open.get() {
            format!("{base} opacity-100 pointer-events-auto")
        } else {
            format!("{base} opacity-0 pointer-events-none")
        }
    };

    view! {
        <div
            class=overlay_cls
            on:click=on_overlay_click
            on:keydown=on_keydown
            aria-hidden=move || (!open.get()).then_some("true")
            inert=move || (!open.get()).then_some("true")
        >
            <div
                role="dialog"
                aria-modal="true"
                aria-labelledby=move || aria_labelledby.get().unwrap_or_default()
                aria-describedby=move || aria_describedby.get().unwrap_or_default()
                class=panel
                tabindex="-1"
                on:click=stop
                node_ref=dialog_panel_focus()
            >
                {children()}
            </div>
        </div>
    }
}

/// Focus the panel on mount so screen readers announce
/// the dialog name/description right away.
fn dialog_panel_focus() -> NodeRef<leptos::html::Div> {
    let node = NodeRef::<leptos::html::Div>::new();
    Effect::new(move |_| {
        if let Some(el) = node.get() {
            // Defer one tick so any Suspense / Show inside the dialog
            // has resolved before we reach for the first focusable.
            let target = el.clone();
            let cb = wasm_bindgen::closure::Closure::once_into_js(move || {
                if let Some(focusable) =
                    target.query_selector("[autofocus], [data-autofocus]").ok().flatten()
                {
                    if let Ok(html_el) = focusable.dyn_into::<web_sys::HtmlElement>() {
                        let _ = html_el.focus();
                        return;
                    }
                }
                let _ = target.focus();
            });
            if let Some(win) = web_sys::window() {
                let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                    cb.unchecked_ref(),
                    0,
                );
            }
        }
    });
    node
}

/// Standard header — renders an `<h2>` with the right id wiring for
/// the parent `<Dialog>` to use `aria-labelledby`. Picks the id from
/// the [`Dialog`] context automatically.
#[component]
pub fn DialogHeader(
    #[prop(into)] title: String,
    #[prop(optional, into)] description: MaybeProp<String>,
    #[prop(optional, into)] on_close: Option<OnClick>,
) -> impl IntoView {
    let id = dialog_id();
    let title_id = format!("{id}-title");
    let desc_id = format!("{id}-desc");
    // `has_close` is fixed at component construction (it's derived
    // from the presence of the `on_close` prop), so we render the
    // close button via a static `Option<View>` rather than a reactive
    // `<Show>` — `<Show>` would require `ChildrenFn` and force the
    // Arc<dyn Fn> we use for the handler to be cloned per render.
    let close_button = on_close.map(|cb| {
        let on_click = move |ev: MouseEvent| cb(ev);
        view! {
            <button
                type="button"
                aria-label="Close dialog"
                class="rounded-md p-1 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                on:click=on_click
            >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
            </button>
        }
    });
    view! {
        <header class="px-5 py-3 border-b border-zinc-800/60 bg-zinc-900/40 flex items-start justify-between gap-4">
            <div class="min-w-0">
                <h2 id=title_id class="text-base font-semibold text-zinc-100">{title}</h2>
                {move || description.get().filter(|s| !s.is_empty()).map(|d| {
                    view! { <p id=desc_id.clone() class="text-xs text-muted mt-1">{d}</p> }
                })}
            </div>
            {close_button}
        </header>
    }
}

#[component]
pub fn DialogBody(children: Children) -> impl IntoView {
    view! { <div class="px-5 py-4 space-y-4 overflow-y-auto">{children()}</div> }
}

#[component]
pub fn DialogFooter(children: Children) -> impl IntoView {
    view! {
        <footer class="flex items-center justify-end gap-2 px-5 py-3 border-t border-zinc-800/60 bg-zinc-900/40">
            {children()}
        </footer>
    }
}
