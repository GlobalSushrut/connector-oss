//! Global toast system — single queue, push-from-anywhere.
//!
//! Up to now every page owned its own `(flash, set_flash)` signal and
//! rendered a fixed-position `.flash-ok` / `.flash-err` pill. That
//! pattern works for one-screen flows but blocks cross-page toasts
//! (e.g. "Workflow installed — opening…" surfacing after a route
//! change), can't stack, and forces every new feature to re-invent
//! the same state machine.
//!
//! This module is a Sonner / react-hot-toast equivalent:
//!
//! - `provide_toaster()` is called once in `App` (sibling to the other
//!   `provide_*()` setup calls) and seeds the context.
//! - `<Toaster />` is mounted once in `App` near the other global
//!   overlays. It renders a fixed bottom-right stack.
//! - Any descendant calls `toast::success("…")`, `toast::error("…")`,
//!   `toast::warn("…")`, `toast::info("…")` to push a message. The
//!   call site doesn't have to thread a signal through.
//!
//! Each toast auto-dismisses after a level-dependent timeout, can be
//! dismissed manually via the `×` close button, and respects
//! `prefers-reduced-motion` via the CSS in `input.css`.

#![allow(dead_code)]

use leptos::prelude::*;
use std::cell::Cell;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;

/// Toast severity. Drives colour + default timeout. Errors stick
/// around longer (8 s) than ok / info (4 s) so operators can read
/// them; warnings split the difference at 6 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastLevel {
    Success,
    Error,
    Warning,
    Info,
}

impl ToastLevel {
    fn class(self) -> &'static str {
        match self {
            ToastLevel::Success => "toaster-item toaster-success",
            ToastLevel::Error => "toaster-item toaster-error",
            ToastLevel::Warning => "toaster-item toaster-warning",
            ToastLevel::Info => "toaster-item toaster-info",
        }
    }

    fn default_ttl_ms(self) -> i32 {
        match self {
            ToastLevel::Error => 8_000,
            ToastLevel::Warning => 6_000,
            _ => 4_000,
        }
    }

    fn aria_role(self) -> &'static str {
        match self {
            ToastLevel::Error | ToastLevel::Warning => "alert",
            _ => "status",
        }
    }
}

#[derive(Clone)]
struct ToastEntry {
    id: u64,
    level: ToastLevel,
    message: String,
}

#[derive(Clone, Copy)]
pub struct Toaster {
    items: RwSignal<Vec<ToastEntry>>,
}

impl Toaster {
    fn next_id() -> u64 {
        thread_local! {
            static SEQ: Cell<u64> = const { Cell::new(0) };
        }
        SEQ.with(|c| {
            let v = c.get().wrapping_add(1);
            c.set(v);
            v
        })
    }

    pub fn push(self, level: ToastLevel, message: impl Into<String>) {
        let id = Self::next_id();
        let message = message.into();
        self.items.update(|v| {
            // Cap the stack so a runaway producer doesn't paint the
            // screen — Sonner keeps the last 3 visible by default; we
            // allow 5 to leave headroom for chained operations.
            if v.len() >= 5 {
                v.remove(0);
            }
            v.push(ToastEntry {
                id,
                level,
                message,
            });
        });

        // Schedule auto-dismiss. Window may be missing during SSR /
        // tests; the `.ok()` chain makes that a no-op.
        let ttl = level.default_ttl_ms();
        let items = self.items;
        if let Some(win) = web_sys::window() {
            let cb = Closure::once_into_js(move || {
                items.update(|v| v.retain(|t| t.id != id));
            });
            let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.unchecked_ref(),
                ttl,
            );
        }
    }

    pub fn dismiss(self, id: u64) {
        self.items.update(|v| v.retain(|t| t.id != id));
    }
}

/// Seed the toaster context. Call once in `App`.
pub fn provide_toaster() {
    let toaster = Toaster {
        items: RwSignal::new(Vec::new()),
    };
    provide_context(toaster);
}

/// Pull the toaster from context. Panics if `provide_toaster` wasn't
/// called — that's a programmer error, surfaced loudly.
fn toaster() -> Toaster {
    use_context::<Toaster>()
        .expect("`provide_toaster()` must run in App before any toast::* call site")
}

pub mod toast {
    use super::*;

    pub fn success(msg: impl Into<String>) {
        toaster().push(ToastLevel::Success, msg)
    }
    pub fn error(msg: impl Into<String>) {
        toaster().push(ToastLevel::Error, msg)
    }
    pub fn warn(msg: impl Into<String>) {
        toaster().push(ToastLevel::Warning, msg)
    }
    pub fn info(msg: impl Into<String>) {
        toaster().push(ToastLevel::Info, msg)
    }
}

/// Renders the live toast stack. Mount once near the top of `App`
/// (sibling to `<UpdateToast />` etc).
#[component]
pub fn Toaster() -> impl IntoView {
    let Some(toaster) = use_context::<super::toaster::Toaster>() else {
        // Don't crash — render nothing and emit a console warning so
        // the integration mistake is visible without breaking the app.
        web_sys::console::warn_1(
            &"<Toaster /> mounted without provide_toaster(); skipping render.".into(),
        );
        return view! { <div></div> }.into_any();
    };

    view! {
        <div class="toaster-stack" aria-label="Notifications" aria-live="polite">
            <For
                each=move || toaster.items.get()
                key=|t| t.id
                children=move |t: ToastEntry| {
                    let id = t.id;
                    let role = t.level.aria_role();
                    let on_close = move |_| toaster.dismiss(id);
                    view! {
                        <div class=t.level.class() role=role aria-live=role>
                            <span class="flex-1 break-words">{t.message}</span>
                            <button
                                type="button"
                                class="toaster-close"
                                aria-label="Dismiss notification"
                                on:click=on_close
                            >
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                </svg>
                            </button>
                        </div>
                    }
                }
            />
        </div>
    }
    .into_any()
}
