//! App-level error boundary.
//!
//! Leptos provides `ErrorBoundary` for `Result`-typed views, but
//! panics inside an async block or signal closure can still take down
//! the whole render tree and leave the user staring at a blank page.
//! `console_error_panic_hook` (already installed in `main.rs`) keeps a
//! stack trace flowing to the console, but the user still sees
//! nothing.
//!
//! `<AppErrorBoundary>` wraps the route tree and:
//!
//! 1. Catches `Result::Err` from any descendant that opted into
//!    `Result`-returning views (via Leptos's native machinery).
//! 2. Surfaces a recoverable "Something broke" panel with the error
//!    message and a "Reload page" button.
//!
//! Pattern matches React's error.tsx / `ErrorBoundary` and Next.js's
//! `app/error.tsx` convention.

#![allow(dead_code)]

use leptos::error::Errors;
use leptos::prelude::*;

/// Wrap the route tree (or any subtree where rendering can fail) with
/// this. Children that return `Result<T, E>` will have their errors
/// caught here instead of crashing the whole shell.
#[component]
pub fn AppErrorBoundary(children: Children) -> impl IntoView {
    let fallback = |errors: ArcRwSignal<Errors>| {
        view! { <AppErrorPanel errors=errors /> }
    };
    view! {
        <ErrorBoundary fallback=fallback>
            {children()}
        </ErrorBoundary>
    }
}

#[component]
fn AppErrorPanel(errors: ArcRwSignal<Errors>) -> impl IntoView {
    let reload = move |_| {
        if let Some(win) = web_sys::window() {
            let _ = win.location().reload();
        }
    };
    view! {
        <div
            class="min-h-[60vh] flex items-center justify-center px-4"
            role="alert"
            aria-live="assertive"
        >
            <div class="max-w-lg w-full card space-y-4">
                <div class="flex items-start gap-3">
                    <div class="rounded-lg bg-danger-10 border border-danger-30 p-2 text-danger shrink-0">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="8" x2="12" y2="12"></line>
                            <line x1="12" y1="16" x2="12.01" y2="16"></line>
                        </svg>
                    </div>
                    <div class="min-w-0">
                        <h2 class="text-base font-semibold text-zinc-100">"Something went wrong"</h2>
                        <p class="mt-1 text-sm text-zinc-400">
                            "The dashboard hit an unexpected error rendering this view. Your data is safe — reload to recover. If it persists, the developer console has the full stack trace."
                        </p>
                    </div>
                </div>

                // Error detail — gated to the developer-view toggle so
                // operators see a clean message and engineers see the
                // raw cause.
                <details class="dev-only rounded-lg border border-zinc-800 bg-zinc-950/60 p-3 text-xs">
                    <summary class="cursor-pointer text-zinc-400 hover:text-zinc-200 select-none">"Error detail (developer view)"</summary>
                    <ul class="mt-2 space-y-1 font-mono text-danger break-all">
                        {move || {
                            errors.get().into_iter().map(|(_, e)| {
                                view! { <li>{format!("{e}")}</li> }
                            }).collect_view()
                        }}
                    </ul>
                </details>

                <div class="flex items-center gap-2">
                    <button
                        type="button"
                        class="btn-primary"
                        on:click=reload
                    >
                        "Reload page"
                    </button>
                    <a href="/run" class="btn-secondary">"Go to RUN"</a>
                </div>
            </div>
        </div>
    }
}
