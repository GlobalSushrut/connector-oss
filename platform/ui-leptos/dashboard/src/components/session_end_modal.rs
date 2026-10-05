//! Session-end modal (Phase 5.1).
//!
//! Triggered automatically by `CountdownPill` once the Playground
//! session has < 60 s remaining, and on demand by the
//! `/install` page or any header link.
//!
//! Three primary actions:
//!
//! * **Extend** — opens the portal signup URL in a new tab so the
//!   operator can graduate their session into a real account.
//! * **Save this session** — downloads `connector-trial-{tenant}.tar.gz`
//!   from `GET /api/v1/playground/session/export` (Phase 5.6 server
//!   PR). The button falls through gracefully if the endpoint isn't
//!   available yet — clicking it kicks off a download attempt; the
//!   user gets a normal browser error if the server hasn't shipped
//!   it.
//! * **End session** — closes the modal; on expiry the page reloads
//!   into the "Session ended" screen.
//!
//! ## Industry-design notes (Phase 8 uplift)
//!
//! This is the proof point for the `components::ui::*` primitives:
//! the modal is now composed entirely of `Dialog` + `DialogHeader` +
//! `DialogBody` + `DialogFooter` + `Button`. That brings:
//!
//! * **Focus management.** Initial focus moves into the dialog on
//!   open; on close, focus returns to the trigger (the CountdownPill
//!   or header link) — `Dialog` snapshots `activeElement` for us.
//! * **Escape to dismiss.** No per-modal keyboard plumbing.
//! * **Scroll lock.** Background `<body>` scroll is locked while the
//!   modal is open — fix for the previous behaviour where the body
//!   could scroll under the backdrop.
//! * **ARIA wiring.** `aria-modal`, `aria-labelledby`, `role="dialog"`
//!   are managed by the primitive; the previous bespoke `<div>` was
//!   missing `aria-labelledby` entirely.

use std::sync::Arc;

use leptos::prelude::*;

use crate::components::ui::{Button, ButtonVariant, Dialog, DialogBody, DialogFooter, DialogHeader};
use crate::deployment::{use_deployment, use_deployment_mode, DeploymentMode};
use crate::ui_state::use_session_end_modal;

const PORTAL_SIGNUP_URL: &str = "https://portal.connector.dev/signup?ref=playground";

#[component]
pub fn SessionEndModal() -> impl IntoView {
    let mode = use_deployment_mode();
    let (open, set_open) = use_session_end_modal();
    let deployment = use_deployment();

    // Bridge the (ReadSignal, WriteSignal) tuple from
    // `use_session_end_modal()` into the `RwSignal<bool>` the Dialog
    // primitive expects. We mirror the canonical read into the local
    // dialog signal AND force it back to `false` when the deployment
    // isn't Playground — that's the runtime-gate that used to be done
    // by a `<Show>` wrapper. Doing it on the open signal keeps the
    // child closures `Fn` (they're only constructed once).
    let dialog_open = RwSignal::new(false);
    // One-way sync: canonical open → dialog visibility. Never write
    // back to `set_open` from an Effect — that created an open↔dialog
    // feedback loop (Firefox "Script terminated by timeout").
    Effect::new(move |_| {
        let allowed = mode.get() == DeploymentMode::Playground;
        let canonical = open.get();
        let next = allowed && canonical;
        if dialog_open.get_untracked() != next {
            dialog_open.set(next);
        }
    });
    // Propagate overlay/Escape dismiss back to the canonical signal.
    // Guarded so we never write when already in sync (avoids loops).
    Effect::new(move |_| {
        if !dialog_open.get() && open.get_untracked() {
            set_open.set(false);
        }
    });

    let on_save: Arc<dyn Fn(_) + Send + Sync> = Arc::new(move |_| {
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_href("/api/v1/playground/session/export");
        }
    });

    let on_extend: Arc<dyn Fn(_) + Send + Sync> = Arc::new(move |_| {
        if let Some(win) = web_sys::window() {
            let _ = win.open_with_url_and_target(PORTAL_SIGNUP_URL, "_blank");
        }
    });

    let on_continue: Arc<dyn Fn(_) + Send + Sync> = Arc::new(move |_| {
        dialog_open.set(false);
        set_open.set(false);
    });
    let on_header_close: Arc<dyn Fn(_) + Send + Sync> = Arc::new(move |_| {
        dialog_open.set(false);
        set_open.set(false);
    });

    view! {
        <Dialog open=dialog_open panel_class="max-w-md".to_string()>
            <DialogHeader
                title="Your session is ending".to_string()
                description="Playground sessions are time-limited. Extend, save, or end it.".to_string()
                on_close=on_header_close
            />
            <DialogBody>
                {move || {
                    let info = deployment.get();
                    if info.public_url.is_empty() {
                        view! { <span></span> }.into_any()
                    } else {
                        view! {
                            <p class="text-xs text-muted font-mono break-all">{info.public_url.clone()}</p>
                        }.into_any()
                    }
                }}
                <div class="space-y-2">
                    <Button
                        variant=ButtonVariant::Primary
                        class="w-full".to_string()
                        on_click=on_extend
                    >
                        "Extend → sign up at portal"
                    </Button>
                    <Button
                        variant=ButtonVariant::Secondary
                        class="w-full".to_string()
                        on_click=on_save
                    >
                        "Save this session (download tar.gz)"
                    </Button>
                    <a
                        href="/install"
                        class="block text-center w-full h-10 leading-10 rounded-lg text-sm font-medium bg-transparent text-zinc-200 border border-zinc-700 hover:bg-zinc-800/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                    >
                        "See install commands →"
                    </a>
                </div>
            </DialogBody>
            <DialogFooter>
                <Button variant=ButtonVariant::Ghost on_click=on_continue>
                    "Continue using this session"
                </Button>
            </DialogFooter>
        </Dialog>
    }
}

/// "Session ended" terminal screen — rendered when a Playground
/// session has expired. The router falls into the regular auth
/// redirect on 401, but we can also render this page proactively
/// from the dashboard root when expiry is detected.
#[component]
pub fn SessionEndedPage() -> impl IntoView {
    view! {
        <div class="min-h-screen flex items-center justify-center bg-zinc-950 text-zinc-200 px-4">
            <div class="max-w-md text-center space-y-4">
                <div class="inline-flex h-14 w-14 mx-auto items-center justify-center rounded-xl bg-amber-500/10 border border-amber-500/30 text-3xl">
                    "⌛"
                </div>
                <div>
                    <h1 class="text-2xl font-semibold text-zinc-100">"Your playground session ended."</h1>
                    <p class="mt-1 text-sm text-zinc-400">"All session data has been released. You can spin up a new playground, or graduate to a real Connector deployment."</p>
                </div>
                <div class="flex flex-col sm:flex-row gap-2 justify-center">
                    <a href="https://try.connector.dev" class="px-3 py-2 rounded-lg text-sm font-semibold bg-indigo-600 hover:bg-indigo-500 text-white">
                        "Start a new playground"
                    </a>
                    <a href="/install" class="px-3 py-2 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-500 text-white">
                        "Install on your infra"
                    </a>
                </div>
                <a href=PORTAL_SIGNUP_URL class="block text-xs text-zinc-500 hover:text-zinc-300">
                    "Sign up at portal.connector.dev →"
                </a>
            </div>
        </div>
    }
}
