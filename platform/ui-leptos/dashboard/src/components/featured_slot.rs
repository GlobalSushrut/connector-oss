//! Featured-workflow slot — sits at the top of `/overview`, advertises
//! the three pre-built workflows shipped with Connector, and disappears
//! once the operator dismisses it.
//!
//! Per `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md` §13.4-B
//! (Phase 3.3, row P1-13):
//!
//! * Dismissed via `localStorage["featured_dismissed_version"]`.
//! * Re-appears when the catalog ships a newer version.
//!
//! "Server-pushed updates" is implemented client-side for now: the
//! `FEATURED_VERSION` constant below acts as the contract revision.
//! Bumping it makes every dashboard re-show the slot the next time it
//! mounts. A real server endpoint (`featured_updated_at`) is one of the
//! P2 polish items in the audit; Phase 3 ships the UX shape first.

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use leptos_router::components::A;

use crate::catalog::reference_workflows;

/// Bumping this number forces the Featured slot to reappear for every
/// operator on their next page load, even if they've previously
/// dismissed. Treat it as an editorial decision — e.g. bump when a new
/// reference workflow ships, or when the marketing copy below is
/// retuned.
const FEATURED_VERSION: u32 = 1;

const STORAGE_KEY: &str = "featured_dismissed_version";

fn load_dismissed_version() -> Option<u32> {
    LocalStorage::get::<u32>(STORAGE_KEY).ok()
}

fn store_dismissed_version() {
    let _ = LocalStorage::set(STORAGE_KEY, FEATURED_VERSION);
}

#[component]
pub fn FeaturedSlot() -> impl IntoView {
    let dismissed_at_mount = load_dismissed_version();
    let initially_visible = match dismissed_at_mount {
        Some(v) => v < FEATURED_VERSION,
        None => true,
    };
    let (visible, set_visible) = signal(initially_visible);

    let workflows = reference_workflows();

    view! {
        <Show when=move || visible.get()>
            <section class="mb-5 rounded-2xl border border-emerald-500/25 bg-gradient-to-br from-emerald-500/5 via-zinc-900/40 to-indigo-500/5 px-5 py-4 flex flex-col gap-3 sm:flex-row sm:items-center">
                <div class="flex-1 min-w-0 space-y-1">
                    <div class="flex items-center gap-2">
                        <span class="text-[10px] uppercase tracking-wider text-emerald-300/80 font-semibold">"Get started"</span>
                        <span class="text-[10px] uppercase tracking-wider text-zinc-500">"Pre-built workflows"</span>
                    </div>
                    <p class="text-sm text-zinc-200">
                        "Try a workflow that ships with Connector — one click installs the CCL and lands you on its run page."
                    </p>
                    <ul class="text-xs text-zinc-400 flex flex-wrap gap-x-3 gap-y-1 mt-1">
                        {workflows.iter().map(|w| view! {
                            <li>
                                <span class="text-zinc-300 font-medium">{w.name.clone()}</span>
                                <span class="text-zinc-600">" — "</span>
                                <span>{w.short_desc.clone()}</span>
                            </li>
                        }).collect::<Vec<_>>()}
                    </ul>
                </div>
                <div class="flex flex-col gap-1.5 shrink-0 sm:items-end">
                    <A
                        href="/apps"
                        attr:class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white"
                    >
                        "Browse all →"
                    </A>
                    <button
                        type="button"
                        class="text-[11px] text-zinc-500 hover:text-zinc-300 underline-offset-2 hover:underline"
                        on:click=move |_| {
                            store_dismissed_version();
                            set_visible.set(false);
                        }
                        title="You can re-trigger this card by clearing `featured_dismissed_version` in localStorage."
                    >
                        "Dismiss"
                    </button>
                </div>
            </section>
        </Show>
    }
}
