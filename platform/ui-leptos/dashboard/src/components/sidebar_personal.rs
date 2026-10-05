//! Sidebar "Pinned" + "Recent" personalisation (Phase 7.8 / P2-15).
//!
//! Two `localStorage`-backed lists threaded into the sidebar above the
//! main IA:
//!
//! - **Pinned** — operator-curated set of paths, manually starred from
//!   the page header. Stored under `sidebar.pinned` as a JSON array of
//!   strings. Order = insertion order; stars on either side toggle the
//!   row in/out.
//! - **Recent** — automatic FIFO list of the last `MAX_RECENTS`
//!   distinct visited paths. Stored under `sidebar.recent`. We trim on
//!   write so the list never grows unbounded.
//!
//! Both lists resolve labels + icons by joining each stored path
//! against `crate::routes::registry()`. Paths that no longer exist in
//! the registry are silently skipped (so renaming `/foo` → `/bar`
//! doesn't leave dead rows in the sidebar).

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::use_location;

use crate::components::icons;
use crate::routes::{registry, RouteDescriptor};

const PINNED_KEY: &str = "sidebar.pinned";
const RECENT_KEY: &str = "sidebar.recent";
const MAX_RECENTS: usize = 5;
const MAX_PINNED: usize = 12;

/// Snapshot reader for the pinned list. Useful for the per-page Star
/// button which needs the current state to render the right icon.
pub fn pinned_paths() -> Vec<String> {
    LocalStorage::get::<Vec<String>>(PINNED_KEY).unwrap_or_default()
}

pub fn recent_paths() -> Vec<String> {
    LocalStorage::get::<Vec<String>>(RECENT_KEY).unwrap_or_default()
}

/// Toggle `path` in the pinned list. Returns the new pinned state.
pub fn toggle_pin(path: &str) -> bool {
    let mut list = pinned_paths();
    if let Some(pos) = list.iter().position(|p| p == path) {
        list.remove(pos);
        let _ = LocalStorage::set(PINNED_KEY, &list);
        false
    } else {
        list.push(path.to_string());
        if list.len() > MAX_PINNED {
            // Drop the oldest pin first; pinned should be a curated
            // short list, not a junk drawer.
            let overflow = list.len() - MAX_PINNED;
            list.drain(0..overflow);
        }
        let _ = LocalStorage::set(PINNED_KEY, &list);
        true
    }
}

fn record_recent(path: &str) {
    // Skip top-level "/" and pre-auth routes; they aren't useful as
    // "recent" suggestions.
    if path == "/" || path == "/login" || path == "/trial" || path == "/connect" {
        return;
    }
    // Only record paths the registry knows about, so renaming a route
    // doesn't poison the list with dead entries.
    if !registry().iter().any(|r| r.path == path) {
        return;
    }
    let mut list = recent_paths();
    if let Some(pos) = list.iter().position(|p| p == path) {
        list.remove(pos);
    }
    list.insert(0, path.to_string());
    if list.len() > MAX_RECENTS {
        list.truncate(MAX_RECENTS);
    }
    let _ = LocalStorage::set(RECENT_KEY, &list);
}

/// Reactive bump signal so the sidebar refreshes after every write
/// without rebuilding the store API.
fn refresh_signal() -> (ReadSignal<u64>, WriteSignal<u64>) {
    use_context::<(ReadSignal<u64>, WriteSignal<u64>)>().unwrap_or_else(|| {
        let (r, w) = signal(0u64);
        provide_context::<(ReadSignal<u64>, WriteSignal<u64>)>((r, w));
        (r, w)
    })
}

/// Install the recent-path tracker. Call once from `App::main` after
/// `<Router>` is mounted so `use_location()` works.
pub fn install_recent_tracker() {
    let location = use_location();
    let pathname = location.pathname;
    let (_, bump) = refresh_signal();
    Effect::new(move |_| {
        let p = pathname.get();
        record_recent(&p);
        bump.update(|v| *v = v.wrapping_add(1));
    });
}

/// Sentinel component that installs the tracker the first time it
/// mounts inside `<Router>`. Renders nothing.
#[component]
pub fn RecentTrackerMount() -> impl IntoView {
    install_recent_tracker();
    view! { <></> }
}

/// Renders the "Pinned" + "Recent" rows above the main IA. Hidden
/// entirely when both lists are empty so the sidebar still feels
/// clean on first login.
fn resolve_paths(paths: Vec<String>) -> Vec<RouteDescriptor> {
    let reg = registry();
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        if let Some(r) = reg.iter().find(|r| r.path == p) {
            out.push(r.clone());
        }
    }
    out
}

#[component]
pub fn SidebarPersonalSection(collapsed: ReadSignal<bool>) -> impl IntoView {
    let (bump, _) = refresh_signal();

    // `RouteDescriptor` doesn't implement `PartialEq` so we can't use
    // `Memo` directly. Each Show/closure recomputes from the bump
    // signal — cheap because the lists are bounded (<= 12 + <= 5).
    let any_visible = move || {
        let _ = bump.get();
        !pinned_paths().is_empty() || !recent_paths().is_empty()
    };

    view! {
        <Show when=any_visible>
            <div class="mb-3">
                // Pinned.
                {move || {
                    let _ = bump.get();
                    let items = resolve_paths(pinned_paths());
                    (!items.is_empty()).then(|| view! {
                        <div class="px-2 mb-2">
                            <Show when=move || !collapsed.get()>
                                <p class="px-2 mb-1 text-[10px] uppercase tracking-wider text-zinc-500 font-semibold">
                                    "Pinned"
                                </p>
                            </Show>
                            <ul aria-label="Pinned routes" class="space-y-0.5">
                                {items.into_iter().map(|r| view! {
                                    <li>
                                        <PersonalRow descriptor=r collapsed=collapsed />
                                    </li>
                                }).collect_view()}
                            </ul>
                        </div>
                    })
                }}
                // Recent.
                {move || {
                    let _ = bump.get();
                    let items = resolve_paths(recent_paths());
                    (!items.is_empty()).then(|| view! {
                        <div class="px-2 mb-2">
                            <Show when=move || !collapsed.get()>
                                <p class="px-2 mb-1 text-[10px] uppercase tracking-wider text-zinc-500 font-semibold">
                                    "Recent"
                                </p>
                            </Show>
                            <ul aria-label="Recently visited routes" class="space-y-0.5">
                                {items.into_iter().map(|r| view! {
                                    <li>
                                        <PersonalRow descriptor=r collapsed=collapsed />
                                    </li>
                                }).collect_view()}
                            </ul>
                        </div>
                    })
                }}
                <div class="mx-3 my-2 border-t border-zinc-800/60"></div>
            </div>
        </Show>
    }
}

#[component]
fn PersonalRow(
    descriptor: RouteDescriptor,
    collapsed: ReadSignal<bool>,
) -> impl IntoView {
    let label = descriptor.label;
    let path = descriptor.path;
    let icon = icons::get_icon(descriptor.icon_key);

    view! {
        <A
            href=path
            attr:class="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-xs text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-100 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50"
            attr:title=label
        >
            <span aria-hidden="true" class="text-zinc-500 shrink-0" inner_html=icon />
            <Show when=move || !collapsed.get()>
                <span class="truncate">{label}</span>
            </Show>
        </A>
    }
}

/// Star-toggle button rendered next to a page title. Lights up when
/// the current path is pinned. Hidden for paths not in the registry
/// (no useful pin target).
#[component]
pub fn StarPinButton(#[prop(into)] path: String) -> impl IntoView {
    let in_registry = registry().iter().any(|r| r.path == path);
    if !in_registry {
        // Bail early on routes that aren't in the registry — there's
        // nothing useful to pin and the button would dangle.
        return view! { <></> }.into_any();
    }

    let path_for_aria_pinned = path.clone();
    let path_for_aria_unpinned = path.clone();
    let path_for_click = path.clone();
    let (is_pinned, set_is_pinned) = signal(pinned_paths().iter().any(|p| p == &path));
    let (_, bump) = refresh_signal();

    let aria_pinned = format!("Unpin {} from sidebar", path_for_aria_pinned);
    let aria_unpinned = format!("Pin {} to sidebar", path_for_aria_unpinned);

    view! {
        <button
            type="button"
            aria-label=move || if is_pinned.get() { aria_pinned.clone() } else { aria_unpinned.clone() }
            aria-pressed=move || is_pinned.get().to_string()
            title=move || if is_pinned.get() { "Pinned".to_string() } else { "Pin to sidebar".to_string() }
            on:click=move |_| {
                let pinned_now = toggle_pin(&path_for_click);
                set_is_pinned.set(pinned_now);
                bump.update(|v| *v = v.wrapping_add(1));
            }
            class=move || {
                let base = "inline-flex items-center justify-center w-7 h-7 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50";
                if is_pinned.get() {
                    format!("{base} text-warn bg-warn-10 hover:bg-warn-20")
                } else {
                    format!("{base} text-muted hover:text-zinc-300 hover:bg-zinc-800/50")
                }
            }
        >
            <span aria-hidden="true">
                {move || if is_pinned.get() { "★" } else { "☆" }}
            </span>
        </button>
    }.into_any()
}
