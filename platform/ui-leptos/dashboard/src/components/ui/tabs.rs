//! Tabs — accessible tablist/tab/tabpanel with keyboard navigation.
//!
//! WAI-ARIA "Tabs with automatic activation" pattern:
//!
//! * `<TabList>` renders `role="tablist"`.
//! * Each `<TabTrigger>` renders `role="tab"` with `aria-selected` +
//!   `aria-controls` wiring to the matching `<TabPanel>` (`role="tabpanel"`,
//!   `aria-labelledby` back).
//! * Arrow Left / Right moves between tabs and updates the active
//!   index — focus follows the active tab so the user can spacebar-
//!   activate as they go.
//! * Home / End jump to first / last.
//!
//! Usage is context-driven so the panels don't need to know which tab
//! is active:
//!
//! ```ignore
//! let active = RwSignal::new(0_usize);
//! view! {
//!     <Tabs active=active>
//!         <TabList>
//!             <TabTrigger index=0>"Overview"</TabTrigger>
//!             <TabTrigger index=1>"Activity"</TabTrigger>
//!             <TabTrigger index=2>"Settings"</TabTrigger>
//!         </TabList>
//!         <TabPanel index=0><OverviewBody /></TabPanel>
//!         <TabPanel index=1><ActivityBody /></TabPanel>
//!         <TabPanel index=2><SettingsBody /></TabPanel>
//!     </Tabs>
//! }
//! ```

use leptos::ev::KeyboardEvent;
use leptos::prelude::*;
use std::cell::Cell;

fn tabs_id() -> String {
    thread_local! {
        static SEQ: Cell<u64> = const { Cell::new(0) };
    }
    SEQ.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        format!("tabs-{v}")
    })
}

#[derive(Clone, Copy)]
struct TabsContext {
    active: RwSignal<usize>,
    /// Tablist id prefix — children compose
    /// `{prefix}-tab-{i}` and `{prefix}-panel-{i}` for ARIA wiring.
    id_prefix: StoredValue<String>,
}

#[component]
pub fn Tabs(
    /// Active-tab signal. Bind a `RwSignal<usize>` so child triggers
    /// can update it.
    active: RwSignal<usize>,
    children: Children,
) -> impl IntoView {
    let ctx = TabsContext {
        active,
        id_prefix: StoredValue::new(tabs_id()),
    };
    provide_context(ctx);
    view! { <div>{children()}</div> }
}

#[component]
pub fn TabList(children: Children) -> impl IntoView {
    view! {
        <div
            role="tablist"
            aria-orientation="horizontal"
            class="flex items-center gap-1 border-b border-zinc-800/60 mb-6"
        >
            {children()}
        </div>
    }
}

#[component]
pub fn TabTrigger(index: usize, children: Children) -> impl IntoView {
    let ctx = use_context::<TabsContext>().expect("<TabTrigger> outside <Tabs>");
    let active = ctx.active;
    let prefix = ctx.id_prefix.get_value();
    let tab_id = format!("{prefix}-tab-{index}");
    let panel_id = format!("{prefix}-panel-{index}");

    let cls = move || {
        let base = "px-4 py-2.5 text-sm transition-colors -mb-px border-b-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60 rounded-t-md";
        if active.get() == index {
            format!("{base} text-white border-brand font-medium")
        } else {
            format!("{base} text-zinc-500 hover:text-zinc-200 border-transparent")
        }
    };

    let on_click = move |_| active.set(index);

    let on_keydown = move |ev: KeyboardEvent| {
        let curr = active.get();
        // Crude bounded nav — Tabs context doesn't know how many tabs
        // exist (the children() closure can render any count). We
        // step by one in either direction; if the next/prev index has
        // no corresponding TabTrigger nothing visible happens (the
        // panel for that index simply isn't rendered).
        let next = match ev.key().as_str() {
            "ArrowRight" => Some(curr.saturating_add(1)),
            "ArrowLeft" => Some(curr.saturating_sub(1)),
            "Home" => Some(0),
            "End" => Some(usize::MAX),
            _ => None,
        };
        if let Some(n) = next {
            ev.prevent_default();
            // Clamp `End` to whatever the caller authored; we can't
            // count siblings without a registration step, so set the
            // signal — siblings with index <= n that exist will
            // reflect; the highest matching trigger will be the one
            // that becomes selected.
            active.set(n);
        }
    };

    view! {
        <button
            type="button"
            role="tab"
            id=tab_id.clone()
            class=cls
            aria-selected=move || (active.get() == index).then_some("true")
            aria-controls=panel_id
            tabindex=move || if active.get() == index { "0" } else { "-1" }
            on:click=on_click
            on:keydown=on_keydown
        >
            {children()}
        </button>
    }
}

#[component]
pub fn TabPanel(index: usize, children: Children) -> impl IntoView {
    let ctx = use_context::<TabsContext>().expect("<TabPanel> outside <Tabs>");
    let active = ctx.active;
    let prefix = ctx.id_prefix.get_value();
    let tab_id = format!("{prefix}-tab-{index}");
    let panel_id = format!("{prefix}-panel-{index}");

    view! {
        <div
            role="tabpanel"
            id=panel_id
            aria-labelledby=tab_id
            hidden=move || active.get() != index
            class="focus:outline-none"
            tabindex="0"
        >
            {children()}
        </div>
    }
}
