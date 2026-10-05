//! One operator editor for bringing an agent or assembling one.
//!
//! `/setup` is the build panel. `/setup/uplink` is the connect panel.
//! Both panels share the purpose check. Saving a purpose configures a
//! product task and does not execute an effect.

use leptos::prelude::*;
use leptos_router::hooks::use_location;

use crate::auth::AuthState;
use crate::components::operator::journey_choice::AgentJourney;
use crate::surfaces::connect::ConnectCanvas;
use crate::surfaces::setup::SetupCanvas;

#[component]
pub fn AgentEditor(auth: ReadSignal<AuthState>) -> impl IntoView {
    let location = use_location();
    let uplink = Signal::derive(move || location.pathname.get().contains("/uplink"));

    view! {
        <div class="w-full px-4 pt-4 sm:px-6">
            <AgentJourney />
            <div class="mb-4 flex flex-wrap gap-2 text-sm">
                <a
                    class="rounded-md border border-zinc-700 px-3 py-2 text-zinc-200"
                    href="/setup"
                    aria-current=move || if uplink.get() { None } else { Some("page") }
                >
                    "Build"
                </a>
                <a
                    class="rounded-md border border-zinc-700 px-3 py-2 text-zinc-200"
                    href="/setup/uplink"
                    aria-current=move || if uplink.get() { Some("page") } else { None }
                >
                    "Connect existing"
                </a>
            </div>
            <p class="mb-2 text-xs text-zinc-500">
                "One editor. Build configures a governed agent. Connect wires models and tools. A discovered tool stays unauthorized."
            </p>
        </div>
        <Show
            when=move || uplink.get()
            fallback=move || view! { <SetupCanvas auth=auth /> }
        >
            <ConnectCanvas auth=auth />
        </Show>
    }
}
