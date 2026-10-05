//! Client-side guards for `/plugins/<id>`: redirect to SETUP when the plugin is
//! disabled via `CONNECTOR_PLUGINS_ENABLED`. Default surface is the light console.

use leptos::prelude::*;
use leptos_router::components::Redirect;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::cards::PageLoading;
use crate::components::operator::shell::OpOperatorShell;

use super::light_consoles::{DevGuardLightConsole, TraceTrampLightConsole, WitnessCtlLightConsole};

fn run_plugin_gate(
    plugin_id: &'static str,
    ready: RwSignal<bool>,
    allow: RwSignal<bool>,
    started: RwSignal<bool>,
) {
    Effect::new(move |_| {
        if started.get() {
            return;
        }
        started.set(true);
        let pid = plugin_id;
        spawn_local(async move {
            let ok = match api::get_value("/plugins/status").await {
                Ok(v) => v
                    .get("plugins")
                    .and_then(|p| p.get(pid))
                    .and_then(|o| o.get("enabled_in_deployment"))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(true),
                Err(_) => true,
            };
            allow.set(ok);
            ready.set(true);
        });
    });
}

#[component]
pub fn DevGuardPluginRouted(auth: ReadSignal<AuthState>) -> impl IntoView {
    let ready = RwSignal::new(false);
    let allow = RwSignal::new(true);
    let started = RwSignal::new(false);
    run_plugin_gate("devguard", ready, allow, started);
    view! {
        <Show when=move || ready.get() fallback=|| view! { <PageLoading /> }>
            <Show
                when=move || allow.get()
                fallback=|| view! { <Redirect path="/setup" /> }
            >
                <OpOperatorShell auth=auth>
                    <DevGuardLightConsole auth=auth />
                </OpOperatorShell>
            </Show>
        </Show>
    }
}

#[component]
pub fn TracetrampPluginRouted(auth: ReadSignal<AuthState>) -> impl IntoView {
    let ready = RwSignal::new(false);
    let allow = RwSignal::new(true);
    let started = RwSignal::new(false);
    run_plugin_gate("tracetramp", ready, allow, started);
    view! {
        <Show when=move || ready.get() fallback=|| view! { <PageLoading /> }>
            <Show
                when=move || allow.get()
                fallback=|| view! { <Redirect path="/setup" /> }
            >
                <OpOperatorShell auth=auth>
                    <TraceTrampLightConsole auth=auth />
                </OpOperatorShell>
            </Show>
        </Show>
    }
}

#[component]
pub fn WitnessctlPluginRouted(auth: ReadSignal<AuthState>) -> impl IntoView {
    let ready = RwSignal::new(false);
    let allow = RwSignal::new(true);
    let started = RwSignal::new(false);
    run_plugin_gate("witnessctl", ready, allow, started);
    view! {
        <Show when=move || ready.get() fallback=|| view! { <PageLoading /> }>
            <Show
                when=move || allow.get()
                fallback=|| view! { <Redirect path="/setup" /> }
            >
                <OpOperatorShell auth=auth>
                    <WitnessCtlLightConsole auth=auth />
                </OpOperatorShell>
            </Show>
        </Show>
    }
}
