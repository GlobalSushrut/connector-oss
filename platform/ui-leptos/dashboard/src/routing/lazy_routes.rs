//! Plugin console route helpers.
//!
//! NOTE: `#[lazy_route]` / `Lazy<T>` require `cargo leptos build --split`.
//! Trunk leave `__wasm_split_placeholder__` unresolved, so local `trunk serve`
//! uses eager components. Re-enable lazy routes only in the leptos --split pipeline.

#![cfg(feature = "full-pages")]

use leptos::prelude::*;

use crate::auth::AuthState;
use crate::pages::plugins::{DevGuardPluginRouted, TracetrampPluginRouted, WitnessctlPluginRouted};

#[component]
pub fn DevGuardPluginRouteView() -> impl IntoView {
    let auth = expect_context::<ReadSignal<AuthState>>();
    view! { <DevGuardPluginRouted auth=auth /> }
}

#[component]
pub fn TracetrampPluginRouteView() -> impl IntoView {
    let auth = expect_context::<ReadSignal<AuthState>>();
    view! { <TracetrampPluginRouted auth=auth /> }
}

#[component]
pub fn WitnessctlPluginRouteView() -> impl IntoView {
    let auth = expect_context::<ReadSignal<AuthState>>();
    view! { <WitnessctlPluginRouted auth=auth /> }
}
