//! Fresh-node redirect into first-run / playground tour.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::deployment::{use_deployment_mode, DeploymentMode};
use gloo_storage::{LocalStorage, Storage};

pub const FIRST_RUN_PATH: &str = "/setup/first-run";

#[component]
pub fn FirstRunGuard(auth: ReadSignal<AuthState>) -> impl IntoView {
    let navigate = use_navigate();
    let mode = use_deployment_mode();
    Effect::new(move |has_run: Option<bool>| {
        if has_run.unwrap_or(false) {
            return true;
        }
        if !auth.get().is_authenticated {
            return false;
        }
        #[cfg(feature = "playground")]
        {
            let _ = LocalStorage::set("wizard:first-run:completed", true);
            let _ = LocalStorage::set("wizard:playground-tour:completed", true);
            return true;
        }
        if mode.get_untracked() == DeploymentMode::Playground {
            let _ = LocalStorage::set("wizard:first-run:completed", true);
            let _ = LocalStorage::set("wizard:playground-tour:completed", true);
            return true;
        }
        if crate::components::wizard::wizard_status("first-run").is_done()
            || crate::components::wizard::wizard_status("playground-tour").is_done()
        {
            return true;
        }
        let path = web_sys::window()
            .and_then(|w| w.location().pathname().ok())
            .unwrap_or_default();
        // Allow setup/auth/onboarding only — /run must not short-circuit first-run.
        if path.starts_with("/setup")
            || path.starts_with("/login")
            || path.starts_with("/trial")
            || path.starts_with("/connect")
            || path.starts_with("/plugins")
        {
            return true;
        }
        let navigate = navigate.clone();
        spawn_local(async move {
            let agents_empty = match api::get_value("/agents").await {
                Ok(v) => v
                    .get("agents")
                    .and_then(|a| a.as_array())
                    .map(|a| a.is_empty())
                    .unwrap_or(true),
                Err(_) => false,
            };
            let workflows_empty = match api::get_value("/workflows").await {
                Ok(v) => v
                    .get("workflows")
                    .and_then(|a| a.as_array())
                    .map(|a| a.is_empty())
                    .unwrap_or(true),
                Err(_) => false,
            };
            if agents_empty && workflows_empty {
                navigate(FIRST_RUN_PATH, NavigateOptions::default());
            }
        });
        true
    });
    ()
}
