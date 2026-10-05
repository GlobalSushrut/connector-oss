//! Shared post-auth routing helpers.
//!
//! Keeps onboarding navigation decisions in one place so trial/setup/login
//! flows don't diverge.

use gloo_storage::{LocalStorage, Storage};
use leptos_router::NavigateOptions;

const PREFERRED_PRODUCT_KEY: &str = "preferred_product";
const ONBOARDING_COMPLETE_KEY: &str = "wizard:first-run:completed";
const PLAYGROUND_TOUR_KEY: &str = "wizard:playground-tour:completed";

fn normalize_product_id(id: &str) -> Option<&'static str> {
    match id.trim().to_ascii_lowercase().as_str() {
        "tracetramp" => Some("tracetramp"),
        "witnessctl" => Some("witnessctl"),
        "devguard" => Some("devguard"),
        _ => None,
    }
}

pub fn get_preferred_product() -> Option<String> {
    LocalStorage::get::<String>(PREFERRED_PRODUCT_KEY)
        .ok()
        .and_then(|id| normalize_product_id(&id).map(str::to_string))
}

pub fn set_preferred_product(id: &str) {
    if let Some(normalized) = normalize_product_id(id) {
        let _ = LocalStorage::set(PREFERRED_PRODUCT_KEY, normalized);
    }
}

/// Mark first-run onboarding as complete so guards don't bounce trial/setup
/// users back into the wizard after they explicitly chose a product.
pub fn mark_onboarding_complete() {
    let _ = LocalStorage::set(ONBOARDING_COMPLETE_KEY, true);
    let _ = LocalStorage::set(PLAYGROUND_TOUR_KEY, true);
}

/// Save preferred product and navigate directly to that plugin's dashboard.
pub fn navigate_to_overview_with_preference<F>(product_id: &str, navigate: F)
where
    F: Fn(&str, NavigateOptions),
{
    set_preferred_product(product_id);
    mark_onboarding_complete();
    let route = match normalize_product_id(product_id) {
        Some("tracetramp") => "/plugins/tracetramp",
        Some("witnessctl") => "/plugins/witnessctl",
        Some("devguard")   => "/run",
        _                  => "/run",
    };
    navigate(route, NavigateOptions::default());
}

