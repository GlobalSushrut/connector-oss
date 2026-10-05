//! Lightweight trial/login entry point — minimal WASM size.
//! This is a separate entry that only includes:
//!   - Trial page
//!   - Login page  
//!   - Minimal routing
//!
//! Build with: TRUNK_CONFIG=Trunk.trial.toml trunk build --release

use leptos::prelude::*;
use leptos_router::prelude::*;
use wasm_bindgen::prelude::*;

mod api;
mod auth;
mod components;
pub mod pages;
pub mod routing;

use auth::{AuthState, fetch_me};
use pages::{LoginPage, TrialPage};
use wasm_bindgen_futures::spawn_local;

#[component]
fn App() -> impl IntoView {
    let (auth, set_auth) = signal(AuthState::default());
    
    // Check auth once on mount
    spawn_local(async move {
        fetch_me(set_auth).await;
    });

    view! {
        <Router>
            <Routes fallback=|| view! { <div>"Page not found"</div> }>
                <Route path=path!("/") view=move || view! { <TrialPage /> } />
                <Route path=path!("/trial") view=move || view! { <TrialPage /> } />
                <Route path=path!("/login") view=move || view! { <LoginPage set_auth=set_auth /> } />
            </Routes>
        </Router>
    }
}

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    
    spawn_local(async {
        let root = web_sys::window()
            .expect("window")
            .document()
            .expect("document")
            .get_element_by_id("root")
            .expect("#root")
            .dyn_into::<web_sys::HtmlElement>()
            .expect("html element");
        
        root.set_inner_html("");
        mount_to(root, App);
    });
}
