//! Minimal entry point - ONLY trial/login/connect pages.
//! This is ~70% smaller than the full dashboard WASM.
//! Build: TRUNK_CONFIG=Trunk.minimal.toml trunk build --release

mod api;
mod auth;
mod deployment;
mod routing;
mod ui_state;
mod components;
mod pages;

use leptos::mount::mount_to;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlElement;
use leptos_router::components::*;
use leptos_router::path;
use auth::{AuthState, fetch_me};
use pages::{login::Login, trial::TrialPage, connect_landing::ConnectLanding};

fn main() {
    console_error_panic_hook::set_once();
    
    spawn_local(async {
        let root = web_sys::window()
            .expect("window")
            .document()
            .expect("document")
            .get_element_by_id("root")
            .expect("#root")
            .dyn_into::<HtmlElement>()
            .expect("html element");
        
        root.set_inner_html("");
        mount_to(root, App);
    });
}

#[component]
fn App() -> impl IntoView {
    let (auth, set_auth) = signal(AuthState::default());
    
    spawn_local(async move {
        fetch_me(set_auth).await;
    });

    view! {
        <Router>
            <Routes fallback=|| view! { <div class="p-4">"Page not found"</div> }>
                <Route path=path!("/") view=move || view! { <TrialPage /> } />
                <Route path=path!("/trial") view=move || view! { <TrialPage /> } />
                <Route path=path!("/login") view=move || view! { <Login set_auth=set_auth /> } />
                <Route path=path!("/connect") view=move || view! { <ConnectLanding /> } />
            </Routes>
        </Router>
    }
}
