mod api;
mod auth;
mod routing;
mod pages;

use leptos::mount::mount_to;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlElement;
use leptos_router::components::*;
use leptos_router::path;
use auth::AuthState;
use pages::{login::Login, trial::TrialPage};

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
        // `.forget()` keeps the view mounted — dropping UnmountHandle unmounts immediately.
        mount_to(root, App).forget();
    });
}

#[component]
fn App() -> impl IntoView {
    let (auth, set_auth) = signal(AuthState::default());
    spawn_local(async move {
        auth::fetch_me(set_auth).await;
    });

    view! {
        <Router>
            <Routes fallback=|| view! { <div class="p-8 text-zinc-400">"Page not found"</div> }>
                <Route path=path!("/")       view=move || view! { <TrialPage /> } />
                <Route path=path!("/trial")  view=move || view! { <TrialPage /> } />
                <Route path=path!("/connect") view=move || view! { <TrialPage /> } />
                <Route path=path!("/login")  view=move || view! { <Login set_auth=set_auth /> } />
            </Routes>
        </Router>
    }
}
