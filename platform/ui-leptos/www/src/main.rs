mod api;
mod auth;
mod components;
mod pages;

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use leptos_router::{components::*, hooks::*};
use leptos_router::path;
use auth::{AuthState, fetch_me};
use pages::{landing::Landing, login::Login, signup::Signup, dashboard::Dashboard, billing::Billing,
            download::Download, usage::Usage, apikeys::ApiKeys, profile::Profile};

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    let (auth, set_auth) = create_signal(AuthState::default());
    Effect::new(move |did_run: Option<bool>| {
        if did_run.is_none() {
            spawn_local(async move { fetch_me(set_auth).await; });
        }
        true
    });
    view! {
        <Router>
            <Routes fallback=|| view!{ <p class="p-8 text-zinc-400">"404"</p> }>
                <Route path=path!("/")       view=move || view!{ <Landing auth=auth /> } />
                <Route path=path!("/login")  view=move || view!{ <Login set_auth=set_auth /> } />
                <Route path=path!("/signup") view=move || view!{ <Signup set_auth=set_auth /> } />
                <ParentRoute path=path!("/app") view=move || view!{
                    <Show when=move || auth.get().is_authenticated
                          fallback=move || view!{ <Redirect path="/login" /> }>
                        <Outlet />
                    </Show>
                }>
                    <Route path=path!("")          view=move || view!{ <Dashboard auth=auth set_auth=set_auth /> } />
                    <Route path=path!("billing")   view=move || view!{ <Billing   auth=auth set_auth=set_auth /> } />
                    <Route path=path!("download")  view=move || view!{ <Download  auth=auth set_auth=set_auth /> } />
                    <Route path=path!("usage")     view=move || view!{ <Usage     auth=auth set_auth=set_auth /> } />
                    <Route path=path!("api-keys")  view=move || view!{ <ApiKeys   auth=auth set_auth=set_auth /> } />
                    <Route path=path!("profile")   view=move || view!{ <Profile   auth=auth set_auth=set_auth /> } />
                </ParentRoute>
            </Routes>
        </Router>
    }
}
