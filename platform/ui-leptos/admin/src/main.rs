mod api;
mod auth;
mod components;
mod pages;

use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use leptos_router::{components::*, hooks::*};
use leptos_router::path;
use auth::{check_auth, AuthState};
use components::layout::Sidebar;
use pages::{
    login::Login, dashboard::Dashboard, customers::Customers,
    keys::Keys, instances::Instances, revenue::Revenue,
    payments::Payments, dunning::Dunning, surveillance::Surveillance,
    pilots::Pilots,
    signups::Signups,
    trial_sessions::TrialSessions,
    plugin_health::PluginHealth,
    distribution::Distribution,
};

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    let (auth, set_auth) = create_signal(check_auth());

    view! {
        <Router>
            <Routes fallback=|| view!{ <p class="p-8 text-zinc-500">"404"</p> }>
                <Route path=path!("/admin/login") view=move || view!{ <Login set_auth=set_auth /> } />
                <ParentRoute path=path!("/admin") view=move || view!{
                    <Show
                        when=move || auth.get().is_authenticated
                        fallback=move || view!{ <Redirect path="/admin/login" /> }
                    >
                        <div class="flex h-screen overflow-hidden bg-zinc-950 text-zinc-200">
                            <Sidebar auth=auth set_auth=set_auth />
                            <main class="flex-1 overflow-y-auto">
                                <Outlet />
                            </main>
                        </div>
                    </Show>
                }>
                    <Route path=path!("/")             view=move || view!{ <Dashboard   auth=auth /> } />
                    <Route path=path!("/customers")    view=move || view!{ <Customers   auth=auth /> } />
                    <Route path=path!("/keys")         view=move || view!{ <Keys        auth=auth /> } />
                    <Route path=path!("/instances")    view=move || view!{ <Instances   auth=auth /> } />
                    <Route path=path!("/revenue")      view=move || view!{ <Revenue     auth=auth /> } />
                    <Route path=path!("/payments")     view=move || view!{ <Payments    auth=auth /> } />
                    <Route path=path!("/dunning")      view=move || view!{ <Dunning     auth=auth /> } />
                    <Route path=path!("/surveillance") view=move || view!{ <Surveillance auth=auth /> } />
                    <Route path=path!("/pilots")          view=move || view!{ <Pilots         auth=auth /> } />
                    <Route path=path!("/signups")         view=move || view!{ <Signups        auth=auth /> } />
                    <Route path=path!("/trial-sessions")  view=move || view!{ <TrialSessions  auth=auth /> } />
                    <Route path=path!("/plugin-health")   view=move || view!{ <PluginHealth   auth=auth /> } />
                    <Route path=path!("/distribution")    view=move || view!{ <Distribution   auth=auth /> } />
                </ParentRoute>
            </Routes>
        </Router>
    }
}
