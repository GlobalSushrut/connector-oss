use leptos::prelude::*;
use leptos_router::components::A;
use crate::auth::{AuthState, logout};

#[component]
pub fn NavBar(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    view! {
        <nav class="cn-nav">
            <div style="display:flex;align-items:center;gap:1.5rem;flex:1;max-width:72rem;margin:0 auto;width:100%">
                <A href="/" attr:class="cn-nav__brand">"Connector"</A>
                <div class="hidden md:flex items-center gap-5" style="gap:1.25rem">
                    <A href="/" attr:class="cn-nav__link">"Overview"</A>
                    {move || if !auth.get().is_authenticated {
                        view!{
                            <>
                                <A href="/signup" attr:class="cn-nav__link">"Join Beta"</A>
                                <A href="/login"  attr:class="cn-nav__link">"Sign in"</A>
                            </>
                        }.into_any()
                    } else {
                        view!{
                            <>
                                <A href="/app"          attr:class="cn-nav__link">"Dashboard"</A>
                                <A href="/app/download" attr:class="cn-nav__link">"Download"</A>
                                <A href="/app/usage"    attr:class="cn-nav__link">"Usage"</A>
                                <A href="/app/billing"  attr:class="cn-nav__link">"Billing"</A>
                                <A href="/app/api-keys" attr:class="cn-nav__link">"API Keys"</A>
                                <A href="/app/profile"  attr:class="cn-nav__link">"Profile"</A>
                            </>
                        }.into_any()
                    }}
                </div>
                <div style="margin-left:auto;display:flex;align-items:center;gap:0.75rem">
                    {move || if auth.get().is_authenticated {
                        view!{
                            <button on:click=move|_| logout(set_auth) class="btn-ghost" style="font-size:0.8rem;padding:0.4rem 0.75rem">
                                "Sign out"
                            </button>
                        }.into_any()
                    } else {
                        view!{
                            <>
                                <A href="/login"  attr:class="btn-secondary btn-sm">"Sign in"</A>
                                <A href="/signup" attr:class="btn-primary btn-sm">"Join Beta"</A>
                            </>
                        }.into_any()
                    }}
                </div>
            </div>
        </nav>
    }
}
