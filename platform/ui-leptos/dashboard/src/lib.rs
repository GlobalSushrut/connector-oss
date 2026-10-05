// Compile-time guard: the two distribution profiles are mutually exclusive.
// Building with both enabled would compile in code paths that contradict each
// other (e.g. countdown timer + real admin pages on the same surface).
#[cfg(all(feature = "playground", feature = "self-deploy"))]
compile_error!(
    "features `playground` and `self-deploy` are mutually exclusive — pick exactly one. \
     Did you mean `--no-default-features --features=playground`?"
);

mod api;
mod iia_api;
mod auth;
mod catalog;
mod deployment;
mod entitlements;
mod routes;
mod routing;
mod request_store;
mod ui_state;
mod utils;
mod components;
mod pages;
mod surfaces;
mod surface_client;

use leptos::mount::mount_to;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlElement;
use leptos_router::components::*;
use leptos_router::path;
use surfaces::{
    AgentEditor, AgentWorkbenchTheater, ActionTrailCanvas, DevCanvas, DevComponentGallery, FirstRunGuard, FixCanvas,
    GuardCanvas, NotFoundSurface, PluginConsoleCanvas, RunCanvas, WatchCanvas,
};
use routing::lazy_routes::{
    DevGuardPluginRouteView, TracetrampPluginRouteView, WitnessctlPluginRouteView,
};
use auth::{AuthState, bootstrap_session};
#[cfg(feature = "dev-bypass")]
use auth::dev_bypass;
use components::session_end_modal::SessionEndModal;
use components::update_toast::UpdateToast;
use components::whats_new_toast::WhatsNewToast;
use components::toaster::{provide_toaster, Toaster as GlobalToaster};
use components::operator::shell::OpOperatorShell;
use pages::{
    connect_landing::ConnectLanding, login::Login, trial::TrialPage,
    install::InstallPage,
    setup_wizards::{
        AgentCharterStudio, ConnectToolWizard, CreateAgentWizard, FirstRunWizard,
        InstallWorkflowWizard, InviteTeammateWizard, PlaygroundTour, SetupBudgetWizard,
    },
    plugins::{
        DevGuardSetupWizard, TraceTrampSetupWizard, WitnessCtlSetupWizard,
    },
};

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn main() {
    hydrate();
}

/// WASM entrypoint for Trunk (legacy) and `cargo leptos build --split`.
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    _ = console_log::init_with_level(log::Level::Info);
    spawn_local(async {
        gloo_timers::future::TimeoutFuture::new(0).await;
        let root = web_sys::window()
            .expect("browser window")
            .document()
            .expect("document")
            .get_element_by_id("root")
            .expect("dashboard index.html must define <div id=\"root\">")
            .dyn_into::<HtmlElement>()
            .expect("#root must be an HTMLElement");
        root.set_inner_html("");
        gloo_timers::future::TimeoutFuture::new(100).await;
        mount_to(root, App).forget();
    });
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BootPhase {
    Checking,
    Ready,
}

#[component]
pub fn App() -> impl IntoView {
    let (phase, set_phase) = signal(BootPhase::Checking);
    let (shell_ready, set_shell_ready) = signal(false);
    let (auth, set_auth) = signal(AuthState::default());

    spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(0).await;
        #[cfg(feature = "dev-bypass")]
        {
            let lab_html = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.document_element())
                .and_then(|el| el.get_attribute("data-dev"))
                .map(|v| {
                    let t = v.trim().to_ascii_lowercase();
                    matches!(t.as_str(), "1" | "true" | "yes" | "on")
                })
                .unwrap_or(false);
            if lab_html {
                dev_bypass(set_auth).await;
                set_phase.set(BootPhase::Ready);
                for _ in 0..3 {
                    gloo_timers::future::TimeoutFuture::new(0).await;
                }
                set_shell_ready.set(true);
                return;
            }
        }
        // Always mount the router after bootstrap — even when unauthenticated.
        // Soft <Redirect> via RequireAuth handles login; never hard-reload here.
        let _ok = bootstrap_session(set_auth).await;
        set_phase.set(BootPhase::Ready);
        for _ in 0..3 {
            gloo_timers::future::TimeoutFuture::new(0).await;
        }
        set_shell_ready.set(true);
    });

    view! {
        {move || match phase.get() {
            BootPhase::Checking => view! { <BootSplash message="Starting Connector…" /> }.into_any(),
            BootPhase::Ready if !shell_ready.get() => {
                view! { <BootSplash message="Loading dashboard…" /> }.into_any()
            }
            BootPhase::Ready => view! {
                <AuthenticatedShell auth=auth set_auth=set_auth />
            }.into_any(),
        }}
    }
}

#[component]
fn BootSplash(message: &'static str) -> impl IntoView {
    view! {
        <div
            class="fixed inset-0 flex flex-col items-center justify-center gap-3 bg-zinc-950 text-zinc-400"
            role="status"
            aria-live="polite"
            aria-busy="true"
        >
            <div class="h-6 w-6 border-2 border-zinc-700 border-t-indigo-500 rounded-full animate-spin" aria-hidden="true"></div>
            <p class="text-sm">{message}</p>
        </div>
    }
}

/// Soft auth gate for operator surfaces. Public routes (/login, /trial, /connect)
/// must stay reachable without a session.
#[component]
fn RequireAuth(
    auth: ReadSignal<AuthState>,
    children: ChildrenFn,
) -> impl IntoView {
    view! {
        <Show
            when=move || auth.get().is_authenticated
            fallback=|| view! { <Redirect path="/login" /> }
        >
            {children()}
        </Show>
    }
}

#[component]
fn AuthenticatedShell(
    auth: ReadSignal<AuthState>,
    set_auth: WriteSignal<AuthState>,
) -> impl IntoView {
    provide_context(set_auth);
    provide_context(auth);

    deployment::provide_deployment_signals();
    request_store::provide_shared_requests(auth);

    ui_state::provide_search_overlay();
    ui_state::install_search_overlay_hotkey();
    ui_state::provide_notify_overlay();
    ui_state::provide_operator_drawer();
    ui_state::provide_agent_explain();
    ui_state::provide_create_modal();
    ui_state::provide_tool_proposals();
    ui_state::provide_workbench_focus();
    ui_state::provide_session_end_modal();
    ui_state::provide_developer_view();

    {
        let (dev_enabled, _) = ui_state::use_developer_view();
        let v = dev_enabled.get_untracked();
        if let Some(body) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.body())
        {
            let _ = body.set_attribute("data-developer", if v { "1" } else { "0" });
        }
    }

    ui_state::provide_mobile_drawer();
    provide_toaster();

    view! {
        <Router>
            <FirstRunGuard auth=auth />
            <SessionEndModal />
            <UpdateToast />
            <WhatsNewToast />
            <GlobalToaster />
            <RouteChangeSideEffects />
            <Routes fallback=move || view!{
                <OpOperatorShell auth=auth>
                    <NotFoundSurface />
                </OpOperatorShell>
            }>
                <Route path=path!("/login") view=move || view!{ <Login set_auth=set_auth /> } />
                <Route path=path!("/connect") view=move || view!{ <ConnectLanding /> } />
                <Route path=path!("/trial") view=move || view!{ <TrialPage /> } />

                <Route path=path!("/") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/run") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><RunCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/run/workbench") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><AgentWorkbenchTheater auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/run/workbench/:pid") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><AgentWorkbenchTheater auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/run/trail") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><ActionTrailCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/run/trail/:pid") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><ActionTrailCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/watch") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><WatchCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/fix") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><FixCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/guard") view=move || view! {
                    <RequireAuth auth=auth>
                        <Redirect path="/setup/access" />
                    </RequireAuth>
                } />
                <Route path=path!("/console") view=|| view! { <Redirect path="/dev?tab=console" /> } />
                <Route path=path!("/books") view=|| view! { <Redirect path="/watch?tab=fuel" /> } />
                <Route path=path!("/setup") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><AgentEditor auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/setup/uplink") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><AgentEditor auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/setup/access") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><GuardCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/monitor") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/dev/components") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><DevComponentGallery auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/dev") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><DevCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/console/:id") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><PluginConsoleCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />

                // Deep-link redirects → operator modes
                <Route path=path!("/workflows") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/activity") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/actionlog") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/history") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/apps") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/command-center") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/home") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/agents") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/runtime-enforcement") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/memory") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/compliance") view=|| view! { <Redirect path="/fix" /> } />
                <Route path=path!("/debug") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/tools") view=|| view! { <Redirect path="/setup/uplink" /> } />
                <Route path=path!("/protocols") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/infra") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/safety") view=|| view! { <Redirect path="/fix" /> } />
                <Route path=path!("/firewall") view=|| view! { <Redirect path="/fix" /> } />
                <Route path=path!("/disputes") view=|| view! { <Redirect path="/fix" /> } />
                <Route path=path!("/trust") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/secrets") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/settings") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/billing") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/license") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/notifications") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/webhooks") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/plugins") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/pipeline") view=|| view! { <Redirect path="/setup/uplink" /> } />
                <Route path=path!("/insights") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/economy") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/marketplace") view=|| view! { <Redirect path="/setup" /> } />
                <Route path=path!("/grounding") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/context") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/verify") view=|| view! { <Redirect path="/fix" /> } />
                <Route path=path!("/orchestrator") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/multiagent") view=|| view! { <Redirect path="/run" /> } />
                <Route path=path!("/notebook") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/experiments") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/prompts") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/service-map") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/topology-center") view=|| view! { <Redirect path="/dev" /> } />
                <Route path=path!("/report-center") view=|| view! { <Redirect path="/watch" /> } />
                <Route path=path!("/cls-catalog") view=|| view! { <Redirect path="/dev?tab=catalog" /> } />
                <Route path=path!("/cls-builder") view=|| view! { <Redirect path="/dev?tab=author" /> } />
                <Route path=path!("/cls-packages") view=|| view! { <Redirect path="/dev?tab=cls" /> } />

                // Playground / onboarding (kept)
                <Route path=path!("/install") view=move || view! { <InstallPage auth=auth /> } />
                <Route path=path!("/setup/first-run") view=move || {
                    let mode = deployment::use_deployment_mode();
                    view! {
                        <RequireAuth auth=auth>
                            <OpOperatorShell auth=auth>
                                {move || if mode.get() == deployment::DeploymentMode::Playground {
                                    view! { <PlaygroundTour auth=auth /> }.into_any()
                                } else {
                                    view! { <FirstRunWizard auth=auth /> }.into_any()
                                }}
                            </OpOperatorShell>
                        </RequireAuth>
                    }
                } />
                <Route path=path!("/setup/connect-tool") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><ConnectToolWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/setup/install-workflow/:template_id") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><InstallWorkflowWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/agents/create") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><CreateAgentWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/agents/:pid/charter") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><AgentCharterStudio /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/billing/setup-budget") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><SetupBudgetWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/setup/invite") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><InviteTeammateWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />

                // Institution light consoles + setup wizards
                <Route path=path!("/plugins/devguard") view=move || view! {
                    <RequireAuth auth=auth><DevGuardPluginRouteView /></RequireAuth>
                } />
                <Route path=path!("/plugins/devguard/setup") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><DevGuardSetupWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/plugins/tracetramp") view=move || view! {
                    <RequireAuth auth=auth><TracetrampPluginRouteView /></RequireAuth>
                } />
                <Route path=path!("/plugins/tracetramp/setup") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><TraceTrampSetupWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/plugins/witnessctl") view=move || view! {
                    <RequireAuth auth=auth><WitnessctlPluginRouteView /></RequireAuth>
                } />
                <Route path=path!("/plugins/witnessctl/setup") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><WitnessCtlSetupWizard auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
                <Route path=path!("/plugins/:id") view=move || view! {
                    <RequireAuth auth=auth>
                        <OpOperatorShell auth=auth><PluginConsoleCanvas auth=auth /></OpOperatorShell>
                    </RequireAuth>
                } />
            </Routes>
        </Router>
    }
}

#[component]
fn RouteChangeSideEffects() -> impl IntoView {
    let location = leptos_router::hooks::use_location();
    Effect::new(move |_| {
        let path = location.pathname.get();

        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            if let Some(el) = doc.get_element_by_id("main-content") {
                if let Ok(target) = el.dyn_into::<web_sys::HtmlElement>() {
                    let _ = target.focus();
                }
            }
        }

        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            if let Some(body) = doc.body() {
                let route_kind = if path.starts_with("/plugins/") {
                    "plugin"
                } else {
                    "dashboard"
                };
                let _ = body.set_attribute("data-dashboard-route", route_kind);
            }
            let title = routes::title_for_path(&path);
            doc.set_title(&format!("{title} · Connector"));
        }
    });
    view! { <span class="hidden" aria-hidden="true"></span> }
}
