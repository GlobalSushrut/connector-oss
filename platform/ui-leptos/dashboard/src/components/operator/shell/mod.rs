use leptos::prelude::*;
use leptos_router::hooks::use_location;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::api;
use crate::auth::{self, AuthState};
use wasm_bindgen_futures::spawn_local;
use crate::components::operator::overlays::{
    OpAgentExplainHost, OpCreateAgentHost, OpCreateWorkflowHost, OpDrawerHost, OpNotifyCenter,
    OpPaletteHost,
};
use crate::components::operator::primitives::chrome::OpModeButton;
use crate::components::operator::primitives::{
    OpEnvBadge, OpHealthDot, OpHealthState, OpKbd, OpNotifyBell, OpPulseWave, OpSpinner,
    OpStatChip, OpStatVariant,
};
use crate::request_store::{bump_reload, use_shared_requests};
use crate::ui_state::{
    open_topic_drawer, toggle_notify_overlay, use_notify_overlay, use_search_overlay, DrawerTopic,
};

#[component]
pub fn OpPulseBar(auth: ReadSignal<AuthState>) -> impl IntoView {
    let shared = use_shared_requests();
    let search = use_search_overlay();
    let set_auth = expect_context::<WriteSignal<AuthState>>();
    let (menu_open, set_menu_open) = signal(false);

    // Click outside / Escape closes the account menu.
    Effect::new(move |_| {
        if !menu_open.get() {
            return;
        }
        use wasm_bindgen::closure::Closure;
        use wasm_bindgen::JsCast;
        let close = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
            set_menu_open.set(false);
        });
        let esc = Closure::<dyn FnMut(_)>::new(move |ev: web_sys::KeyboardEvent| {
            if ev.key() == "Escape" {
                set_menu_open.set(false);
            }
        });
        if let Some(w) = web_sys::window() {
            let _ = w.add_event_listener_with_callback("click", close.as_ref().unchecked_ref());
            let _ = w.add_event_listener_with_callback("keydown", esc.as_ref().unchecked_ref());
            close.forget();
            esc.forget();
        }
    });

    view! {
        <Suspense fallback=move || view! {
            <header class="op-pulse-bar flex h-12 shrink-0 items-center border-b px-4">
                <OpSpinner size="sm" />
            </header>
        }>
            {move || Suspend::new(async move {
                let pulse = shared.pulse.await.ok();
                let health = shared.health.await.ok();
                let notes = shared.notifications.await.ok();

                let running = pulse.as_ref().and_then(|v| count_path(v, &["workflows", "running"]));
                let needs_you = pulse.as_ref().and_then(|v| count_path(v, &["workflows", "needs_you"]));
                let idle = pulse.as_ref().and_then(|v| count_path(v, &["workflows", "idle"]));

                // Honesty: None = API unreachable (Down). `critical` = node up, gates failed.
                let health_state = match &health {
                    Some(h) => h
                        .get("status")
                        .and_then(|s| s.as_str())
                        .map(OpHealthState::from_api)
                        .unwrap_or(OpHealthState::Ok),
                    None => OpHealthState::Down,
                };
                let health_label = health
                    .as_ref()
                    .and_then(|h| h.get("status").and_then(|s| s.as_str()))
                    .unwrap_or(if health.is_some() { "ok" } else { "down" })
                    .to_string();
                let node_name = pulse
                    .as_ref()
                    .and_then(|v| v.pointer("/node/name"))
                    .and_then(|s| s.as_str())
                    .or_else(|| health.as_ref().and_then(|h| h.get("node").and_then(|n| n.as_str())))
                    .unwrap_or("connector-node")
                    .to_string();

                let unread = unread_count(notes.as_ref());

                view! {
                    <header class="op-pulse-bar relative z-[60] flex h-12 shrink-0 items-center gap-3 border-b px-3 sm:gap-4 sm:px-4">
                        <div class="flex items-center gap-2.5 min-w-0">
                            <a href="/" class="flex items-center min-w-0" aria-label="cnktros home">
                                <img src="/logo.png" alt="cnktros" class="h-7 w-auto max-w-[9.5rem]" />
                            </a>
                            <p class="hidden text-[10px] text-zinc-500 sm:block">"Operator"</p>
                        </div>
                        <OpPulseWave />
                        <div class="flex items-center gap-2 sm:gap-3">
                            <OpStatChip variant=OpStatVariant::Running count=running />
                            <OpStatChip variant=OpStatVariant::NeedsYou count=needs_you />
                            <OpStatChip variant=OpStatVariant::Idle count=idle />
                            <PulseFuelLink />
                        </div>
                        <div class="flex-1"></div>
                        <button
                            type="button"
                            class="op-icon-btn"
                            title="Refresh shared data"
                            on:click=move |_| bump_reload()
                        >"↻"</button>
                        <OpEnvBadge name=node_name />
                        <OpHealthDot state=health_state show_label=true label=health_label />
                        <button
                            type="button"
                            class="op-icon-btn hidden sm:inline-flex"
                            aria-label="Open command palette"
                            on:click=move |_| search.set_open.set(true)
                        >
                            <OpKbd keys="⌘K".to_string() />
                        </button>
                        <OpNotifyBell
                            unread=unread
                            on_click=Arc::new(move |ev| {
                                ev.stop_propagation();
                                toggle_notify_overlay();
                            })
                        />
                        <div class="relative">
                            <button
                                type="button"
                                class="op-account-trigger"
                                aria-haspopup="menu"
                                aria-expanded=move || menu_open.get()
                                on:click=move |ev| {
                                    ev.stop_propagation();
                                    set_menu_open.update(|v| *v = !*v);
                                }
                            >
                                <span class="op-account-avatar">
                                    {move || {
                                        let a = auth.get();
                                        let name = a.user.as_ref().map(|u| {
                                            if !u.name.is_empty() { u.name.clone() } else { u.email.clone() }
                                        }).unwrap_or_else(|| "?".into());
                                        name.chars().next().unwrap_or('?').to_ascii_uppercase().to_string()
                                    }}
                                </span>
                                <span class="hidden min-w-0 max-w-[10rem] text-left sm:block">
                                    <span class="block truncate text-xs font-medium text-zinc-100">
                                        {move || {
                                            let a = auth.get();
                                            a.user.as_ref().map(|u| {
                                                if !u.name.is_empty() { u.name.clone() } else { u.email.clone() }
                                            }).unwrap_or_else(|| "Operator".into())
                                        }}
                                    </span>
                                    <span class="block truncate text-[10px] text-zinc-500">
                                        {move || {
                                            let a = auth.get();
                                            let email = a.user.as_ref().map(|u| u.email.clone()).unwrap_or_default();
                                            let role = a.user.as_ref().map(|u| u.role.clone()).unwrap_or_else(|| "session".into());
                                            if email.is_empty() { role } else { format!("{email} · {role}") }
                                        }}
                                    </span>
                                </span>
                                <span class="text-[10px] text-zinc-500">"▾"</span>
                            </button>
                            <Show when=move || menu_open.get()>
                                <div
                                    class="op-account-menu"
                                    role="menu"
                                    on:click=move |ev| ev.stop_propagation()
                                >
                                    <div class="op-account-menu__head">
                                        <p class="truncate text-xs font-semibold text-zinc-100">
                                            {move || auth.get().user.as_ref().map(|u| u.email.clone()).unwrap_or_else(|| "signed in".into())}
                                        </p>
                                        <p class="truncate text-[10px] text-zinc-500">
                                            {move || auth.get().user.as_ref().map(|u| u.role.clone()).unwrap_or_else(|| "operator".into())}
                                        </p>
                                    </div>
                                    <button
                                        type="button"
                                        class="op-account-menu__item"
                                        role="menuitem"
                                        on:click=move |_| {
                                            set_menu_open.set(false);
                                            open_topic_drawer(DrawerTopic::Settings("node".into()));
                                        }
                                    >"Settings · node"</button>
                                    <button
                                        type="button"
                                        class="op-account-menu__item"
                                        role="menuitem"
                                        on:click=move |_| {
                                            set_menu_open.set(false);
                                            open_topic_drawer(DrawerTopic::Settings("account".into()));
                                        }
                                    >"Account"</button>
                                    <a
                                        href="/login"
                                        class="op-account-menu__item"
                                        role="menuitem"
                                        on:click=move |_| set_menu_open.set(false)
                                    >"Switch account · Login"</a>
                                    <button
                                        type="button"
                                        class="op-account-menu__item"
                                        role="menuitem"
                                        on:click=move |_| {
                                            set_menu_open.set(false);
                                            if let Some(w) = web_sys::window() {
                                                let origin = w.location().origin().unwrap_or_default();
                                                let url = format!("{origin}/api/v1/monitor/health");
                                                let _ = w.open_with_url_and_target(&url, "_blank");
                                            }
                                        }
                                    >"Go to server"</button>
                                    <button
                                        type="button"
                                        class="op-account-menu__item op-account-menu__item--danger"
                                        role="menuitem"
                                        on:click=move |_| {
                                            set_menu_open.set(false);
                                            auth::logout(set_auth);
                                        }
                                    >"Logout"</button>
                                </div>
                            </Show>
                        </div>
                    </header>
                }.into_any()
            })}
        </Suspense>
    }
}

fn count_path(v: &Value, path: &[&str]) -> Option<u64> {
    let mut cur = v;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_u64().or_else(|| cur.as_i64().map(|n| n as u64))
}

fn unread_count(notes: Option<&Value>) -> Option<u64> {
    let v = notes?;
    if let Some(n) = v.get("pending").and_then(|x| x.as_u64()) {
        return if n > 0 { Some(n) } else { None };
    }
    if let Some(n) = v.get("unread").and_then(|x| x.as_u64()) {
        return if n > 0 { Some(n) } else { None };
    }
    let arr = v
        .get("notifications")
        .or_else(|| v.get("items"))
        .and_then(|x| x.as_array())?;
    let n = arr
        .iter()
        .filter(|i| {
            let status = i.get("status").and_then(|s| s.as_str()).unwrap_or("");
            matches!(status, "PENDING" | "DELIVERED" | "SNOOZED")
                && i.get("acknowledged_at").map(|a| a.is_null()).unwrap_or(true)
        })
        .count() as u64;
    if n > 0 { Some(n) } else { None }
}

/// Measured fuel only — never invent $0. Hidden when usage data absent.
#[component]
fn PulseFuelLink() -> impl IntoView {
    let costs = LocalResource::new(|| api::get_value("/books/costs"));
    view! {
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                match costs.await {
                    Ok(v) => {
                        let src = api::resource_object(&v);
                        let has = src
                            .pointer("/data/has_usage_data")
                            .or_else(|| src.get("has_usage_data"))
                            .and_then(|x| x.as_bool())
                            .unwrap_or(false);
                        if !has {
                            return ().into_any();
                        }
                        let tokens = src
                            .pointer("/data/total_tokens")
                            .or_else(|| src.get("total_tokens"))
                            .and_then(|x| x.as_u64());
                        let label = tokens
                            .map(|n| format!("{n} tok"))
                            .unwrap_or_else(|| "fuel".into());
                        view! {
                            <a
                                href="/watch?tab=fuel"
                                class="hidden sm:inline-flex items-center gap-1 text-[11px] font-medium text-cyan-400/90 hover:text-cyan-300"
                                title="Measured tokens from GET /books/costs"
                            >
                                <span class="font-mono tabular-nums">{label}</span>
                                <span class="text-zinc-500">"fuel"</span>
                            </a>
                        }.into_any()
                    }
                    Err(_) => ().into_any(),
                }
            })}
        </Suspense>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpMode {
    Run,
    Watch,
    Fix,
    Setup,
    Dev,
}

impl OpMode {
    fn path(self) -> &'static str {
        match self {
            Self::Run => "/run",
            Self::Watch => "/watch",
            Self::Fix => "/fix",
            Self::Setup => "/setup",
            Self::Dev => "/dev",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Run => "Run",
            Self::Watch => "Watch",
            Self::Fix => "Fix",
            Self::Setup => "Setup",
            Self::Dev => "Dev",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Self::Run => "▶",
            Self::Watch => "◎",
            Self::Fix => "⚠",
            Self::Setup => "⚙",
            Self::Dev => "⌘",
        }
    }

    fn matches_path(self, path: &str) -> bool {
        path == self.path()
            || path.starts_with(&format!("{}/", self.path()))
            || (self == OpMode::Run
                && (path == "/" || path.starts_with("/workflows") || path.starts_with("/agents")))
            || (self == OpMode::Watch
                && (path.starts_with("/monitor")
                    || path.starts_with("/books")
                    || path.starts_with("/report-center")
                    || path.starts_with("/runtime-enforcement")))
            || (self == OpMode::Setup
                && (path.starts_with("/setup")
                    || path.starts_with("/guard")
                    || path.starts_with("/apps")
                    || path.starts_with("/settings")
                    || path.starts_with("/billing")
                    || path.starts_with("/install")
                    || path.starts_with("/plugins")))
            || (self == OpMode::Dev
                && (path.starts_with("/dev") || path.starts_with("/console") || path.starts_with("/cls-")))
    }
}

#[component]
pub fn OpModeRail(fix_count: Option<u64>) -> impl IntoView {
    let location = use_location();
    let pathname = location.pathname;
    let set_auth = expect_context::<WriteSignal<AuthState>>();
    let modes = [
        OpMode::Run,
        OpMode::Watch,
        OpMode::Fix,
        OpMode::Setup,
        OpMode::Dev,
    ];
    let badge = fix_count.unwrap_or(0);

    view! {
        <nav class="op-mode-rail" aria-label="Operator modes">
            <p class="op-rail-label">"Modes"</p>
            <div class="flex flex-col items-stretch gap-1.5 px-1.5">
                {modes.into_iter().map(|mode| {
                    let href = mode.path();
                    let fix_badge = if mode == OpMode::Fix { badge } else { 0 };
                    let active = Signal::derive(move || mode.matches_path(pathname.get().as_str()));
                    view! {
                        <OpModeButton
                            href=href
                            icon=mode.icon()
                            label=mode.label()
                            active=active
                            badge=fix_badge
                        />
                    }
                }).collect_view()}
            </div>
            <div class="mt-auto flex flex-col gap-1 px-1.5 pb-2">
                <p class="op-rail-label">"Account"</p>
                <a href="/login" class="op-rail-action" title="Login / switch account">
                    <span class="op-plugin-link__mark">"↵"</span>
                    <span class="op-rail-action__name">"Login"</span>
                </a>
                <button
                    type="button"
                    class="op-rail-action w-full text-left"
                    title="Open this Connector server (API health)"
                    on:click=move |_| {
                        if let Some(w) = web_sys::window() {
                            let origin = w.location().origin().unwrap_or_default();
                            let url = format!("{origin}/api/v1/monitor/health");
                            let _ = w.open_with_url_and_target(&url, "_blank");
                        }
                    }
                >
                    <span class="op-plugin-link__mark">"⬡"</span>
                    <span class="op-rail-action__name">"Server"</span>
                </button>
                <button
                    type="button"
                    class="op-rail-action op-rail-action--danger w-full text-left"
                    title="Log out"
                    on:click=move |_| auth::logout(set_auth)
                >
                    <span class="op-plugin-link__mark">"⏻"</span>
                    <span class="op-rail-action__name">"Logout"</span>
                </button>
            </div>
        </nav>
    }
}

/// DI-0 / DI-3 — loud banner when intelligence hardening flags are off + one-click enable.
#[component]
fn LabModeBanner() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (flash, set_flash) = signal(String::new());
    let resource = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/runtime/lab-mode").await }
    });
    view! {
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                match resource.await {
                    Ok(v) if v.get("lab_mode").and_then(|x| x.as_bool()) == Some(true) => {
                        let reasons = v
                            .get("reasons")
                            .and_then(|r| r.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        let preset = v
                            .get("preset")
                            .and_then(|x| x.as_str())
                            .unwrap_or("local")
                            .to_string();
                        view! {
                            <div class="sticky top-0 z-40 flex shrink-0 flex-wrap items-center gap-2 border-b-2 border-amber-500/80 bg-amber-950 px-3 py-2.5 text-xs text-amber-50 shadow-lg shadow-amber-950/50">
                                <span class="rounded bg-amber-300 px-1.5 py-0.5 text-[11px] font-black uppercase tracking-widest text-amber-950">"LAB MODE"</span>
                                <span class="font-medium">{format!("preset={preset} · {reasons}")}</span>
                                <span class="text-amber-200/90">"Not a production distributed-intelligence posture."</span>
                                <button
                                    type="button"
                                    class="rounded bg-amber-200 px-2.5 py-1 text-[11px] font-bold text-amber-950 hover:bg-amber-100"
                                    on:click=move |_| {
                                        set_flash.set("Enabling…".into());
                                        spawn_local(async move {
                                            match api::post_value("/runtime/enable-hardening", json!({})).await {
                                                Ok(r) if r.get("ok").and_then(|x| x.as_bool()) == Some(true) => {
                                                    set_flash.set("Hardening on — reload surfaces".into());
                                                    set_reload.update(|n| *n += 1);
                                                }
                                                Ok(r) => {
                                                    let reason = r
                                                        .get("error")
                                                        .and_then(|item| item.as_str())
                                                        .unwrap_or("enable_hardening_failed");
                                                    set_flash.set(format!("Failed: {reason}. Hardening stays off."));
                                                }
                                                Err(e) => set_flash.set(format!("Failed: {e}. Hardening stays off.")),
                                            }
                                        });
                                    }
                                >
                                    "Enable intelligence hardening"
                                </button>
                                <span class="text-amber-100/90">{move || flash.get()}</span>
                            </div>
                        }.into_any()
                    }
                    _ => view! { <></> }.into_any(),
                }
            })}
        </Suspense>
    }
}

#[component]
pub fn OpOperatorShell(
    auth: ReadSignal<crate::auth::AuthState>,
    children: Children,
) -> impl IntoView {
    let shared = use_shared_requests();
    let notify = use_notify_overlay();

    view! {
        // Outer shell: overlays sit outside the clipped chrome so popups/modals are never hidden.
        <div class="op-shell relative flex min-h-dvh flex-col">
            <div class="op-chrome flex flex-col">
                <LabModeBanner />
                <OpPulseBar auth=auth />
                <div class="op-body flex items-start">
                    <Suspense fallback=move || view! { <OpModeRail fix_count=None /> }>
                        {move || Suspend::new(async move {
                            let count = shared
                                .fix_queue
                                .await
                                .ok()
                                .and_then(|v| v.get("count").and_then(|c| c.as_u64()));
                            view! { <OpModeRail fix_count=count /> }.into_any()
                        })}
                    </Suspense>
                    <main id="main-content" class="relative min-w-0 flex-1 pb-12" tabindex="-1">
                        {children()}
                    </main>
                </div>
            </div>
            <OpNotifyCenter open=notify.open set_open=notify.set_open />
            <OpDrawerHost />
            <OpPaletteHost />
            <OpCreateWorkflowHost />
            <OpCreateAgentHost />
            <OpAgentExplainHost />
        </div>
    }
}
