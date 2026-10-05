//! Deployment-mode awareness for the Leptos dashboard.
//!
//! Single source of truth for "which distribution am I rendering?":
//!
//! - **Playground** — vendor-hosted 90-minute trial (`try.cnktros.com`).
//!   Drives the countdown timer, conversion CTAs, and playground-only
//!   wizards. Compile-gated *and* runtime-checked.
//! - **Self-hosted** — tarball / Compose install. Real admin pages, no
//!   countdown, conversion CTAs hidden. Compile-gated *and*
//!   runtime-checked.
//! - **Unknown** — fetch in flight or `/deployment/info` failed. The UI
//!   should fall back to the most conservative behaviour (no countdown,
//!   no admin elevation, generic affordances).
//!
//! The module exposes:
//!
//! - [`DeploymentMode`] / [`DeploymentInfo`] data types.
//! - [`provide_deployment_signals`] — call once in `App::main`. Provides
//!   `ReadSignal<DeploymentInfo>` and `Memo<DeploymentMode>` via context.
//!   Kicks off the initial fetch and a 60-second refresh tick.
//! - [`use_deployment`] / [`use_deployment_mode`] — context accessors
//!   for downstream widgets.
//!
//! Phase 1 lands the plumbing only; consumers arrive in Phases 2–5. The
//! module-wide `dead_code` allow is intentional — every item below is
//! part of the foundation surface that later phases consume.

#![allow(dead_code)]

use std::time::Duration;

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::api;

/// Server-reported distribution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// 90-minute hosted trial. Drives playground-only UI affordances.
    Playground,
    /// Self-deploy tarball / Compose install. Full operator dashboard.
    SelfHosted,
    /// First fetch in flight or `/deployment/info` failed. Treat as the
    /// most conservative subset of capabilities until a real response
    /// arrives. **Never persisted on disk.**
    #[default]
    #[serde(other)]
    Unknown,
}

impl DeploymentMode {
    pub fn label(&self) -> &'static str {
        match self {
            DeploymentMode::Playground => "Playground",
            DeploymentMode::SelfHosted => "Self-hosted",
            DeploymentMode::Unknown => "Detecting…",
        }
    }

    pub fn is_playground(&self) -> bool {
        matches!(self, DeploymentMode::Playground)
    }

    pub fn is_self_hosted(&self) -> bool {
        matches!(self, DeploymentMode::SelfHosted)
    }

    /// True once the dashboard has observed *any* successful response.
    pub fn is_known(&self) -> bool {
        !matches!(self, DeploymentMode::Unknown)
    }
}

/// Compile-time feature-flag check.
///
/// `Cargo.toml` defines `playground` and `self-deploy` features (Phase 1
/// PR 1.2). Each release artefact opts into exactly one. This helper lets
/// downstream code assert that the runtime mode matches the compile-time
/// build (loud `tracing::warn!` if not — e.g. someone shipped a
/// `self-deploy` binary against a `CONNECTOR_PRESET=playground` server).
#[cfg(feature = "playground")]
pub fn build_profile() -> &'static str {
    "playground"
}
#[cfg(feature = "self-deploy")]
pub fn build_profile() -> &'static str {
    "self-deploy"
}
#[cfg(not(any(feature = "playground", feature = "self-deploy")))]
pub fn build_profile() -> &'static str {
    "unspecified"
}

/// Full payload returned by `GET /api/v1/deployment/info`.
///
/// Field names match the server-side `services::deployment` module. All
/// fields are optional on the client because we want to render *something*
/// even if the server returns a minimal subset (forward compatibility).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct DeploymentInfo {
    #[serde(default)]
    pub mode: DeploymentMode,
    #[serde(default)]
    pub edition: String,
    #[serde(default)]
    pub public_url: String,
    #[serde(default)]
    pub version: String,

    // Playground-only.
    #[serde(default)]
    pub session_expires_at: Option<i64>,
    #[serde(default)]
    pub session_ttl_secs: Option<u64>,

    // Self-hosted only.
    #[serde(default)]
    pub license_tier: Option<String>,
    #[serde(default)]
    pub license_status: Option<String>,

    #[serde(default)]
    pub feature_flags: DeploymentFeatureFlags,

    /// Playground-only — current usage relative to per-session caps.
    /// Self-deploy nodes omit this and the meters component hides
    /// itself. Server populates this on every refresh of
    /// `/deployment/info` so the meters tick down in near-real-time.
    #[serde(default)]
    pub caps: Option<DeploymentCaps>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct DeploymentCaps {
    #[serde(default)]
    pub agents_used: u32,
    #[serde(default)]
    pub agents_max: u32,
    #[serde(default)]
    pub tokens_used: u64,
    #[serde(default)]
    pub tokens_max: u64,
    #[serde(default)]
    pub workflows_used: u32,
    #[serde(default)]
    pub workflows_max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct DeploymentFeatureFlags {
    #[serde(default)]
    pub wizards_enabled: bool,
    #[serde(default)]
    pub playground_telemetry: bool,
    #[serde(default)]
    pub self_deploy_admin: bool,
}

impl DeploymentInfo {
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn mode(&self) -> DeploymentMode {
        self.mode
    }
}

/// Refresh cadence for the deployment payload. Playground needs a tighter
/// tick for session countdown + capacity meters; self-hosted can relax.
const PLAYGROUND_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const BACKGROUND_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Install the deployment signals into the Leptos context graph.
///
/// Call **once**, at the very top of `App::main` — before any route
/// renders. The function:
///
/// 1. Creates `(read, write)` signals seeded with [`DeploymentMode::Unknown`].
/// 2. Provides both halves via `provide_context` so downstream widgets
///    can call [`use_deployment`] / [`use_deployment_mode`] without
///    prop-drilling through every page.
/// 3. Fetches once on boot, refetches when the tab becomes visible again,
///    then polls on a mode-aware interval (60 s playground / 5 min else).
pub fn provide_deployment_signals() {
    let (info, set_info) = signal(DeploymentInfo::unknown());
    let mode = Memo::new(move |_| info.get().mode);

    provide_context(info);
    provide_context(set_info);
    provide_context(mode);

    install_visibility_refresh(set_info);

    spawn_local(async move {
        fetch_and_store(set_info).await;
        loop {
            let ms = if info.get_untracked().mode.is_playground() {
                PLAYGROUND_REFRESH_INTERVAL
            } else {
                BACKGROUND_REFRESH_INTERVAL
            };
            gloo_timers::future::TimeoutFuture::new(ms.as_millis() as u32).await;
            fetch_and_store(set_info).await;
        }
    });
}

/// Refetch deployment info when the user returns to the tab.
fn install_visibility_refresh(set_info: WriteSignal<DeploymentInfo>) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let closure = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
        let visible = web_sys::window()
            .and_then(|w| w.document())
            .map(|d| !d.hidden())
            .unwrap_or(false);
        if visible {
            spawn_local(async move {
                fetch_and_store(set_info).await;
            });
        }
    }) as Box<dyn FnMut()>);
    let _ = window.add_event_listener_with_callback(
        "visibilitychange",
        closure.as_ref().unchecked_ref(),
    );
    closure.forget();
}

async fn fetch_and_store(set_info: WriteSignal<DeploymentInfo>) {
    match api::get_value("/deployment/info").await {
        Ok(value) => {
            match serde_json::from_value::<DeploymentInfo>(value) {
                Ok(parsed) => {
                    log_build_drift(parsed.mode);
                    set_info.set(parsed);
                }
                Err(e) => {
                    log::warn!(
                        "deployment/info parse failed — keeping current value: {e}"
                    );
                }
            }
        }
        Err(e) => {
            log::warn!(
                "deployment/info fetch failed (status={}, msg={}) — keeping current value",
                e.status,
                e.message,
            );
        }
    }
}

fn log_build_drift(runtime: DeploymentMode) {
    let build = build_profile();
    let drift = matches!(
        (build, runtime),
        ("playground", DeploymentMode::SelfHosted)
            | ("self-deploy", DeploymentMode::Playground),
    );
    if drift {
        log::warn!(
            "deployment drift detected: built with feature='{build}' but server reports mode='{runtime:?}'. \
             UI affordances will favour the runtime mode."
        );
    }
}

/// Subscribe to the full deployment info inside a component.
///
/// Returns the read signal. Use [`Signal::get`] inside a closure (e.g.
/// `move || info.get().mode.is_playground()`) to react to changes.
///
/// Panics in debug builds if [`provide_deployment_signals`] has not been
/// called — this is a programming bug, not a runtime condition.
pub fn use_deployment() -> ReadSignal<DeploymentInfo> {
    expect_context::<ReadSignal<DeploymentInfo>>()
}

/// Shortcut for the most common access pattern: `mode == Playground`.
pub fn use_deployment_mode() -> Memo<DeploymentMode> {
    expect_context::<Memo<DeploymentMode>>()
}
