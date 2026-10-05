//! "Update available" toast (Phase 5.9).
//!
//! Polls `https://releases.connector.dev/latest.json` once on mount
//! and compares the returned version to the running node's
//! `DeploymentInfo.version`. If newer, a small dismissable toast
//! anchors to the bottom-right of every page while
//! `mode == SelfHosted`.
//!
//! Playground bundles never poll — sessions are ephemeral and the
//! release feed isn't relevant to a hosted demo.
//!
//! Dismissal is per-version: clicking "Dismiss" sets a localStorage
//! key (`update_toast_dismissed_for=<latest_version>`) so the same
//! release won't pop up again, but the next release will.

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::Deserialize;

use crate::deployment::{use_deployment, use_deployment_mode, DeploymentMode};

const LATEST_URL: &str = "https://releases.connector.dev/latest.json";
const DISMISS_KEY: &str = "update_toast_dismissed_for";

#[derive(Debug, Clone, Deserialize)]
struct LatestRelease {
    version: String,
    #[serde(default)]
    release_url: String,
    #[serde(default)]
    notes: String,
}

#[component]
pub fn UpdateToast() -> impl IntoView {
    let mode = use_deployment_mode();
    let deployment = use_deployment();
    let (latest, set_latest) = signal::<Option<LatestRelease>>(None);
    let (dismissed, set_dismissed) = signal(false);

    // Fire one fetch on mount; bail out before the network call if
    // we're in Playground mode.
    Effect::new(move |has_run: Option<bool>| {
        if has_run.unwrap_or(false) {
            return true;
        }
        if mode.get() != DeploymentMode::SelfHosted {
            return true;
        }
        let current = deployment.get().version;
        spawn_local(async move {
            match fetch_latest().await {
                Ok(release) => {
                    if is_newer(&release.version, &current) {
                        let last_dismissed: Result<String, _> = LocalStorage::get(DISMISS_KEY);
                        if last_dismissed.ok().as_deref() != Some(release.version.as_str()) {
                            set_latest.set(Some(release));
                        }
                    }
                }
                Err(_) => {
                    // Network errors are silent — toast just won't appear.
                }
            }
        });
        true
    });

    let on_dismiss = move |_| {
        if let Some(l) = latest.get() {
            let _ = LocalStorage::set(DISMISS_KEY, l.version);
        }
        set_dismissed.set(true);
    };

    view! {
        <Show when=move || !dismissed.get() && latest.get().is_some() && mode.get() == DeploymentMode::SelfHosted>
            {move || {
                let release = latest.get().expect("guarded by Show");
                let current = deployment.get().version;
                view! {
                    <aside
                        class="fixed bottom-4 right-4 z-40 max-w-sm rounded-xl border border-indigo-500/30 bg-zinc-950/95 shadow-2xl shadow-black/60 px-4 py-3 space-y-2"
                        role="status"
                        aria-live="polite"
                    >
                        <div class="flex items-start justify-between gap-3">
                            <div>
                                <p class="text-[10px] uppercase tracking-wider text-indigo-300/80 font-semibold">"Update available"</p>
                                <h3 class="text-sm font-semibold text-zinc-100">
                                    "Connector "
                                    <span class="font-mono">{release.version.clone()}</span>
                                    " is ready."
                                </h3>
                                <p class="text-[11px] text-zinc-500 mt-0.5">
                                    "You're on "<span class="font-mono">{current}</span>"."
                                </p>
                            </div>
                            <button
                                type="button"
                                class="text-zinc-500 hover:text-zinc-300 text-xs"
                                on:click=on_dismiss
                                aria-label="Dismiss update toast"
                            >
                                "✕"
                            </button>
                        </div>
                        {(!release.notes.is_empty()).then(|| view! {
                            <p class="text-xs text-zinc-400 line-clamp-2">{release.notes.clone()}</p>
                        })}
                        <div class="flex items-center gap-2 pt-1">
                            {(!release.release_url.is_empty()).then(|| view! {
                                <a
                                    href=release.release_url.clone()
                                    target="_blank"
                                    rel="noreferrer"
                                    class="px-2 py-1 rounded text-[11px] font-semibold bg-indigo-600 hover:bg-indigo-500 text-white"
                                >
                                    "Release notes ↗"
                                </a>
                            })}
                            <a
                                href="/install"
                                class="px-2 py-1 rounded text-[11px] font-semibold bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700/60"
                            >
                                "Upgrade steps"
                            </a>
                        </div>
                    </aside>
                }
            }}
        </Show>
    }
}

async fn fetch_latest() -> Result<LatestRelease, String> {
    use gloo_net::http::Request;
    let resp = Request::get(LATEST_URL)
        .send()
        .await
        .map_err(|e| format!("network: {e}"))?;
    if !resp.ok() {
        return Err(format!("status: {}", resp.status()));
    }
    resp.json::<LatestRelease>()
        .await
        .map_err(|e| format!("decode: {e}"))
}

/// Naïve SemVer compare: split on `.` and `-`, parse leading numeric
/// chunks. Falls back to string compare if either side doesn't look
/// like a version string. Sufficient for a "newer than" check
/// because the release feed publishes plain SemVer
/// (`1.4.2`, `1.5.0-rc.1`, …).
fn is_newer(latest: &str, current: &str) -> bool {
    if current.trim().is_empty() {
        // Can't compare against an unknown node version — skip the toast.
        return false;
    }
    if latest.trim().is_empty() || latest == current {
        return false;
    }
    let lp = parse_version(latest);
    let cp = parse_version(current);
    for (l, c) in lp.iter().zip(cp.iter()) {
        if l > c {
            return true;
        }
        if l < c {
            return false;
        }
    }
    lp.len() > cp.len()
}

fn parse_version(v: &str) -> Vec<u32> {
    v.trim_start_matches('v')
        .split(|c: char| c == '.' || c == '-' || c == '+')
        .filter_map(|chunk| {
            let digits: String = chunk.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u32>().ok()
        })
        .collect()
}
