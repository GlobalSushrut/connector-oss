//! "What's new" release-notes toast (Phase 7.7 / P2-11).
//!
//! Pops up once per installed version after an upgrade with a short
//! summary of the changes. Distinct from [`UpdateToast`] — that one
//! tells you a *newer* version is available; this one tells you what
//! actually shipped in the version you are now running.
//!
//! Trigger conditions (all must hold):
//!
//! 1. `mode == SelfHosted` — Playground sessions are ephemeral and
//!    don't get release notes.
//! 2. `DeploymentInfo.version` is non-empty.
//! 3. `localStorage["whats_new_seen"]` is missing or `!= version` —
//!    the operator hasn't acknowledged this release yet.
//! 4. A matching notes blob loaded from
//!    `https://releases.connector.dev/notes/{version}.json` (404 is
//!    silent: most patch releases don't ship notes).
//!
//! Once dismissed, the version goes into `whats_new_seen` and the
//! toast stays gone until the node upgrades again.

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::Deserialize;

use crate::deployment::{use_deployment, use_deployment_mode, DeploymentMode};

const NOTES_URL_PREFIX: &str = "https://releases.connector.dev/notes/";
const SEEN_KEY: &str = "whats_new_seen";

#[derive(Debug, Clone, Deserialize)]
struct ReleaseNotes {
    /// Headline summary shown in the toast title (≤ 80 chars).
    #[serde(default)]
    headline: String,
    /// 1–4 bullet points; we render the first three and ellipsise.
    #[serde(default)]
    highlights: Vec<String>,
    /// Optional URL to the full release post (blog, GitHub Release).
    #[serde(default)]
    url: String,
}

#[component]
pub fn WhatsNewToast() -> impl IntoView {
    let mode = use_deployment_mode();
    let deployment = use_deployment();
    let (notes, set_notes) = signal::<Option<ReleaseNotes>>(None);
    let (version, set_version) = signal(String::new());
    let (dismissed, set_dismissed) = signal(false);

    // Fire one fetch on mount, gated on a known version + self-hosted
    // mode + a fresh post-upgrade `localStorage` state.
    Effect::new(move |has_run: Option<bool>| {
        if has_run.unwrap_or(false) {
            return true;
        }
        if mode.get() != DeploymentMode::SelfHosted {
            return true;
        }
        let v = deployment.get().version;
        if v.trim().is_empty() {
            return true;
        }
        let last_seen: Result<String, _> = LocalStorage::get(SEEN_KEY);
        if last_seen.ok().as_deref() == Some(v.as_str()) {
            // Operator already saw this release.
            return true;
        }
        set_version.set(v.clone());
        spawn_local(async move {
            if let Ok(payload) = fetch_notes(&v).await {
                set_notes.set(Some(payload));
            }
        });
        true
    });

    let on_dismiss = move |_| {
        let v = version.get();
        if !v.is_empty() {
            let _ = LocalStorage::set(SEEN_KEY, v);
        }
        set_dismissed.set(true);
    };

    view! {
        <Show when=move || !dismissed.get() && notes.get().is_some() && mode.get() == DeploymentMode::SelfHosted>
            {move || {
                let n = notes.get().expect("guarded by Show");
                let v = version.get();
                let headline = if n.headline.is_empty() {
                    format!("What's new in v{}", v)
                } else {
                    n.headline.clone()
                };
                let bullets: Vec<String> = n
                    .highlights
                    .iter()
                    .take(3)
                    .cloned()
                    .collect();
                view! {
                    <aside
                        role="status"
                        aria-live="polite"
                        aria-label="What's new in this release"
                        class="fixed bottom-4 right-4 z-40 max-w-sm rounded-xl border border-success/30 bg-zinc-950/95 shadow-2xl shadow-black/60 px-4 py-3 space-y-2"
                    >
                        <div class="flex items-start justify-between gap-3">
                            <div>
                                <p class="text-[10px] uppercase tracking-wider text-success font-semibold">
                                    "What's new"
                                </p>
                                <h3 class="text-sm font-semibold text-zinc-100">
                                    {headline}
                                </h3>
                                <p class="text-[11px] text-muted mt-0.5">
                                    "Running "<span class="font-mono">"v"{v}</span>"."
                                </p>
                            </div>
                            <button
                                type="button"
                                class="text-zinc-500 hover:text-zinc-300 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 rounded-sm"
                                on:click=on_dismiss
                                aria-label="Dismiss What's new toast"
                            >
                                "✕"
                            </button>
                        </div>
                        {(!bullets.is_empty()).then(|| view! {
                            <ul class="list-disc list-inside text-[11px] text-zinc-300 space-y-0.5 leading-snug">
                                {bullets.into_iter().map(|b| view! {
                                    <li>{b}</li>
                                }).collect_view()}
                            </ul>
                        })}
                        <div class="flex items-center gap-2 pt-1">
                            {(!n.url.is_empty()).then(|| view! {
                                <a
                                    href=n.url.clone()
                                    target="_blank"
                                    rel="noreferrer"
                                    class="px-2 py-1 rounded text-[11px] font-semibold bg-brand text-white hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 no-underline"
                                >
                                    "Read more ↗"
                                </a>
                            })}
                        </div>
                    </aside>
                }
            }}
        </Show>
    }
}

async fn fetch_notes(version: &str) -> Result<ReleaseNotes, String> {
    use gloo_net::http::Request;
    // Strip a leading "v" if the server reports `v1.4.2` since the
    // release feed publishes plain SemVer paths.
    let stripped = version.trim_start_matches('v');
    let url = format!("{NOTES_URL_PREFIX}{stripped}.json");
    let resp = Request::get(&url)
        .send()
        .await
        .map_err(|e| format!("network: {e}"))?;
    if !resp.ok() {
        return Err(format!("status: {}", resp.status()));
    }
    resp.json::<ReleaseNotes>()
        .await
        .map_err(|e| format!("decode: {e}"))
}
