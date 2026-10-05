//! Recommended next steps (Phase 6.10 / P1-15).
//!
//! Polls `GET /api/v1/setup/recommendations` (server-side engine
//! computes 0–3 cards from current state). Each card has:
//!
//! * `id`     — stable key used for per-user dismissal.
//! * `title`  — bold one-liner.
//! * `body`   — optional secondary line.
//! * `cta_label` + `cta_path` — primary action.
//!
//! Operators can dismiss individual cards locally; the dismissal is
//! keyed by `recommendation:dismissed:<id>` in `localStorage`. The
//! server is free to bump card IDs (e.g. `set_budget_v2`) to force
//! a re-show.
//!
//! Hidden entirely on a fully-onboarded node (server returns an
//! empty list).

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use leptos_router::components::A;
use serde::Deserialize;

use crate::api;

const DISMISS_PREFIX: &str = "recommendation:dismissed:";

#[derive(Debug, Clone, Deserialize)]
struct Recommendation {
    id: String,
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default = "default_cta_label")]
    cta_label: String,
    cta_path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RecommendationsPayload {
    #[serde(default)]
    recommendations: Vec<Recommendation>,
}

fn default_cta_label() -> String {
    "Get started →".into()
}

#[component]
pub fn RecommendationsPanel() -> impl IntoView {
    let resource = LocalResource::new(|| async {
        api::get::<RecommendationsPayload>("/setup/recommendations").await
    });
    let (bump, set_bump) = signal(0u64);

    view! {
        <Suspense fallback=|| view! { <span></span> }>
            {move || Suspend::new(async move {
                let _ = bump.get();
                let r = resource.await;
                let payload = r.unwrap_or_default();
                let visible: Vec<Recommendation> = payload
                    .recommendations
                    .into_iter()
                    .filter(|c| !is_dismissed(&c.id))
                    .collect();
                if visible.is_empty() {
                    return view! { <span></span> }.into_any();
                }
                view! {
                    <section class="rounded-2xl border border-indigo-500/20 bg-gradient-to-br from-indigo-500/5 to-violet-500/5 px-4 py-3 space-y-2">
                        <div class="flex items-center justify-between gap-2">
                            <p class="text-[10px] uppercase tracking-wider text-indigo-300/80 font-semibold">"Suggested next steps"</p>
                            <span class="text-[10px] text-zinc-500">{format!("{} suggestion(s)", visible.len())}</span>
                        </div>
                        <ul class="grid grid-cols-1 md:grid-cols-3 gap-2">
                            {visible.into_iter().map(|c| {
                                let id_for_dismiss = c.id.clone();
                                view! {
                                    <li class="rounded-xl border border-zinc-800/60 bg-zinc-950/40 px-3 py-2 flex flex-col gap-1">
                                        <p class="text-sm font-semibold text-zinc-100">{c.title.clone()}</p>
                                        {(!c.body.is_empty()).then(|| view! {
                                            <p class="text-[11px] text-zinc-500">{c.body.clone()}</p>
                                        })}
                                        <div class="flex items-center gap-2 mt-1">
                                            <A href=c.cta_path.clone() attr:class="text-[11px] font-semibold text-indigo-300 hover:text-indigo-200">
                                                {c.cta_label.clone()}
                                            </A>
                                            <button
                                                type="button"
                                                class="ml-auto text-[11px] text-zinc-500 hover:text-zinc-300"
                                                on:click=move |_| {
                                                    let _ = LocalStorage::set(format!("{DISMISS_PREFIX}{id_for_dismiss}"), true);
                                                    set_bump.update(|b| *b += 1);
                                                }
                                            >
                                                "Dismiss"
                                            </button>
                                        </div>
                                    </li>
                                }
                            }).collect::<Vec<_>>()}
                        </ul>
                    </section>
                }.into_any()
            })}
        </Suspense>
    }
}

fn is_dismissed(id: &str) -> bool {
    let key = format!("{DISMISS_PREFIX}{id}");
    LocalStorage::get::<bool>(&key).unwrap_or(false)
}
