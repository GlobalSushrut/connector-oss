//! Mode-aware banner for admin pages (Phase 5.8).
//!
//! `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md` §15 (P1-26): admin surfaces
//! like `/billing`, `/license`, `/secrets`, `/webhooks`, and
//! `/settings/custom-domains` should *feel intentional* in Self-deploy
//! — these are real production controls, not demo widgets — and
//! *clearly absent* in Playground.
//!
//! In Playground these pages already render `PlaygroundDeflect` from
//! Phase 2.5; here we add a small "Self-hosted node" banner to the
//! Self-deploy version so the operator knows changes apply
//! immediately to a real deployment.

use leptos::prelude::*;

use crate::deployment::{use_deployment, use_deployment_mode, DeploymentMode};

/// Surface kind controls the copy in the banner. Keep this list
/// small — one variant per page that needs a banner.
#[derive(Debug, Clone, Copy)]
pub enum ProductionSurface {
    Billing,
    License,
    Secrets,
    Webhooks,
    CustomDomains,
}

impl ProductionSurface {
    fn copy(self) -> (&'static str, &'static str) {
        match self {
            ProductionSurface::Billing => (
                "Real billing",
                "Charges, overages, and entitlement changes apply to this node's tenant immediately.",
            ),
            ProductionSurface::License => (
                "Live license",
                "License operations (activate, refresh, refuse) take effect on this node's kernel within ~5 s.",
            ),
            ProductionSurface::Secrets => (
                "Persistent secrets",
                "Secrets are stored in the local vault and used by plugins on next invocation — no demo reset.",
            ),
            ProductionSurface::Webhooks => (
                "Outbound webhooks",
                "Each enabled webhook signs requests with this node's secret and fires for every matching event.",
            ),
            ProductionSurface::CustomDomains => (
                "DNS-bound endpoints",
                "Custom domains rewrite this node's public URL once verified — clients see the new hostname immediately.",
            ),
        }
    }
}

#[component]
pub fn ProductionModeBanner(surface: ProductionSurface) -> impl IntoView {
    let mode = use_deployment_mode();
    let deployment = use_deployment();

    view! {
        {move || {
            if mode.get() != DeploymentMode::SelfHosted {
                return view! { <span></span> }.into_any();
            }
            let (eyebrow, body) = surface.copy();
            let info = deployment.get();
            let instance_label = if info.public_url.is_empty() {
                String::from("this node")
            } else {
                info.public_url.clone()
            };
            view! {
                <aside class="mb-4 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3.5 py-2.5 flex items-start gap-2.5">
                    <span class="mt-0.5 inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400 shrink-0"></span>
                    <div class="flex-1 min-w-0">
                        <div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                            <p class="text-[10px] uppercase tracking-wider text-emerald-300/80 font-semibold">{eyebrow}</p>
                            <span class="text-[10px] text-zinc-500 font-mono truncate">{instance_label}</span>
                        </div>
                        <p class="text-xs text-zinc-300 mt-0.5">{body}</p>
                    </div>
                </aside>
            }.into_any()
        }}
    }
}
