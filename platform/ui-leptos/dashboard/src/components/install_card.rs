//! Install-on-your-own-infra card (Phase 2.8).
//!
//! Rendered in place of every admin / self-hosted-only page (Billing,
//! License, Settings, Webhooks, Notifications, Secrets) when the
//! Leptos dashboard is running against the Playground distribution.
//! Visitors of the 90-minute hosted trial see this card; visitors of a
//! self-hosted node see the real admin UI underneath.
//!
//! Pattern: wrap any admin route in [`PlaygroundDeflect`]; the
//! component watches the runtime `DeploymentMode` signal and swaps the
//! tree at runtime.
//!
//! The card is intentionally **content-light** — it is shared across
//! ~7 admin routes; per-route copy is owned by the wrapped page.
//! Chrome matches `/install` (PKG LOADSTATION).

#![allow(dead_code)]

use leptos::prelude::*;

use crate::deployment::{use_deployment_mode, DeploymentMode};

/// Standalone install card. Shows the canonical
/// "install on your own infra" CTA. Use [`PlaygroundDeflect`] for
/// runtime-gated routing; use this component directly only for one-off
/// embeds (e.g. inside Settings sub-tabs).
#[component]
pub fn InstallCard() -> impl IntoView {
    view! {
        <div class="page-wrapper fcs-install">
            <div class="page-content">
                <div class="max-w-2xl mx-auto fcs-bezel">
                    <div class="fcs-titlebar">
                        <div class="fcs-titlebar-mark">
                            <span class="fcs-win-controls" aria-hidden="true">
                                <span class="fcs-win-btn close"></span>
                                <span class="fcs-win-btn"></span>
                                <span class="fcs-win-btn"></span>
                            </span>
                            <span class="truncate">"CONNECTOR OS  ·  RESTRICTED BAY"</span>
                        </div>
                        <div class="fcs-lights">
                            <span class="fcs-light pwr"><span class="dot"></span>"PWR"</span>
                            <span class="fcs-light stby"><span class="dot"></span>"NO-GO"</span>
                        </div>
                    </div>

                    <div class="fcs-body space-y-4">
                        <div class="fcs-telemetry">
                            <div class="fcs-telem">
                                <span class="k">"MODE"</span>
                                <span class="v">"PLAYGROUND"</span>
                            </div>
                            <div class="fcs-telem">
                                <span class="k">"CLEARANCE"</span>
                                <span class="v">"SELF-HOST ONLY"</span>
                            </div>
                            <div class="fcs-telem">
                                <span class="k">"BAY"</span>
                                <span class="v">"ADMIN / LOCKED"</span>
                            </div>
                            <div class="fcs-telem">
                                <span class="k">"ACTION"</span>
                                <span class="v">"LOAD PKG"</span>
                            </div>
                        </div>

                        <div>
                            <p class="text-[9px] uppercase tracking-[0.2em] text-amber-300/80 font-semibold">"Self-hosted only"</p>
                            <h2 class="text-xl font-semibold text-stone-100 mt-1">
                                "Install Connector on your own infra"
                            </h2>
                            <p class="text-sm text-stone-400 mt-2 leading-relaxed">
                                "This page manages production-grade settings — billing, license keys, webhooks, secrets, custom domains. They live on a node " <strong class="text-stone-200">"you control"</strong>", not on the 90-minute hosted Playground."
                            </p>
                        </div>

                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                            <a
                                href="/install"
                                class="fcs-btn go"
                            >
                                "OPEN LOADSTATION"
                            </a>
                            <a
                                href="https://connector.dev/get-started"
                                class="fcs-btn amber"
                                target="_blank"
                                rel="noopener"
                            >
                                "GET INSTALL TARBALL"
                            </a>
                            <a
                                href="/apps"
                                class="fcs-btn sm:col-span-2"
                            >
                                "KEEP EXPLORING TRIAL"
                            </a>
                        </div>

                        <details class="text-xs text-stone-500 pt-2 border-t border-stone-800/60">
                            <summary class="cursor-pointer hover:text-amber-200/80 tracking-wide uppercase text-[10px]">"What does the tarball ship?"</summary>
                            <ul class="mt-2 space-y-1 list-disc list-inside text-stone-400 normal-case tracking-normal">
                                <li>"Single binary + systemd unit"</li>
                                <li>"Built-in admin UI (the page you just tried to open)"</li>
                                <li>"License manager, webhooks, secrets vault"</li>
                                <li>"All 9 marketed plugins gated by your license tier"</li>
                                <li>"Migration tool to import your Playground session as a starting point"</li>
                            </ul>
                        </details>
                    </div>

                    <div class="fcs-statusbar">
                        <span>"PAD LOCKED  ·  HOSTED TRIAL"</span>
                        <span>"OPEN /INSTALL TO LOAD"</span>
                    </div>
                </div>
            </div>
        </div>
    }
}

/// Conditional wrapper for admin pages.
///
/// - **Playground build / runtime**: renders [`InstallCard`].
/// - **Self-hosted build / runtime**: renders `children` unchanged.
/// - **Unknown** (cold start, fetch in flight): renders children (the
///   conservative choice — Self-hosted is the common case).
#[component]
pub fn PlaygroundDeflect(children: ChildrenFn) -> impl IntoView {
    let mode = use_deployment_mode();
    view! {
        <Show
            when=move || mode.get() != DeploymentMode::Playground
            fallback=|| view! { <InstallCard /> }
        >
            {children()}
        </Show>
    }
}
