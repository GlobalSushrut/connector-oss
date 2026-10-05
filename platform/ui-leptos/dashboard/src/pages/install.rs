//! `/install` — Phase 5.5.
//!
//! Single-page "take Connector home" surface. Reachable from:
//!
//! * The Playground footer "Take this home →" link.
//! * The Session-end modal's "See install commands →" button.
//! * The Playground tour's Finish step.
//! * The marketing site (deep link).
//!
//! Three sections:
//!
//! 1. **Install commands** — copy-paste cards for curl, Docker, and
//!    Helm (styled as flight-control load pads).
//! 2. **Save this session** — downloads `connector-trial-{tenant}.tar.gz`
//!    from `GET /api/v1/playground/session/export` (Phase 5.6 server
//!    work). The button degrades gracefully if the endpoint isn't
//!    shipped yet.
//! 3. **Pricing + portal CTA** — three-tier overview with a sign-up
//!    button (clearance bands).
//!
//! Visual language: nostalgic OS installer chrome inside an avionics
//! bezel — PKG LOADSTATION. Behaviour is unchanged.

use leptos::prelude::*;
use leptos_router::components::A;
use std::time::Duration;

use crate::auth::AuthState;
use crate::components::layout::Header;
use crate::components::page_title::use_page_title;
use crate::deployment::{use_deployment_mode, DeploymentMode};

const PORTAL_SIGNUP_URL: &str = "https://portal.connector.dev/signup";
const SESSION_EXPORT_PATH: &str = "/api/v1/playground/session/export";

fn zulu_now() -> String {
    let d = js_sys::Date::new_0();
    format!(
        "{:02}:{:02}:{:02}Z",
        d.get_utc_hours(),
        d.get_utc_minutes(),
        d.get_utc_seconds()
    )
}

#[component]
pub fn InstallPage(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("PKG Loadstation");
    let mode = use_deployment_mode();
    let (clock, set_clock) = signal(zulu_now());

    Effect::new(move |has_run: Option<bool>| {
        if has_run.unwrap_or(false) {
            return true;
        }
        let _ = set_interval_with_handle(
            move || set_clock.set(zulu_now()),
            Duration::from_millis(1000),
        );
        true
    });

    view! {
        <div class="page-wrapper fcs-install">
            <Header title="PKG Loadstation" auth=auth />
            <div class="page-content max-w-3xl">
                <div class="fcs-bezel">
                    <div class="fcs-titlebar">
                        <div class="fcs-titlebar-mark">
                            <span class="fcs-win-controls" aria-hidden="true">
                                <span class="fcs-win-btn close"></span>
                                <span class="fcs-win-btn"></span>
                                <span class="fcs-win-btn"></span>
                            </span>
                            <span class="truncate">"CONNECTOR OS  ·  PKG INSTALLER  ·  LOADSTATION"</span>
                        </div>
                        <div class="fcs-lights">
                            <span class="fcs-light pwr"><span class="dot"></span>"PWR"</span>
                            <span class="fcs-light stby"><span class="dot"></span>"STBY"</span>
                            <span class="fcs-light go"><span class="dot"></span>"GO"</span>
                        </div>
                    </div>

                    <div class="fcs-body space-y-5">
                        <div class="fcs-telemetry">
                            <div class="fcs-telem">
                                <span class="k">"STATION"</span>
                                <span class="v">":8080 / LOCAL"</span>
                            </div>
                            <div class="fcs-telem">
                                <span class="k">"NODE"</span>
                                <span class="v">{move || match mode.get() {
                                    DeploymentMode::Playground => "PLAYGROUND",
                                    DeploymentMode::SelfHosted => "SELF-HOST",
                                    DeploymentMode::Unknown => "DETECTING",
                                }}</span>
                            </div>
                            <div class="fcs-telem">
                                <span class="k">"BAY"</span>
                                <span class="v">"PKG · 3 PADS"</span>
                            </div>
                            <div class="fcs-telem">
                                <span class="k">"ZULU"</span>
                                <span class="v">{move || clock.get()}</span>
                            </div>
                        </div>

                        <div class="fcs-heading-tape" aria-hidden="true">
                            <div class="fcs-heading-track">
                                <span>"HDG 270  ·  ALT HOLD  ·  KERNEL NOMINAL  ·  CAGE ARMED  ·  WITNESS CTL  ·  "</span>
                                <span>"HDG 270  ·  ALT HOLD  ·  KERNEL NOMINAL  ·  CAGE ARMED  ·  WITNESS CTL  ·  "</span>
                            </div>
                        </div>

                        <div class="fcs-checklist" role="list">
                            <div class="fcs-check go" role="listitem"><span class="box"></span>"IDENT"</div>
                            <div class="fcs-check go" role="listitem"><span class="box"></span>"KERNEL"</div>
                            <div class="fcs-check stby" role="listitem"><span class="box"></span>"PAD SELECT"</div>
                            <div class="fcs-check" role="listitem"><span class="box"></span>"LOAD"</div>
                        </div>

                        <div>
                            <p class="text-[10px] uppercase tracking-[0.22em] text-amber-200/80 font-semibold">"Take Connector home"</p>
                            <h2 class="text-lg font-semibold text-stone-100 mt-1 tracking-tight">"Run Connector on your own infrastructure."</h2>
                            <p class="text-sm text-stone-400 mt-2 max-w-2xl leading-relaxed">
                                "All three load pads produce the same node — same kernel, same plugin substrate, same dashboard. Pick the pad that fits your shop."
                            </p>
                        </div>

                        <Show when=move || mode.get() == DeploymentMode::Playground>
                            <section class="fcs-pad space-y-3">
                                <div class="flex items-center justify-between gap-2">
                                    <p class="fcs-pad-id">"TAPE  ·  FLIGHT BAG"</p>
                                    <span class="text-[9px] tracking-[0.16em] uppercase text-emerald-400/90">"PLAYGROUND ONLY"</span>
                                </div>
                                <h3 class="text-sm font-semibold text-stone-100">"Save this playground session"</h3>
                                <p class="text-xs text-stone-400 leading-relaxed">
                                    "Downloads a "<span class="text-emerald-300/90">"connector-trial-{tenant}.tar.gz"</span>" with your "
                                    <span class="text-stone-200">"connector.yaml"</span>", installed workflows, and receipts. "
                                    "Drop it into a fresh node's "<span class="text-stone-300">"/var/lib/connector/import/"</span>" and the first-run wizard will pre-fill from it."
                                </p>
                                <a href=SESSION_EXPORT_PATH class="fcs-btn go">
                                    "DOWNLOAD SESSION TAPE"
                                </a>
                                <p class="text-[10px] text-stone-600">
                                    "Backed by "<span class="dev-only">"GET /api/v1/playground/session/export"</span>"."
                                </p>
                            </section>
                        </Show>

                        <section class="space-y-3" id="install-commands">
                            <h2 class="fcs-section-label">"Load pads  ·  install commands"</h2>
                            <InstallCommandCard
                                pad="PAD-1"
                                kind="One-line install"
                                desc="Single command, sensible defaults. Provisions Docker, pulls the Connector image, and starts the node on :8080."
                                cmd="curl -fsSL https://install.connector.dev | sh"
                            />
                            <InstallCommandCard
                                pad="PAD-2"
                                kind="Docker"
                                desc="Run the image directly. Mount a host volume for persistent state."
                                cmd="docker run -d --name connector \\\n  -p 8080:8080 \\\n  -v /var/lib/connector:/var/lib/connector \\\n  ghcr.io/connector-dev/connector:latest"
                            />
                            <InstallCommandCard
                                pad="PAD-3"
                                kind="Kubernetes (Helm)"
                                desc="Production-grade install. Configures cage isolation, persistent volumes, and the gateway service."
                                cmd="helm repo add connector https://charts.connector.dev\nhelm install connector connector/connector --namespace connector --create-namespace"
                            />
                        </section>

                        <section class="space-y-3">
                            <h2 class="fcs-section-label">"Clearance  ·  pricing"</h2>
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                                <PricingCard
                                    band="CIVIL"
                                    tier="Community"
                                    price="Free"
                                    tag="open source"
                                    bullets=vec![
                                        "All 9 plugins included",
                                        "Up to 3 active agents",
                                        "Self-managed updates",
                                        "Community support",
                                    ]
                                    cta_label="ARM PAD-1"
                                    cta_href="#install-commands"
                                />
                                <PricingCard
                                    band="CREW"
                                    tier="Team"
                                    price="$199 / mo / node"
                                    tag="for production"
                                    bullets=vec![
                                        "Unlimited agents",
                                        "Managed updates",
                                        "Plugin marketplace access",
                                        "Email support",
                                    ]
                                    cta_label="CLEARANCE → PORTAL"
                                    cta_href=PORTAL_SIGNUP_URL
                                />
                                <PricingCard
                                    band="FLAG"
                                    tier="Enterprise"
                                    price="Custom"
                                    tag="for regulated industries"
                                    bullets=vec![
                                        "WitnessCtl evidence retention",
                                        "On-prem private marketplace",
                                        "24/7 support + SLAs",
                                        "Custom plugin signing",
                                    ]
                                    cta_label="TALK TO SALES"
                                    cta_href="https://connector.dev/contact"
                                />
                            </div>
                        </section>

                        <p class="text-[11px] text-stone-600 text-center pt-1">
                            "Stuck on install? See "
                            <A href="/docs/BOOTSTRAP_RUNBOOK.md" attr:class="text-amber-500/80 hover:text-amber-300">"BOOTSTRAP_RUNBOOK"</A>
                            " or hop in our community at "
                            <a href="https://connector.dev/community" class="text-amber-500/80 hover:text-amber-300">"connector.dev/community"</a>"."
                        </p>
                    </div>

                    <div class="fcs-statusbar">
                        <span>"KERNEL READY  ·  3 PADS ARMED"</span>
                        <span>"SETUP WIZARD  ·  CONNECTOR OS"</span>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn InstallCommandCard(
    pad: &'static str,
    kind: &'static str,
    desc: &'static str,
    cmd: &'static str,
) -> impl IntoView {
    let cmd_for_copy = cmd.to_string();
    let (copied, set_copied) = signal(false);
    view! {
        <article class="fcs-pad space-y-2">
            <div class="flex items-center justify-between gap-2">
                <div class="min-w-0">
                    <p class="fcs-pad-id">{pad}</p>
                    <h3 class="text-sm font-semibold text-stone-100 mt-0.5">{kind}</h3>
                </div>
                <button
                    type="button"
                    class="fcs-btn"
                    on:click=move |_| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.navigator().clipboard().write_text(&cmd_for_copy);
                        }
                        set_copied.set(true);
                        let _ = set_timeout_with_handle(
                            move || set_copied.set(false),
                            Duration::from_millis(1600),
                        );
                    }
                >
                    {move || if copied.get() { "COPIED" } else { "COPY TAPE" }}
                </button>
            </div>
            <p class="text-xs text-stone-400">{desc}</p>
            <pre class="fcs-pre">{cmd}</pre>
        </article>
    }
}

#[component]
fn PricingCard(
    band: &'static str,
    tier: &'static str,
    price: &'static str,
    tag: &'static str,
    bullets: Vec<&'static str>,
    cta_label: &'static str,
    cta_href: &'static str,
) -> impl IntoView {
    view! {
        <article class="fcs-clearance">
            <p class="text-[9px] uppercase tracking-[0.2em] text-amber-300/80 font-semibold">{band}"  ·  "{tag}</p>
            <h3 class="text-base font-semibold text-stone-100">{tier}</h3>
            <p class="text-lg text-emerald-300/90">{price}</p>
            <ul class="text-xs text-stone-400 space-y-1 list-disc pl-4 flex-1">
                {bullets.into_iter().map(|b| view! {
                    <li>{b}</li>
                }).collect::<Vec<_>>()}
            </ul>
            <a href=cta_href class="fcs-btn go mt-1">
                {cta_label}
            </a>
        </article>
    }
}
