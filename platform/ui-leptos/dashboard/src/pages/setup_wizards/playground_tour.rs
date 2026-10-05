//! Playground guided tour — replaces the first-run wizard when
//! `mode == Playground`.
//!
//! Per `LEPTOS_UI_AUDIT_AND_FIX_REPORT.md` §16.1 and Phase 5.4: the
//! first-run wizard is the wrong shape for a 90-minute hosted demo —
//! visitors don't have a workspace to detect, a license to activate,
//! or teammates to invite. They want a 90-second narrative tour that
//! ends in a clear "install on your infra" CTA.
//!
//! Four short steps × ~30 seconds:
//!
//! 1. **PII redaction in flight** — the redaction workflow is
//!    already installed; click into it to see live decisions.
//! 2. **Incident routing** — alert → Slack channel → Jira ticket
//!    pattern, also pre-installed.
//! 3. **HITL approval** — TraceTramp capture → WitnessCtl seal →
//!    human approval gate.
//! 4. **Install on your infra ↓** — links to `/install`.
//!
//! Each step shares the [`WizardController`] state machine
//! (`wizard:playground-tour:*` in localStorage) so reloading the
//! browser resumes at the last step.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::auth::AuthState;
use crate::components::layout::Header;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{WizardController, WizardShell, WizardStep};

const WIZARD_ID: &str = "playground-tour";

#[component]
pub fn PlaygroundTour(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("Welcome to the Connector playground");

    let steps = vec![
        WizardStep::new("devguard", "Step 1 · DevGuard")
            .with_subtitle("A coding agent that cannot leave its lane."),
        WizardStep::new("tracetramp", "Step 2 · TraceTramp")
            .with_subtitle("Who did what — the path, not a log dump."),
        WizardStep::new("witnessctl", "Step 3 · WitnessCtl")
            .with_subtitle("A receipt a reviewer can inspect. Not a certificate."),
        WizardStep::new("install", "Step 4 · Take this home")
            .with_subtitle("Install Connector on your own infrastructure.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! { <TourStepOne /> }.into_any(),
            1 => view! { <TourStepTwo /> }.into_any(),
            2 => view! { <TourStepThree /> }.into_any(),
            3 => view! { <TourStepFour /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    view! {
        <div class="page-wrapper">
            <Header title="Playground tour" auth=auth />
            <div class="page-content max-w-3xl">
                <WizardShell
                    controller=controller
                    steps=steps
                    step_view=step_view
                    on_finish=Callback::new(|()| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href("/install");
                        }
                    })
                    on_cancel=Callback::new(|()| {
                        if let Some(win) = web_sys::window() {
                            let _ = win.location().set_href("/");
                        }
                    })
                />
                <p class="mt-4 text-[11px] text-zinc-600 text-center">
                    "Hosted playground · 90 minutes · "
                    <A href="/install" attr:class="text-zinc-500 hover:text-zinc-300">"see install commands"</A>
                </p>
            </div>
        </div>
    }
}

#[component]
fn TourStepOne() -> impl IntoView {
    view! {
        <div class="space-y-3">
            <div class="rounded-xl border border-emerald-500/20 bg-gradient-to-br from-emerald-500/5 to-zinc-900/40 px-4 py-4">
                <p class="text-[10px] uppercase tracking-wider text-emerald-300/80 font-semibold">"Ready in this session"</p>
                <h3 class="text-base font-semibold text-zinc-100 mt-0.5">"DevGuard"</h3>
                <p class="text-sm text-zinc-400 mt-1">
                    "Paste a GitHub URL. DevGuard gives that checkout an address, config, and cage. Any agent in the folder follows the rules."
                </p>
            </div>
            <ul class="text-sm text-zinc-300 list-disc pl-5 space-y-1">
                <li>"Open "<A href="/plugins/devguard" attr:class="text-indigo-400">"DevGuard"</A>" — paste org/repo, then stamp address + cage onto the checkout."</li>
            </ul>
        </div>
    }
}

#[component]
fn TourStepTwo() -> impl IntoView {
    view! {
        <div class="space-y-3">
            <div class="rounded-xl border border-amber-500/20 bg-gradient-to-br from-amber-500/5 to-zinc-900/40 px-4 py-4">
                <p class="text-[10px] uppercase tracking-wider text-amber-300/80 font-semibold">"Ready in this session"</p>
                <h3 class="text-base font-semibold text-zinc-100 mt-0.5">"TraceTramp"</h3>
                <p class="text-sm text-zinc-400 mt-1">
                    "Your TraceTramp agent records the execution graph — tools, order, identity."
                </p>
            </div>
            <ul class="text-sm text-zinc-300 list-disc pl-5 space-y-1">
                <li>"Open "<A href="/plugins/tracetramp" attr:class="text-indigo-400">"TraceTramp"</A>" after you send a call."</li>
                <li>"That is who-did-what. Not a CSV export."</li>
            </ul>
        </div>
    }
}

#[component]
fn TourStepThree() -> impl IntoView {
    view! {
        <div class="space-y-3">
            <div class="rounded-xl border border-violet-500/20 bg-gradient-to-br from-violet-500/5 to-zinc-900/40 px-4 py-4">
                <p class="text-[10px] uppercase tracking-wider text-violet-300/80 font-semibold">"Ready in this session"</p>
                <h3 class="text-base font-semibold text-zinc-100 mt-0.5">"WitnessCtl"</h3>
                <p class="text-sm text-zinc-400 mt-1">
                    "Your WitnessCtl agent seals a hash-chained receipt. Evidence, not a SOC 2 certificate."
                </p>
            </div>
            <ul class="text-sm text-zinc-300 list-disc pl-5 space-y-1">
                <li>"Open "<A href="/plugins/witnessctl" attr:class="text-indigo-400">"WitnessCtl"</A>" to inspect the chain."</li>
                <li>"That is prove. The other seven workflows are not in this playground."</li>
            </ul>
        </div>
    }
}

#[component]
fn TourStepFour() -> impl IntoView {
    view! {
        <div class="space-y-3 text-center">
            <div class="mx-auto inline-flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-2xl">
                "📦"
            </div>
            <h3 class="text-base font-semibold text-zinc-100">"Take Connector home."</h3>
            <p class="text-sm text-zinc-400 max-w-md mx-auto">
                "Hit Finish to open the install page — single-command setup, Docker image, or Helm chart. You can also save your playground session as a tarball to bootstrap your own node."
            </p>
            <div class="flex flex-col sm:flex-row gap-2 justify-center pt-2">
                <A href="/install" attr:class="px-3 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white">
                    "Install on your infra →"
                </A>
                <A href="https://portal.connector.dev/signup?ref=playground" attr:class="px-3 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white">
                    "Sign up at portal ↗"
                </A>
            </div>
        </div>
    }
}
