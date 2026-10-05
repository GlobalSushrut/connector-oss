//! First-budget wizard — `/billing/setup-budget`.
//!
//! Phase 4.9. Mirrors LedgerLens's budget-setup TUI flow: scope → token
//! cap → cost cap → alert thresholds → action.
//!
//! Finish posts to `/billing/budget`. The wizard stays on the last step
//! until that write succeeds — a failed POST is shown as an error, not
//! as a completed budget.

use leptos::prelude::*;
use leptos_router::components::A;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::install_card::PlaygroundDeflect;
use crate::components::layout::Header;
use crate::components::page_title::use_page_title;
use crate::components::wizard::{
    use_wizard_form_state, WizardController, WizardShell, WizardStep,
};

const WIZARD_ID: &str = "first-budget";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BudgetState {
    scope: String,
    scope_id: String,
    token_cap: u64,
    cost_cap_usd: f64,
    alert_at_pct_warn: u32,
    alert_at_pct_hard: u32,
    action: String,
}

impl Default for BudgetState {
    fn default() -> Self {
        Self {
            scope: "tenant".into(),
            scope_id: "default".into(),
            token_cap: 1_000_000,
            cost_cap_usd: 250.0,
            alert_at_pct_warn: 80,
            alert_at_pct_hard: 100,
            action: "throttle".into(),
        }
    }
}

#[component]
pub fn SetupBudgetWizard(auth: ReadSignal<AuthState>) -> impl IntoView {
    use_page_title("Set up a budget");

    view! {
        <div class="page-wrapper">
            <Header title="Set up a budget" auth=auth />
            <div class="page-content max-w-3xl">
                <PlaygroundDeflect>
                    <SetupBudgetInner />
                </PlaygroundDeflect>
            </div>
        </div>
    }
}

#[component]
fn SetupBudgetInner() -> impl IntoView {
    let steps = vec![
        WizardStep::new("scope", "Scope")
            .with_subtitle("Where this budget applies — tenant, team, or single agent."),
        WizardStep::new("tokens", "Token cap")
            .with_subtitle("Hard ceiling on tokens consumed in the window."),
        WizardStep::new("cost", "Cost cap")
            .with_subtitle("USD ceiling — derived from your provider price book."),
        WizardStep::new("alerts", "Alert thresholds")
            .with_subtitle("Warn early, fail hard at the ceiling."),
        WizardStep::new("action", "Action + finish")
            .with_subtitle("What happens when the cap is hit.")
            .finish(),
    ];

    let controller = WizardController::new(WIZARD_ID, steps.len());
    let (state, set_state) = use_wizard_form_state::<BudgetState>(WIZARD_ID);
    let (err, set_err) = signal::<Option<String>>(None);

    let on_finish = Callback::new(move |()| {
        let s = state.get();
        spawn_local(async move {
            let payload = serde_json::to_value(&s).unwrap_or_default();
            match api::post_value("/billing/budget", payload).await {
                Ok(v) => {
                    if let Some(e) = api::body_error(&v) {
                        set_err.set(Some(e));
                        return;
                    }
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().set_href("/billing");
                    }
                }
                Err(e) => set_err.set(Some(e.message)),
            }
        });
    });

    let step_view = Callback::new(move |idx: usize| -> AnyView {
        match idx {
            0 => view! { <ScopeStep state=state set_state=set_state /> }.into_any(),
            1 => view! { <TokenStep state=state set_state=set_state /> }.into_any(),
            2 => view! { <CostStep state=state set_state=set_state /> }.into_any(),
            3 => view! { <AlertStep state=state set_state=set_state /> }.into_any(),
            4 => view! { <ActionStep state=state set_state=set_state err=err /> }.into_any(),
            _ => view! { <span></span> }.into_any(),
        }
    });

    view! {
        <WizardShell
            controller=controller
            steps=steps
            step_view=step_view
            on_finish=on_finish
            defer_complete=true
            on_cancel=Callback::new(|()| {
                if let Some(win) = web_sys::window() {
                    let _ = win.location().set_href("/billing");
                }
            })
        />
        <p class="mt-3 text-[11px] text-zinc-600">
            "Budgets are enforced by LedgerLens (see "
            <A href="/plugins/ledgerlens" attr:class="text-zinc-500">"/plugins/ledgerlens"</A>") — this wizard writes the policy; the plugin runs it."
        </p>
    }
}

#[component]
fn ScopeStep(state: ReadSignal<BudgetState>, set_state: WriteSignal<BudgetState>) -> impl IntoView {
    let options = [
        ("tenant", "Tenant — applies to every agent in the org"),
        ("team", "Team — scoped to one namespace"),
        ("agent", "Agent — single agent ceiling"),
    ];
    view! {
        <div class="space-y-3">
            <div class="grid grid-cols-1 gap-2">
                {options.iter().map(|(slug, label)| {
                    let slug_owned = slug.to_string();
                    let selected = {
                        let s = slug_owned.clone();
                        Memo::new(move |_| state.get().scope == s)
                    };
                    let slug_click = slug_owned.clone();
                    view! {
                        <button
                            type="button"
                            class=move || if selected.get() {
                                "rounded-lg border border-indigo-500/50 bg-indigo-500/10 px-3 py-2 text-left"
                            } else {
                                "rounded-lg border border-zinc-800/60 bg-zinc-900/40 px-3 py-2 text-left hover:border-zinc-700/80"
                            }
                            on:click=move |_| {
                                let v = slug_click.clone();
                                set_state.update(|s| s.scope = v);
                            }
                        >
                            <p class="text-sm text-zinc-200">{*label}</p>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Scope id"</span>
                <input
                    type="text"
                    class="w-full px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    prop:value=move || state.get().scope_id
                    on:input=move |ev| {
                        let v = event_target_value(&ev);
                        set_state.update(|s| s.scope_id = v);
                    }
                />
                <p class="text-[11px] text-zinc-500 mt-1">"Tenant slug, namespace, or agent id (pid)."</p>
            </label>
        </div>
    }
}

#[component]
fn TokenStep(state: ReadSignal<BudgetState>, set_state: WriteSignal<BudgetState>) -> impl IntoView {
    view! {
        <label class="block">
            <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Token cap (per month)"</span>
            <input
                type="number"
                class="w-44 px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                prop:value=move || state.get().token_cap
                on:input=move |ev| {
                    let v: u64 = event_target_value(&ev).parse().unwrap_or(0);
                    set_state.update(|s| s.token_cap = v);
                }
            />
        </label>
    }
}

#[component]
fn CostStep(state: ReadSignal<BudgetState>, set_state: WriteSignal<BudgetState>) -> impl IntoView {
    view! {
        <label class="block">
            <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Cost cap (USD per month)"</span>
            <input
                type="number"
                step="0.01"
                class="w-32 px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                prop:value=move || state.get().cost_cap_usd
                on:input=move |ev| {
                    let v: f64 = event_target_value(&ev).parse().unwrap_or(0.0);
                    set_state.update(|s| s.cost_cap_usd = v);
                }
            />
            <p class="text-[11px] text-zinc-500 mt-1">"Derived from your provider price book. Edit prices in Settings → Pricing."</p>
        </label>
    }
}

#[component]
fn AlertStep(state: ReadSignal<BudgetState>, set_state: WriteSignal<BudgetState>) -> impl IntoView {
    view! {
        <div class="space-y-3">
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Warn at (%)"</span>
                <input
                    type="number"
                    min="1"
                    max="100"
                    class="w-24 px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    prop:value=move || state.get().alert_at_pct_warn
                    on:input=move |ev| {
                        let v: u32 = event_target_value(&ev).parse().unwrap_or(80);
                        set_state.update(|s| s.alert_at_pct_warn = v.min(100));
                    }
                />
            </label>
            <label class="block">
                <span class="block text-xs uppercase tracking-wider text-zinc-500 mb-1">"Hard fail at (%)"</span>
                <input
                    type="number"
                    min="1"
                    max="100"
                    class="w-24 px-3 py-2 rounded-lg bg-zinc-900/60 border border-zinc-700/60 text-sm text-zinc-100 font-mono focus:outline-none focus:border-indigo-500/60"
                    prop:value=move || state.get().alert_at_pct_hard
                    on:input=move |ev| {
                        let v: u32 = event_target_value(&ev).parse().unwrap_or(100);
                        set_state.update(|s| s.alert_at_pct_hard = v.min(100));
                    }
                />
            </label>
        </div>
    }
}

#[component]
fn ActionStep(
    state: ReadSignal<BudgetState>,
    set_state: WriteSignal<BudgetState>,
    err: ReadSignal<Option<String>>,
) -> impl IntoView {
    let options = [
        ("warn", "Warn — log + alert, allow the call"),
        ("throttle", "Throttle — slow new calls + alert"),
        ("downshift", "Downshift — route to cheaper provider"),
        ("reject", "Reject — hard fail at cap"),
    ];
    view! {
        <div class="space-y-3">
            <div class="grid grid-cols-1 gap-2">
                {options.iter().map(|(slug, label)| {
                    let slug_owned = slug.to_string();
                    let selected = {
                        let s = slug_owned.clone();
                        Memo::new(move |_| state.get().action == s)
                    };
                    let slug_click = slug_owned.clone();
                    view! {
                        <button
                            type="button"
                            class=move || if selected.get() {
                                "rounded-lg border border-indigo-500/50 bg-indigo-500/10 px-3 py-2 text-left"
                            } else {
                                "rounded-lg border border-zinc-800/60 bg-zinc-900/40 px-3 py-2 text-left hover:border-zinc-700/80"
                            }
                            on:click=move |_| {
                                let v = slug_click.clone();
                                set_state.update(|s| s.action = v);
                            }
                        >
                            <p class="text-sm text-zinc-200">{*label}</p>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>
            {move || {
                let s = state.get();
                let json = serde_json::to_string_pretty(&s).unwrap_or_default();
                view! {
                    <pre class="rounded-lg border border-zinc-800/60 bg-zinc-950/60 px-3 py-3 text-[11px] font-mono text-zinc-200 whitespace-pre-wrap max-h-60 overflow-auto">{json}</pre>
                }
            }}
            {move || err.get().map(|m| view! {
                <p class="text-xs text-amber-300">{m}</p>
            })}
        </div>
    }
}
