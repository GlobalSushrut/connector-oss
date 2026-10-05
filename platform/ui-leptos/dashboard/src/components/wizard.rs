//! Reusable wizard primitive (Phase 1.4 foundation).
//!
//! Every wizard the dashboard ships in Phase 4 (first-run, connect-a-tool,
//! install-a-workflow, DevGuard / TraceTramp / WitnessCtl setup) is built
//! out of:
//!
//! - [`WizardShell`] — the surrounding chrome (title + progress + body
//!   slot + back/next/skip/cancel + completion banner).
//! - [`WizardStep`] — declarative description of one step (id, title,
//!   subtitle, optional, can_skip, finish-step flag).
//! - [`WizardController`] — the reactive state holder (current step,
//!   completed flag) wired to `localStorage`.
//! - [`use_wizard_form_state`] — typed per-wizard form-state persistence.
//!
//! Persistence keys (all in `localStorage`, namespaced by wizard id):
//!
//! ```text
//! wizard:<id>:step           usize       — index of the currently-shown step
//! wizard:<id>:completed      bool        — true after the finish step ran
//! wizard:<id>:dismissed_until u64        — unix secs; surfaces "Resume later"
//! wizard:<id>:state          T (JSON)    — arbitrary per-wizard form state
//! ```
//!
//! Phase 1 (this file) ships the primitive; Phase 4 layers domain
//! wizards on top. The module-wide `dead_code` allow is intentional
//! while the first consumer wizard lands.

#![allow(dead_code)]

use std::marker::PhantomData;

use gloo_storage::{LocalStorage, Storage};
use leptos::prelude::*;
use serde::{de::DeserializeOwned, Serialize};

/// Declarative description of one wizard step. Cheap to clone.
#[derive(Debug, Clone)]
pub struct WizardStep {
    /// Stable identifier — used in localStorage and in the per-step
    /// child render selector. Kebab-case recommended.
    pub id: &'static str,
    /// Human-visible heading.
    pub title: &'static str,
    /// Optional one-line subtitle under the heading.
    pub subtitle: Option<&'static str>,
    /// When `true`, the "Skip" affordance is shown next to "Next".
    pub can_skip: bool,
    /// When `true`, advancing past this step marks the wizard complete.
    /// Only the terminal step should set this.
    pub is_finish: bool,
}

impl WizardStep {
    pub const fn new(id: &'static str, title: &'static str) -> Self {
        Self {
            id,
            title,
            subtitle: None,
            can_skip: false,
            is_finish: false,
        }
    }

    pub const fn with_subtitle(mut self, subtitle: &'static str) -> Self {
        self.subtitle = Some(subtitle);
        self
    }

    pub const fn skippable(mut self) -> Self {
        self.can_skip = true;
        self
    }

    pub const fn finish(mut self) -> Self {
        self.is_finish = true;
        self
    }
}

/// Reactive state holder for a wizard. Cheap (`Copy`) to pass around.
#[derive(Debug, Clone, Copy)]
pub struct WizardController {
    id: &'static str,
    step: RwSignal<usize>,
    completed: RwSignal<bool>,
    step_count: usize,
}

impl WizardController {
    /// Initialise a controller. Reads the resume point and completion
    /// flag from `localStorage`. Safe to call multiple times (idempotent).
    pub fn new(id: &'static str, step_count: usize) -> Self {
        let initial_step: usize = LocalStorage::get(step_key(id)).unwrap_or(0);
        let initial_step = initial_step.min(step_count.saturating_sub(1));
        let initial_completed: bool = LocalStorage::get(completed_key(id)).unwrap_or(false);
        Self {
            id,
            step: RwSignal::new(initial_step),
            completed: RwSignal::new(initial_completed),
            step_count,
        }
    }

    pub fn id(&self) -> &'static str {
        self.id
    }

    pub fn step_count(&self) -> usize {
        self.step_count
    }

    pub fn current_step(&self) -> ReadSignal<usize> {
        self.step.read_only()
    }

    pub fn is_completed(&self) -> ReadSignal<bool> {
        self.completed.read_only()
    }

    /// Advance to the next step (or mark complete if at the finish step).
    pub fn next(&self, is_finish: bool) {
        if is_finish {
            self.completed.set(true);
            let _ = LocalStorage::set(completed_key(self.id), true);
            return;
        }
        let next = (self.step.get_untracked() + 1).min(self.step_count.saturating_sub(1));
        self.step.set(next);
        let _ = LocalStorage::set(step_key(self.id), next);
    }

    /// Move to the previous step (no-op when on step 0).
    pub fn back(&self) {
        let prev = self.step.get_untracked().saturating_sub(1);
        self.step.set(prev);
        let _ = LocalStorage::set(step_key(self.id), prev);
    }

    /// Jump to an arbitrary step index. Clamped to `[0, step_count)`.
    pub fn goto(&self, idx: usize) {
        let idx = idx.min(self.step_count.saturating_sub(1));
        self.step.set(idx);
        let _ = LocalStorage::set(step_key(self.id), idx);
    }

    /// Reset the wizard to the first step and clear the completed flag.
    /// Does **not** wipe per-wizard form state — call
    /// `clear_wizard_form_state::<T>(id)` for that.
    pub fn reset(&self) {
        self.step.set(0);
        self.completed.set(false);
        let _ = LocalStorage::set(step_key(self.id), 0);
        let _ = LocalStorage::set(completed_key(self.id), false);
    }
}

fn step_key(id: &str) -> String {
    format!("wizard:{id}:step")
}
fn completed_key(id: &str) -> String {
    format!("wizard:{id}:completed")
}
fn state_key(id: &str) -> String {
    format!("wizard:{id}:state")
}

/// Lightweight read-only status of a wizard, derived from localStorage.
/// Used by the Setup hub (`pages::setup`) to render ✓ / ◐ / ○ icons
/// without instantiating a full [`WizardController`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStatus {
    /// Wizard has never been opened (no step key in storage).
    NotStarted,
    /// Wizard is in progress — paused at `step` (0-indexed).
    Resume { step: usize },
    /// Wizard's finish step ran. Re-running clears this.
    Done,
}

impl WizardStatus {
    /// Cheap badge label for hub UIs.
    pub fn label(&self) -> &'static str {
        match self {
            WizardStatus::NotStarted => "Start",
            WizardStatus::Resume { .. } => "Resume",
            WizardStatus::Done => "Done",
        }
    }

    /// Icon glyph used by the Setup hub list.
    pub fn icon(&self) -> &'static str {
        match self {
            WizardStatus::NotStarted => "○",
            WizardStatus::Resume { .. } => "◐",
            WizardStatus::Done => "✓",
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, WizardStatus::Done)
    }
}

/// Read a wizard's persistence keys and classify it. Safe to call from
/// anywhere — purely reads `localStorage`.
pub fn wizard_status(id: &str) -> WizardStatus {
    if LocalStorage::get::<bool>(completed_key(id)).unwrap_or(false) {
        return WizardStatus::Done;
    }
    match LocalStorage::get::<usize>(step_key(id)).ok() {
        Some(step) if step > 0 => WizardStatus::Resume { step },
        _ => WizardStatus::NotStarted,
    }
}

/// Mark a wizard as never-run (clears step + completed + form state).
/// Used by the Setup hub's "Restart" affordance.
pub fn reset_wizard(id: &str) {
    let _ = LocalStorage::raw().remove_item(&step_key(id));
    let _ = LocalStorage::raw().remove_item(&completed_key(id));
    let _ = LocalStorage::raw().remove_item(&state_key(id));
}

/// Persist arbitrary per-wizard form state to `localStorage` under
/// `wizard:<id>:state`. The returned `(read, set)` pair behaves exactly
/// like a normal signal pair, but every write also serialises to disk
/// so the wizard resumes with form fields intact on page reload.
pub fn use_wizard_form_state<T>(id: &'static str) -> (ReadSignal<T>, WriteSignal<T>)
where
    T: Serialize + DeserializeOwned + Default + Clone + Send + Sync + 'static,
{
    let initial: T = LocalStorage::get(state_key(id)).unwrap_or_default();
    let (read, write) = signal(initial);
    Effect::new(move |_| {
        let value = read.get();
        if let Ok(json) = serde_json::to_string(&value) {
            let _ = LocalStorage::raw().set_item(&state_key(id), &json);
        }
    });
    (read, write)
}

/// Drop per-wizard form state from `localStorage`. Useful when the
/// wizard finishes and the form values shouldn't persist for a future
/// rerun.
pub fn clear_wizard_form_state<T>(id: &'static str) {
    let _ = LocalStorage::raw().remove_item(&state_key(id));
    let _ = PhantomData::<T>; // satisfy the type parameter for callers
}

/// The wizard shell — title + progress + back/next/skip/cancel + body.
///
/// Children render the **current step's body**. The shell handles the
/// chrome and step transitions. Pass a `step_view` callback that maps a
/// step index → the view for that step's body. Returning `().into_any()`
/// for unexpected indices is fine; the shell guards against out-of-range
/// indices internally.
#[component]
pub fn WizardShell(
    controller: WizardController,
    steps: Vec<WizardStep>,
    /// Render fn — given the current step index, return the view body.
    step_view: Callback<usize, AnyView>,
    /// Called on the final step's "Finish" click. Use it to fire the
    /// real product API call. The shell will mark the wizard complete
    /// regardless of whether this callback errors — callers should
    /// communicate failures via their own UI state.
    #[prop(optional)] on_finish: Option<Callback<()>>,
    /// Called whenever the operator clicks "Cancel". Defaults to a
    /// no-op (the shell unmounts; navigation is the caller's concern).
    #[prop(optional)] on_cancel: Option<Callback<()>>,
    /// When true, Finish runs `on_finish` but does **not** mark the
    /// wizard complete — the caller must call [`WizardController::next`]
    /// with `is_finish=true` after a successful API round-trip (so the
    /// review step can show issued credentials before the chrome flips).
    #[prop(optional, default = false)] defer_complete: bool,
    /// Optional class hook on the outer `<section>` for layout tweaks.
    #[prop(into, default = String::new())] class: String,
) -> impl IntoView {
    let total = steps.len();
    let steps_for_body = steps.clone();
    let outer_class = format!(
        "wizard-shell flex flex-col rounded-2xl border border-zinc-800/60 bg-zinc-950/60 shadow-2xl shadow-black/40 backdrop-blur-xl {class}"
    );

    let current_step_signal = controller.current_step();
    let completed_signal = controller.is_completed();

    let header_step_count = total;

    view! {
        <section class=outer_class aria-labelledby=format!("wizard-{}-title", controller.id())>
            <header class="shrink-0 border-b border-zinc-800/60 bg-zinc-900/40 px-6 py-4">
                <div class="flex items-center justify-between gap-3">
                    <div class="min-w-0">
                        {
                            let steps_for_title = steps.clone();
                            move || {
                                let idx = current_step_signal.get();
                                let step = steps_for_title.get(idx);
                                let title = step.map(|s| s.title).unwrap_or("Wizard");
                                let subtitle = step.and_then(|s| s.subtitle);
                                view! {
                                    <h2
                                        id=format!("wizard-{}-title", controller.id())
                                        class="truncate text-base font-semibold tracking-tight text-zinc-100"
                                    >
                                        {title}
                                    </h2>
                                    {subtitle.map(|sub| view! {
                                        <p class="mt-0.5 truncate text-[11px] text-zinc-500">{sub}</p>
                                    })}
                                }
                            }
                        }
                    </div>
                    <span class="shrink-0 font-mono text-[10px] text-zinc-500">
                        {move || format!("Step {}/{}", current_step_signal.get() + 1, header_step_count)}
                    </span>
                </div>
                <WizardProgressBar
                    current=current_step_signal
                    total=total
                />
            </header>

            <div class="px-6 py-5">
                {move || {
                    if completed_signal.get() {
                        view! {
                            <div class="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3">
                                <p class="text-sm font-medium text-emerald-200">"All set."</p>
                                <p class="mt-1 text-xs text-emerald-100/80">
                                    "This wizard is complete. Re-open it from the Setup hub at any time."
                                </p>
                            </div>
                        }.into_any()
                    } else {
                        step_view.run(current_step_signal.get())
                    }
                }}
            </div>

            <footer class="flex shrink-0 items-center justify-between gap-3 border-t border-zinc-800/60 bg-zinc-900/30 px-6 py-3">
                <button
                    type="button"
                    class="text-xs text-zinc-500 hover:text-zinc-200 transition-colors"
                    on:click=move |_| {
                        if let Some(cb) = on_cancel { cb.run(()); }
                    }
                >
                    "Cancel"
                </button>
                <div class="flex items-center gap-2">
                    <button
                        type="button"
                        class="px-3 py-1.5 rounded-lg text-xs font-medium text-zinc-300 border border-zinc-700/60 bg-zinc-800/40 hover:bg-zinc-800/80 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                        prop:disabled=move || current_step_signal.get() == 0 || completed_signal.get()
                        on:click=move |_| controller.back()
                    >
                        "Back"
                    </button>
                    {
                        let steps_for_skip_style = steps_for_body.clone();
                        let steps_for_skip_click = steps_for_body.clone();
                        view! {
                            <button
                                type="button"
                                class="px-3 py-1.5 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 transition-colors"
                                style=move || {
                                    if completed_signal.get() {
                                        "display: none".into()
                                    } else {
                                        let idx = current_step_signal.get();
                                        let can_skip = steps_for_skip_style
                                            .get(idx)
                                            .map(|s| s.can_skip)
                                            .unwrap_or(false);
                                        if can_skip { String::new() } else { "display: none".into() }
                                    }
                                }
                                on:click=move |_| {
                                    let idx = current_step_signal.get();
                                    let is_finish = steps_for_skip_click
                                        .get(idx)
                                        .map(|s| s.is_finish)
                                        .unwrap_or(false);
                                    controller.next(is_finish);
                                }
                            >
                                "Skip"
                            </button>
                        }
                    }
                    {
                        let steps_for_next_click = steps_for_body.clone();
                        let steps_for_next_label = steps_for_body.clone();
                        view! {
                            <button
                                type="button"
                                class="px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-indigo-500 hover:bg-indigo-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                                prop:disabled=move || completed_signal.get()
                                on:click=move |_| {
                                    let idx = current_step_signal.get();
                                    let is_finish = steps_for_next_click
                                        .get(idx)
                                        .map(|s| s.is_finish)
                                        .unwrap_or(false);
                                    if is_finish {
                                        if let Some(cb) = on_finish {
                                            cb.run(());
                                        }
                                        if !defer_complete {
                                            controller.next(true);
                                        }
                                    } else {
                                        controller.next(false);
                                    }
                                }
                            >
                                {
                                    move || {
                                        let idx = current_step_signal.get();
                                        let is_finish = steps_for_next_label
                                            .get(idx)
                                            .map(|s| s.is_finish)
                                            .unwrap_or(false);
                                        if is_finish { "Finish" } else { "Next" }
                                    }
                                }
                            </button>
                        }
                    }
                </div>
            </footer>
        </section>
    }
}

#[component]
fn WizardProgressBar(current: ReadSignal<usize>, total: usize) -> impl IntoView {
    let denom = total.max(1);
    view! {
        <div
            class="mt-3 h-1.5 rounded-full bg-zinc-800/60 overflow-hidden"
            role="progressbar"
            aria-valuemin="0"
            aria-valuemax=format!("{}", denom)
        >
            <div
                class="h-full bg-gradient-to-r from-indigo-500 to-violet-400 transition-all duration-300"
                style=move || {
                    let pct = ((current.get() + 1) as f32 / denom as f32) * 100.0;
                    format!("width: {:.1}%", pct.clamp(0.0, 100.0))
                }
            ></div>
        </div>
    }
}
