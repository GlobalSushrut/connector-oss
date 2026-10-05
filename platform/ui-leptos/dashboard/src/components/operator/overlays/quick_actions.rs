use leptos::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::overlays::result_sheet::OpResultSheet;
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpSpinner};
use crate::components::operator::workflow_actions::{
    archive_workflow, current_state, run_surface_action,
};
use crate::request_store::bump_reload;

type DoneFn = Arc<dyn Fn() + Send + Sync>;

#[component]
pub fn OpQuickActions(
    workflow_id: String,
    surface: Value,
    /// Current workflow state from GET /workflows/:id (filters when_states).
    #[prop(optional, into)]
    state: String,
    #[prop(optional)] on_done: Option<DoneFn>,
) -> impl IntoView {
    let (busy, set_busy) = signal(false);
    let (result_open, set_result_open) = signal(false);
    let (result_title, set_result_title) = signal(String::new());
    let (result_summary, set_result_summary) = signal(String::new());

    let state_upper = if state.is_empty() {
        String::new()
    } else {
        state.to_ascii_uppercase()
    };

    let actions = surface
        .get("actions")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();

    let actionable: Vec<Value> = actions
        .into_iter()
        .filter(|a| {
            let id = a.get("id").and_then(|x| x.as_str()).unwrap_or("");
            if id == "current_state" || a.get("kind").and_then(|x| x.as_str()) == Some("state_badge")
            {
                return false;
            }
            if state_upper.is_empty() {
                return true;
            }
            a.get("when_states")
                .and_then(|w| w.as_array())
                .map(|arr| {
                    arr.iter()
                        .any(|s| s.as_str().map(|x| x.eq_ignore_ascii_case(&state_upper)).unwrap_or(false))
                })
                .unwrap_or(true)
        })
        .collect();

    // Prefer Activate over separate enable/compile/stage when DRAFT/COMPILED/STAGED.
    let prefer_activate = matches!(
        state_upper.as_str(),
        "DRAFT" | "COMPILED" | "STAGED" | "PAUSED" | ""
    );
    let actionable: Vec<Value> = if prefer_activate && actionable.iter().any(|a| a.get("id").and_then(|x| x.as_str()) == Some("activate")) {
        actionable
            .into_iter()
            .filter(|a| {
                !matches!(
                    a.get("id").and_then(|x| x.as_str()),
                    Some("enable" | "compile" | "stage")
                )
            })
            .collect()
    } else {
        actionable
    };

    let machine = surface
        .pointer("/lifecycle/state_machine")
        .and_then(|x| x.as_str())
        .unwrap_or("DRAFT → COMPILED → STAGED → ENABLED ⇄ PAUSED → ARCHIVED")
        .to_string();

    view! {
        <div class="space-y-2">
            <div class="flex items-baseline justify-between gap-2">
                <p class="text-xs font-semibold uppercase tracking-wide text-zinc-500">"Quick actions"</p>
                <p class="font-mono text-[10px] text-zinc-600">{format!("state={state_upper}")}</p>
            </div>
            <p class="text-[10px] text-zinc-600">{machine}</p>
            <div class="flex flex-wrap items-center gap-2">
                {actionable.into_iter().map(|action| {
                    let wf = workflow_id.clone();
                    let action_run = action.clone();
                    let label = action
                        .get("label")
                        .and_then(|x| x.as_str())
                        .unwrap_or("Run")
                        .to_string();
                    let id = action.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let variant = match id.as_str() {
                        "dry_run" | "activate" => OpButtonVariant::Primary,
                        "pause" | "archive" => OpButtonVariant::Ghost,
                        _ => OpButtonVariant::Secondary,
                    };
                    let on_done = on_done.clone();
                    let path = action
                        .get("path")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .replace("{workflow_id}", &workflow_id);
                    let path_title = path.clone();
                    view! {
                        <div class="flex flex-col gap-0.5">
                            <OpButton
                                label=label
                                variant=variant
                                on_click=Arc::new(move |_| {
                                    if busy.get_untracked() {
                                        return;
                                    }
                                    set_busy.set(true);
                                    let wf = wf.clone();
                                    let action_run = action_run.clone();
                                    let on_done = on_done.clone();
                                    let id = id.clone();
                                    spawn_local(async move {
                                        let result = if id == "archive" {
                                            archive_workflow(&wf).await.map(|m| {
                                                format!("{m}\nAPI: POST /workflows/{wf}/lifecycle")
                                            })
                                        } else {
                                            run_surface_action(&wf, &action_run).await
                                        };
                                        match result {
                                            Ok(msg) => {
                                                let st = current_state(&wf).await.unwrap_or_default();
                                                set_result_title.set(format!("{wf} · {st}"));
                                                set_result_summary.set(msg);
                                                set_result_open.set(true);
                                                bump_reload();
                                                if let Some(cb) = on_done {
                                                    cb();
                                                }
                                            }
                                            Err(e) => {
                                                set_result_title.set(format!("Failed · {id}"));
                                                set_result_summary.set(e);
                                                set_result_open.set(true);
                                            }
                                        }
                                        set_busy.set(false);
                                    });
                                })
                            />
                            <span class="max-w-[10rem] truncate font-mono text-[9px] text-zinc-700" title=path_title>{path}</span>
                        </div>
                    }
                }).collect_view()}
                // P4.2 — Hub workflow publish honesty (never fake success).
                {
                    let wf_pub = workflow_id.clone();
                    view! {
                        <div class="flex flex-col gap-0.5">
                            <OpButton
                                label="Publish to Hub".to_string()
                                variant=OpButtonVariant::Secondary
                                on_click=Arc::new(move |_| {
                                    if busy.get_untracked() {
                                        return;
                                    }
                                    set_busy.set(true);
                                    let wf = wf_pub.clone();
                                    spawn_local(async move {
                                        match api::post_value(
                                            "/hub/workflows/publish",
                                            json!({ "workflow_id": wf }),
                                        )
                                        .await
                                        {
                                            Ok(v) => {
                                                let implemented = v
                                                    .get("implemented")
                                                    .and_then(|x| x.as_bool())
                                                    .unwrap_or(false);
                                                let status = v
                                                    .get("status")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("—");
                                                let honesty = v
                                                    .get("honesty")
                                                    .and_then(|x| x.as_str())
                                                    .unwrap_or("");
                                                let raw = serde_json::to_string_pretty(&v)
                                                    .unwrap_or_else(|_| v.to_string());
                                                set_result_title.set(format!(
                                                    "Hub publish · implemented:{implemented} · {status}"
                                                ));
                                                set_result_summary.set(format!(
                                                    "POST /hub/workflows/publish\nimplemented: {implemented}\nstatus: {status}\n{honesty}\n\n{raw}"
                                                ));
                                                set_result_open.set(true);
                                            }
                                            Err(e) => {
                                                set_result_title
                                                    .set("Hub publish failed".into());
                                                set_result_summary.set(e.message);
                                                set_result_open.set(true);
                                            }
                                        }
                                        set_busy.set(false);
                                    });
                                })
                            />
                            <span
                                class="max-w-[10rem] truncate font-mono text-[9px] text-zinc-700"
                                title="POST /hub/workflows/publish"
                            >
                                "POST /hub/workflows/publish"
                            </span>
                        </div>
                    }
                }
                <Show when=move || busy.get()>
                    <OpSpinner size="sm" />
                </Show>
            </div>
            <p class="text-[10px] text-amber-200/80">
                "Publish shows honesty (implemented:false) — Hub .cpkg registry is not shipping; do not treat as success."
            </p>
            <OpResultSheet
                open=result_open
                set_open=set_result_open
                title=result_title
                summary=result_summary
            />
        </div>
    }
}
