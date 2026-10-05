//! `connector.yaml` editor (Phase 7 / P2-24).
//!
//! Self-deploy operators can author / edit the running node's
//! `connector.yaml` from the dashboard without SSH'ing into the box.
//! The editor is a plain `<textarea>` with a Validate + Save button
//! pair; the server is responsible for syntactic and semantic
//! validation (YAML parse + schema check). The UI surfaces the
//! server's diagnostic verbatim so authors can fix issues without
//! leaving the page.
//!
//! Endpoints (server contract):
//!
//! - `GET  /api/v1/settings/connector-yaml` → `{ source, last_modified, schema_version }`
//! - `POST /api/v1/settings/connector-yaml/validate` (body `{ source }`) → `{ ok, errors[] }`
//! - `PUT  /api/v1/settings/connector-yaml` (body `{ source }`) → `{ ok, applied_at, errors[] }`
//!
//! Playground bundles deflect via [`PlaygroundDeflect`] because there
//! is no persistent config file backing a hosted trial session.

use leptos::prelude::*;
use serde_json::json;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::cards::PageLoading;
use crate::components::install_card::PlaygroundDeflect;
use crate::deployment::{use_deployment_mode, DeploymentMode};

#[component]
pub fn ConnectorYamlEditor() -> impl IntoView {
    view! {
        <PlaygroundDeflect>
            <ConnectorYamlEditorInner />
        </PlaygroundDeflect>
    }
}

#[component]
fn ConnectorYamlEditorInner() -> impl IntoView {
    let mode = use_deployment_mode();
    // Hide the editor entirely on `Unknown` / `Playground`. We
    // already wrap in PlaygroundDeflect but that fires on Playground
    // only; Unknown still lands here on first-boot and we don't want
    // to show the editor before we know what mode we're in.
    let visible = move || matches!(mode.get(), DeploymentMode::SelfHosted);

    let (source, set_source) = signal(String::new());
    let (last_modified, set_last_modified) = signal(String::new());
    let (errors, set_errors) = signal::<Vec<String>>(Vec::new());
    let (status, set_status) = signal::<Option<(String, bool)>>(None);
    let (busy, set_busy) = signal(false);
    let (loaded, set_loaded) = signal(false);

    // Initial load.
    Effect::new(move |has_run: Option<bool>| {
        if has_run.unwrap_or(false) {
            return true;
        }
        spawn_local(async move {
            match api::get_value("/settings/connector-yaml").await {
                Ok(v) => {
                    let src = v.get("source").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    let lm = v
                        .get("last_modified")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    set_source.set(src);
                    set_last_modified.set(lm);
                    set_loaded.set(true);
                }
                Err(e) => {
                    set_status.set(Some((
                        format!("Could not load connector.yaml: {}", e.message),
                        false,
                    )));
                    set_loaded.set(true);
                }
            }
        });
        true
    });

    let on_validate = move |_| {
        if busy.get() { return; }
        set_busy.set(true);
        set_status.set(None);
        let body = json!({ "source": source.get() });
        spawn_local(async move {
            match api::post_value("/settings/connector-yaml/validate", body).await {
                Ok(v) => {
                    let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                    let errs = v
                        .get("errors")
                        .and_then(|x| x.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    set_errors.set(errs);
                    set_status.set(Some((
                        if ok { "Validation passed".to_string() } else { "Validation failed".to_string() },
                        ok,
                    )));
                }
                Err(e) => {
                    set_status.set(Some((
                        format!("Validate endpoint unavailable: {}", e.message),
                        false,
                    )));
                }
            }
            set_busy.set(false);
        });
    };

    let on_save = move |_| {
        if busy.get() { return; }
        set_busy.set(true);
        set_status.set(None);
        let body = json!({ "source": source.get() });
        spawn_local(async move {
            match api::put_value("/settings/connector-yaml", body).await {
                Ok(v) => {
                    let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                    let errs = v
                        .get("errors")
                        .and_then(|x| x.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|e| e.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    set_errors.set(errs);
                    let applied_at = v
                        .get("applied_at")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    if ok {
                        set_last_modified.set(applied_at.to_string());
                        set_status.set(Some(("Saved · applied to running node".to_string(), true)));
                    } else {
                        set_status.set(Some(("Save rejected — see errors below".to_string(), false)));
                    }
                }
                Err(e) => {
                    set_status.set(Some((
                        format!("Save endpoint unavailable: {}", e.message),
                        false,
                    )));
                }
            }
            set_busy.set(false);
        });
    };

    view! {
        <Show when=visible>
            <section
                aria-labelledby="connector-yaml-heading"
                class="card-3d space-y-4"
            >
                <div class="flex items-start justify-between gap-4 flex-wrap">
                    <div>
                        <p class="text-[11px] text-muted uppercase tracking-wider font-semibold">"Settings → System (advanced)"</p>
                        <h2 id="connector-yaml-heading" class="mt-2 text-xl font-bold tracking-tight text-zinc-100">"connector.yaml"</h2>
                        <p class="mt-2 max-w-3xl text-sm text-zinc-400">
                            "Edit the running node's "<span class="font-mono">"connector.yaml"</span>" without SSH. Validation runs server-side; Save applies in-place once validation passes."
                        </p>
                    </div>
                    <Show when=move || !last_modified.get().is_empty()>
                        <div class="text-[11px] text-muted">
                            "Last modified: "<span class="font-mono">{move || last_modified.get()}</span>
                        </div>
                    </Show>
                </div>

                <Show
                    when=move || loaded.get()
                    fallback=|| view! { <PageLoading /> }
                >
                    <textarea
                        spellcheck="false"
                        aria-label="connector.yaml source"
                        class="w-full min-h-[20rem] rounded-xl border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs font-mono text-zinc-100 leading-relaxed focus:outline-none focus:border-brand focus-visible:ring-2 focus-visible:ring-brand/50"
                        prop:value=move || source.get()
                        on:input=move |e| set_source.set(event_target_value(&e))
                    />
                    <div class="flex items-center gap-2">
                        <button
                            type="button"
                            class="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-xs font-semibold text-zinc-200 hover:bg-zinc-700 disabled:opacity-60 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50"
                            disabled=move || busy.get()
                            on:click=on_validate
                        >
                            {move || if busy.get() { "Working…" } else { "Validate" }}
                        </button>
                        <button
                            type="button"
                            class="rounded-lg bg-brand text-white px-3 py-2 text-xs font-semibold hover:brightness-110 disabled:opacity-60 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/60"
                            disabled=move || busy.get()
                            on:click=on_save
                        >
                            {move || if busy.get() { "Saving…" } else { "Save" }}
                        </button>
                        <p class="text-[11px] text-muted ml-2">
                            "Save is idempotent — the server diffs against the on-disk file and only applies new lines."
                        </p>
                    </div>
                    {move || status.get().map(|(msg, ok)| {
                        let cls = if ok {
                            "rounded-lg border border-success-30 bg-success-5 px-3 py-2 text-xs text-success"
                        } else {
                            "rounded-lg border border-danger-30 bg-danger-10 px-3 py-2 text-xs text-danger"
                        };
                        view! { <div role="status" aria-live="polite" class=cls>{msg}</div> }
                    })}
                    {move || {
                        let errs = errors.get();
                        (!errs.is_empty()).then(|| view! {
                            <div role="alert" class="rounded-lg border border-danger-30 bg-danger-10 px-3 py-2 text-xs text-danger space-y-1">
                                <p class="font-semibold">"Errors:"</p>
                                <ul class="list-disc list-inside space-y-0.5 font-mono">
                                    {errs.into_iter().map(|e| view! { <li>{e}</li> }).collect_view()}
                                </ul>
                            </div>
                        })
                    }}
                </Show>
            </section>
        </Show>
    }
}
