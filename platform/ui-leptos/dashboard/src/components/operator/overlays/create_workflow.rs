//! New workflow modal — reference templates only. Author + .cpkg live on DEV.

use leptos::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpSpinner};
use crate::request_store::bump_reload;
use crate::ui_state::{open_workflow_drawer, use_create_modal, CreateModal, CreateModalKind};

#[component]
pub fn OpCreateWorkflowHost() -> impl IntoView {
    let modal = use_create_modal();
    view! {
        <Show when=move || modal.kind.get() == CreateModalKind::Workflow>
            <OpCreateWorkflowModal />
        </Show>
    }
}

#[component]
fn OpCreateWorkflowModal() -> impl IntoView {
    let modal = use_create_modal();
    let (busy, set_busy) = signal(false);
    let (installing, set_installing) = signal(String::new());
    let (error, set_error) = signal(String::new());
    let (notice, set_notice) = signal(String::new());
    let templates = LocalResource::new(|| api::get_value("/workflows/reference-templates"));

    let close = move || modal.set_kind.set(CreateModalKind::None);

    view! {
        <div class="fixed inset-0 z-[95] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="New workflow">
            <button type="button" class="absolute inset-0 bg-black/60 backdrop-blur-sm" aria-label="Close" on:click=move |_| close()></button>
            <div class="relative flex max-h-[90vh] w-full max-w-xl flex-col overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-2xl">
                <header class="flex shrink-0 items-center justify-between border-b border-zinc-800/60 px-5 py-3">
                    <h2 class="text-base font-semibold text-zinc-100">"New workflow"</h2>
                    <button type="button" class="text-zinc-500 hover:text-zinc-200" on:click=move |_| close()>"×"</button>
                </header>
                <p class="shrink-0 border-b border-zinc-800/60 px-5 py-2 text-[11px] text-zinc-400">
                    "One-click templates. Author CCL or install .cpkg in "
                    <a class="text-indigo-400 hover:underline" href="/dev?tab=author" on:click=move |_| close()>"DEV → Author"</a>
                    " / "
                    <a class="text-indigo-400 hover:underline" href="/dev?tab=packages" on:click=move |_| close()>"Packages"</a>
                    "."
                </p>
                <Show when=move || !error.get().is_empty()>
                    <p class="shrink-0 mx-5 mt-3 rounded-md border border-red-900/40 bg-red-950/30 px-3 py-2 text-xs text-red-300">{move || error.get()}</p>
                </Show>
                <Show when=move || !notice.get().is_empty()>
                    <p class="shrink-0 mx-5 mt-3 rounded-md border border-emerald-900/40 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-200">{move || notice.get()}</p>
                </Show>
                <div class="min-h-0 flex-1 overflow-auto p-5">
                    <Suspense fallback=move || view! { <div class="flex justify-center py-8"><OpSpinner /></div> }>
                        {move || Suspend::new(async move {
                            let list = match templates.await {
                                Ok(v) => template_list(&v),
                                Err(e) => {
                                    return view! {
                                        <p class="text-sm text-red-300">{format!("Templates unavailable: {}", e.message)}</p>
                                    }.into_any();
                                }
                            };
                            if list.is_empty() {
                                view! {
                                    <p class="text-sm text-zinc-500">
                                        "No reference templates from GET /workflows/reference-templates. Open DEV to author or install a package."
                                    </p>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="space-y-2">
                                        <p class="rounded-md border border-zinc-800/70 bg-zinc-900/40 px-3 py-2 text-[11px] leading-relaxed text-zinc-400">
                                            "Templates register → compile → stage → enable → dry-run. ENABLE walks the lifecycle; a single ENABLED post from DRAFT is rejected."
                                        </p>
                                        {list.into_iter().map(|(id, title, desc)| {
                                            view! {
                                                <TemplateInstallRow
                                                    id=id
                                                    title=title
                                                    desc=desc
                                                    installing=installing
                                                    set_installing=set_installing
                                                    set_busy=set_busy
                                                    set_error=set_error
                                                    set_notice=set_notice
                                                    modal=modal
                                                />
                                            }
                                        }).collect_view()}
                                    </div>
                                }.into_any()
                            }
                        })}
                    </Suspense>
                </div>
                <Show when=move || busy.get()>
                    <div class="flex shrink-0 justify-center border-t border-zinc-800/80 px-5 py-2">
                        <OpSpinner />
                    </div>
                </Show>
            </div>
        </div>
    }
}

#[component]
fn TemplateInstallRow(
    id: String,
    title: String,
    desc: String,
    installing: ReadSignal<String>,
    set_installing: WriteSignal<String>,
    set_busy: WriteSignal<bool>,
    set_error: WriteSignal<String>,
    set_notice: WriteSignal<String>,
    modal: CreateModal,
) -> impl IntoView {
    let id_install = id.clone();
    let loading = Signal::derive({
        let id = id.clone();
        move || installing.get() == id
    });
    view! {
        <div class="flex items-start justify-between gap-3 rounded-lg border border-zinc-800/70 bg-zinc-900/30 px-3 py-2">
            <div class="min-w-0">
                <p class="text-sm font-medium text-zinc-100">{title}</p>
                <p class="text-[11px] text-zinc-500">{desc}</p>
                <p class="mt-0.5 font-mono text-[10px] text-zinc-600">{id.clone()}</p>
            </div>
            <OpButton
                label="Install".to_string()
                variant=OpButtonVariant::Primary
                loading=loading.get()
                on_click=Arc::new(move |_| {
                    let tid = id_install.clone();
                    set_installing.set(tid.clone());
                    set_busy.set(true);
                    set_error.set(String::new());
                    set_notice.set(String::new());
                    spawn_local(async move {
                        match api::post_value(
                            &format!("/workflows/reference/{tid}/install"),
                            json!({}),
                        )
                        .await
                        {
                            Ok(v) => {
                                if let Some(msg) = fail_message(&v) {
                                    set_error.set(msg);
                                } else {
                                    let wid = v
                                        .pointer("/workflow_id")
                                        .or_else(|| v.pointer("/data/workflow_id"))
                                        .and_then(|x| x.as_str())
                                        .unwrap_or(&tid)
                                        .to_string();
                                    set_notice.set(format!("Installed {wid}"));
                                    bump_reload();
                                    modal.set_kind.set(CreateModalKind::None);
                                    open_workflow_drawer(&wid);
                                }
                            }
                            Err(e) => set_error.set(e.message),
                        }
                        set_installing.set(String::new());
                        set_busy.set(false);
                    });
                })
            />
        </div>
    }
}

fn template_list(v: &Value) -> Vec<(String, String, String)> {
    let src = api::resource_object(v);
    let arr = src
        .get("templates")
        .or_else(|| src.get("items"))
        .or_else(|| v.get("templates"))
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    arr.into_iter()
        .filter_map(|t| {
            let id = t
                .get("id")
                .or_else(|| t.get("template_id"))
                .and_then(|x| x.as_str())?
                .to_string();
            let title = t
                .get("title")
                .or_else(|| t.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or(&id)
                .to_string();
            let desc = t
                .get("description")
                .or_else(|| t.get("summary"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            Some((id, title, desc))
        })
        .collect()
}

fn fail_message(v: &Value) -> Option<String> {
    let src = api::resource_object(v);
    let ok = src
        .get("ok")
        .and_then(|x| x.as_bool())
        .or_else(|| v.get("ok").and_then(|x| x.as_bool()));
    if ok != Some(false) {
        return None;
    }
    Some(
        src.get("error")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("error").and_then(|x| x.as_str()))
            .unwrap_or("request failed")
            .to_string(),
    )
}
