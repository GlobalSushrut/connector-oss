//! Live court-defensible checklist (CD-1…CD-7) on the agent Evidence tab.

use leptos::prelude::*;
use serde_json::Value;

use crate::components::operator::api_state::OpLoadingBlock;
use crate::components::operator::primitives::{OpButton, OpButtonVariant};
use crate::iia_api;

fn cd_title(id: &str) -> &'static str {
    match id {
        "CD-1" => "Harden (LAB off)",
        "CD-2" => "CFNI secret",
        "CD-3" => "WitnessCtl live",
        "CD-4" => "Forensic profile court",
        "CD-5" => "No LLM stub",
        "CD-6" => "Court-tier package",
        "CD-7" => "Offline verify ready",
        _ => "Step",
    }
}

#[component]
pub fn OpCourtDefensiblePanel(#[prop(into)] pid: String) -> impl IntoView {
    let pid_load = pid.clone();
    let (reload, set_reload) = signal(0u32);
    let court = LocalResource::new(move || {
        let pid = pid_load.clone();
        let _ = reload.get();
        async move { iia_api::court_readiness(&pid).await }
    });
    view! {
        <section class="rounded-lg border border-zinc-800/70 bg-zinc-900/40 p-3 space-y-2">
            <div class="flex flex-wrap items-center gap-2">
                <p class="mr-auto text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                    "Court-defensible · CD-1…CD-7"
                </p>
                <OpButton
                    label="Refresh".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=std::sync::Arc::new(move |_| {
                        set_reload.update(|n| *n += 1);
                    })
                />
            </div>
            <p class="text-[11px] text-zinc-500">
                "Live from GET /forensics/court-readiness. Green here is not a market claim — CD-9 (human + counsel) still required."
            </p>
            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading court checklist…".to_string() /> }>
                {move || Suspend::new(async move {
                    match court.await {
                        Ok(v) => view! { <CourtBody v=v /> }.into_any(),
                        Err(e) => view! {
                            <p class="text-[11px] text-rose-300">{format!("Court readiness failed: {e}")}</p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

#[component]
fn CourtBody(v: Value) -> impl IntoView {
    let ready = v
        .get("ready")
        .or_else(|| v.get("live_court_e2e_ready"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let profile = v
        .get("forensic_profile")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let lab = v.get("lab_mode").and_then(|x| x.as_bool());
    let tier = v
        .pointer("/package/signing_tier")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let missing = v
        .get("missing")
        .and_then(|m| m.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let rows: Vec<(String, bool, String)> = v
        .get("checklist")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .map(|row| {
                    let id = row
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                        .to_string();
                    let ok = row.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                    let fix = row
                        .get("fix")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    (id, ok, fix)
                })
                .collect()
        })
        .unwrap_or_default();
    let badge = if ready {
        "bg-emerald-950/50 text-emerald-300 border-emerald-800/60"
    } else {
        "bg-amber-950/40 text-amber-200 border-amber-800/50"
    };
    let badge_label = if ready {
        "CD-1…CD-7 green"
    } else {
        "not court-defensible yet"
    };
    view! {
        <div class="space-y-2">
            <div class="flex flex-wrap items-center gap-2 text-[11px]">
                <span class=format!("rounded border px-2 py-0.5 font-medium {badge}")>{badge_label}</span>
                <span class="font-mono text-zinc-500">{format!("profile={profile}")}</span>
                <span class="font-mono text-zinc-500">{format!("lab_mode={}", match lab { Some(true) => "true", Some(false) => "false", None => "—" })}</span>
                <span class="font-mono text-zinc-500">{format!("signing={tier}")}</span>
            </div>
            <div class="space-y-1">
                {rows.into_iter().map(|(id, ok, fix)| {
                    let title = cd_title(&id);
                    let row_cls = if ok {
                        "border-emerald-900/40 bg-emerald-950/20"
                    } else {
                        "border-zinc-800/60 bg-zinc-950/40"
                    };
                    let mark = if ok { "PASS" } else { "FAIL" };
                    let mark_cls = if ok { "text-emerald-400" } else { "text-amber-300" };
                    view! {
                        <div class=format!("rounded border px-2 py-1.5 {row_cls}")>
                            <div class="flex items-baseline gap-2">
                                <span class=format!("w-10 shrink-0 font-mono text-[10px] {mark_cls}")>{mark}</span>
                                <span class="font-mono text-[10px] text-zinc-400">{id.clone()}</span>
                                <span class="text-[11px] text-zinc-200">{title}</span>
                            </div>
                            {(!ok).then(|| view! {
                                <p class="mt-0.5 pl-12 font-mono text-[10px] text-zinc-500">{fix}</p>
                            })}
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </div>
            {(!missing.is_empty() && !ready).then(move || {
                let m = missing.clone();
                view! {
                    <p class="font-mono text-[10px] text-zinc-500">{format!("missing: {m}")}</p>
                }
            })}
        </div>
    }
}
