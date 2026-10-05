use leptos::prelude::*;
use serde_json::Value;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpLoadingBlock};
use crate::components::operator::primitives::{OpText, OpTextVariant, OpTruncMono};

/// Normalize custody honesty strip — only `local_only` | `partial` | `quorum_met`.
fn custody_strip_label(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "quorum_met" => "quorum_met",
        "partial" => "partial",
        _ => "local_only",
    }
}

fn strip_tone(strip: &str) -> &'static str {
    match strip {
        "quorum_met" => "text-emerald-300",
        "partial" => "text-amber-200",
        _ => "text-zinc-400",
    }
}

fn root_data(v: &Value) -> &Value {
    v.get("data").unwrap_or(v)
}

/// P6.4 — FNI badge + moment link from GET /forensics/status `fni_moment_join`.
/// Shared by Forensics panel and TT/WC light consoles.
#[component]
pub fn OpFniMomentBadge(
    #[prop(optional, into, default = String::new())] prop_flow: String,
    #[prop(optional, into, default = String::new())] prop_moment: String,
) -> impl IntoView {
    let status = LocalResource::new(|| async move { api::get_value("/forensics/status").await });
    view! {
        <Suspense fallback=move || view! {
            <section class="rounded-lg border border-zinc-800/60 bg-zinc-950/40 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"FNI · moment"</p>
                <p class="mt-1 text-[11px] text-zinc-600">"Loading forensics status…"</p>
            </section>
        }>
            {move || {
                let flow = prop_flow.clone();
                let moment = prop_moment.clone();
                Suspend::new(async move {
                    match status.await {
                        Ok(v) => fni_badge_view(&v, &flow, &moment).into_any(),
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

fn fni_badge_view(v: &Value, prop_flow: &str, prop_moment: &str) -> impl IntoView {
    let root = root_data(v);
    let join = root.get("fni_moment_join").cloned().unwrap_or(Value::Null);
    let fni_verify = root.get("fni_verify").cloned().unwrap_or(Value::Null);
    let join_flow = join
        .get("fni_flow_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            if prop_flow.is_empty() {
                None
            } else {
                Some(prop_flow.to_string())
            }
        });
    let join_moment = join
        .get("moment_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            if prop_moment.is_empty() {
                None
            } else {
                Some(prop_moment.to_string())
            }
        });
    let flow_display = join_flow.clone().unwrap_or_else(|| "null".into());
    let moment_display = join_moment.clone().unwrap_or_else(|| "null".into());
    let has_fni = join_flow.is_some();
    let badge_class = if has_fni {
        "inline-flex rounded px-2 py-0.5 text-[11px] font-medium bg-sky-950/50 text-sky-200 border border-sky-800/40"
    } else {
        "inline-flex rounded px-2 py-0.5 text-[11px] font-medium bg-zinc-900 text-zinc-400 border border-zinc-700/60"
    };
    let verify_status = fni_verify
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("unverified")
        .to_string();
    let verify_honesty = fni_verify
        .get("honesty")
        .and_then(|x| x.as_str())
        .unwrap_or("verified only after independent recompute")
        .to_string();
    let join_honesty = join
        .get("honesty")
        .and_then(|x| x.as_str())
        .unwrap_or("fni_moment_join awaiting TT/WC persist")
        .to_string();
    let moment_href = join_moment
        .as_ref()
        .filter(|m| *m != "null" && !m.is_empty())
        .map(|m| format!("#moment-{m}"));

    view! {
        <section class="space-y-2 rounded-lg border border-zinc-800/60 bg-zinc-950/40 p-3">
            <div class="flex flex-wrap items-center gap-2">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"FNI · moment"</p>
                <span class=badge_class>
                    {if has_fni { "FNI" } else { "FNI · unset" }}
                </span>
                <span class="inline-flex rounded px-2 py-0.5 font-mono text-[10px] text-amber-200/90 border border-amber-800/30 bg-amber-950/30">
                    {format!("verify:{verify_status}")}
                </span>
            </div>
            <div class="space-y-1.5 text-xs">
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"fni_flow_id"</span>
                    <OpTruncMono text=flow_display />
                </div>
                <div class="flex items-center justify-between gap-2">
                    <span class="text-zinc-500">"moment_id"</span>
                    {match moment_href {
                        Some(href) => {
                            let label = moment_display.clone();
                            view! {
                                <a class="font-mono text-[11px] text-sky-300 hover:underline truncate max-w-[60%]" href=href title="Moment join key (Memory / Moments)">
                                    {label}
                                </a>
                            }.into_any()
                        }
                        None => view! { <OpTruncMono text=moment_display /> }.into_any(),
                    }}
                </div>
            </div>
            <p class="text-[10px] text-amber-200/80">{join_honesty}</p>
            <p class="text-[10px] text-zinc-600">{verify_honesty}</p>
            <p class="font-mono text-[10px] text-zinc-600">"GET /forensics/status · fni_moment_join · fni_verify"</p>
        </section>
    }
}

/// O15 — custody / trace forensics sections + aggregate timeline from GET /forensics/status.
/// Prefer CFNI `flow_id` as the substrate join key; TT/WC ids are projections (U6.2 / I-24).
/// Never shows decorative `verified: true`. Custody strip never labels court-grade early.
#[component]
pub fn OpForensicsPanel(
    #[prop(optional, into, default = String::new())] custody_id: String,
    #[prop(optional, into, default = String::new())] trace_id: String,
    #[prop(optional, into, default = String::new())] flow_id: String,
    #[prop(optional, into, default = String::new())] moment_id: String,
    #[prop(optional, into, default = String::new())] artifact_id: String,
    /// Honesty strip: `local_only` | `partial` | `quorum_met` (never decorative court-grade).
    #[prop(optional, into, default = String::new())] custody_honesty: String,
    /// True only when backend `court_export_ready` (requires quorum_met + verify).
    #[prop(optional)] court_export_ready: bool,
    /// When true, also fetch GET /forensics/status for aggregate timeline + fni_moment_join.
    #[prop(optional, default = true)]
    load_status: bool,
) -> impl IntoView {
    let flow_for_status = flow_id.clone();
    let moment_for_status = moment_id.clone();
    let strip = custody_strip_label(&custody_honesty).to_string();
    let strip_class = strip_tone(&strip).to_string();
    let export_ready = court_export_ready && strip == "quorum_met";
    let strip_label = strip.clone();

    let status = LocalResource::new(move || async move {
        if !load_status {
            return Err(api::ApiError {
                status: 0,
                code: None,
                message: "status fetch skipped".into(),
                detail: None,
                hints: vec![],
                docs: None,
            });
        }
        api::get_value("/forensics/status").await
    });

    view! {
        <section class="space-y-3 rounded-xl border border-zinc-800/70 bg-zinc-900/35 p-4">
            <OpText text="Forensics".to_string() variant=OpTextVariant::Caption />
            <p class="text-[10px] text-zinc-500">
                "Join on CFNI flow_id when present. TraceTramp / WitnessCtl rows are projections — not a second kernel SoT. verified=false until independent recompute."
            </p>
            <OpFniMomentBadge prop_flow=flow_id.clone() prop_moment=moment_id.clone() />
            <div class="space-y-2 text-xs">
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"CFNI flow_id"</span>
                    <OpTruncMono text=if flow_id.is_empty() { "unavailable".into() } else { flow_id } />
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"Moment"</span>
                    <OpTruncMono text=if moment_id.is_empty() { "—".into() } else { moment_id } />
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"ArtifactLog"</span>
                    <OpTruncMono text=if artifact_id.is_empty() { "—".into() } else { artifact_id } />
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"Witness custody"</span>
                    <OpTruncMono text=if custody_id.is_empty() { "—".into() } else { custody_id } />
                </div>
                <div class="flex items-center justify-between gap-2 border-t border-zinc-800/50 pt-2">
                    <span class="text-zinc-500">"Custody strip"</span>
                    <span class=format!("font-mono text-[11px] {strip_class}")>{strip_label}</span>
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"court_export_ready"</span>
                    <span class="font-mono text-[11px] text-zinc-400">
                        {if export_ready { "true" } else { "false" }}
                    </span>
                </div>
                <p class="text-[10px] text-zinc-600">
                    "Enums: local_only · partial · quorum_met. Never court-grade until quorum_met + independent verify."
                </p>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"TraceTramp trace"</span>
                    <OpTruncMono text=if trace_id.is_empty() { "—".into() } else { trace_id } />
                </div>
            </div>
            {if load_status {
                view! {
                    <Suspense fallback=move || view! { <OpLoadingBlock message="Loading forensics status…".to_string() /> }>
                        {move || {
                            let flow = flow_for_status.clone();
                            let moment = moment_for_status.clone();
                            Suspend::new(async move {
                                match status.await {
                                    Ok(v) => aggregate_timeline_view(&v, &flow, &moment).into_any(),
                                    Err(e) if e.message == "status fetch skipped" => ().into_any(),
                                    Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                                }
                            })
                        }}
                    </Suspense>
                }.into_any()
            } else {
                ().into_any()
            }}
        </section>
    }
}

fn aggregate_timeline_view(v: &Value, prop_flow: &str, prop_moment: &str) -> impl IntoView {
    let root = root_data(v);
    let timeline = root.get("timeline").cloned().unwrap_or(Value::Null);
    let join = root.get("fni_moment_join").cloned().unwrap_or(Value::Null);
    let of = root.get("object_fabric").cloned().unwrap_or(Value::Null);
    let al = root.get("artifact_log").cloned().unwrap_or(Value::Null);
    let fni_verify = root.get("fni_verify").cloned().unwrap_or(Value::Null);
    let causal = timeline
        .get("causal_envelopes")
        .or_else(|| root.pointer("/causal/envelope_count"))
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let moments = timeline
        .get("moments")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let artifacts = timeline
        .get("artifact_log")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let handoff = timeline
        .get("handoff_pending")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unavailable".into());
    // Honesty: never treat missing join as verified.
    let verified = timeline
        .get("verified")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let verified_label = if verified {
        "recomputed".to_string()
    } else {
        "not verified".to_string()
    };
    let join_flow = join
        .get("fni_flow_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            if prop_flow.is_empty() {
                None
            } else {
                Some(prop_flow.to_string())
            }
        })
        .unwrap_or_else(|| "null".into());
    let join_moment = join
        .get("moment_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            if prop_moment.is_empty() {
                None
            } else {
                Some(prop_moment.to_string())
            }
        })
        .unwrap_or_else(|| "null".into());
    let join_honesty = join
        .get("honesty")
        .and_then(|x| x.as_str())
        .unwrap_or("fni_moment_join awaiting TT/WC persist")
        .to_string();
    let storage = of
        .get("storage_backend")
        .and_then(|x| x.as_str())
        .unwrap_or("unavailable")
        .to_string();
    let of_count = of
        .get("count")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "—".into());
    let record_ids: Vec<String> = al
        .get("record_ids")
        .or_else(|| timeline.get("artifact_log_record_ids"))
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .take(8)
                .collect()
        })
        .unwrap_or_default();
    let verify_status = fni_verify
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("unverified")
        .to_string();

    view! {
        <div class="mt-3 space-y-2 border-t border-zinc-800/60 pt-3">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Aggregate timeline"</p>
            <p class="font-mono text-[10px] text-zinc-600">"GET /forensics/status"</p>
            <div class="space-y-1.5 text-xs">
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"Causal envelopes"</span>
                    <span class="font-mono text-zinc-300">{causal}</span>
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"Moments"</span>
                    <span class="font-mono text-zinc-300">{moments}</span>
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"ArtifactLog"</span>
                    <span class="font-mono text-zinc-300">{artifacts}</span>
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"Handoff pending"</span>
                    <span class="font-mono text-zinc-300">{handoff}</span>
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"Verified"</span>
                    <span class="font-mono text-amber-200/90">{verified_label}</span>
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"FNI verify"</span>
                    <span class="font-mono text-amber-200/90">{verify_status}</span>
                </div>
            </div>
            <p class="pt-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"ArtifactLog record ids"</p>
            {if record_ids.is_empty() {
                view! {
                    <p class="text-[11px] text-zinc-600">"No artifact log ids yet — cite when records append (GET /forensics/status → artifact_log.record_ids)."</p>
                }.into_any()
            } else {
                view! {
                    <ul class="space-y-0.5 font-mono text-[10px] text-zinc-400">
                        {record_ids.into_iter().map(|id| view! { <li class="truncate">{id}</li> }).collect_view()}
                    </ul>
                }.into_any()
            }}
            <p class="pt-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"fni_moment_join"</p>
            <div class="space-y-1.5 text-xs">
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"fni_flow_id"</span>
                    <OpTruncMono text=join_flow />
                </div>
                <div class="flex justify-between gap-2">
                    <span class="text-zinc-500">"moment_id"</span>
                    <OpTruncMono text=join_moment />
                </div>
            </div>
            <p class="text-[10px] text-amber-200/80">{join_honesty}</p>
            <div class="flex justify-between gap-2 text-xs">
                <span class="text-zinc-500">"Object Fabric"</span>
                <span class="font-mono text-zinc-300">{format!("{of_count} · {storage}")}</span>
            </div>
        </div>
    }
}
