//! Bound intelligence pack strip — class, skills, portals, rules.

use leptos::prelude::*;
use serde_json::Value;

use crate::components::operator::api_state::OpLoadingBlock;
use crate::iia_api;

#[component]
pub fn OpIntelligencePackStrip(#[prop(into)] pid: String) -> impl IntoView {
    let pid_r = pid.clone();
    let pack = LocalResource::new(move || {
        let pid = pid_r.clone();
        async move { iia_api::intelligence_pack(&pid).await }
    });
    view! {
        <Suspense fallback=move || view! { <OpLoadingBlock message="Loading bound pack…".to_string() /> }>
            {move || Suspend::new(async move {
                match pack.await {
                    Ok(v) => view! { <PackBody v=v /> }.into_any(),
                    Err(_) => view! {
                        <p class="text-[11px] text-zinc-600">"No intelligence pack yet — created via minimal register or pre-spec agent."</p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

#[component]
fn PackBody(v: Value) -> impl IntoView {
    let class = v
        .get("class")
        .and_then(|x| x.as_str())
        .unwrap_or("—");
    let purpose = v
        .get("purpose")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let harden = v.get("harden").and_then(|x| x.as_bool()).unwrap_or(false);
    let skills: Vec<String> = v
        .get("skills")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| {
                    let cap = s.get("capability").and_then(|x| x.as_str())?;
                    let kind = s.get("kind").and_then(|x| x.as_str()).unwrap_or("?");
                    Some(format!("{kind}:{cap}"))
                })
                .collect()
        })
        .unwrap_or_default();
    let portals: Vec<String> = v
        .get("portals")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| {
                    let id = p.get("id").and_then(|x| x.as_str()).unwrap_or("portal");
                    let ty = p
                        .get("type")
                        .or_else(|| p.get("portal_type"))
                        .and_then(|x| x.as_str())
                        .unwrap_or("?");
                    let ent = p.get("entity_id").and_then(|x| x.as_str()).unwrap_or("");
                    if ent.is_empty() {
                        Some(format!("{id} ({ty})"))
                    } else {
                        Some(format!("{id} ({ty} · {ent})"))
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let rules: Vec<String> = v
        .get("rules")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|r| {
                    let effect = r.get("effect").and_then(|x| x.as_str()).unwrap_or("note");
                    let text = r.get("text").and_then(|x| x.as_str()).unwrap_or("");
                    if text.is_empty() {
                        Some(effect.to_string())
                    } else {
                        Some(format!("{effect}: {text}"))
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let skill_empty = skills.is_empty();
    let portal_empty = portals.is_empty();
    let rule_empty = rules.is_empty();
    let has_purpose = !purpose.is_empty();
    view! {
        <section class="rounded-lg border border-zinc-800/70 bg-zinc-900/40 p-3 space-y-2">
            <div class="flex flex-wrap items-center gap-2">
                <span class="rounded-full border border-emerald-800/60 bg-emerald-950/40 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-emerald-200">
                    {class.to_string()}
                </span>
                <Show when=move || harden>
                    <span class="rounded-full border border-cyan-800/50 bg-cyan-950/30 px-2 py-0.5 text-[10px] text-cyan-100">
                        "harden"
                    </span>
                </Show>
                <span class="text-xs font-medium text-zinc-100">{name}</span>
            </div>
            {
                let purpose = purpose;
                has_purpose.then(|| view! { <p class="text-[11px] text-zinc-400">{purpose}</p> })
            }
            <dl class="grid gap-2 sm:grid-cols-3 text-[11px]">
                <div>
                    <dt class="uppercase tracking-wide text-[10px] text-zinc-500">"Skills"</dt>
                    <dd class="mt-0.5 font-mono text-zinc-300">
                        {if skill_empty {
                            "none bound".to_string()
                        } else {
                            skills.join(" · ")
                        }}
                    </dd>
                </div>
                <div>
                    <dt class="uppercase tracking-wide text-[10px] text-zinc-500">"World portals"</dt>
                    <dd class="mt-0.5 font-mono text-zinc-300">
                        {if portal_empty {
                            "none".to_string()
                        } else {
                            portals.join(" · ")
                        }}
                    </dd>
                </div>
                <div>
                    <dt class="uppercase tracking-wide text-[10px] text-zinc-500">"Rules"</dt>
                    <dd class="mt-0.5 font-mono text-zinc-300">
                        {if rule_empty {
                            "none".to_string()
                        } else {
                            rules.join(" · ")
                        }}
                    </dd>
                </div>
            </dl>
            <p class="text-[10px] text-zinc-600">
                "Typed bounds — not markdown. Tools/CONP must match if skills are set."
            </p>
        </section>
    }
}
