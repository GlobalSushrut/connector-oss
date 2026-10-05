//! Per-agent power: bound skills, CNP/CONP portals, rules, AAPI policy.
//! Each agent_pid has its own pack — not a shared global allow-list.

use leptos::prelude::*;
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::components::operator::overlays::gateway_form::OpGatewayGrantForm;
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpSelect, OpTextField};
use crate::api;
use crate::iia_api;

#[component]
pub fn OpPowerWorldEditor(#[prop(into)] pid: String) -> impl IntoView {
    let pid_sv = StoredValue::new(pid.clone());
    let (skill_kind, set_skill_kind) = signal("tool".to_string());
    let (skill_cap, set_skill_cap) = signal(String::new());
    let (portal_type, set_portal_type) = signal("http_api".to_string());
    let (portal_entity, set_portal_entity) = signal(String::new());
    let (rule_effect, set_rule_effect) = signal("ask".to_string());
    let (rule_text, set_rule_text) = signal(String::new());
    let (flash, set_flash) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (reload, set_reload) = signal(0u32);

    let pid_load = pid.clone();
    let pack = LocalResource::new(move || {
        let pid = pid_load.clone();
        let _ = reload.get();
        async move { iia_api::intelligence_pack(&pid).await }
    });

    let save_pack = {
        let pid_sv = pid_sv;
        Arc::new(move |_| {
            let pid = pid_sv.get_value();
            set_busy.set(true);
            set_flash.set("Saving this agent's pack…".into());
            let mut skills = vec![];
            let cap = skill_cap.get_untracked().trim().to_string();
            if !cap.is_empty() {
                skills.push(json!({
                    "id": "primary",
                    "kind": skill_kind.get_untracked(),
                    "capability": cap,
                    "risk": "tool",
                    "requires_hitl": true,
                }));
            }
            let mut portals = vec![];
            let ent = portal_entity.get_untracked().trim().to_string();
            if !ent.is_empty() {
                portals.push(json!({
                    "id": "primary",
                    "type": portal_type.get_untracked(),
                    "entity_id": ent,
                }));
            }
            let mut rules = vec![];
            let rt = rule_text.get_untracked().trim().to_string();
            if !rt.is_empty() {
                rules.push(json!({
                    "id": "operator-rule-1",
                    "effect": rule_effect.get_untracked(),
                    "text": rt,
                }));
            }
            let body = json!({
                "setup_complete": true,
                "skills": skills,
                "portals": portals,
                "rules": rules,
            });
            spawn_local(async move {
                match iia_api::post_setup(&pid, body).await {
                    Ok(v) => {
                        if let Some(e) = api::body_error(&v) {
                            set_flash.set(format!("Save failed: {e}"));
                        } else {
                            set_flash.set("Saved — this pid only. Other agents keep their own packs.".into());
                            set_reload.update(|n| *n += 1);
                        }
                    }
                    Err(e) => set_flash.set(format!("Save failed: {e}")),
                }
                set_busy.set(false);
            });
        })
    };

    view! {
        <section class="space-y-3 rounded-xl border border-zinc-800/70 bg-zinc-900/35 p-3">
            <div>
                <p class="text-[10px] font-semibold uppercase tracking-wide text-cyan-500/90">"Power · world · AAPI — this agent only"</p>
                <p class="mt-1 text-[11px] text-zinc-400">
                    "Four layers, all keyed by this pid: (1) charter cage · (2) bound skills · (3) CNP/CONP portals · (4) AAPI policy/budget. Empty skills = charter-only (legacy). If skills are set, tools/CONP must match."
                </p>
            </div>
            <Suspense fallback=|| ()>
                {move || Suspend::new(async move {
                    if let Ok(v) = pack.await {
                        let class = v.get("class").and_then(|x| x.as_str()).unwrap_or("—");
                        let n_sk = v.get("skills").and_then(|x| x.as_array()).map(|a| a.len().to_string()).unwrap_or_else(|| "—".into());
                        let n_po = v.get("portals").and_then(|x| x.as_array()).map(|a| a.len().to_string()).unwrap_or_else(|| "—".into());
                        let n_ru = v.get("rules").and_then(|x| x.as_array()).map(|a| a.len().to_string()).unwrap_or_else(|| "—".into());
                        view! {
                            <p class="font-mono text-[10px] text-zinc-500">
                                {format!("class={class} · {n_sk} skills · {n_po} portals · {n_ru} rules")}
                            </p>
                        }.into_any()
                    } else {
                        ().into_any()
                    }
                })}
            </Suspense>
            <div class="grid gap-2 sm:grid-cols-2">
                <OpSelect
                    label="Skill kind"
                    value=skill_kind
                    set_value=set_skill_kind
                    options=vec![
                        ("tool".into(), "tool".into()),
                        ("conp".into(), "conp (machines)".into()),
                        ("mcp".into(), "mcp".into()),
                        ("http".into(), "http".into()),
                    ]
                />
                <OpTextField
                    label="Allowed capability / tool".to_string()
                    value=skill_cap
                    set_value=set_skill_cap
                    placeholder="web_search or machine.move_axis"
                />
                <OpSelect
                    label="World portal type"
                    value=portal_type
                    set_value=set_portal_type
                    options=vec![
                                        ("http_api".into(), "http_api".into()),
                                        ("browser".into(), "browser".into()),
                        ("machine".into(), "machine".into()),
                        ("device".into(), "device".into()),
                        ("sensor".into(), "sensor".into()),
                        ("mcp".into(), "mcp".into()),
                        ("a2a".into(), "a2a".into()),
                    ]
                />
                <OpTextField
                    label="Portal entity / URL".to_string()
                    value=portal_entity
                    set_value=set_portal_entity
                    placeholder="machine:arm-1 or https://…"
                />
            </div>
            <div class="grid gap-2 sm:grid-cols-2">
                <OpSelect
                    label="Extra rule"
                    value=rule_effect
                    set_value=set_rule_effect
                    options=vec![
                        ("ask".into(), "ask (HITL)".into()),
                        ("block".into(), "block".into()),
                        ("allow".into(), "allow".into()),
                        ("note".into(), "note".into()),
                    ]
                />
                <OpTextField
                    label="Rule text".to_string()
                    value=rule_text
                    set_value=set_rule_text
                    placeholder="Bay doors need HITL"
                />
            </div>
            <div class="flex flex-wrap gap-2">
                <OpButton
                    label="Save pack for this agent".to_string()
                    variant=OpButtonVariant::Primary
                    loading=busy.get()
                    on_click=save_pack
                />
                <OpButton
                    label="AAPI: issue cap to this pid".to_string()
                    variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        let cap = skill_cap.get();
                        let actions = if cap.trim().is_empty() {
                            vec!["talk".to_string(), "tool".to_string()]
                        } else {
                            vec![cap.trim().to_string()]
                        };
                        spawn_local(async move {
                            match iia_api::aapi_issue_capability(&pid, actions).await {
                                Ok(v) => set_flash.set(format!(
                                    "AAPI cap issued · {}",
                                    v.get("token_id").and_then(|x| x.as_str()).unwrap_or("ok")
                                )),
                                Err(e) => set_flash.set(format!("AAPI cap: {e}")),
                            }
                        });
                    })
                />
                <OpButton
                    label="AAPI: require-approval CONP".to_string()
                    variant=OpButtonVariant::Ghost
                    on_click=Arc::new(move |_| {
                        let pid = pid_sv.get_value();
                        spawn_local(async move {
                            match iia_api::aapi_agent_world_policy(&pid).await {
                                Ok(_) => set_flash.set("AAPI policy: CONP/command require_approval for this subject pattern.".into()),
                                Err(e) => set_flash.set(format!("AAPI policy: {e}")),
                            }
                        });
                    })
                />
            </div>
            <p class="text-[11px] text-zinc-400">{move || flash.get()}</p>
            <p class="text-[10px] text-zinc-600">
                "Cage (network deny, HITL) is the Charter stage above. Node lab vs harden is a node switch — not copied between agents. HIPAA/financial AAPI templates are node-wide extras."
            </p>
        </section>
        <OpGatewayGrantForm agent_pid=pid_sv.get_value() />
    }
}
