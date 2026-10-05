//! Light contract panels — every proxied backend surface an operator needs
//! to play status / configure / rules / HITL for DG · TT · WC.
//!
//! Intentionally dense forms, not dashboards. No fake `/setup` POSTs.
//! TT tenants/providers omitted (not hub-proxied). DG teams live in `contract_live`.

use leptos::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpClick};
use crate::utils::trigger_download_bytes;

fn soft_err(v: &Value) -> Option<String> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return Some(
            v.get("error")
                .and_then(|e| e.as_str())
                .or_else(|| v.get("message").and_then(|m| m.as_str()))
                .or_else(|| v.get("hint").and_then(|h| h.as_str()))
                .unwrap_or("Request failed")
                .into(),
        );
    }
    if let Some(status) = v.get("status").and_then(|s| s.as_u64()) {
        if status >= 400 {
            return Some(
                v.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("Request failed")
                    .into(),
            );
        }
    }
    v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string())
}

fn actor_from_auth(auth: ReadSignal<AuthState>) -> String {
    auth.get()
        .user
        .as_ref()
        .map(|u| {
            if !u.email.is_empty() {
                u.email.clone()
            } else if !u.user_id.is_empty() {
                u.user_id.clone()
            } else {
                "operator".into()
            }
        })
        .unwrap_or_else(|| "operator".into())
}

fn flash_line(msg: ReadSignal<Option<(String, bool)>>) -> impl IntoView {
    view! {
        <Show when=move || msg.get().is_some()>
            <p class=move || if msg.get().map(|(_, ok)| ok).unwrap_or(false) {
                "text-xs text-emerald-400"
            } else {
                "text-xs text-amber-400"
            }>
                {move || msg.get().map(|(m, _)| m).unwrap_or_default()}
            </p>
        </Show>
    }
}

fn section_head(title: &'static str, api: &'static str) -> impl IntoView {
    view! {
        <div>
            <p class="lc-panel__eyebrow">{title}</p>
            <p class="lc-panel__api">{api}</p>
        </div>
    }
}

fn arr_items(v: &Value, keys: &[&str]) -> Vec<Value> {
    let src = crate::api::resource_object(v);
    for root in [src, v] {
        for k in keys {
            if let Some(a) = root.get(*k).and_then(|x| x.as_array()) {
                return a.clone();
            }
        }
    }
    Vec::new()
}

const DG_TOOLS: &[&str] = &["cursor", "windsurf", "claude_code", "generic"];

fn mode_for_tool(profile: &Value, tool: &str) -> String {
    let role_name = profile
        .get("default_role_name")
        .and_then(|x| x.as_str())
        .unwrap_or("developer");
    let roles = profile.get("roles").and_then(|x| x.as_array());
    let Some(roles) = roles else {
        return "neutral".into();
    };
    let role = roles
        .iter()
        .find(|r| r.get("name").and_then(|n| n.as_str()) == Some(role_name))
        .or_else(|| roles.first());
    let Some(role) = role else {
        return "neutral".into();
    };
    role.get("tool_access")
        .and_then(|a| a.as_array())
        .and_then(|rows| {
            rows.iter().find_map(|row| {
                if row.get("tool").and_then(|t| t.as_str()) == Some(tool) {
                    row.get("mode").and_then(|m| m.as_str()).map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "neutral".into())
}

fn set_tool_mode(mut profile: Value, tool: &str, mode: &str) -> Value {
    let role_name = profile
        .get("default_role_name")
        .and_then(|x| x.as_str())
        .unwrap_or("developer")
        .to_string();
    let roles_val = profile.get("roles").cloned().unwrap_or(json!([]));
    let mut roles: Vec<Value> = roles_val.as_array().cloned().unwrap_or_default();
    if roles.is_empty() {
        roles.push(json!({
            "name": role_name,
            "description": "Default local developer",
            "tool_access": []
        }));
    }
    let idx = roles
        .iter()
        .position(|r| r.get("name").and_then(|n| n.as_str()) == Some(role_name.as_str()))
        .unwrap_or(0);
    let mut access = roles[idx]
        .get("tool_access")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    if let Some(row) = access
        .iter_mut()
        .find(|r| r.get("tool").and_then(|t| t.as_str()) == Some(tool))
    {
        if let Some(o) = row.as_object_mut() {
            o.insert("mode".into(), json!(mode));
        }
    } else {
        access.push(json!({ "tool": tool, "mode": mode }));
    }
    for t in DG_TOOLS {
        if !access
            .iter()
            .any(|r| r.get("tool").and_then(|x| x.as_str()) == Some(*t))
        {
            access.push(json!({ "tool": *t, "mode": "neutral" }));
        }
    }
    if let Some(obj) = roles[idx].as_object_mut() {
        obj.insert("tool_access".into(), json!(access));
    }
    if let Some(o) = profile.as_object_mut() {
        o.insert("roles".into(), json!(roles));
        o.insert("single_workstation_acknowledged".into(), json!(true));
        if !o.contains_key("schema_version") {
            o.insert("schema_version".into(), json!(1));
        }
    }
    profile
}

// ═══════════════════════════════════════════════════════════════════════════
// DevGuard — rules + sessions + extension (+ connect/info)
// ═══════════════════════════════════════════════════════════════════════════

#[component]
pub fn DevGuardRulesPanel() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (profile, set_profile) = signal(Option::<Value>::None);
    let (sessions, set_sessions) = signal(Vec::<Value>::new());
    let (ext, set_ext) = signal(Option::<Value>::None);
    let (connect_info, set_connect_info) = signal(Option::<Value>::None);
    let (audit, set_audit) = signal(Option::<Value>::None);
    let (session_detail, set_session_detail) = signal(Option::<Value>::None);
    let (selected, set_selected) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (msg, set_msg) = signal(Option::<(String, bool)>::None);

    // optional start-session fields
    let (ss_workspace, set_ss_workspace) = signal(String::new());
    let (ss_tool, set_ss_tool) = signal("cursor".to_string());
    let (ss_role, set_ss_role) = signal("developer".to_string());
    let (policy_yaml, set_policy_yaml) = signal(String::new());

    Effect::new(move |_| {
        let _ = reload.get();
        spawn_local(async move {
            if let Ok(v) = api::get_value("/plugins/devguard/local-profile").await {
                if soft_err(&v).is_none() {
                    let p = v.get("profile").cloned();
                    if let Some(ref pr) = p {
                        if ss_workspace.get_untracked().is_empty() {
                            if let Some(hint) = pr
                                .get("workspace_root_hint")
                                .and_then(|x| x.as_str())
                                .filter(|s| !s.is_empty())
                            {
                                set_ss_workspace.set(hint.to_string());
                            }
                        }
                    }
                    set_profile.set(p);
                }
            }
            if let Ok(v) = api::get_value("/devguard/sessions").await {
                set_sessions.set(arr_items(&v, &["sessions"]));
            }
            set_ext.set(api::get_value("/plugins/devguard/extension/status").await.ok());
            set_connect_info.set(api::get_value("/devguard/connect/info").await.ok());
            let sid = selected.get_untracked();
            if !sid.is_empty() {
                set_session_detail.set(
                    api::get_value(&format!("/devguard/sessions/{sid}"))
                        .await
                        .ok(),
                );
                set_audit.set(
                    api::get_value(&format!("/devguard/sessions/{sid}/audit"))
                        .await
                        .ok(),
                );
            }
        });
    });

    view! {
        <section class="space-y-3 lc-panel">
            {section_head("Rules · allow / block / neutral", "GET/POST /plugins/devguard/local-profile")}
            {move || {
                let Some(p) = profile.get() else {
                    return view! { <p class="text-xs text-zinc-500">"Loading profile…"</p> }.into_any();
                };
                let tools: Vec<(String, String)> = DG_TOOLS
                    .iter()
                    .map(|t| ((*t).to_string(), mode_for_tool(&p, t)))
                    .collect();
                view! {
                    <ul class="space-y-2">
                        {tools.into_iter().map(|(tool, mode)| {
                            let tool_btn = tool.clone();
                            view! {
                                <li class="lc-row">
                                    <span class="font-mono text-xs text-zinc-200">{tool.clone()}</span>
                                    <div class="flex gap-1">
                                        {["allow", "neutral", "block"].into_iter().map(|m| {
                                            let active = mode == m;
                                            let tool_c = tool_btn.clone();
                                            let mode_c = m.to_string();
                                            let cls = if active {
                                                match m {
                                                    "allow" => "lc-mode-btn lc-mode-btn--allow",
                                                    "block" => "lc-mode-btn lc-mode-btn--block",
                                                    _ => "lc-mode-btn lc-mode-btn--neutral",
                                                }
                                            } else {
                                                "lc-mode-btn"
                                            };
                                            view! {
                                                <button type="button" class=cls disabled=move || busy.get()
                                                    on:click={
                                                        let tool_c = tool_c.clone();
                                                        let mode_c = mode_c.clone();
                                                        move |_| {
                                                            let tool_c = tool_c.clone();
                                                            let mode_c = mode_c.clone();
                                                            let Some(cur) = profile.get() else { return };
                                                            let next = set_tool_mode(cur, &tool_c, &mode_c);
                                                            set_busy.set(true);
                                                            spawn_local(async move {
                                                                match api::post_value("/plugins/devguard/local-profile", json!({ "profile": next })).await {
                                                                    Ok(v) => {
                                                                        if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                                                        else {
                                                                            set_msg.set(Some((format!("{tool_c} → {mode_c}"), true)));
                                                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                                                        }
                                                                    }
                                                                    Err(e) => set_msg.set(Some((e.message, false))),
                                                                }
                                                                set_busy.set(false);
                                                            });
                                                        }
                                                    }
                                                >{m}</button>
                                            }
                                        }).collect_view()}
                                    </div>
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                }.into_any()
            }}
        </section>

        <section class="space-y-3 lc-panel">
            {section_head("Sessions", "GET/POST /devguard/sessions · end · audit")}
            <div class="grid grid-cols-2 gap-2">
                <label class="block col-span-2">
                    <span class="mb-1 block text-[10px] text-zinc-500">"project name or path"</span>
                    <input class="lc-field text-xs"
                        prop:value=move || ss_workspace.get()
                        on:input=move |ev| set_ss_workspace.set(event_target_value(&ev)) />
                </label>
                <label class="block">
                    <span class="mb-1 block text-[10px] text-zinc-500">"tool"</span>
                    <select class="lc-field text-xs"
                        prop:value=move || ss_tool.get()
                        on:change=move |ev| set_ss_tool.set(event_target_value(&ev))>
                        <option value="cursor">"cursor"</option>
                        <option value="windsurf">"windsurf"</option>
                        <option value="claude_code">"claude_code"</option>
                        <option value="generic">"generic"</option>
                    </select>
                </label>
                <label class="block">
                    <span class="mb-1 block text-[10px] text-zinc-500">"role"</span>
                    <input class="lc-field text-xs"
                        prop:value=move || ss_role.get()
                        on:input=move |ev| set_ss_role.set(event_target_value(&ev)) />
                </label>
            </div>
            <label class="block">
                <span class="mb-1 block text-[10px] text-zinc-500">"policy_yaml (optional)"</span>
                <textarea class="lc-field h-16 text-[11px]"
                    prop:value=move || policy_yaml.get()
                    on:input=move |ev| set_policy_yaml.set(event_target_value(&ev))
                    placeholder="omit → default deny-all" />
            </label>
            <div class="flex flex-wrap gap-2">
                <OpButton label="Start session".to_string() variant=OpButtonVariant::Primary loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let ws = ss_workspace.get().trim().to_string();
                        if ws.is_empty() {
                            set_msg.set(Some(("Name the project first.".into(), false)));
                            return;
                        }
                        let mut body = json!({
                            "workspace": ws,
                            "tool": ss_tool.get(),
                            "role": ss_role.get(),
                        });
                        let py = policy_yaml.get();
                        if !py.trim().is_empty() {
                            body.as_object_mut().unwrap().insert("policy_yaml".into(), json!(py));
                        }
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value("/devguard/sessions", body).await {
                                Ok(v) => {
                                    if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                    else {
                                        if let Some(id) = v.get("session_id").and_then(|x| x.as_str()) {
                                            set_selected.set(id.to_string());
                                        }
                                        set_msg.set(Some(("Session started.".into(), true)));
                                        set_reload.update(|n| *n = n.wrapping_add(1));
                                    }
                                }
                                Err(e) => set_msg.set(Some((e.message, false))),
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <OpButton label="Refresh".to_string() variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| set_reload.update(|n| *n = n.wrapping_add(1))) />
            </div>
            {move || {
                let list = sessions.get();
                if list.is_empty() {
                    return view! { <p class="text-xs text-zinc-500">"No sessions."</p> }.into_any();
                }
                view! {
                    <ul class="max-h-48 space-y-1 overflow-y-auto">
                        {list.into_iter().map(|s| {
                            let id = s.get("session_id").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                            let active = s.get("active").and_then(|x| x.as_bool()).unwrap_or(false);
                            let tool = s.get("tool").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                            let id_end = id.clone();
                            let id_sel = id.clone();
                            view! {
                                <li class="lc-row text-[11px]">
                                    <button type="button" class="min-w-0 truncate text-left font-mono text-zinc-300 hover:text-white"
                                        on:click=move |_| {
                                            set_selected.set(id_sel.clone());
                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                        }>
                                        {format!("{id} · {tool} · active={active}")}
                                    </button>
                                    <OpButton label="End".to_string() variant=OpButtonVariant::Secondary
                                        on_click=Arc::new(move |_| {
                                            let path = format!("/devguard/sessions/{id_end}/end");
                                            set_busy.set(true);
                                            spawn_local(async move {
                                                match api::post_value(&path, json!({})).await {
                                                    Ok(v) => {
                                                        if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                                        else {
                                                            set_msg.set(Some(("Ended.".into(), true)));
                                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                                        }
                                                    }
                                                    Err(e) => set_msg.set(Some((e.message, false))),
                                                }
                                                set_busy.set(false);
                                            });
                                        })
                                    />
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                }.into_any()
            }}
            <Show when=move || session_detail.get().is_some()>
                <pre class="lc-pre max-h-28">
                    {move || session_detail.get().map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()).unwrap_or_default()}
                </pre>
            </Show>
            <Show when=move || audit.get().is_some()>
                <pre class="lc-pre max-h-32">
                    {move || audit.get().map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()).unwrap_or_default()}
                </pre>
            </Show>
        </section>

        <section class="space-y-3 lc-panel">
            {section_head("Extension · connect recipes", "GET …/extension/status · GET /devguard/connect/info")}
            {move || ext.get().map(|v| {
                let raw = serde_json::to_string_pretty(&v).unwrap_or_default();
                view! {
                    <pre class="lc-pre max-h-28">{raw}</pre>
                }
            })}
            {move || connect_info.get().map(|v| {
                let gw = v.get("openai_base_url").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                let hint = v.get("hint").and_then(|x| x.as_str()).unwrap_or("").to_string();
                view! {
                    <dl class="space-y-1 text-xs">
                        <div class="flex justify-between gap-2"><dt class="text-zinc-500">"openai_base_url"</dt><dd class="truncate font-mono text-zinc-300">{gw}</dd></div>
                    </dl>
                    {(!hint.is_empty()).then(|| view! { <p class="text-[11px] text-zinc-500">{hint}</p> })}
                }
            })}
            <label class="block">
                <span class="mb-1 block text-[10px] text-zinc-500">"extension audit session_id"</span>
                <div class="flex gap-2">
                    <input class="lc-field min-w-0 flex-1 text-xs"
                        prop:value=move || selected.get()
                        on:input=move |ev| set_selected.set(event_target_value(&ev)) />
                    <OpButton label="Audit".to_string() variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let sid = selected.get().trim().to_string();
                            if sid.is_empty() { return; }
                            set_busy.set(true);
                            spawn_local(async move {
                                match api::get_value(&format!("/plugins/devguard/extension/audit/{sid}")).await {
                                    Ok(v) => {
                                        set_audit.set(Some(v));
                                        set_msg.set(Some(("Extension audit loaded.".into(), true)));
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                </div>
            </label>
            {flash_line(msg)}
        </section>
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TraceTramp — HITL + policies + blocks + quarantine + traces
// ═══════════════════════════════════════════════════════════════════════════

#[component]
pub fn TraceTrampRulesHitlPanel(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (approvals, set_approvals) = signal(Vec::<Value>::new());
    let (policies, set_policies) = signal(Vec::<Value>::new());
    let (blocks, set_blocks) = signal(Vec::<Value>::new());
    let (quarantines, set_quarantines) = signal(Vec::<Value>::new());
    let (traces, set_traces) = signal(Vec::<Value>::new());
    let (busy, set_busy) = signal(false);
    let (acting_id, set_acting_id) = signal(String::new());
    let (msg, set_msg) = signal(Option::<(String, bool)>::None);
    let (connector_agents, set_connector_agents) = signal(0u64);

    let (tenant_id, set_tenant_id) = signal("default".to_string());
    let (policy_name, set_policy_name) = signal("ui-tool-gate".to_string());
    let (policy_type, set_policy_type) = signal("tool_permission".to_string());
    let (enforcement, set_enforcement) = signal("block".to_string());
    let (rules_json, set_rules_json) =
        signal(r#"{"tools":{"bash":"deny","shell":"deny"},"default":"allow"}"#.to_string());

    let (block_actor, set_block_actor) = signal("*".to_string());
    let (block_op, set_block_op) = signal("tool:bash".to_string());
    let (block_reason, set_block_reason) = signal("operator block from UI".to_string());

    let (q_actor, set_q_actor) = signal(String::new());
    let (q_reason, set_q_reason) = signal("operator quarantine".to_string());

    Effect::new(move |_| {
        let _ = reload.get();
        spawn_local(async move {
            if let Ok(v) = api::get_value("/agents").await {
                let n = crate::api::resource_object(&v)
                    .get("total_agents")
                    .or_else(|| v.get("total_agents"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0);
                set_connector_agents.set(n);
            }
            if let Ok(v) = api::get_value("/plugins/tracetramp/admin/approvals").await {
                if soft_err(&v).is_none() {
                    set_approvals.set(arr_items(&v, &["approvals", "items"]));
                }
            }
            if let Ok(v) = api::get_value("/plugins/tracetramp/admin/policies").await {
                set_policies.set(arr_items(&v, &["policies", "items"]));
            }
            if let Ok(v) = api::get_value("/plugins/tracetramp/admin/operation-blocks").await {
                set_blocks.set(arr_items(&v, &["operation_blocks", "blocks", "items"]));
            }
            if let Ok(v) = api::get_value("/plugins/tracetramp/admin/quarantine").await {
                set_quarantines.set(arr_items(&v, &["quarantines", "items"]));
            }
            if let Ok(v) = api::get_value("/plugins/tracetramp/admin/traces").await {
                set_traces.set(arr_items(&v, &["traces", "items", "data"]));
            }
        });
    });

    view! {
        <section class="space-y-4 lc-panel">
            <div class="flex items-start justify-between gap-2">
                {section_head("HITL · policies · blocks · TraceTramp traffic quarantine · traces", "proxied /plugins/tracetramp/admin/* — ≠ agent brain/broker quarantine")}
                <OpButton label="Refresh".to_string() variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| set_reload.update(|n| *n = n.wrapping_add(1))) />
            </div>
            {flash_line(msg)}
            <p class="text-[11px] text-zinc-500">
                {move || {
                    let n = connector_agents.get();
                    format!("TraceTramp approval_queue is that plugin's store. This Connector node currently has {n} kernel agents — rows whose actor_id is not one of those agents are leftover plugin holds, not operator work for a Connector agent.")
                }}
            </p>

            // Approvals
            <div class="space-y-2">
                <p class="text-[11px] font-medium text-zinc-400">"Approvals · approve / reject / quarantine / execute"</p>
                {move || {
                    let mut items = approvals.get();
                    items.retain(|a| {
                        a.get("status")
                            .and_then(|s| s.as_str())
                            .map(|s| s.eq_ignore_ascii_case("pending") || s.eq_ignore_ascii_case("approved"))
                            .unwrap_or(true)
                    });
                    let total = items.len();
                    if total == 0 {
                        return view! { <p class="text-xs text-zinc-500">"No pending TraceTramp approvals."</p> }.into_any();
                    }
                    let shown: Vec<Value> = items.into_iter().take(25).collect();
                    let hidden = total.saturating_sub(shown.len());
                    view! {
                        <p class="font-mono text-[10px] text-zinc-600">
                            {format!("showing {} of {total} (cap 25)", shown.len())}
                            {if hidden > 0 { format!(" · {hidden} more in TraceTramp") } else { String::new() }}
                        </p>
                        <ul class="space-y-2">
                            {shown.into_iter().map(|item| {
                                let id = item.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let status = item.get("status").and_then(|x| x.as_str()).unwrap_or("pending").to_string();
                                let actor = item.get("actor_id").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                let created = item.get("created_at").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let summary = item.get("reason").or_else(|| item.get("operation_key"))
                                    .and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let mk = |action: &'static str, id: String| -> OpClick {
                                    Arc::new(move |_| {
                                        let path = format!("/plugins/tracetramp/admin/approvals/{id}/{action}");
                                        let approver = actor_from_auth(auth);
                                        set_busy.set(true);
                                        set_acting_id.set(id.clone());
                                        set_msg.set(Some((format!("{action}… POST {path}"), true)));
                                        spawn_local(async move {
                                            match api::post_value(&path, json!({ "approver_id": approver })).await {
                                                Ok(v) => {
                                                    if let Some(e) = soft_err(&v) {
                                                        set_msg.set(Some((format!("{action} failed: {e}"), false)));
                                                    } else {
                                                        let server_msg = crate::api::resource_object(&v)
                                                            .get("message")
                                                            .or_else(|| v.get("message"))
                                                            .and_then(|m| m.as_str())
                                                            .unwrap_or("ok");
                                                        set_msg.set(Some((format!("{action}: {server_msg}"), true)));
                                                        set_reload.update(|n| *n = n.wrapping_add(1));
                                                    }
                                                }
                                                Err(e) => set_msg.set(Some((format!("{action} failed: {}", e.message), false))),
                                            }
                                            set_busy.set(false);
                                            set_acting_id.set(String::new());
                                        });
                                    })
                                };
                                let a1 = mk("approve", id.clone());
                                let a2 = mk("reject", id.clone());
                                let a3 = mk("quarantine", id.clone());
                                let a4 = mk("execute", id.clone());
                                let row_busy = busy.get() && acting_id.get() == id;
                                view! {
                                    <li class="lc-row">
                                        <div class="min-w-0">
                                            <p class="truncate font-mono text-[11px] text-zinc-300">{id.clone()}</p>
                                            <p class="truncate text-[11px] text-zinc-500">{format!("{status} · actor {actor} · {summary}")}</p>
                                            {(!created.is_empty()).then(|| view! {
                                                <p class="truncate font-mono text-[10px] text-zinc-600">{created}</p>
                                            })}
                                        </div>
                                        <div class="flex flex-wrap gap-1">
                                            <OpButton label="Approve".to_string() variant=OpButtonVariant::Primary loading=row_busy on_click=a1 />
                                            <OpButton label="Reject".to_string() variant=OpButtonVariant::Secondary loading=row_busy on_click=a2 />
                                            <OpButton label="Quarantine".to_string() variant=OpButtonVariant::Secondary loading=row_busy on_click=a3 />
                                            <OpButton label="Execute".to_string() variant=OpButtonVariant::Secondary loading=row_busy on_click=a4 />
                                        </div>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }}
            </div>

            // Policies
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"Policies · list + create"</p>
                {move || {
                    let items = policies.get();
                    if items.is_empty() {
                        view! { <p class="text-xs text-zinc-500">"No policies listed."</p> }.into_any()
                    } else {
                        view! {
                            <ul class="max-h-28 space-y-1 overflow-y-auto text-[11px] text-zinc-400">
                                {items.into_iter().take(20).map(|p| {
                                    let line = format!(
                                        "{} · {} · {} · active={}",
                                        p.get("name").and_then(|x| x.as_str()).unwrap_or("—"),
                                        p.get("policy_type").and_then(|x| x.as_str()).unwrap_or("—"),
                                        p.get("enforcement_mode").and_then(|x| x.as_str()).unwrap_or("—"),
                                        p.get("is_active").map(|x| x.to_string()).unwrap_or_else(|| "?".into()),
                                    );
                                    view! { <li class="truncate font-mono">{line}</li> }
                                }).collect_view()}
                            </ul>
                        }.into_any()
                    }
                }}
                <div class="grid grid-cols-2 gap-2">
                    <label class="block">
                        <span class="mb-1 block text-[10px] text-zinc-500">"tenant_id"</span>
                        <input class="lc-field text-xs"
                            prop:value=move || tenant_id.get() on:input=move |ev| set_tenant_id.set(event_target_value(&ev)) />
                    </label>
                    <label class="block">
                        <span class="mb-1 block text-[10px] text-zinc-500">"name"</span>
                        <input class="lc-field text-xs"
                            prop:value=move || policy_name.get() on:input=move |ev| set_policy_name.set(event_target_value(&ev)) />
                    </label>
                    <label class="block">
                        <span class="mb-1 block text-[10px] text-zinc-500">"policy_type"</span>
                        <select class="lc-field text-xs"
                            prop:value=move || policy_type.get() on:change=move |ev| set_policy_type.set(event_target_value(&ev))>
                            <option value="tool_permission">"tool_permission"</option>
                            <option value="content_filter">"content_filter"</option>
                            <option value="rate_limit">"rate_limit"</option>
                            <option value="pii_redact">"pii_redact"</option>
                        </select>
                    </label>
                    <label class="block">
                        <span class="mb-1 block text-[10px] text-zinc-500">"enforcement"</span>
                        <select class="lc-field text-xs"
                            prop:value=move || enforcement.get() on:change=move |ev| set_enforcement.set(event_target_value(&ev))>
                            <option value="block">"block"</option>
                            <option value="monitor">"monitor"</option>
                            <option value="alert">"alert"</option>
                        </select>
                    </label>
                </div>
                <textarea class="lc-field h-16 text-[11px]"
                    prop:value=move || rules_json.get() on:input=move |ev| set_rules_json.set(event_target_value(&ev)) />
                <OpButton label="Create policy".to_string() variant=OpButtonVariant::Primary loading=busy.get()
                    on_click=Arc::new(move |_| {
                        let rules: Value = match serde_json::from_str(&rules_json.get()) {
                            Ok(v) => v,
                            Err(e) => { set_msg.set(Some((format!("rules JSON: {e}"), false))); return; }
                        };
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value("/plugins/tracetramp/admin/policies", json!({
                                "tenant_id": tenant_id.get(),
                                "name": policy_name.get(),
                                "policy_type": policy_type.get(),
                                "rules": rules,
                                "enforcement_mode": enforcement.get(),
                                "priority": 100,
                            })).await {
                                Ok(v) => {
                                    if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                    else { set_msg.set(Some(("Policy created.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                }
                                Err(e) => set_msg.set(Some((e.message, false))),
                            }
                            set_busy.set(false);
                        });
                    })
                />
            </div>

            // Operation blocks
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"Operation blocks"</p>
                <div class="grid grid-cols-2 gap-2">
                    <input class="lc-field text-xs" placeholder="actor_id"
                        prop:value=move || block_actor.get() on:input=move |ev| set_block_actor.set(event_target_value(&ev)) />
                    <input class="lc-field text-xs" placeholder="operation_key"
                        prop:value=move || block_op.get() on:input=move |ev| set_block_op.set(event_target_value(&ev)) />
                </div>
                <input class="lc-field text-xs" placeholder="reason"
                    prop:value=move || block_reason.get() on:input=move |ev| set_block_reason.set(event_target_value(&ev)) />
                <div class="flex flex-wrap gap-2">
                    <OpButton label="Block".to_string() variant=OpButtonVariant::Primary
                        on_click=Arc::new(move |_| {
                            set_busy.set(true);
                            let body = json!({
                                "tenant_id": tenant_id.get(),
                                "actor_id": block_actor.get(),
                                "operation_key": block_op.get(),
                                "reason": block_reason.get(),
                                "created_by": actor_from_auth(auth),
                            });
                            spawn_local(async move {
                                match api::post_value("/plugins/tracetramp/admin/operation-blocks", body).await {
                                    Ok(v) => {
                                        if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                        else { set_msg.set(Some(("Block active.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                    <OpButton label="Release".to_string() variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            set_busy.set(true);
                            let body = json!({
                                "tenant_id": tenant_id.get(),
                                "actor_id": block_actor.get(),
                                "operation_key": block_op.get(),
                            });
                            spawn_local(async move {
                                match api::post_value("/plugins/tracetramp/admin/operation-blocks/release", body).await {
                                    Ok(v) => {
                                        if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                        else { set_msg.set(Some(("Released.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                </div>
                {move || {
                    let items = blocks.get();
                    if items.is_empty() {
                        return view! { <p class="text-xs text-zinc-500">"No blocks."</p> }.into_any();
                    }
                    view! {
                        <ul class="max-h-24 space-y-1 overflow-y-auto text-[11px] text-zinc-400">
                            {items.into_iter().take(12).map(|b| {
                                let line = format!(
                                    "{} · {} · active={}",
                                    b.get("operation_key").and_then(|x| x.as_str()).unwrap_or("—"),
                                    b.get("actor_id").and_then(|x| x.as_str()).unwrap_or("—"),
                                    b.get("active").map(|x| x.to_string()).unwrap_or_else(|| "?".into()),
                                );
                                view! { <li class="truncate font-mono">{line}</li> }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }}
            </div>

            // Quarantine lane
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"Quarantine · list / create / release"</p>
                <div class="grid grid-cols-2 gap-2">
                    <input class="lc-field text-xs" placeholder="actor_id"
                        prop:value=move || q_actor.get() on:input=move |ev| set_q_actor.set(event_target_value(&ev)) />
                    <input class="lc-field text-xs" placeholder="reason"
                        prop:value=move || q_reason.get() on:input=move |ev| set_q_reason.set(event_target_value(&ev)) />
                </div>
                <div class="flex flex-wrap gap-2">
                    <OpButton label="Quarantine actor".to_string() variant=OpButtonVariant::Primary
                        on_click=Arc::new(move |_| {
                            let actor = q_actor.get().trim().to_string();
                            if actor.is_empty() {
                                set_msg.set(Some(("actor_id required".into(), false)));
                                return;
                            }
                            set_busy.set(true);
                            spawn_local(async move {
                                match api::post_value("/plugins/tracetramp/admin/quarantine", json!({
                                    "tenant_id": tenant_id.get(),
                                    "actor_id": actor,
                                    "reason": q_reason.get(),
                                })).await {
                                    Ok(v) => {
                                        if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                        else { set_msg.set(Some(("Quarantined.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                    <OpButton label="Release quarantine".to_string() variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            set_busy.set(true);
                            spawn_local(async move {
                                match api::post_value("/plugins/tracetramp/admin/quarantine/release", json!({
                                    "tenant_id": tenant_id.get(),
                                    "actor_id": q_actor.get(),
                                })).await {
                                    Ok(v) => {
                                        if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                        else { set_msg.set(Some(("Quarantine released.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                </div>
                {move || {
                    let items = quarantines.get();
                    if items.is_empty() {
                        return view! { <p class="text-xs text-zinc-500">"No quarantines."</p> }.into_any();
                    }
                    view! {
                        <ul class="max-h-24 space-y-1 overflow-y-auto text-[11px] text-zinc-400">
                            {items.into_iter().take(12).map(|q| {
                                let line = format!(
                                    "{} · {} · {}",
                                    q.get("actor_id").and_then(|x| x.as_str()).unwrap_or("—"),
                                    q.get("status").and_then(|x| x.as_str()).unwrap_or("—"),
                                    q.get("reason").and_then(|x| x.as_str()).unwrap_or(""),
                                );
                                view! { <li class="truncate font-mono">{line}</li> }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }}
            </div>

            // Traces peek
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"Recent traces"</p>
                {move || {
                    let items = traces.get();
                    if items.is_empty() {
                        return view! { <p class="text-xs text-zinc-500">"No traces (or upstream offline)."</p> }.into_any();
                    }
                    view! {
                        <ul class="max-h-28 space-y-1 overflow-y-auto text-[11px] text-zinc-400">
                            {items.into_iter().take(15).map(|t| {
                                let line = format!(
                                    "{} · {} · {}",
                                    t.get("id").or_else(|| t.get("trace_id")).and_then(|x| x.as_str()).unwrap_or("—"),
                                    t.get("actor_id").and_then(|x| x.as_str()).unwrap_or(""),
                                    t.get("operation_key").or_else(|| t.get("status")).map(|x| x.to_string()).unwrap_or_default(),
                                );
                                view! { <li class="truncate font-mono">{line}</li> }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }}
            </div>
        </section>
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WitnessCtl — sessions + HITL + compliance + custody + pentest + ingest + export
// ═══════════════════════════════════════════════════════════════════════════

#[component]
pub fn WitnessCtlRulesHitlPanel(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (session_id, set_session_id) = signal(String::new());
    let (sessions, set_sessions) = signal(Vec::<String>::new());
    let (hitl, set_hitl) = signal(Vec::<Value>::new());
    let (compliance, set_compliance) = signal(Option::<Value>::None);
    let (custody, set_custody) = signal(Option::<Value>::None);
    let (pentest, set_pentest) = signal(Vec::<Value>::new());
    let (detail, set_detail) = signal(Option::<Value>::None);
    let (busy, set_busy) = signal(false);
    let (msg, set_msg) = signal(Option::<(String, bool)>::None);

    let (upstream, set_upstream) = signal("http://127.0.0.1:11434".to_string());
    let (role, set_role) = signal("auditor".to_string());
    let (control_name, set_control_name) = signal("manual_review".to_string());
    let (severity, set_severity) = signal("medium".to_string());
    let (note, set_note) = signal(String::new());
    let (ingest_json, set_ingest_json) = signal(
        r#"{"session_id":"","request":{"method":"GET","url":"https://example.com","headers":{},"body":null},"response":null}"#.to_string(),
    );
    let (export_fmt, set_export_fmt) = signal("json".to_string());
    let (report_fw, set_report_fw) = signal("soc2".to_string());

    let load_session_surfaces = move |sid: String| {
        spawn_local(async move {
            if sid.is_empty() {
                set_hitl.set(vec![]);
                set_compliance.set(None);
                set_custody.set(None);
                set_pentest.set(vec![]);
                set_detail.set(None);
                return;
            }
            set_detail.set(api::get_value(&format!("/plugins/witnessctl/sessions/{sid}")).await.ok());
            match api::get_value(&format!("/plugins/witnessctl/compliance/{sid}/hitl")).await {
                Ok(v) => {
                    if let Some(e) = soft_err(&v) {
                        set_msg.set(Some((e, false)));
                        set_hitl.set(vec![]);
                    } else {
                        set_hitl.set(arr_items(&v, &["items"]));
                    }
                }
                Err(e) => set_msg.set(Some((e.message, false))),
            }
            set_compliance.set(
                api::get_value(&format!("/plugins/witnessctl/compliance/{sid}"))
                    .await
                    .ok(),
            );
            set_custody.set(
                api::get_value(&format!("/plugins/witnessctl/custody/{sid}/status"))
                    .await
                    .ok(),
            );
            if let Ok(v) = api::get_value(&format!("/plugins/witnessctl/pentest/{sid}/decisions")).await
            {
                set_pentest.set(arr_items(&v, &["decisions", "items", "data"]));
            }
        });
    };

    Effect::new(move |_| {
        let _ = reload.get();
        spawn_local(async move {
            if let Ok(v) = api::get_value("/plugins/witnessctl/sessions").await {
                let ids: Vec<String> = arr_items(&v, &["sessions", "items"])
                    .into_iter()
                    .filter_map(|s| {
                        s.get("id")
                            .or_else(|| s.get("session_id"))
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect();
                if session_id.get_untracked().is_empty() {
                    if let Some(first) = ids.first() {
                        set_session_id.set(first.clone());
                    }
                }
                set_sessions.set(ids);
            }
            load_session_surfaces(session_id.get_untracked());
        });
    });

    view! {
        <section class="space-y-4 lc-panel">
            <div class="flex items-start justify-between gap-2">
                {section_head("Sessions · HITL · compliance · custody · export", "proxied /plugins/witnessctl/*")}
                <OpButton label="Refresh".to_string() variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| set_reload.update(|n| *n = n.wrapping_add(1))) />
            </div>

            // Create / select session
            <div class="space-y-2">
                <p class="text-[11px] font-medium text-zinc-400">"Sessions · create / seal / detail"</p>
                <div class="grid grid-cols-2 gap-2">
                    <input class="lc-field text-xs" placeholder="upstream"
                        prop:value=move || upstream.get() on:input=move |ev| set_upstream.set(event_target_value(&ev)) />
                    <input class="lc-field text-xs" placeholder="role"
                        prop:value=move || role.get() on:input=move |ev| set_role.set(event_target_value(&ev)) />
                </div>
                <OpButton label="Create session".to_string() variant=OpButtonVariant::Primary loading=busy.get()
                    on_click=Arc::new(move |_| {
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value("/plugins/witnessctl/sessions", json!({
                                "upstream": upstream.get(),
                                "role": role.get(),
                            })).await {
                                Ok(v) => {
                                    if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                    else {
                                        if let Some(id) = v.get("session_id").or_else(|| v.get("id")).and_then(|x| x.as_str()) {
                                            set_session_id.set(id.to_string());
                                        }
                                        set_msg.set(Some(("Session created.".into(), true)));
                                        set_reload.update(|n| *n = n.wrapping_add(1));
                                    }
                                }
                                Err(e) => set_msg.set(Some((e.message, false))),
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <label class="block">
                    <span class="mb-1 block text-[10px] text-zinc-500">"session_id"</span>
                    <div class="flex gap-2">
                        <input class="lc-field min-w-0 flex-1 text-xs"
                            prop:value=move || session_id.get()
                            on:input=move |ev| set_session_id.set(event_target_value(&ev)) />
                        <OpButton label="Load".to_string() variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| set_reload.update(|n| *n = n.wrapping_add(1))) />
                        <OpButton label="Seal".to_string() variant=OpButtonVariant::Secondary
                            on_click=Arc::new(move |_| {
                                let sid = session_id.get().trim().to_string();
                                if sid.is_empty() { return; }
                                set_busy.set(true);
                                spawn_local(async move {
                                    match api::post_value(&format!("/plugins/witnessctl/sessions/{sid}/seal"), json!({})).await {
                                        Ok(v) => {
                                            if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                            else { set_msg.set(Some(("Sealed.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                        }
                                        Err(e) => set_msg.set(Some((e.message, false))),
                                    }
                                    set_busy.set(false);
                                });
                            })
                        />
                    </div>
                    <Show when=move || !sessions.get().is_empty()>
                        <select class="lc-field mt-2 text-xs"
                            prop:value=move || session_id.get()
                            on:change=move |ev| {
                                set_session_id.set(event_target_value(&ev));
                                set_reload.update(|n| *n = n.wrapping_add(1));
                            }>
                            {move || sessions.get().into_iter().map(|id| {
                                let label = id.clone();
                                view! { <option value=id>{label}</option> }
                            }).collect_view()}
                        </select>
                    </Show>
                </label>
                <Show when=move || detail.get().is_some()>
                    <pre class="lc-pre max-h-24">
                        {move || detail.get().map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()).unwrap_or_default()}
                    </pre>
                </Show>
            </div>

            // HITL
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"HITL · create / approve / reject"</p>
                <div class="grid grid-cols-2 gap-2">
                    <input class="lc-field text-xs" placeholder="control_name"
                        prop:value=move || control_name.get() on:input=move |ev| set_control_name.set(event_target_value(&ev)) />
                    <select class="lc-field text-xs"
                        prop:value=move || severity.get() on:change=move |ev| set_severity.set(event_target_value(&ev))>
                        <option value="low">"low"</option>
                        <option value="medium">"medium"</option>
                        <option value="high">"high"</option>
                        <option value="critical">"critical"</option>
                    </select>
                </div>
                <input class="lc-field text-xs" placeholder="note"
                    prop:value=move || note.get() on:input=move |ev| set_note.set(event_target_value(&ev)) />
                <OpButton label="Create HITL".to_string() variant=OpButtonVariant::Primary
                    on_click=Arc::new(move |_| {
                        let sid = session_id.get().trim().to_string();
                        if sid.is_empty() {
                            set_msg.set(Some(("session_id required".into(), false)));
                            return;
                        }
                        let actor = actor_from_auth(auth);
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value(&format!("/plugins/witnessctl/compliance/{sid}/hitl"), json!({
                                "control_name": control_name.get(),
                                "severity": severity.get(),
                                "primary_reviewer": actor,
                                "note": note.get(),
                            })).await {
                                Ok(v) => {
                                    if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                    else { set_msg.set(Some(("HITL created.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                }
                                Err(e) => set_msg.set(Some((e.message, false))),
                            }
                            set_busy.set(false);
                        });
                    })
                />
                {move || {
                    let list = hitl.get();
                    if list.is_empty() {
                        return view! { <p class="text-xs text-zinc-500">"No HITL items."</p> }.into_any();
                    }
                    view! {
                        <ul class="space-y-2">
                            {list.into_iter().map(|item| {
                                let id = item.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let status = item.get("status").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                let control = item.get("control_name").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                let pending = status == "pending";
                                let mk_resolve = |st: &'static str, item_id: String| -> OpClick {
                                    Arc::new(move |_| {
                                        let item_id = item_id.clone();
                                        let sid = session_id.get();
                                        let actor = actor_from_auth(auth);
                                        set_busy.set(true);
                                        spawn_local(async move {
                                            match api::post_value(
                                                &format!("/plugins/witnessctl/compliance/{sid}/hitl/{item_id}/resolve"),
                                                json!({ "actor": actor, "status": st, "note": note.get() }),
                                            ).await {
                                                Ok(v) => {
                                                    if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                                    else { set_msg.set(Some((format!("{st}."), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                                }
                                                Err(e) => set_msg.set(Some((e.message, false))),
                                            }
                                            set_busy.set(false);
                                        });
                                    })
                                };
                                let a_ok = mk_resolve("approved", id.clone());
                                let a_no = mk_resolve("rejected", id.clone());
                                let a_esc = mk_resolve("escalated", id.clone());
                                view! {
                                    <li class="lc-row">
                                        <div class="min-w-0">
                                            <p class="truncate text-xs text-zinc-200">{control}</p>
                                            <p class="truncate font-mono text-[10px] text-zinc-500">{format!("{id} · {status}")}</p>
                                        </div>
                                        {if pending {
                                            view! {
                                                <div class="flex flex-wrap gap-1">
                                                    <OpButton label="Approve".to_string() variant=OpButtonVariant::Primary on_click=a_ok />
                                                    <OpButton label="Reject".to_string() variant=OpButtonVariant::Secondary on_click=a_no />
                                                    <OpButton label="Escalate".to_string() variant=OpButtonVariant::Secondary on_click=a_esc />
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! { <span></span> }.into_any()
                                        }}
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }}
            </div>

            // Compliance + custody + pentest
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"Compliance · custody · pentest"</p>
                <Show when=move || compliance.get().is_some()>
                    <pre class="lc-pre max-h-28">
                        {move || compliance.get().map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()).unwrap_or_default()}
                    </pre>
                </Show>
                <Show when=move || custody.get().is_some()>
                    {move || custody.get().map(|v| {
                        let strip = v.get("honesty_strip")
                            .and_then(|x| x.as_str())
                            .unwrap_or("local_only")
                            .to_string();
                        let strip = match strip.as_str() {
                            "quorum_met" | "partial" | "local_only" => strip,
                            _ => "local_only".into(),
                        };
                        let court = v.get("court_export_ready").and_then(|x| x.as_bool()).unwrap_or(false)
                            && strip == "quorum_met";
                        let tone = match strip.as_str() {
                            "quorum_met" => "text-emerald-300",
                            "partial" => "text-amber-200",
                            _ => "text-zinc-400",
                        };
                        view! {
                            <div class="rounded-lg border border-zinc-800/60 bg-zinc-950/40 p-2 space-y-1">
                                <div class="flex items-center justify-between gap-2 text-[11px]">
                                    <span class="text-zinc-500">"Custody strip"</span>
                                    <span class=format!("font-mono {tone}")>{strip}</span>
                                </div>
                                <div class="flex items-center justify-between gap-2 text-[11px]">
                                    <span class="text-zinc-500">"court_export_ready"</span>
                                    <span class="font-mono text-zinc-400">{if court { "true" } else { "false" }}</span>
                                </div>
                                <p class="text-[10px] text-zinc-600">
                                    "local_only · partial · quorum_met — never court-grade until quorum_met + verify."
                                </p>
                                <pre class="lc-pre max-h-16 mt-1">
                                    {serde_json::to_string_pretty(&v).unwrap_or_default()}
                                </pre>
                            </div>
                        }
                    })}
                </Show>
                {move || {
                    let items = pentest.get();
                    if items.is_empty() {
                        return view! { <p class="text-xs text-zinc-500">"No pentest decisions."</p> }.into_any();
                    }
                    view! {
                        <ul class="max-h-24 space-y-1 overflow-y-auto text-[11px] text-zinc-400">
                            {items.into_iter().take(12).map(|d| {
                                let line = d.get("trace_id").or_else(|| d.get("id")).map(|x| x.to_string())
                                    .unwrap_or_else(|| serde_json::to_string(&d).unwrap_or_default());
                                view! { <li class="truncate font-mono">{line}</li> }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }}
            </div>

            // Ingest
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"Ingest evidence"</p>
                <textarea class="lc-field h-24 text-[11px]"
                    prop:value=move || ingest_json.get() on:input=move |ev| set_ingest_json.set(event_target_value(&ev)) />
                <OpButton label="POST ingest".to_string() variant=OpButtonVariant::Primary
                    on_click=Arc::new(move |_| {
                        let mut body: Value = match serde_json::from_str(&ingest_json.get()) {
                            Ok(v) => v,
                            Err(e) => { set_msg.set(Some((format!("ingest JSON: {e}"), false))); return; }
                        };
                        let sid = session_id.get();
                        if !sid.is_empty() {
                            if let Some(o) = body.as_object_mut() {
                                if o.get("session_id").and_then(|x| x.as_str()).unwrap_or("").is_empty() {
                                    o.insert("session_id".into(), json!(sid));
                                }
                            }
                        }
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value("/plugins/witnessctl/ingest", body).await {
                                Ok(v) => {
                                    if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                    else { set_msg.set(Some(("Ingested.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                }
                                Err(e) => set_msg.set(Some((e.message, false))),
                            }
                            set_busy.set(false);
                        });
                    })
                />
            </div>

            // Export / report
            <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                <p class="text-[11px] font-medium text-zinc-400">"Export · report"</p>
                <div class="grid grid-cols-2 gap-2">
                    <select class="lc-field text-xs"
                        prop:value=move || export_fmt.get() on:change=move |ev| set_export_fmt.set(event_target_value(&ev))>
                        <option value="json">"json"</option>
                        <option value="pdf">"pdf"</option>
                        <option value="html">"html"</option>
                        <option value="md">"md"</option>
                        <option value="csv">"csv"</option>
                    </select>
                    <select class="lc-field text-xs"
                        prop:value=move || report_fw.get() on:change=move |ev| set_report_fw.set(event_target_value(&ev))>
                        <option value="soc2">"soc2"</option>
                        <option value="iso27001">"iso27001"</option>
                        <option value="hipaa">"hipaa"</option>
                        <option value="gdpr">"gdpr"</option>
                    </select>
                </div>
                <div class="flex flex-wrap gap-2">
                    <OpButton label="Download export".to_string() variant=OpButtonVariant::Primary
                        on_click=Arc::new(move |_| {
                            let sid = session_id.get().trim().to_string();
                            if sid.is_empty() { return; }
                            let fmt = export_fmt.get();
                            let path = format!("/plugins/witnessctl/sessions/{sid}/export?format={fmt}");
                            set_busy.set(true);
                            spawn_local(async move {
                                match api::get_bytes(&path).await {
                                    Ok(bytes) => {
                                        let mime = match fmt.as_str() {
                                            "pdf" => "application/pdf",
                                            "html" => "text/html",
                                            "csv" => "text/csv",
                                            "md" => "text/markdown",
                                            _ => "application/json",
                                        };
                                        trigger_download_bytes(&bytes, &format!("witness-{sid}.{fmt}"), mime);
                                        set_msg.set(Some(("Export downloaded.".into(), true)));
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                    <OpButton label="Download report".to_string() variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let sid = session_id.get().trim().to_string();
                            if sid.is_empty() { return; }
                            let fw = report_fw.get();
                            let fmt = export_fmt.get();
                            let path = format!("/plugins/witnessctl/sessions/{sid}/report?framework={fw}&format={fmt}");
                            set_busy.set(true);
                            spawn_local(async move {
                                match api::get_bytes(&path).await {
                                    Ok(bytes) => {
                                        trigger_download_bytes(&bytes, &format!("witness-{sid}-{fw}.{fmt}"), "application/octet-stream");
                                        set_msg.set(Some(("Report downloaded.".into(), true)));
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                    <OpButton label="Batch report".to_string() variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let sid = session_id.get().trim().to_string();
                            if sid.is_empty() { return; }
                            let path = format!("/plugins/witnessctl/sessions/{sid}/report/batch?format={}", export_fmt.get());
                            set_busy.set(true);
                            spawn_local(async move {
                                match api::get_bytes(&path).await {
                                    Ok(bytes) => {
                                        trigger_download_bytes(&bytes, &format!("witness-{sid}-batch.zip"), "application/zip");
                                        set_msg.set(Some(("Batch downloaded.".into(), true)));
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                </div>
            </div>

            {flash_line(msg)}
        </section>
    }
}
