//! Live contract strips + remaining DevGuard team surfaces for light consoles.
//! Every proxied hub endpoint appears here so operators can see / probe coverage.

use leptos::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::operator::primitives::{OpButton, OpButtonVariant};

fn soft_err(v: &Value) -> Option<String> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return Some(
            v.get("error")
                .and_then(|e| e.as_str())
                .or_else(|| v.get("message").and_then(|m| m.as_str()))
                .unwrap_or("failed")
                .into(),
        );
    }
    v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string())
}

#[derive(Clone, Copy)]
struct Endpoint {
    method: &'static str,
    path: &'static str,
    note: &'static str,
}

const DG_ENDPOINTS: &[Endpoint] = &[
    Endpoint { method: "GET", path: "/plugins/devguard/status", note: "status" },
    Endpoint { method: "GET/POST", path: "/plugins/devguard/configure", note: "configure" },
    Endpoint { method: "GET/POST", path: "/plugins/devguard/local-profile", note: "rules" },
    Endpoint { method: "POST", path: "/devguard/connect", note: "connect" },
    Endpoint { method: "GET", path: "/devguard/connect/info", note: "recipes" },
    Endpoint { method: "GET/POST", path: "/devguard/sessions", note: "sessions" },
    Endpoint { method: "GET", path: "/devguard/sessions/:id", note: "session" },
    Endpoint { method: "POST", path: "/devguard/sessions/:id/end", note: "end" },
    Endpoint { method: "GET", path: "/devguard/sessions/:id/audit", note: "audit" },
    Endpoint { method: "GET", path: "/plugins/devguard/extension/status", note: "ext" },
    Endpoint { method: "GET", path: "/plugins/devguard/extension/audit/:id", note: "ext-audit" },
    Endpoint { method: "GET/POST", path: "/plugins/devguard/teams", note: "teams" },
    Endpoint { method: "GET", path: "/plugins/devguard/teams/:id", note: "team" },
    Endpoint { method: "GET/POST", path: "/plugins/devguard/teams/:id/members", note: "members" },
    Endpoint { method: "POST", path: "/plugins/devguard/teams/:id/members/:mid/role", note: "role" },
    Endpoint { method: "GET/POST", path: "/plugins/devguard/teams/:id/actions", note: "actions" },
    Endpoint { method: "GET", path: "/plugins/devguard/teams/:id/command-center", note: "cmd" },
    Endpoint { method: "GET", path: "/plugins/devguard/roles", note: "roles" },
];

const TT_ENDPOINTS: &[Endpoint] = &[
    Endpoint { method: "GET", path: "/plugins/tracetramp/status", note: "status" },
    Endpoint { method: "GET/POST", path: "/plugins/tracetramp/configure", note: "configure" },
    Endpoint { method: "GET", path: "/plugins/tracetramp/admin/stats", note: "stats" },
    Endpoint { method: "GET", path: "/plugins/tracetramp/admin/traces", note: "traces" },
    Endpoint { method: "GET", path: "/plugins/tracetramp/admin/approvals", note: "HITL" },
    Endpoint { method: "POST", path: "…/approvals/:id/approve|reject|quarantine|execute", note: "decide" },
    Endpoint { method: "GET/POST", path: "/plugins/tracetramp/admin/policies", note: "policies" },
    Endpoint { method: "GET/POST", path: "/plugins/tracetramp/admin/operation-blocks", note: "blocks" },
    Endpoint { method: "POST", path: "…/operation-blocks/release", note: "release" },
    Endpoint { method: "GET/POST", path: "/plugins/tracetramp/admin/quarantine", note: "quarantine" },
    Endpoint { method: "POST", path: "…/quarantine/release", note: "q-release" },
];

const WC_ENDPOINTS: &[Endpoint] = &[
    Endpoint { method: "GET", path: "/plugins/witnessctl/status", note: "status" },
    Endpoint { method: "GET/POST", path: "/plugins/witnessctl/configure", note: "configure" },
    Endpoint { method: "GET", path: "/plugins/witnessctl/health", note: "health" },
    Endpoint { method: "GET/POST", path: "/plugins/witnessctl/sessions", note: "sessions" },
    Endpoint { method: "GET", path: "/plugins/witnessctl/sessions/:id", note: "detail" },
    Endpoint { method: "POST", path: "/plugins/witnessctl/sessions/:id/seal", note: "seal" },
    Endpoint { method: "POST", path: "/plugins/witnessctl/ingest", note: "ingest" },
    Endpoint { method: "GET", path: "/plugins/witnessctl/compliance/:id", note: "compliance" },
    Endpoint { method: "GET/POST", path: "…/compliance/:id/hitl", note: "HITL" },
    Endpoint { method: "POST", path: "…/hitl/:item/resolve", note: "resolve" },
    Endpoint { method: "GET", path: "/plugins/witnessctl/custody/:id/status", note: "custody" },
    Endpoint { method: "GET", path: "/plugins/witnessctl/pentest/:id/decisions", note: "pentest" },
    Endpoint { method: "GET", path: "…/sessions/:id/export", note: "export" },
    Endpoint { method: "GET", path: "…/sessions/:id/report", note: "report" },
    Endpoint { method: "GET", path: "…/sessions/:id/report/batch", note: "batch" },
];

#[component]
pub fn LiveContractMap(plugin: &'static str) -> impl IntoView {
    let endpoints = match plugin {
        "devguard" => DG_ENDPOINTS,
        "tracetramp" => TT_ENDPOINTS,
        "witnessctl" => WC_ENDPOINTS,
        _ => &[][..],
    };
    view! {
        <section class="lc-contract">
            <p class="lc-contract__label">
                {format!("Live contract · {plugin} · {} endpoints", endpoints.len())}
            </p>
            <p class="lc-contract__hint">
                "Hub-proxied surfaces this light console plays. Scroll sections below to operate each one."
            </p>
            <ul class="mt-2.5 flex flex-wrap gap-1.5">
                {endpoints.iter().map(|ep| {
                    view! {
                        <li class="lc-chip" title=format!("{} {}", ep.method, ep.path)>
                            <span>{ep.method}</span>
                            " "
                            <span>{ep.note}</span>
                        </li>
                    }
                }).collect_view()}
            </ul>
        </section>
    }
}

/// DevGuard configure + teams / roles / command-center — was setup-only / missing.
#[component]
pub fn DevGuardConfigureAndTeamsPanel() -> impl IntoView {
    let (reload, set_reload) = signal(0u32);
    let (mgmt_url, set_mgmt_url) = signal(String::new());
    let (teams, set_teams) = signal(Vec::<Value>::new());
    let (roles, set_roles) = signal(Vec::<Value>::new());
    let (selected, set_selected) = signal(String::new());
    let (members, set_members) = signal(Vec::<Value>::new());
    let (actions, set_actions) = signal(Vec::<Value>::new());
    let (cmd, set_cmd) = signal(Option::<Value>::None);
    let (busy, set_busy) = signal(false);
    let (msg, set_msg) = signal(Option::<(String, bool)>::None);

    let (team_name, set_team_name) = signal("lab-team".to_string());
    let (admin_email, set_admin_email) = signal("admin@local".to_string());
    let (admin_name, set_admin_name) = signal("Admin".to_string());
    let (mem_email, set_mem_email) = signal(String::new());
    let (mem_name, set_mem_name) = signal(String::new());
    let (mem_role, set_mem_role) = signal("junior".to_string());

    Effect::new(move |_| {
        let _ = reload.get();
        spawn_local(async move {
            if let Ok(v) = api::get_value("/plugins/devguard/configure").await {
                if let Some(u) = v
                    .pointer("/values/management_url")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                {
                    set_mgmt_url.set(u.to_string());
                }
            }
            if let Ok(v) = api::get_value("/plugins/devguard/teams").await {
                let list = v
                    .get("teams")
                    .and_then(|a| a.as_array())
                    .cloned()
                    .unwrap_or_default();
                if selected.get_untracked().is_empty() {
                    if let Some(id) = list
                        .first()
                        .and_then(|t| t.get("id").and_then(|x| x.as_str()))
                    {
                        set_selected.set(id.to_string());
                    }
                }
                set_teams.set(list);
            }
            if let Ok(v) = api::get_value("/plugins/devguard/roles").await {
                set_roles.set(
                    v.get("roles")
                        .and_then(|a| a.as_array())
                        .cloned()
                        .unwrap_or_default(),
                );
            }
            let tid = selected.get_untracked();
            if !tid.is_empty() {
                if let Ok(v) = api::get_value(&format!("/plugins/devguard/teams/{tid}/members")).await
                {
                    set_members.set(
                        v.get("members")
                            .and_then(|a| a.as_array())
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                if let Ok(v) = api::get_value(&format!("/plugins/devguard/teams/{tid}/actions")).await
                {
                    set_actions.set(
                        v.get("actions")
                            .and_then(|a| a.as_array())
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                set_cmd.set(
                    api::get_value(&format!("/plugins/devguard/teams/{tid}/command-center"))
                        .await
                        .ok(),
                );
            }
        });
    });

    view! {
        <section class="lc-panel">
            <div>
                <p class="lc-panel__eyebrow">"Configure · extension management URL"</p>
                <p class="lc-panel__api">"GET/POST /plugins/devguard/configure"</p>
            </div>
            <div class="flex flex-wrap gap-2">
                <input class="lc-field min-w-0 flex-1 text-xs"
                    placeholder="http://127.0.0.1:…. status-api (optional)"
                    prop:value=move || mgmt_url.get()
                    on:input=move |ev| set_mgmt_url.set(event_target_value(&ev)) />
                <OpButton label="Save configure".to_string() variant=OpButtonVariant::Primary loading=busy.get()
                    on_click=Arc::new(move |_| {
                        set_busy.set(true);
                        spawn_local(async move {
                            match api::post_value("/plugins/devguard/configure", json!({
                                "values": {
                                    "management_url": mgmt_url.get().trim(),
                                    "enforce_mode": true,
                                }
                            })).await {
                                Ok(v) => {
                                    if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                    else { set_msg.set(Some(("Configured.".into(), true))); }
                                }
                                Err(e) => set_msg.set(Some((e.message, false))),
                            }
                            set_busy.set(false);
                        });
                    })
                />
            </div>
        </section>

        <section class="lc-panel">
            <div class="flex items-start justify-between gap-2">
                <div>
                    <p class="lc-panel__eyebrow">"Teams · members · roles · command-center"</p>
                    <p class="lc-panel__api">"/plugins/devguard/teams* · /roles"</p>
                </div>
                <OpButton label="Refresh".to_string() variant=OpButtonVariant::Secondary
                    on_click=Arc::new(move |_| set_reload.update(|n| *n = n.wrapping_add(1))) />
            </div>

            <div class="grid grid-cols-2 gap-2">
                <input class="lc-field text-xs" placeholder="team name"
                    prop:value=move || team_name.get() on:input=move |ev| set_team_name.set(event_target_value(&ev)) />
                <input class="lc-field text-xs" placeholder="admin name"
                    prop:value=move || admin_name.get() on:input=move |ev| set_admin_name.set(event_target_value(&ev)) />
                <input class="lc-field col-span-2 text-xs" placeholder="admin email"
                    prop:value=move || admin_email.get() on:input=move |ev| set_admin_email.set(event_target_value(&ev)) />
            </div>
            <OpButton label="Create team".to_string() variant=OpButtonVariant::Primary
                on_click=Arc::new(move |_| {
                    set_busy.set(true);
                    spawn_local(async move {
                        match api::post_value("/plugins/devguard/teams", json!({
                            "name": team_name.get(),
                            "admin_email": admin_email.get(),
                            "admin_name": admin_name.get(),
                        })).await {
                            Ok(v) => {
                                if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                else {
                                    if let Some(id) = v.pointer("/team/id").or_else(|| v.get("id")).and_then(|x| x.as_str()) {
                                        set_selected.set(id.to_string());
                                    }
                                    set_msg.set(Some(("Team created.".into(), true)));
                                    set_reload.update(|n| *n = n.wrapping_add(1));
                                }
                            }
                            Err(e) => set_msg.set(Some((e.message, false))),
                        }
                        set_busy.set(false);
                    });
                })
            />

            {move || {
                let list = teams.get();
                if list.is_empty() {
                    return view! { <p class="text-xs text-zinc-500">"No teams yet."</p> }.into_any();
                }
                view! {
                    <ul class="space-y-1">
                        {list.into_iter().map(|t| {
                            let id = t.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let name = t.get("name").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                            let id_c = id.clone();
                            let active = selected.get() == id;
                            view! {
                                <li>
                                    <button type="button"
                                        class=if active {
                                            "w-full truncate rounded border border-indigo-500/40 bg-indigo-500/10 px-2 py-1.5 text-left font-mono text-[11px] text-indigo-200"
                                        } else {
                                            "w-full truncate rounded border border-zinc-800 px-2 py-1.5 text-left font-mono text-[11px] text-zinc-400 hover:border-zinc-600"
                                        }
                                        on:click=move |_| {
                                            set_selected.set(id_c.clone());
                                            set_reload.update(|n| *n = n.wrapping_add(1));
                                        }>
                                        {format!("{name} · {id}")}
                                    </button>
                                </li>
                            }
                        }).collect_view()}
                    </ul>
                }.into_any()
            }}

            <Show when=move || !selected.get().is_empty()>
                <div class="space-y-2 border-t border-zinc-800/60 pt-3">
                    <p class="text-[11px] text-zinc-400">"Add member · POST …/members"</p>
                    <div class="grid grid-cols-2 gap-2">
                        <input class="lc-field text-xs" placeholder="name"
                            prop:value=move || mem_name.get() on:input=move |ev| set_mem_name.set(event_target_value(&ev)) />
                        <select class="lc-field text-xs"
                            prop:value=move || mem_role.get() on:change=move |ev| set_mem_role.set(event_target_value(&ev))>
                            <option value="admin">"admin"</option>
                            <option value="senior">"senior"</option>
                            <option value="junior">"junior"</option>
                            <option value="observer">"observer"</option>
                        </select>
                        <input class="lc-field col-span-2 text-xs" placeholder="email"
                            prop:value=move || mem_email.get() on:input=move |ev| set_mem_email.set(event_target_value(&ev)) />
                    </div>
                    <OpButton label="Add member".to_string() variant=OpButtonVariant::Secondary
                        on_click=Arc::new(move |_| {
                            let tid = selected.get();
                            if tid.is_empty() { return; }
                            set_busy.set(true);
                            spawn_local(async move {
                                match api::post_value(&format!("/plugins/devguard/teams/{tid}/members"), json!({
                                    "email": mem_email.get(),
                                    "name": mem_name.get(),
                                    "role": mem_role.get(),
                                })).await {
                                    Ok(v) => {
                                        if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                        else { set_msg.set(Some(("Member added.".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                    }
                                    Err(e) => set_msg.set(Some((e.message, false))),
                                }
                                set_busy.set(false);
                            });
                        })
                    />
                    {move || {
                        let list = members.get();
                        view! {
                            <ul class="max-h-28 space-y-1 overflow-y-auto text-[11px] text-zinc-400">
                                {list.into_iter().map(|m| {
                                    let mid = m.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                    let line = format!(
                                        "{} · {} · {}",
                                        m.get("email").and_then(|x| x.as_str()).unwrap_or("—"),
                                        m.get("role").map(|x| x.to_string()).unwrap_or_default(),
                                        mid,
                                    );
                                    let mid_c = mid.clone();
                                    view! {
                                        <li class="flex flex-wrap items-center justify-between gap-1">
                                            <span class="truncate font-mono">{line}</span>
                                            <button type="button" class="rounded border border-zinc-700 px-1.5 py-0.5 text-[10px] text-zinc-400 hover:border-zinc-500"
                                                on:click=move |_| {
                                                    let tid = selected.get();
                                                    let mid = mid_c.clone();
                                                    spawn_local(async move {
                                                        match api::post_value(
                                                            &format!("/plugins/devguard/teams/{tid}/members/{mid}/role"),
                                                            json!({ "role": "senior" }),
                                                        ).await {
                                                            Ok(v) => {
                                                                if let Some(e) = soft_err(&v) { set_msg.set(Some((e, false))); }
                                                                else { set_msg.set(Some(("Role → senior".into(), true))); set_reload.update(|n| *n = n.wrapping_add(1)); }
                                                            }
                                                            Err(e) => set_msg.set(Some((e.message, false))),
                                                        }
                                                    });
                                                }
                                            >"→ senior"</button>
                                        </li>
                                    }
                                }).collect_view()}
                            </ul>
                        }
                    }}
                    <Show when=move || cmd.get().is_some()>
                        <pre class="lc-pre max-h-28">
                            {move || cmd.get().map(|v| serde_json::to_string_pretty(&v).unwrap_or_default()).unwrap_or_default()}
                        </pre>
                    </Show>
                    {move || {
                        let list = actions.get();
                        if list.is_empty() {
                            return view! { <p class="text-xs text-zinc-500">"No team actions."</p> }.into_any();
                        }
                        view! {
                            <ul class="max-h-20 space-y-1 overflow-y-auto text-[11px] text-zinc-500">
                                {list.into_iter().take(12).map(|a| {
                                    let line = format!(
                                        "{} · {}",
                                        a.get("action_type").and_then(|x| x.as_str()).unwrap_or("—"),
                                        a.get("description").and_then(|x| x.as_str()).unwrap_or(""),
                                    );
                                    view! { <li class="truncate font-mono">{line}</li> }
                                }).collect_view()}
                            </ul>
                        }.into_any()
                    }}
                </div>
            </Show>

            {move || {
                let list = roles.get();
                if list.is_empty() { return view! { <></> }.into_any(); }
                view! {
                    <div class="border-t border-zinc-800/60 pt-3">
                        <p class="mb-1 text-[11px] text-zinc-400">"Roles catalog · GET /plugins/devguard/roles"</p>
                        <ul class="flex flex-wrap gap-1">
                            {list.into_iter().map(|r| {
                                let label = r.get("id").or_else(|| r.get("name")).and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                view! { <li class="rounded border border-zinc-700 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">{label}</li> }
                            }).collect_view()}
                        </ul>
                    </div>
                }.into_any()
            }}

            <Show when=move || msg.get().is_some()>
                <p class=move || if msg.get().map(|(_, ok)| ok).unwrap_or(false) {
                    "text-xs text-emerald-400"
                } else {
                    "text-xs text-amber-400"
                }>
                    {move || msg.get().map(|(m, _)| m).unwrap_or_default()}
                </p>
            </Show>
        </section>
    }
}
