//! Agent Charter Studio — full-page stage rail (`/agents/:pid/charter`).
//!
//! Stages S1–S11 map to SetupSpec + contract cage + activate (UI plan §10 E2).

use std::sync::Arc;

use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use wasm_bindgen::JsCast;

use crate::components::operator::api_state::OpLoadingBlock;
use crate::components::operator::overlays::intelligence_pack::OpIntelligencePackStrip;
use crate::components::operator::overlays::power_world::OpPowerWorldEditor;
use crate::components::operator::primitives::{OpButton, OpButtonVariant, OpText, OpTextVariant};
use crate::components::page_title::use_page_title;
use crate::iia_api;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Purpose,
    Cage,
    World,
    Hitl,
    Forensic,
    Memory,
    Grants,
    Tools,
    Budgets,
    Institutions,
    Review,
}

impl Stage {
    fn all() -> &'static [Stage] {
        &[
            Stage::Purpose,
            Stage::Cage,
            Stage::World,
            Stage::Hitl,
            Stage::Forensic,
            Stage::Memory,
            Stage::Grants,
            Stage::Tools,
            Stage::Budgets,
            Stage::Institutions,
            Stage::Review,
        ]
    }

    fn id(self) -> &'static str {
        match self {
            Stage::Purpose => "S1",
            Stage::Cage => "S2",
            Stage::World => "S2b",
            Stage::Hitl => "S3",
            Stage::Forensic => "S4",
            Stage::Memory => "S5",
            Stage::Grants => "S6",
            Stage::Tools => "S7",
            Stage::Budgets => "S8",
            Stage::Institutions => "S9",
            Stage::Review => "S10–S11",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Stage::Purpose => "Purpose",
            Stage::Cage => "Contract cage",
            Stage::World => "Power · world · AAPI",
            Stage::Hitl => "HITL policy",
            Stage::Forensic => "Forensic",
            Stage::Memory => "Memory / KB",
            Stage::Grants => "Grants",
            Stage::Tools => "Tools / clearance",
            Stage::Budgets => "Budgets",
            Stage::Institutions => "WC / TT bind",
            Stage::Review => "Review + Activate",
        }
    }
}

#[component]
pub fn AgentCharterStudio() -> impl IntoView {
    use_page_title("Charter Studio");
    let params = use_params_map();
    let pid = Memo::new(move |_| {
        params
            .with(|p| p.get("pid").map(|s| s.to_string()))
            .unwrap_or_default()
    });

    view! {
        <Show
            when=move || !pid.get().is_empty()
            fallback=move || view! {
                <div class="p-6">
                    <OpText text="Charter Studio".to_string() variant=OpTextVariant::Title />
                    <p class="mt-2 text-sm text-zinc-400">
                        "Open from an agent drawer or navigate to "
                        <code class="font-mono text-zinc-300">"/agents/<pid>/charter"</code>
                        ". "
                        <A href="/agents/create" attr:class="underline text-zinc-200">"Create intelligence"</A>
                        " first if needed."
                    </p>
                </div>
            }
        >
            {move || {
                let p = pid.get();
                view! { <CharterStudioBody pid=p /> }
            }}
        </Show>
    }
}

#[component]
fn CharterStudioBody(pid: String) -> impl IntoView {
    let (stage, set_stage) = signal(Stage::Purpose);
    let (name, set_name) = signal(String::new());
    let (acume, set_acume) = signal(String::new());
    let (purpose, set_purpose) = signal(String::new());
    let (cap_text, set_cap_text) = signal(String::new());
    let (denied_text, set_denied_text) = signal(String::new());
    let (fs_read, set_fs_read) = signal(String::new());
    let (fs_write, set_fs_write) = signal(String::new());
    let (net_allow, set_net_allow) = signal(String::new());
    let (net_default, set_net_default) = signal("deny".to_string());
    let (receipt_req, set_receipt_req) = signal("true".to_string());
    let (hitl, set_hitl) = signal("none".to_string());
    let (forensic, set_forensic) = signal("off".to_string());
    let (mem_types, set_mem_types) = signal(
        "working,episodic,semantic,procedural,reflective,social,prospective".to_string(),
    );
    let (kb_id, set_kb_id) = signal(String::new());
    let (grant_path, set_grant_path) = signal(String::new());
    let (grant_readers, set_grant_readers) = signal(String::new());
    let (tool_ids, set_tool_ids) = signal(String::new());
    let (clearance, set_clearance) = signal("standard".to_string());
    let (token_budget, set_token_budget) = signal("16000".to_string());
    let (flash, set_flash) = signal(String::new());
    let (loaded, set_loaded) = signal(false);
    let pid_sv = StoredValue::new(pid.clone());

    Effect::new(move |_| {
        if loaded.get() {
            return;
        }
        let pid = pid_sv.get_value();
        spawn_local(async move {
            if let Ok(c) = iia_api::agent_contract(&pid).await {
                let contract = c
                    .get("contract")
                    .or_else(|| c.pointer("/data/contract"))
                    .unwrap_or(&c);
                set_cap_text.set(join_csv(contract.get("capabilities")));
                set_denied_text.set(join_csv(contract.get("denied_operations")));
                set_purpose.set(join_csv(contract.get("purpose")));
                set_fs_read.set(join_csv(contract.get("filesystem_read")));
                set_fs_write.set(join_csv(contract.get("filesystem_write")));
                set_net_allow.set(join_csv(contract.get("network_allow")));
                if let Some(nd) = contract.get("network_default").and_then(|v| v.as_str()) {
                    set_net_default.set(nd.to_string());
                }
                if let Some(rr) = contract.get("receipt_required").and_then(|v| v.as_bool()) {
                    set_receipt_req.set(if rr { "true" } else { "false" }.into());
                }
            }
            if let Ok(s) = iia_api::agent_setup(&pid).await {
                let setup = s
                    .get("setup")
                    .or_else(|| s.pointer("/data/setup"))
                    .unwrap_or(&s);
                if let Some(n) = setup.get("name").and_then(|v| v.as_str()) {
                    set_name.set(n.to_string());
                }
                if let Some(a) = setup.get("acume").and_then(|v| v.as_str()) {
                    set_acume.set(a.to_string());
                }
                if let Some(k) = setup.get("knowledge_base_id").and_then(|v| v.as_str()) {
                    set_kb_id.set(k.to_string());
                }
                if let Some(h) = setup.get("hitl_policy").and_then(|v| v.as_str()) {
                    set_hitl.set(h.to_string());
                }
                if let Some(f) = setup.get("forensic_profile").and_then(|v| v.as_str()) {
                    set_forensic.set(f.to_string());
                }
                if let Some(mt) = setup.pointer("/memory_profile/enabled_types") {
                    set_mem_types.set(join_csv(Some(mt)));
                }
                if let Some(spaces) = setup.get("common_spaces").and_then(|v| v.as_array()) {
                    if let Some(g0) = spaces.first() {
                        if let Some(p) = g0.get("path").and_then(|x| x.as_str()) {
                            set_grant_path.set(p.to_string());
                        }
                        set_grant_readers.set(join_csv(g0.get("readable_by")));
                    }
                }
            }
            set_loaded.set(true);
        });
    });

    let save_contract = move || {
        let pid = pid_sv.get_value();
        let body = serde_json::json!({
            "purpose": split_csv(&purpose.get()),
            "capabilities": split_csv(&cap_text.get()),
            "denied_operations": split_csv(&denied_text.get()),
            "filesystem_read": split_csv(&fs_read.get()),
            "filesystem_write": split_csv(&fs_write.get()),
            "network_allow": split_csv(&net_allow.get()),
            "network_default": net_default.get(),
            "receipt_required": receipt_req.get() == "true",
        });
        spawn_local(async move {
            match iia_api::patch_contract(&pid, body).await {
                Ok(v) => {
                    let nr = v
                        .get("needs_reactivate")
                        .and_then(|x| x.as_bool())
                        .unwrap_or(false);
                    set_flash.set(format!("Contract saved (needs_reactivate={nr})"));
                }
                Err(e) => set_flash.set(format!("Contract error: {e}")),
            }
        });
    };

    let save_setup = move || {
        let pid = pid_sv.get_value();
        let mut readers = split_csv(&grant_readers.get());
        if !readers.iter().any(|r| r == &pid) {
            readers.push(pid.clone());
        }
        let path = grant_path.get();
        let common_spaces = if path.trim().is_empty() {
            serde_json::json!([])
        } else {
            serde_json::json!([{
                "grant_id": format!("ng_studio_{}", &pid[..pid.len().min(8)]),
                "path": path,
                "readable_by": readers,
                "writable_by": [pid.clone()],
            }])
        };
        let body = serde_json::json!({
            "name": name.get(),
            "acume": acume.get(),
            "knowledge_base_id": kb_id.get(),
            "hitl_policy": hitl.get(),
            "forensic_profile": forensic.get(),
            "setup_complete": true,
            "memory_profile": {
                "default_memory_type": "working",
                "quota_tier": "standard",
                "enabled_types": split_csv(&mem_types.get()),
            },
            "common_spaces": common_spaces,
        });
        spawn_local(async move {
            match iia_api::post_setup(&pid, body).await {
                Ok(_) => set_flash.set("Setup saved".into()),
                Err(e) => set_flash.set(format!("Setup error: {e}")),
            }
        });
    };

    view! {
        <div class="flex min-h-[70vh] gap-0 border-t border-zinc-800/80">
            <aside class="w-52 shrink-0 border-r border-zinc-800/80 bg-zinc-950/40 p-3">
                <p class="mb-2 text-[10px] font-semibold uppercase tracking-wide text-zinc-500">
                    "Charter stages"
                </p>
                <p class="mb-3 font-mono text-[10px] text-zinc-600">{pid_sv.get_value()}</p>
                <nav class="space-y-0.5">
                    {Stage::all().iter().map(|s| {
                        let s = *s;
                        view! {
                            <button
                                type="button"
                                class=move || {
                                    if stage.get() == s {
                                        "w-full rounded px-2 py-1.5 text-left text-[11px] font-medium bg-zinc-100 text-zinc-900"
                                    } else {
                                        "w-full rounded px-2 py-1.5 text-left text-[11px] text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200"
                                    }
                                }
                                on:click=move |_| set_stage.set(s)
                            >
                                <span class="font-mono text-zinc-500">{s.id()}</span>
                                " "
                                {s.title()}
                            </button>
                        }
                    }).collect_view()}
                </nav>
                <div class="mt-4 space-y-1 text-[10px]">
                    <A href="/run" attr:class="block text-zinc-500 underline hover:text-zinc-300">"← RUN"</A>
                    <a
                        class="block text-zinc-500 underline hover:text-zinc-300"
                        href=format!("/run")
                    >
                        "Agent workbench (drawer)"
                    </a>
                </div>
            </aside>
            <main class="flex-1 space-y-4 p-5">
                <div class="flex items-baseline justify-between gap-3">
                    <div>
                        <h1 class="text-lg font-semibold text-zinc-100">
                            {move || format!("{} · {}", stage.get().id(), stage.get().title())}
                        </h1>
                        <p class="mt-1 text-[11px] text-zinc-500">
                            "Full-page Charter Studio — writes SetupSpec + AgentContract, then Activate."
                        </p>
                    </div>
                </div>
                <OpIntelligencePackStrip pid=pid_sv.get_value() />
                <Show when=move || !loaded.get()>
                    <OpLoadingBlock message="Loading charter…".to_string() />
                </Show>
                <Show when=move || loaded.get()>
                    {move || match stage.get() {
                        Stage::Purpose => view! {
                            <div class="max-w-xl space-y-3">
                                <p class="text-[11px] text-zinc-500">
                                    "Purpose is the mission sentence stored on the contract. A blank or general-purpose purpose is not a valid product task."
                                </p>
                                <StudioField label="Display name" value=name on_input=set_name />
                                <StudioField label="Acume" value=acume on_input=set_acume />
                                <StudioField label="Purpose tags (comma)" value=purpose on_input=set_purpose />
                                <OpButton label="Save purpose → cage".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| { save_contract(); set_stage.set(Stage::Cage); }) />
                            </div>
                        }.into_any(),
                        Stage::Cage => view! {
                            <div class="max-w-xl space-y-3">
                                <p class="text-[11px] text-zinc-500">
                                    "Keep ambient_shell / modify_contract denied. Add network hosts or set network_default=allow if the agent needs egress. Talk itself uses the platform LLM proxy."
                                </p>
                                <StudioField label="Capabilities" value=cap_text on_input=set_cap_text />
                                <StudioField label="Denied operations" value=denied_text on_input=set_denied_text />
                                <StudioField label="FS read globs" value=fs_read on_input=set_fs_read />
                                <StudioField label="FS write globs" value=fs_write on_input=set_fs_write />
                                <StudioField label="Network allow" value=net_allow on_input=set_net_allow />
                                <StudioSelect label="Network default" value=net_default on_change=set_net_default options=&["deny", "allow"] />
                                <StudioSelect label="Receipt required" value=receipt_req on_change=set_receipt_req options=&["true", "false"] />
                                <OpButton
                                    label="Widen for general use (caps + network allow)".to_string()
                                    variant=OpButtonVariant::Ghost
                                    on_click=Arc::new(move |_| {
                                        set_cap_text.set(
                                            "read, write, llm, chat, tool, memory, network".into(),
                                        );
                                        set_denied_text.set("modify_contract, ambient_shell".into());
                                        set_net_default.set("allow".into());
                                    })
                                />
                                <OpButton label="Save cage".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| { save_contract(); set_stage.set(Stage::World); }) />
                            </div>
                        }.into_any(),
                        Stage::World => view! {
                            <div class="max-w-xl space-y-3">
                                <p class="text-[11px] text-zinc-500">
                                    "Different agents do not share skills, portals, or AAPI caps. Set this pid's outer-world power here, then continue HITL."
                                </p>
                                <OpPowerWorldEditor pid=pid_sv.get_value() />
                                <OpButton label="Next · HITL".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| set_stage.set(Stage::Hitl)) />
                            </div>
                        }.into_any(),
                        Stage::Hitl => view! {
                            <div class="max-w-xl space-y-3">
                                <StudioSelect label="HITL policy" value=hitl on_change=set_hitl
                                    options=&["none", "egress", "tool", "export", "all_material"] />
                                <p class="text-[11px] text-zinc-500">
                                    "Default none = agent can use tools without approval queue. Policy ≠ queue — queue lives in Manage / FIX."
                                </p>
                                <OpButton label="Next · Forensic".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| set_stage.set(Stage::Forensic)) />
                            </div>
                        }.into_any(),
                        Stage::Forensic => view! {
                            <div class="max-w-xl space-y-3">
                                <StudioSelect label="Forensic profile" value=forensic on_change=set_forensic
                                    options=&["off", "standard", "soc2", "hipaa", "court"] />
                                <p class="text-[11px] text-zinc-500">
                                    "Off/standard for everyday use. Soc2/Hipaa/Court require WitnessCtl on activate."
                                </p>
                                <OpButton label="Next · Memory".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| set_stage.set(Stage::Memory)) />
                            </div>
                        }.into_any(),
                        Stage::Memory => view! {
                            <div class="max-w-xl space-y-3">
                                <StudioField label="Enabled memory types" value=mem_types on_input=set_mem_types />
                                <StudioField label="Knowledge base id" value=kb_id on_input=set_kb_id />
                                <OpButton label="Next · Grants".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| set_stage.set(Stage::Grants)) />
                            </div>
                        }.into_any(),
                        Stage::Grants => view! {
                            <div class="max-w-xl space-y-3">
                                <StudioField label="Common space path" value=grant_path on_input=set_grant_path />
                                <StudioField label="Readable by (pids)" value=grant_readers on_input=set_grant_readers />
                                <OpButton label="Save setup → Tools".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| { save_setup(); set_stage.set(Stage::Tools); }) />
                            </div>
                        }.into_any(),
                        Stage::Tools => view! {
                            <div class="max-w-xl space-y-3">
                                <p class="text-[11px] text-zinc-500">
                                    "S7 — MAC clearance + optional scoped tool bind. Tools run under Ring-1 when hardening is on."
                                </p>
                                <StudioSelect label="Clearance" value=clearance on_change=set_clearance
                                    options=&["public", "tool_io", "standard", "protected", "control", "kernel"] />
                                <StudioField label="Tool ids to bind (comma)" value=tool_ids on_input=set_tool_ids />
                                <OpButton label="Apply clearance".to_string() variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        let level = clearance.get();
                                        spawn_local(async move {
                                            match crate::api::post_value(
                                                &format!("/agents/{pid}/clearance"),
                                                serde_json::json!({ "level": level }),
                                            ).await {
                                                Ok(_) => set_flash.set("Clearance applied".into()),
                                                Err(e) => set_flash.set(format!("Clearance: {e}")),
                                            }
                                        });
                                    }) />
                                <OpButton label="Bind tools (scoped)".to_string() variant=OpButtonVariant::Ghost
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        let tools = split_csv(&tool_ids.get());
                                        spawn_local(async move {
                                            let mut ok = 0usize;
                                            let mut err = String::new();
                                            for tool_id in tools {
                                                let body = serde_json::json!({
                                                    "agent_pid": pid,
                                                    "tool_id": tool_id,
                                                    "allowed_operations": ["invoke"],
                                                    "allowed_paths": [],
                                                });
                                                match crate::api::post_value("/tools/bindings/scoped", body).await {
                                                    Ok(_) => ok += 1,
                                                    Err(e) => {
                                                        if !err.is_empty() { err.push_str("; "); }
                                                        err.push_str(&e.to_string());
                                                    }
                                                }
                                            }
                                            set_flash.set(if err.is_empty() {
                                                format!("Bound {ok} tool(s)")
                                            } else {
                                                format!("Bound {ok}; errors: {err}")
                                            });
                                        });
                                    }) />
                                <OpButton label="Next · Budgets".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| set_stage.set(Stage::Budgets)) />
                            </div>
                        }.into_any(),
                        Stage::Budgets => view! {
                            <div class="max-w-xl space-y-3">
                                <p class="text-[11px] text-zinc-500">
                                    "S8 — token budget for this intelligence. HIPAA/BAA remains under org legal surfaces."
                                </p>
                                <StudioField label="Token budget (daily)" value=token_budget on_input=set_token_budget />
                                <OpButton label="Save budget".to_string() variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        let tokens = token_budget.get().parse::<u64>().unwrap_or(16_000);
                                        spawn_local(async move {
                                            match crate::api::patch_value(
                                                &format!("/agents/{pid}/budget"),
                                                serde_json::json!({ "tokens": tokens, "enforce": true }),
                                            ).await {
                                                Ok(_) => set_flash.set(format!("Budget set to {tokens}")),
                                                Err(e) => set_flash.set(format!("Budget: {e}")),
                                            }
                                        });
                                    }) />
                                <OpButton label="Next · Institutions".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| set_stage.set(Stage::Institutions)) />
                            </div>
                        }.into_any(),
                        Stage::Institutions => view! {
                            <div class="max-w-xl space-y-3">
                                <p class="text-xs text-zinc-400">
                                    "Bind TraceTramp monitor policy and open WitnessCtl / Evidence for WC join."
                                </p>
                                <OpButton label="Bind TT monitor policy".to_string() variant=OpButtonVariant::Secondary
                                    on_click=Arc::new(move |_| {
                                        let pid = pid_sv.get_value();
                                        spawn_local(async move {
                                            let name = format!("charter-{}", &pid[..pid.len().min(12)]);
                                            match iia_api::tt_bind_agent_policy(&pid, "default", &name).await {
                                                Ok(_) => set_flash.set("TT policy bound".into()),
                                                Err(e) => set_flash.set(format!("TT bind: {e}")),
                                            }
                                        });
                                    }) />
                                <div class="flex gap-3 text-[11px]">
                                    <a class="underline text-zinc-300" href="/plugins/witnessctl">"WitnessCtl"</a>
                                    <a class="underline text-zinc-300" href="/plugins/tracetramp">"TraceTramp"</a>
                                </div>
                                <OpButton label="Next · Review".to_string() variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| { save_setup(); set_stage.set(Stage::Review); }) />
                            </div>
                        }.into_any(),
                        Stage::Review => view! {
                            <div class="max-w-2xl space-y-3">
                                <pre class="max-h-64 overflow-y-auto whitespace-pre-wrap rounded border border-zinc-800/60 bg-zinc-950/50 p-3 text-[10px] font-mono text-zinc-300">
                                    {move || format!(
                                        "name={}\nacume={}\npurpose={}\ncaps={}\ndenied={}\nfs_r={}\nfs_w={}\nnet={}/{}\nhitl={}\nforensic={}\nmemory={}\nkb={}\ngrant={}\nreaders={}\nclearance={}\ntools={}\nbudget={}",
                                        name.get(), acume.get(), purpose.get(), cap_text.get(), denied_text.get(),
                                        fs_read.get(), fs_write.get(), net_allow.get(), net_default.get(),
                                        hitl.get(), forensic.get(), mem_types.get(), kb_id.get(),
                                        grant_path.get(), grant_readers.get(),
                                        clearance.get(), tool_ids.get(), token_budget.get()
                                    )}
                                </pre>
                                <div class="flex flex-wrap gap-2">
                                    <OpButton label="Save all".to_string() variant=OpButtonVariant::Secondary
                                        on_click=Arc::new(move |_| { save_contract(); save_setup(); }) />
                                    <OpButton label="Activate".to_string() variant=OpButtonVariant::Primary
                                        on_click=Arc::new(move |_| {
                                            let pid = pid_sv.get_value();
                                            spawn_local(async move {
                                                match iia_api::activate(&pid).await {
                                                    Ok(_) => set_flash.set("Activated — open Evidence for WC join".into()),
                                                    Err(e) => set_flash.set(format!("Activate: {e}")),
                                                }
                                            });
                                        }) />
                                </div>
                            </div>
                        }.into_any(),
                    }}
                </Show>
                <p class="text-xs text-zinc-300">{move || flash.get()}</p>
            </main>
        </div>
    }
}

#[component]
fn StudioField(
    label: &'static str,
    value: ReadSignal<String>,
    on_input: WriteSignal<String>,
) -> impl IntoView {
    view! {
        <label class="block text-[10px] uppercase text-zinc-500">
            {label}
            <input
                class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100 font-mono"
                prop:value=move || value.get()
                on:input=move |ev| on_input.set(event_target_value(&ev))
            />
        </label>
    }
}

#[component]
fn StudioSelect(
    label: &'static str,
    value: ReadSignal<String>,
    on_change: WriteSignal<String>,
    options: &'static [&'static str],
) -> impl IntoView {
    view! {
        <label class="block text-[10px] uppercase text-zinc-500">
            {label}
            <select
                class="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-xs text-zinc-100"
                prop:value=move || value.get()
                on:change=move |ev| on_change.set(event_target_value(&ev))
            >
                {options.iter().map(|o| {
                    let o = *o;
                    view! { <option value=o>{o}</option> }
                }).collect_view()}
            </select>
        </label>
    }
}

fn event_target_value(ev: &web_sys::Event) -> String {
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.value())
        .or_else(|| {
            ev.target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
                .map(|el| el.value())
        })
        .or_else(|| {
            ev.target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlTextAreaElement>().ok())
                .map(|el| el.value())
        })
        .unwrap_or_default()
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

fn join_csv(v: Option<&serde_json::Value>) -> String {
    v.and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}
