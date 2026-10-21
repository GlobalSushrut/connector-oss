//! Operator reading of the eleven roles. Vendor names stay off this surface.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;

const ROLES: &[(&str, &str)] = &[
    ("iam", "sign-in"),
    ("spire", "workload"),
    ("openshell", "boundary"),
    ("opa", "policy"),
    ("firecracker", "isolation"),
    ("otel", "trace"),
    ("cosign", "supply"),
    ("traffic", "traffic"),
    ("brain", "recall"),
    ("broker", "model"),
    ("orchestrate", "flow"),
];

fn operator_state(state: &str) -> &'static str {
    match state {
        "followed" => "up",
        "supervised" => "not following this task",
        _ => "down",
    }
}

fn state_class(operator: &str) -> &'static str {
    match operator {
        "up" => "text-cyan-300",
        "not following this task" => "text-amber-200/90",
        _ => "text-zinc-500",
    }
}

fn fingers_of(body: &Value) -> Vec<Value> {
    for pointer in [
        "/body/fingers",
        "/data/body/fingers",
        "/fingers",
        "/data/fingers",
    ] {
        if let Some(rows) = body.pointer(pointer).and_then(|value| value.as_array()) {
            if !rows.is_empty() {
                return rows.clone();
            }
        }
    }
    Vec::new()
}

fn flag(body: &Value, key: &str) -> Option<bool> {
    body.get(key)
        .or_else(|| body.pointer(&format!("/data/{key}")))
        .or_else(|| body.pointer(&format!("/body/{key}")))
        .and_then(|value| value.as_bool())
}

fn text_at(body: &Value, key: &str) -> String {
    body.get(key)
        .or_else(|| body.pointer(&format!("/data/{key}")))
        .or_else(|| body.pointer(&format!("/body/{key}")))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

fn ordered(fingers: &[Value]) -> Vec<(&'static str, &'static str, String)> {
    ROLES
        .iter()
        .map(|(id, role)| {
            let reading = fingers
                .iter()
                .find(|row| row.get("id").and_then(|value| value.as_str()) == Some(*id))
                .and_then(|row| row.get("state").and_then(|value| value.as_str()))
                .unwrap_or("absent");
            (*role, operator_state(reading), reading.to_string())
        })
        .collect()
}

fn boot_line(value: &Value) -> String {
    if value.get("ok").and_then(|item| item.as_bool()) == Some(false) {
        let reason = value
            .get("reason")
            .or_else(|| value.pointer("/data/reason"))
            .and_then(|item| item.as_str())
            .unwrap_or("Connector did not start the roles.");
        return reason.to_string();
    }
    let running = value
        .get("running")
        .or_else(|| value.pointer("/data/running"))
        .and_then(|item| item.as_bool())
        .unwrap_or(false);
    if running {
        return "Connector is starting the roles.".into();
    }
    let seven = text_at(value, "sign_in_through_traffic");
    let intel = text_at(value, "recall_model_flow");
    if seven == "not started" && intel == "not started" {
        return String::new();
    }
    format!("sign-in through traffic: {seven} · recall, model, flow: {intel}")
}

fn summary(rows: &[(&str, &str, String)]) -> String {
    let up = rows.iter().filter(|(_, operator, _)| *operator == "up").count();
    let waiting = rows
        .iter()
        .filter(|(_, operator, _)| *operator == "not following this task")
        .count();
    let down = rows.len().saturating_sub(up + waiting);
    format!("{up} up · {waiting} not following this task · {down} down")
}

#[component]
fn RoleGrid(rows: Vec<(&'static str, &'static str, String)>) -> impl IntoView {
    view! {
        <div class="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
            {rows.into_iter().map(|(role, operator, reading)| {
                let class = format!(
                    "rounded-lg border border-zinc-800 bg-zinc-950/70 px-3 py-2 {}",
                    state_class(operator)
                );
                view! {
                    <article class=class title=format!("{role} · {reading}")>
                        <p class="text-[11px] font-medium text-zinc-100">{role}</p>
                        <p class="mt-1 font-mono text-[11px]">{operator}</p>
                    </article>
                }
            }).collect_view()}
        </div>
    }
}

#[component]
pub fn ElevenFingersPanel(#[prop(default = false)] show_agent: bool) -> impl IntoView {
    let (system, set_system) = signal(Value::Null);
    let (system_error, set_system_error) = signal(String::new());
    let (agent, set_agent) = signal(Value::Null);
    let (agent_error, set_agent_error) = signal(String::new());
    let (agent_pid, set_agent_pid) = signal(String::new());
    let (compliance, set_compliance) = signal(Value::Null);
    let (compliance_error, set_compliance_error) = signal(String::new());
    let (tick, set_tick) = signal(0u32);
    let (boot, set_boot) = signal(String::new());

    Effect::new(move |_| {
        let _ = tick.get();
        spawn_local(async move {
            match api::get_value("/reports/system").await {
                Ok(value) => {
                    set_system_error.set(String::new());
                    set_system.set(value);
                }
                Err(err) => set_system_error.set(format!("GET /reports/system — {err}")),
            }
            if let Ok(value) = api::get_value("/runtime/eleven/up").await {
                set_boot.set(boot_line(&value));
            }
        });
    });

    let load_agent = move |_| {
        let pid = agent_pid.get_untracked();
        let pid = pid.trim().to_string();
        if pid.is_empty() {
            set_agent_error.set("Enter the agent id.".into());
            return;
        }
        spawn_local(async move {
            match api::get_value(&format!("/reports/agent/{pid}")).await {
                Ok(value) => {
                    set_agent_error.set(String::new());
                    set_agent.set(value);
                }
                Err(err) => set_agent_error.set(format!("GET /reports/agent — {err}")),
            }
        });
    };

    let load_compliance = move |_| {
        let pid = agent_pid.get_untracked();
        let pid = pid.trim().to_string();
        let body = if pid.is_empty() {
            json!({})
        } else {
            json!({ "agent_pid": pid })
        };
        spawn_local(async move {
            match api::post_value("/reports/compliance", body).await {
                Ok(value) => {
                    set_compliance_error.set(String::new());
                    set_compliance.set(value);
                }
                Err(err) => set_compliance_error.set(format!("POST /reports/compliance — {err}")),
            }
        });
    };

    view! {
        <section class="mb-6 rounded-xl border border-zinc-800 bg-zinc-950/50 p-5">
            <div class="flex flex-wrap items-start justify-between gap-3">
                <div>
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"This node"</p>
                    <h2 class="mt-1 text-lg font-semibold text-zinc-50">"Eleven roles"</h2>
                </div>
                <div class="flex gap-2">
                    <button
                        type="button"
                        class="rounded-md border border-cyan-900 px-2 py-1 text-[11px] text-cyan-200 hover:border-cyan-700"
                        on:click=move |_| {
                            set_boot.set("Connector is starting the roles.".into());
                            spawn_local(async move {
                                match api::post_value("/runtime/eleven/up", json!({})).await {
                                    Ok(value) => set_boot.set(boot_line(&value)),
                                    Err(err) => set_boot.set(format!("POST /runtime/eleven/up — {err}")),
                                }
                                set_tick.update(|n| *n = n.wrapping_add(1));
                            });
                        }
                    >
                        "Start"
                    </button>
                    <button
                        type="button"
                        class="rounded-md border border-zinc-700 px-2 py-1 text-[11px] text-zinc-300 hover:border-cyan-800 hover:text-cyan-200"
                        on:click=move |_| set_tick.update(|n| *n = n.wrapping_add(1))
                    >
                        "Refresh"
                    </button>
                </div>
            </div>
            <p class="mt-2 max-w-3xl text-sm text-zinc-400">
                "Connector keeps these roles. Up means the role followed a stored task. Not following this task means the pinned process is up and has not acted. Down means it is absent."
            </p>
            <p class="mt-2 text-[11px] text-amber-200/80">{move || system_error.get()}</p>
            <p class="mt-2 font-mono text-[11px] text-zinc-400">{move || boot.get()}</p>
            <p class="mt-2 font-mono text-[11px] text-zinc-300">{move || {
                let value = system.get();
                if value.is_null() {
                    return "Reading the node.".into();
                }
                let fingers = fingers_of(&value);
                if fingers.is_empty() {
                    return "The node did not return the eleven roles.".into();
                }
                let rows = ordered(&fingers);
                let acceptance = flag(&value, "acceptance_passed").unwrap_or(false);
                format!("{} · acceptance_passed: {acceptance}", summary(&rows))
            }}</p>
            {move || {
                let fingers = fingers_of(&system.get());
                if fingers.is_empty() {
                    ().into_any()
                } else {
                    let rows = ordered(&fingers);
                    view! { <RoleGrid rows=rows /> }.into_any()
                }
            }}
            <p class="mt-3 text-[11px] text-zinc-500">
                "This reading is not a certification, and it does not say a model answer was correct."
            </p>
            <Show when=move || show_agent>
                <div class="mt-5 border-t border-zinc-800 pt-4">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"One agent"</p>
                    <p class="mt-1 text-sm text-zinc-400">"The same eleven roles for one agent. A role is up only when that agent's own record says the finger acted."</p>
                    <div class="mt-3 flex flex-wrap items-center gap-2">
                        <input
                            class="w-full max-w-sm rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1.5 font-mono text-[11px] text-zinc-200"
                            placeholder="agent id"
                            prop:value=move || agent_pid.get()
                            on:input=move |ev| {
                                use wasm_bindgen::JsCast;
                                let value = ev
                                    .target()
                                    .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
                                    .map(|input| input.value())
                                    .unwrap_or_default();
                                set_agent_pid.set(value);
                            }
                        />
                        <button
                            type="button"
                            class="rounded-md border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200"
                            on:click=load_agent
                        >
                            "Read agent"
                        </button>
                        <button
                            type="button"
                            class="rounded-md border border-zinc-700 px-2 py-1 text-[11px] text-zinc-200"
                            on:click=load_compliance
                        >
                            "Read compliance"
                        </button>
                    </div>
                    <p class="mt-2 text-[11px] text-amber-200/80">{move || agent_error.get()}</p>
                    <p class="mt-2 font-mono text-[11px] text-zinc-300">{move || {
                        let value = agent.get();
                        if value.is_null() {
                            return String::new();
                        }
                        let fingers = fingers_of(&value);
                        if fingers.is_empty() {
                            return "The agent report did not list the eleven roles.".into();
                        }
                        summary(&ordered(&fingers))
                    }}</p>
                    {move || {
                        let fingers = fingers_of(&agent.get());
                        if fingers.is_empty() {
                            ().into_any()
                        } else {
                            let rows = ordered(&fingers);
                            view! { <RoleGrid rows=rows /> }.into_any()
                        }
                    }}
                    <p class="mt-2 text-[11px] text-amber-200/80">{move || compliance_error.get()}</p>
                    <p class="mt-2 font-mono text-[11px] text-zinc-400">{move || {
                        let value = compliance.get();
                        if value.is_null() {
                            return String::new();
                        }
                        let status = {
                            let raw = text_at(&value, "witnessctl_status");
                            if raw.is_empty() { "pending_wc_unavailable".into() } else { raw }
                        };
                        let seal = flag(&value, "court_seal").unwrap_or(false);
                        let kind = text_at(&value, "report_type");
                        format!("witnessctl: {status} · court_seal: {seal} · report_type: {kind}")
                    }}</p>
                </div>
            </Show>
        </section>
    }
}
