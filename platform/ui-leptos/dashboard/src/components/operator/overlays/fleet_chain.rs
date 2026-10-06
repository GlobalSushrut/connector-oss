//! Fleet action chain. The decision shown here is a robustness number.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;

fn num_list(text: &str) -> Option<Vec<f64>> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for part in text.split(|c: char| c == ',' || c == ' ' || c == ';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(part.parse::<f64>().ok()?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn intervals_of(text: &str) -> Option<Vec<Value>> {
    let nums = num_list(text)?;
    if nums.len() < 2 || nums.len() % 2 != 0 {
        return None;
    }
    Some(
        nums.chunks(2)
            .map(|pair| json!([pair[0], pair[1]]))
            .collect(),
    )
}

fn flags_of(text: &str, n: usize) -> Vec<bool> {
    let mut flags: Vec<bool> = text
        .split(|c: char| c == ',' || c == ' ')
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            let s = s.trim();
            s == "1" || s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("yes")
        })
        .collect();
    flags.resize(n, false);
    flags.truncate(n);
    flags
}

fn rows_from(primary: &str, primary_flags: &str, secondary: &str, secondary_flags: &str) -> Result<Vec<Value>, String> {
    let first = intervals_of(primary).ok_or_else(|| "First row needs pairs: low,high low,high".to_string())?;
    let mut rows = vec![json!({
        "id": "a1",
        "intervals": first,
        "controllable": flags_of(primary_flags, intervals_of(primary).map(|v| v.len()).unwrap_or(0)),
    })];
    if !secondary.trim().is_empty() {
        let second = intervals_of(secondary).ok_or_else(|| "Second row needs pairs: low,high low,high".to_string())?;
        rows.push(json!({
            "id": "a2",
            "intervals": second,
            "controllable": flags_of(secondary_flags, second.len()),
        }));
    }
    Ok(rows)
}

#[component]
pub fn FleetChainPanel() -> impl IntoView {
    let (verbs, set_verbs) = signal(Vec::<String>::new());
    let (goal, set_goal) = signal("goal".to_string());
    let (agent, set_agent) = signal(String::new());
    let (address, set_address) = signal(String::new());
    let (address_type, set_address_type) = signal("browser".to_string());
    let (task, set_task) = signal("browse.navigate".to_string());
    let (row_a, set_row_a) = signal("0, 10".to_string());
    let (flags_a, set_flags_a) = signal("true".to_string());
    let (row_b, set_row_b) = signal(String::new());
    let (flags_b, set_flags_b) = signal(String::new());
    let (situation, set_situation) = signal("5".to_string());
    let (receipt, set_receipt) = signal(Value::Null);
    let (walk, set_walk) = signal(Value::Null);
    let (error, set_error) = signal(String::new());

    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(body) = api::get_value("/kernel/fleet-chain/verbs").await {
                let names = body
                    .get("verbs")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                set_verbs.set(names);
            }
        });
    });

    let refresh = move || {
        let goal = goal.get_untracked();
        let agent = agent.get_untracked();
        if goal.trim().is_empty() || agent.trim().is_empty() {
            return;
        }
        spawn_local(async move {
            let path = format!(
                "/kernel/fleet-chain?goal_id={}&agent_pid={}",
                urlencoding_min(&goal),
                urlencoding_min(&agent)
            );
            match api::get_value(&path).await {
                Ok(body) => {
                    if let Some(err) = api::body_error(&body) {
                        set_error.set(err);
                    } else {
                        set_walk.set(body);
                    }
                }
                Err(err) => set_error.set(err.to_string()),
            }
        });
    };

    let save_charter = move |_| {
        set_error.set(String::new());
        let rows = match rows_from(
            &row_a.get_untracked(),
            &flags_a.get_untracked(),
            &row_b.get_untracked(),
            &flags_b.get_untracked(),
        ) {
            Ok(rows) => rows,
            Err(err) => {
                set_error.set(err);
                return;
            }
        };
        let body = json!({
            "goal_id": goal.get_untracked().trim(),
            "agent_pid": agent.get_untracked().trim(),
            "address": address.get_untracked().trim(),
            "address_type": address_type.get_untracked(),
            "task": task.get_untracked().trim(),
            "rows": rows,
        });
        spawn_local(async move {
            match api::post_value("/kernel/fleet-chain/charter", body).await {
                Ok(value) => {
                    if let Some(err) = api::body_error(&value) {
                        set_error.set(err);
                    } else {
                        set_receipt.set(value);
                    }
                }
                Err(err) => set_error.set(err.to_string()),
            }
        });
    };

    let take_step = move |_| {
        set_error.set(String::new());
        let Some(y) = num_list(&situation.get_untracked()) else {
            set_error.set("Situation needs numbers, for example 5 or 4, 12".into());
            return;
        };
        let path = if address_type.get_untracked() == "browser" {
            "/kernel/fleet-chain/step"
        } else {
            "/kernel/fleet-chain/effect"
        };
        let body = json!({
            "goal_id": goal.get_untracked().trim(),
            "agent_pid": agent.get_untracked().trim(),
            "address": address.get_untracked().trim(),
            "address_type": address_type.get_untracked(),
            "task": task.get_untracked().trim(),
            "y": y,
        });
        let goal_id = goal.get_untracked();
        let agent_pid = agent.get_untracked();
        spawn_local(async move {
            match api::post_value(path, body).await {
                Ok(value) => {
                    if let Some(err) = api::body_error(&value) {
                        set_error.set(err);
                        set_receipt.set(value);
                    } else {
                        set_receipt.set(value);
                    }
                }
                Err(err) => set_error.set(err.to_string()),
            }
            let status = format!(
                "/kernel/fleet-chain?goal_id={}&agent_pid={}",
                urlencoding_min(&goal_id),
                urlencoding_min(&agent_pid)
            );
            if let Ok(body) = api::get_value(&status).await {
                set_walk.set(body);
            }
        });
    };

    view! {
        <section class="mb-6 rounded-xl border border-zinc-800 bg-zinc-950/50 p-5">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Fleet action chain"</p>
            <h2 class="mt-1 text-lg font-semibold text-zinc-50">"Robustness"</h2>
            <p class="mt-1 text-sm text-zinc-400">"A goal walks granted addresses. Each hop has its own range. The result is how far the situation sits inside that range. Cease still stops the agent from outside this panel."</p>
            <p class="mt-2 text-[11px] text-zinc-500">
                {move || {
                    let names = verbs.get();
                    if names.is_empty() {
                        "The eleven verbs load from the node.".to_string()
                    } else {
                        format!("{} verbs. The last is the fence.", names.join(" · "))
                    }
                }}
            </p>
            <p class="mt-2 text-[11px] text-amber-200/80">{move || error.get()}</p>
            <div class="mt-4 grid gap-3 sm:grid-cols-2">
                <Field label="Goal" value=goal set_value=set_goal />
                <Field label="Agent" value=agent set_value=set_agent />
                <Field label="Address" value=address set_value=set_address />
                <label class="block text-[11px] text-zinc-400">
                    "Address type"
                    <select
                        class="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-sm text-zinc-100"
                        on:change=move |ev| set_address_type.set(event_target_value(&ev))
                    >
                        <option value="browser" selected=move || address_type.get() == "browser">"browser"</option>
                        <option value="http_api" selected=move || address_type.get() == "http_api">"http_api"</option>
                        <option value="a2a_task" selected=move || address_type.get() == "a2a_task">"a2a_task"</option>
                    </select>
                </label>
                <Field label="Task" value=task set_value=set_task />
                <Field label="Situation y" value=situation set_value=set_situation />
                <Field label="Row a1 ranges (low, high pairs)" value=row_a set_value=set_row_a />
                <Field label="Row a1 controllable (true or false)" value=flags_a set_value=set_flags_a />
                <Field label="Row a2 ranges, optional" value=row_b set_value=set_row_b />
                <Field label="Row a2 controllable" value=flags_b set_value=set_flags_b />
            </div>
            <div class="mt-3 flex gap-2">
                <button type="button" class="rounded bg-zinc-100 px-3 py-1 text-sm text-zinc-950" on:click=save_charter>"Save charter"</button>
                <button type="button" class="rounded border border-zinc-700 px-3 py-1 text-sm text-zinc-100" on:click=take_step>"Measure and step"</button>
                <button type="button" class="rounded border border-zinc-800 px-3 py-1 text-sm text-zinc-400" on:click=move |_| refresh()>"Refresh walk"</button>
            </div>
            <div class="mt-5">
                {move || {
                    let body = receipt.get();
                    let number = body.get("robustness").cloned().or_else(|| body.pointer("/charter/range_digest").cloned());
                    let outcome = body.get("outcome").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let infimum = body.get("sequence_infimum").map(|v| v.to_string()).unwrap_or_default();
                    let digest = body.pointer("/sequence/sequence_digest").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let shown = if body.get("robustness").is_some() {
                        body.get("robustness").map(|v| v.to_string()).unwrap_or_else(|| "—".into())
                    } else if number.is_some() && outcome.is_empty() {
                        "charter stored".into()
                    } else {
                        "—".into()
                    };
                    view! {
                        <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Robustness"</p>
                        <p class="mt-1 font-mono text-3xl text-zinc-50">{shown}</p>
                        <p class="mt-1 text-sm text-zinc-300">{outcome}</p>
                        <p class="mt-1 text-[11px] text-zinc-500">"Sequence infimum " {infimum}</p>
                        <p class="mt-1 break-all font-mono text-[11px] text-zinc-500">{digest}</p>
                    }
                }}
            </div>
            <div class="mt-4 overflow-hidden rounded border border-zinc-800">
                <table class="w-full text-left text-[11px]">
                    <thead class="bg-zinc-900/70 text-zinc-500">
                        <tr><th class="px-2 py-1">"Index"</th><th>"Address"</th><th>"Robustness"</th><th>"Effect taken"</th></tr>
                    </thead>
                    <tbody>
                        {move || {
                            let steps = walk.get()
                                .pointer("/walk/committed")
                                .and_then(|v| v.as_array())
                                .cloned()
                                .unwrap_or_default();
                            if steps.is_empty() {
                                view! { <tr><td colspan="4" class="px-2 py-3 text-zinc-500">"No committed hop yet. A hop is committed only when robustness is nonnegative, the grant edge is open, and the walk is not a cycle or a seal."</td></tr> }.into_any()
                            } else {
                                steps.into_iter().enumerate().map(|(i, step)| {
                                    let address = step.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let robustness = step.get("robustness").map(|v| v.to_string()).unwrap_or_else(|| "—".into());
                                    let taken = step.get("effect_taken").and_then(|v| v.as_bool()).unwrap_or(false).to_string();
                                    view! {
                                        <tr class="border-t border-zinc-800">
                                            <td class="px-2 py-1 text-zinc-400">{i}</td>
                                            <td class="px-2 py-1 text-zinc-200">{address}</td>
                                            <td class="px-2 py-1 font-mono text-zinc-100">{robustness}</td>
                                            <td class="px-2 py-1 text-zinc-400">{taken}</td>
                                        </tr>
                                    }
                                }).collect_view().into_any()
                            }
                        }}
                    </tbody>
                </table>
            </div>
        </section>
    }
}

#[component]
fn Field(
    label: &'static str,
    value: ReadSignal<String>,
    set_value: WriteSignal<String>,
) -> impl IntoView {
    view! {
        <label class="block text-[11px] text-zinc-400">
            {label}
            <input
                class="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 px-2 py-1 text-sm text-zinc-100"
                prop:value=move || value.get()
                on:input=move |ev| set_value.set(event_target_value(&ev))
            />
        </label>
    }
}

fn urlencoding_min(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
