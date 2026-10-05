//! Books / Cost drawer — usage-first agentic economy (not fake USD).

use leptos::prelude::*;
use serde_json::Value;

use crate::api;
use crate::components::operator::api_state::{OpApiErrorBanner, OpDevDisclosure, OpLoadingBlock};
use crate::components::operator::cards::OpMetricRow;
use crate::components::operator::primitives::{OpText, OpTextVariant};
use crate::ui_state::use_developer_view;

/// Render a count that may legitimately be missing. The panel's own banner
/// promises "unavailable ≠ $0", so a null must never print as `0`.
fn count(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "unavailable".into(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

#[component]
pub fn OpBooksEconomyPanel() -> impl IntoView {
    let (dev, _) = use_developer_view();
    let (reload, set_reload) = signal(0u32);
    let resource = LocalResource::new(move || {
        let _ = reload.get();
        async move {
            let books = api::get_value("/books").await;
            let costs = api::get_value_q("/books/costs", &[("period", "today")]).await;
            let journal = api::get_value_q("/books/journal", &[("limit", "12")]).await;
            (books, costs, journal)
        }
    });

    view! {
        <div class="space-y-4 p-4">
            <div class="flex items-start justify-between gap-2">
                <div>
                    <OpText text="Books · agentic economy".to_string() variant=OpTextVariant::Title />
                    <p class="mt-1 text-xs text-zinc-500">
                        "Usage-first meters from GET /books and /books/costs — tokens, calls, model. Cost only with a rate card. unavailable ≠ $0. Not invoice USD."
                    </p>
                </div>
                <button
                    type="button"
                    class="rounded-md border border-zinc-700 px-2 py-1 text-[11px] text-zinc-300 hover:bg-zinc-900"
                    on:click=move |_| set_reload.update(|n| *n = n.wrapping_add(1))
                >"Refresh"</button>
            </div>

            <Suspense fallback=move || view! { <OpLoadingBlock message="Loading books…".to_string() /> }>
                {move || Suspend::new(async move {
                    let (books_res, costs_res, journal_res) = resource.await;
                    match books_res {
                        Ok(books) => {
                            let resources = books.get("data").and_then(|d| d.get("resources")).cloned().unwrap_or(Value::Null);
                            let integrity = books.get("data").and_then(|d| d.get("integrity")).cloned().unwrap_or(Value::Null);
                            let cost = books.get("data").and_then(|d| d.get("cost")).cloned().unwrap_or(Value::Null);
                            let today_tok = count(cost.get("today_tokens"));
                            let month_tok = count(cost.get("month_tokens"));
                            let running = count(resources.get("running_agents"));
                            let suspended = count(resources.get("suspended_agents"));
                            let sessions = count(resources.get("active_sessions"));
                            let mem = count(resources.get("active_memory_count"));
                            let mem_bytes = count(resources.get("active_memory_bytes"));
                            let chain = count(integrity.get("chain_length"));
                            let chain_ok = match integrity.get("chain_verified").and_then(|x| x.as_bool()) {
                                Some(true) => "verified".to_string(),
                                Some(false) => "BROKEN".to_string(),
                                None => "unavailable".to_string(),
                            };
                            let recon = integrity.get("reconciliation_status").and_then(|x| x.as_str()).unwrap_or("unavailable").to_string();
                            let unmetered = books.get("unmetered_peer").cloned().unwrap_or(Value::Null);

                            let costs_view = match costs_res {
                                Ok(c) => books_costs_section(&c),
                                Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                            };
                            let journal_view = match journal_res {
                                Ok(j) => journal_section(&j),
                                Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                            };
                            let raw = serde_json::to_string_pretty(&books).unwrap_or_default();

                            view! {
                                <div class="space-y-4">
                                    <div class="rounded-lg border border-emerald-500/25 bg-emerald-950/15 p-3 text-[11px] text-zinc-300">
                                        "Primary FinOps signals are machine-recorded: tokens, memory units, sessions, agents, audit journal actions. USD in Books cost rows is optional list-price estimate only — unavailable ≠ $0."
                                    </div>
                                    {unmetered_peer_section(&unmetered)}
                                    <OpMetricRow metrics=vec![
                                        ("Today tokens".into(), today_tok),
                                        ("Month tokens".into(), month_tok),
                                        ("Running agents".into(), running),
                                        ("Suspended agents".into(), suspended),
                                        ("Active sessions".into(), sessions),
                                        ("Active memory".into(), mem),
                                        ("Memory bytes".into(), mem_bytes),
                                        ("Audit chain".into(), chain),
                                        ("Chain integrity".into(), chain_ok),
                                        ("Reconcile".into(), recon),
                                    ] />
                                    {costs_view}
                                    {journal_view}
                                    <Show when=move || dev.get()>
                                        <OpDevDisclosure label="Books JSON".to_string() raw=raw.clone() />
                                    </Show>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <OpApiErrorBanner error=e /> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

/// P6.5 — surface `unmetered_peer` from GET /books; never invent $0 for peer hops.
fn unmetered_peer_section(u: &Value) -> AnyView {
    if u.is_null() {
        return view! {
            <section class="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-amber-200/90">"Unmetered peer"</p>
                <p class="mt-1 text-[11px] text-zinc-400">
                    "GET /books did not return unmetered_peer — peer meters unavailable (not $0)."
                </p>
            </section>
        }
        .into_any();
    }
    let unmetered = u
        .get("unmetered_peer_count")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let metered = u
        .get("metered_peer_count")
        .and_then(|x| x.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let honesty = u
        .get("honesty")
        .and_then(|x| x.as_str())
        .unwrap_or("unavailable ≠ $0")
        .to_string();
    let never_fake = u
        .get("never_fake_zero_usd")
        .and_then(|x| x.as_bool());
    let never_fake_disp = match never_fake {
        Some(true) => "true".into(),
        Some(false) => "false".into(),
        None => "—".into(),
    };
    let samples = u
        .get("sample_peer_ids")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let sample_line: String = samples
        .iter()
        .filter_map(|x| x.as_str())
        .take(6)
        .collect::<Vec<_>>()
        .join(", ");
    view! {
        <section class="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-amber-200/90">"Unmetered peer (UsageReceipt)"</p>
            <p class="mt-1 font-mono text-[10px] text-zinc-600">"GET /books → unmetered_peer"</p>
            <OpMetricRow metrics=vec![
                ("Unmetered hops".into(), unmetered),
                ("Metered hops".into(), metered),
                ("Never fake $0".into(), never_fake_disp),
            ] />
            <p class="mt-2 text-[11px] text-amber-100/90">{honesty}</p>
            {if sample_line.is_empty() {
                view! { <p class="mt-1 text-[11px] text-zinc-500">"No sample peer ids yet — MCP/A2A hops append receipts when called."</p> }.into_any()
            } else {
                view! { <p class="mt-1 truncate font-mono text-[10px] text-zinc-400">{format!("peers: {sample_line}")}</p> }.into_any()
            }}
        </section>
    }
    .into_any()
}

fn books_costs_section(c: &Value) -> AnyView {
    let data = c.get("data").cloned().unwrap_or(Value::Null);
    let meta = c.get("meta").cloned().unwrap_or(Value::Null);
    let honesty = meta
        .get("honesty_note")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let has = meta.get("has_usage_data").and_then(|x| x.as_bool()).unwrap_or(false);
    let tokens = data.get("total_tokens");
    let token_disp = match tokens {
        Some(Value::Null) | None => "unavailable".to_string(),
        Some(v) => v.as_u64().map(|n| n.to_string()).unwrap_or_else(|| v.to_string()),
    };
    let by_agent = data
        .get("by_agent")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let by_tool = data
        .get("by_tool")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();

    view! {
        <section class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Cost statement (usage)"</p>
            <p class="mt-1 font-mono text-[10px] text-zinc-600">"GET /books/costs?period=today"</p>
            <p class="mt-2 text-xs text-zinc-200">{format!("total_tokens = {token_disp} · has_usage_data={has}")}</p>
            {if honesty.is_empty() {
                ().into_any()
            } else {
                view! { <p class="mt-1 text-[11px] text-amber-200/90">{honesty}</p> }.into_any()
            }}
            <p class="mt-2 text-[10px] font-semibold uppercase text-zinc-500">"By agent"</p>
            {if by_agent.is_empty() {
                view! { <p class="text-xs text-zinc-600">"No agent usage rows in period."</p> }.into_any()
            } else {
                by_agent.into_iter().take(12).map(|a| {
                    let name = a.get("agent_pid").or_else(|| a.get("pid")).or_else(|| a.get("name")).and_then(|x| x.as_str()).unwrap_or("agent").to_string();
                    let tok = a
                        .get("tokens")
                        .or_else(|| a.get("total_tokens"))
                        .and_then(|x| x.as_u64())
                        .map(|n| format!("{n} tok"))
                        .unwrap_or_else(|| "unavailable".into());
                    view! {
                        <div class="flex justify-between gap-2 border-b border-zinc-800/40 py-1 text-[11px]">
                            <span class="truncate font-mono text-zinc-300">{name}</span>
                            <span class="text-zinc-400">{tok}</span>
                        </div>
                    }
                }).collect_view().into_any()
            }}
            <p class="mt-3 text-[10px] font-semibold uppercase text-zinc-500">"By tool"</p>
            {if by_tool.is_empty() {
                view! { <p class="text-xs text-zinc-600">"No tool usage rows in period."</p> }.into_any()
            } else {
                by_tool.into_iter().take(12).map(|t| {
                    let name = t.get("tool_id").or_else(|| t.get("name")).and_then(|x| x.as_str()).unwrap_or("tool").to_string();
                    let tok = t
                        .get("tokens")
                        .or_else(|| t.get("total_tokens"))
                        .and_then(|x| x.as_u64())
                        .map(|n| format!("{n} tok"))
                        .unwrap_or_else(|| "tok unavailable".into());
                    let calls = t
                        .get("calls")
                        .or_else(|| t.get("count"))
                        .and_then(|x| x.as_u64())
                        .map(|n| format!("{n} calls"))
                        .unwrap_or_else(|| "calls unavailable".into());
                    view! {
                        <div class="flex justify-between gap-2 border-b border-zinc-800/40 py-1 text-[11px]">
                            <span class="truncate font-mono text-zinc-300">{name}</span>
                            <span class="text-zinc-400">{format!("{calls} · {tok}")}</span>
                        </div>
                    }
                }).collect_view().into_any()
            }}
        </section>
    }.into_any()
}

fn journal_section(j: &Value) -> AnyView {
    let entries = j
        .pointer("/data/entries")
        .or_else(|| j.get("entries"))
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    view! {
        <section class="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Recent journal (ops)"</p>
            <p class="mt-1 font-mono text-[10px] text-zinc-600">"GET /books/journal — debit/credit counts, not dollars"</p>
            {if entries.is_empty() {
                view! { <p class="mt-2 text-xs text-zinc-600">"No journal entries."</p> }.into_any()
            } else {
                entries.into_iter().take(12).map(|e| {
                    let action = e.get("action").and_then(|x| x.as_str()).unwrap_or("op").to_string();
                    let actor = e.pointer("/actor/display_name").or_else(|| e.pointer("/actor/id")).and_then(|x| x.as_str()).unwrap_or("—").to_string();
                    let outcome = e.get("outcome").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                    let unit = e.pointer("/debit/unit").and_then(|x| x.as_str()).unwrap_or("count").to_string();
                    let amt = e
                        .pointer("/debit/amount")
                        .and_then(|x| x.as_f64())
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "—".into());
                    view! {
                        <div class="mt-1 border-b border-zinc-800/40 py-1 text-[11px]">
                            <div class="flex justify-between gap-2">
                                <span class="truncate font-mono text-zinc-300">{action}</span>
                                <span class="shrink-0 text-zinc-500">{format!("{amt} {unit} · {outcome}")}</span>
                            </div>
                            <p class="truncate text-zinc-600">{actor}</p>
                        </div>
                    }
                }).collect_view().into_any()
            }}
        </section>
    }.into_any()
}
