//! `/books` — Books & Meters.
//!
//! The drawer panel only ever read `/books`, `/books/costs` and
//! `/books/journal`. The ledger, per-account statements, receipts, balance,
//! reconciliation and session close-out were all backend-only. This surface
//! exposes the whole double-entry story plus LLM usage tracking.
//!
//! House rule, carried from the backend: **unavailable is not $0.** Tokens,
//! calls, memory units and journal actions are machine-recorded and always
//! trustworthy. USD only appears when a rate card is configured, and a missing
//! rate card renders as "unavailable" rather than a zero.

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::primitives::{OpText, OpTextVariant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Position,
    Llm,
    Journal,
    Ledger,
    Closeout,
}

impl Tab {
    fn code(self) -> &'static str {
        match self {
            Tab::Position => "POS",
            Tab::Llm => "LLM",
            Tab::Journal => "JRN",
            Tab::Ledger => "LDG",
            Tab::Closeout => "CLS",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Tab::Position => "Position",
            Tab::Llm => "LLM usage",
            Tab::Journal => "Journal",
            Tab::Ledger => "Ledger",
            Tab::Closeout => "Close-out",
        }
    }
}

/// Render a number that may legitimately be missing. Never coerces to 0.
fn metric(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "unavailable".into(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

#[component]
pub fn BooksCanvas(
    auth: ReadSignal<AuthState>,
    #[prop(optional, default = false)] embedded: bool,
) -> impl IntoView {
    let _ = auth;
    if !embedded {
        crate::components::page_title::use_page_title("Books & Meters");
    }

    if embedded {
        view! {
            <div class="space-y-4 fcs-install">
                <div class="fcs-body space-y-4 rounded-xl border border-zinc-800/60 bg-zinc-900/20 p-4">
                    <BooksContent embedded=true />
                </div>
                <p class="text-[10px] font-mono text-zinc-600">"UNAVAILABLE ≠ $0 · measured usage only"</p>
            </div>
        }
        .into_any()
    } else {
        view! {
            <div class="w-full px-4 py-4 sm:px-6 pb-10 fcs-install">
                <div class="fcs-bezel">
                    <div class="fcs-titlebar">
                        <div class="fcs-titlebar-mark">
                            <span class="fcs-win-controls" aria-hidden="true">
                                <span class="fcs-win-btn close"></span>
                                <span class="fcs-win-btn"></span>
                                <span class="fcs-win-btn"></span>
                            </span>
                            <span class="truncate">"CONNECTOR OS  ·  BOOKS & METERS"</span>
                        </div>
                        <div class="fcs-lights">
                            <span class="fcs-light pwr"><span class="dot"></span>"METER"</span>
                            <span class="fcs-light pwr"><span class="dot"></span>"LEDGER"</span>
                        </div>
                    </div>
                    <div class="fcs-body space-y-4">
                        <BooksContent embedded=false />
                    </div>
                    <div class="fcs-statusbar">
                        <span>"UNAVAILABLE ≠ $0  ·  USAGE IS MACHINE-RECORDED"</span>
                        <span>"BOOKS & METERS"</span>
                    </div>
                </div>
            </div>
        }
        .into_any()
    }
}

#[component]
fn BooksContent(embedded: bool) -> impl IntoView {
    let tab = RwSignal::new(if embedded { Tab::Llm } else { Tab::Position });
    let (reload, set_reload) = signal(0u32);
    let position = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/books").await }
    });
    let tabs = if embedded {
        vec![Tab::Llm, Tab::Position, Tab::Journal]
    } else {
        vec![Tab::Position, Tab::Llm, Tab::Journal, Tab::Ledger, Tab::Closeout]
    };

    view! {
        <div class="flex flex-wrap items-start justify-between gap-2">
            <div>
                <OpText
                    text=if embedded { "FUEL".to_string() } else { "BOOKS & METERS".to_string() }
                    variant=OpTextVariant::Title
                />
                <p class="mt-1 text-sm leading-relaxed text-stone-400">
                    "Usage-first accounting. Tokens, calls, memory units and journal actions are machine-recorded. USD appears only where a rate card exists — unavailable ≠ $0."
                </p>
            </div>
            <button
                type="button"
                class="fcs-btn"
                on:click=move |_| set_reload.update(|n| *n = n.wrapping_add(1))
            >
                "REFRESH"
            </button>
        </div>

        <Suspense fallback=move || {
            view! { <p class="fcs-pad text-xs text-stone-400">"Reading position…"</p> }
        }>
            {move || Suspend::new(async move {
                match position.await {
                    Ok(v) => {
                        let d = v.get("data").cloned().unwrap_or(Value::Null);
                        let res = d.get("resources").cloned().unwrap_or(Value::Null);
                        let integ = d.get("integrity").cloned().unwrap_or(Value::Null);
                        let cost = d.get("cost").cloned().unwrap_or(Value::Null);
                        let cells = vec![
                            ("TODAY TOK", metric(cost.get("today_tokens"))),
                            ("MONTH TOK", metric(cost.get("month_tokens"))),
                            ("AGENTS", metric(res.get("running_agents"))),
                            ("SESSIONS", metric(res.get("active_sessions"))),
                            ("MEM UNITS", metric(res.get("active_memory_count"))),
                            ("CHAIN", metric(integ.get("chain_length"))),
                            (
                                "INTEGRITY",
                                match integ.get("chain_verified").and_then(|x| x.as_bool()) {
                                    Some(true) => "VERIFIED".to_string(),
                                    Some(false) => "BROKEN".to_string(),
                                    None => "unavailable".to_string(),
                                },
                            ),
                            ("RECONCILE", metric(integ.get("reconciliation_status"))),
                        ];
                        view! {
                            <div class="fcs-telemetry">
                                {cells
                                    .into_iter()
                                    .map(|(k, val)| {
                                        view! {
                                            <div class="fcs-telem">
                                                <span class="k">{k}</span>
                                                <span class="v">{val}</span>
                                            </div>
                                        }
                                    })
                                    .collect_view()}
                            </div>
                        }
                        .into_any()
                    }
                    Err(e) => {
                        view! { <p class="fcs-pad text-xs text-rose-300">{e.message}</p> }.into_any()
                    }
                }
            })}
        </Suspense>

        <div class="flex flex-wrap items-center gap-2">
            {tabs
                .into_iter()
                .map(|t| {
                    let is_active = move || tab.get() == t;
                    view! {
                        <button
                            type="button"
                            class=move || if is_active() { "fcs-btn go" } else { "fcs-btn" }
                            on:click=move |_| tab.set(t)
                        >
                            {format!("{} · {}", t.code(), t.label())}
                        </button>
                    }
                })
                .collect_view()}
        </div>

        {move || match tab.get() {
            Tab::Position => view! { <PositionTab /> }.into_any(),
            Tab::Llm => view! { <LlmUsageTab /> }.into_any(),
            Tab::Journal => view! { <JournalTab /> }.into_any(),
            Tab::Ledger => view! { <LedgerTab /> }.into_any(),
            Tab::Closeout => view! { <CloseoutTab /> }.into_any(),
        }}
    }
}

// ── Position ─────────────────────────────────────────────────────────────────

#[component]
fn PositionTab() -> impl IntoView {
    let period = RwSignal::new("today".to_string());
    let costs = LocalResource::new(move || {
        let p = period.get();
        async move { api::get_value_q("/books/costs", &[("period", p.as_str())]).await }
    });

    view! {
        <div class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
                <span class="fcs-section-label">"Period"</span>
                // The handler only understands `today` and `month`; anything
                // else silently falls back to `month`, so don't offer it.
                {["today", "month"].into_iter().map(|p| {
                    let is_active = move || period.get() == p;
                    view! {
                        <button
                            type="button"
                            class=move || if is_active() { "fcs-btn go" } else { "fcs-btn" }
                            on:click=move |_| period.set(p.to_string())
                        >{p.to_uppercase()}</button>
                    }
                }).collect_view()}
            </div>

            <Suspense fallback=move || view! { <p class="fcs-pad text-xs text-stone-400">"Reading statement…"</p> }>
                {move || Suspend::new(async move {
                    match costs.await {
                        Ok(c) => {
                            let data = c.get("data").cloned().unwrap_or(Value::Null);
                            let meta = c.get("meta").cloned().unwrap_or(Value::Null);
                            let has = meta.get("has_usage_data").and_then(|x| x.as_bool()).unwrap_or(false);
                            let honesty = meta.get("honesty_note").and_then(|x| x.as_str()).unwrap_or("").to_string();
                            let total = metric(data.get("total_tokens"));
                            let total_usd = metric(data.get("total_cost_usd"));
                            let basis = data.get("cost_basis").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                            let by_agent = data.get("by_agent").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                            let by_model = data.get("by_model").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                            let by_tool = data.get("by_tool").and_then(|x| x.as_array()).cloned().unwrap_or_default();

                            view! {
                                <div class="space-y-2">
                                    <div class="fcs-pad space-y-1">
                                        <p class="fcs-pad-id">"GET /books/costs"</p>
                                        <p class="text-xs text-stone-100">
                                            {format!("Total tokens: {total} · Estimated USD: {total_usd}")}
                                        </p>
                                        <p class="text-[11px] text-stone-500">{format!("Cost basis: {basis}")}</p>
                                        <p class="text-[11px] text-stone-400">
                                            {if has { "Usage rows present for this period." } else { "No usage rows recorded in this period." }}
                                        </p>
                                        {(!honesty.is_empty()).then(|| view! {
                                            <p class="text-[11px] text-amber-300">{honesty}</p>
                                        })}
                                    </div>

                                    <UsageList title="By model".to_string() rows=by_model name_keys=vec!["model_id", "model"] />
                                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                        <UsageList title="By agent".to_string() rows=by_agent name_keys=vec!["agent_id", "agent_pid", "display_name"] />
                                        <UsageList title="By tool".to_string() rows=by_tool name_keys=vec!["tool_id", "name"] />
                                    </div>
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <p class="fcs-pad text-xs text-rose-300">{e.message}</p> }.into_any(),
                    }
                })}
            </Suspense>

            <ReadCard
                title="Reconciliation balance".to_string()
                desc="T0 kernel counts against T1 engine audit counts, metric by metric.".to_string()
                path="/books/balance".to_string()
            />
            <ReadCard
                title="Cost chain".to_string()
                desc="The per-account hash chain over usage events — a break means an event was written outside the metered path.".to_string()
                path="/monitor/cost-chain".to_string()
            />
            <ReadCard
                title="Usage export".to_string()
                desc="Export-shaped usage rows for downstream FinOps.".to_string()
                path="/monitor/usage-export".to_string()
            />
            <div class="fcs-pad">
                <p class="fcs-pad-id">"GET /books/live"</p>
                <p class="text-[11px] text-stone-400">
                    "The live meter is a server-sent event stream rather than a JSON document, so it is not fetched here. Point an SSE client at it to watch postings land in real time."
                </p>
            </div>
        </div>
    }
}

#[component]
fn UsageList(title: String, rows: Vec<Value>, name_keys: Vec<&'static str>) -> impl IntoView {
    view! {
        <div class="fcs-pad space-y-1">
            <p class="fcs-pad-id">{title}</p>
            {if rows.is_empty() {
                view! { <p class="text-[11px] text-stone-500">"No rows in period."</p> }.into_any()
            } else {
                rows.into_iter().take(15).map(|r| {
                    let name = name_keys
                        .iter()
                        .find_map(|k| r.get(*k).and_then(|x| x.as_str()))
                        .unwrap_or("—")
                        .to_string();
                    let tok = metric(r.get("tokens").or_else(|| r.get("total_tokens")));
                    let calls = r.get("calls").or_else(|| r.get("count")).and_then(|x| x.as_u64());
                    let usd = metric(r.get("cost_usd"));
                    let right = match calls {
                        Some(c) => format!("{c} calls · {tok} tok · {usd} USD"),
                        None => format!("{tok} tok · {usd} USD"),
                    };
                    view! {
                        <div class="flex justify-between gap-2 border-b border-stone-800/40 py-1 text-[11px]">
                            <span class="truncate text-stone-200">{name}</span>
                            <span class="shrink-0 text-stone-400">{right}</span>
                        </div>
                    }
                }).collect_view().into_any()
            }}
        </div>
    }
}

// ── LLM usage ────────────────────────────────────────────────────────────────

/// The cost cap the gateway actually consults before every chat completion.
#[component]
fn CostCapForm() -> impl IntoView {
    let (budget, set_budget) = signal(String::new());
    let (warn, set_warn) = signal("80".to_string());
    let (hard, set_hard) = signal("100".to_string());
    let (msg, set_msg) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let (reload, set_reload) = signal(0u32);

    let current = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/settings/llms/guardrails").await }
    });

    let save = move |_| {
        let b: f64 = match budget.get().trim().parse() {
            Ok(v) => v,
            Err(_) => {
                set_msg.set("Monthly budget must be a number in USD.".into());
                return;
            }
        };
        let w: f64 = warn.get().trim().parse().unwrap_or(80.0);
        let h: f64 = hard.get().trim().parse().unwrap_or(100.0);
        set_busy.set(true);
        set_msg.set(String::new());
        spawn_local(async move {
            let body = json!({
                "monthly_budget_usd": b,
                "warning_pct": w,
                "hard_stop_pct": h,
            });
            match api::post_value("/settings/llms/guardrails", body).await {
                Ok(v) => {
                    if let Some(e) = api::body_error(&v) {
                        set_msg.set(e);
                    } else {
                        set_msg.set("Cap armed.".into());
                        set_reload.update(|n| *n += 1);
                    }
                }
                Err(e) => set_msg.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <section class="fcs-pad space-y-2">
            <p class="fcs-pad-id">"GET / POST /settings/llms/guardrails"</p>
            <h4 class="text-xs font-semibold text-stone-100">"Monthly cost cap"</h4>
            <p class="text-[11px] text-stone-400">
                "This is the only spend control the chat path enforces. When the month's estimated USD reaches budget × hard-stop, gateway completions are refused. A budget of 0 disables the stop entirely, so a fresh node is never locked out."
            </p>

            <Suspense fallback=move || view! { <p class="text-[11px] text-stone-500">"Reading cap…"</p> }>
                {move || Suspend::new(async move {
                    match current.await {
                        Ok(v) => {
                            let g = v.get("guardrails").cloned().unwrap_or(Value::Null);
                            let b = metric(g.get("monthly_budget_usd"));
                            let w = metric(g.get("warning_pct"));
                            let h = metric(g.get("hard_stop_pct"));
                            view! {
                                <p class="text-[11px] text-stone-300">
                                    {format!("Current: {b} USD/month · warn at {w}% · hard stop at {h}%")}
                                </p>
                            }.into_any()
                        }
                        Err(e) => view! { <p class="text-[11px] text-rose-300">{e.message}</p> }.into_any(),
                    }
                })}
            </Suspense>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-1.5">
                <label class="flex flex-col gap-1">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Monthly budget USD"</span>
                    <input class="fcs-input" placeholder="250"
                        prop:value=move || budget.get()
                        on:input=move |ev| set_budget.set(event_target_value(&ev)) />
                </label>
                <label class="flex flex-col gap-1">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Warn at %"</span>
                    <input class="fcs-input" placeholder="80"
                        prop:value=move || warn.get()
                        on:input=move |ev| set_warn.set(event_target_value(&ev)) />
                </label>
                <label class="flex flex-col gap-1">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Hard stop at %"</span>
                    <input class="fcs-input" placeholder="100"
                        prop:value=move || hard.get()
                        on:input=move |ev| set_hard.set(event_target_value(&ev)) />
                </label>
            </div>
            <button type="button" class="fcs-btn amber" prop:disabled=move || busy.get() on:click=save>
                {move || if busy.get() { "ARMING…" } else { "ARM CAP" }}
            </button>
            {move || {
                let m = msg.get();
                (!m.is_empty()).then(|| view! { <p class="text-[11px] text-amber-300">{m}</p> })
            }}
        </section>
    }
}

#[component]
fn LlmUsageTab() -> impl IntoView {
    let (pid, set_pid) = signal(String::new());
    let (out, set_out) = signal(String::new());
    let (busy, set_busy) = signal(false);

    let load_agent = move |path_kind: &'static str| {
        move |_| {
            let p = pid.get().trim().to_string();
            if p.is_empty() {
                set_out.set("Enter an agent pid.".into());
                return;
            }
            let path = match path_kind {
                "timeline" => format!("/history/agents/{p}/cost-timeline"),
                _ => format!("/agents/{p}/cost"),
            };
            set_busy.set(true);
            spawn_local(async move {
                match api::get_value(&path).await {
                    Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                    Err(e) => set_out.set(e.message),
                }
                set_busy.set(false);
            });
        }
    };

    view! {
        <div class="space-y-3">
            <CostCapForm />
            <ReadCard
                title="LLM charts".to_string()
                desc="Model mix, token volume and fallback rate as the router recorded it.".to_string()
                path="/settings/llms/charts".to_string()
            />
            <ReadCard
                title="Budget alerts".to_string()
                desc="Agents approaching or over their token budget.".to_string()
                path="/monitor/budget-alerts".to_string()
            />
            <ReadCard
                title="Entitlements".to_string()
                desc="Tier limits the billing path enforces — daily and monthly token ceilings.".to_string()
                path="/billing/entitlements".to_string()
            />
            <ReadCard
                title="Cost dashboard".to_string()
                desc="Aggregate spend signals across the node.".to_string()
                path="/monitor/cost-dashboard".to_string()
            />
            <ReadCard
                title="Cost centers".to_string()
                desc="Attribution by namespace and tenant.".to_string()
                path="/monitor/cost-center".to_string()
            />
            <ReadCard
                title="Billing usage".to_string()
                desc="Usage as the billing path sees it.".to_string()
                path="/billing/usage".to_string()
            />
            <ReadCard
                title="License usage".to_string()
                desc="Seat and entitlement consumption.".to_string()
                path="/license/usage".to_string()
            />

            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"PER-AGENT SPEND"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Trace one agent's spend"</h4>
                <label class="flex flex-col gap-1 max-w-sm">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Agent pid"</span>
                    <input
                        class="fcs-input"
                        placeholder="agent-pid"
                        prop:value=move || pid.get()
                        on:input=move |ev| set_pid.set(event_target_value(&ev))
                    />
                </label>
                <div class="flex flex-wrap gap-2">
                    <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=load_agent("cost")>"COST"</button>
                    <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=load_agent("timeline")>"TIMELINE"</button>
                </div>
                {move || {
                    let o = out.get();
                    (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-72 overflow-auto">{o}</pre> })
                }}
            </section>
        </div>
    }
}

// ── Journal ──────────────────────────────────────────────────────────────────

#[component]
fn JournalTab() -> impl IntoView {
    let (limit, set_limit) = signal("25".to_string());
    let (actor, set_actor) = signal(String::new());
    let (action, set_action) = signal(String::new());
    let (outcome, set_outcome) = signal(String::new());
    let (seq, set_seq) = signal(String::new());
    let (detail, set_detail) = signal(String::new());
    let (reload, set_reload) = signal(0u32);

    let journal = LocalResource::new(move || {
        let _ = reload.get();
        let (l, ac, an, oc) = (limit.get(), actor.get(), action.get(), outcome.get());
        async move {
            let mut q: Vec<(&str, &str)> = vec![("limit", l.as_str())];
            for (k, v) in [("actor", &ac), ("action", &an), ("outcome", &oc)] {
                if !v.trim().is_empty() {
                    q.push((k, v.as_str()));
                }
            }
            api::get_value_q("/books/journal", &q).await
        }
    });

    let open_detail = move |kind: &'static str| {
        move |_| {
            let s = seq.get().trim().to_string();
            if s.is_empty() {
                set_detail.set("Enter a journal sequence number.".into());
                return;
            }
            let path = match kind {
                // Tier controls how much of the decision context is unredacted.
                "receipt" => format!("/books/receipt/{s}?tier=detailed"),
                _ => format!("/books/journal/{s}"),
            };
            spawn_local(async move {
                match api::get_value(&path).await {
                    Ok(v) => set_detail.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                    Err(e) => set_detail.set(e.message),
                }
            });
        }
    };

    view! {
        <div class="space-y-3">
            <div class="fcs-pad flex flex-wrap items-end gap-2">
                <label class="flex flex-col gap-1">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Limit"</span>
                    <input class="fcs-input max-w-[6rem]"
                        prop:value=move || limit.get()
                        on:input=move |ev| set_limit.set(event_target_value(&ev)) />
                </label>
                <label class="flex flex-col gap-1">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Actor"</span>
                    <input class="fcs-input max-w-[10rem]" placeholder="agent or operator"
                        prop:value=move || actor.get()
                        on:input=move |ev| set_actor.set(event_target_value(&ev)) />
                </label>
                <label class="flex flex-col gap-1">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Action"</span>
                    <input class="fcs-input max-w-[10rem]" placeholder="tool_call"
                        prop:value=move || action.get()
                        on:input=move |ev| set_action.set(event_target_value(&ev)) />
                </label>
                <label class="flex flex-col gap-1">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Outcome"</span>
                    <input class="fcs-input max-w-[9rem]" placeholder="cleared / rejected"
                        prop:value=move || outcome.get()
                        on:input=move |ev| set_outcome.set(event_target_value(&ev)) />
                </label>
                <button type="button" class="fcs-btn" on:click=move |_| set_reload.update(|n| *n += 1)>"LOAD"</button>
            </div>

            <Suspense fallback=move || view! { <p class="fcs-pad text-xs text-stone-400">"Reading journal…"</p> }>
                {move || Suspend::new(async move {
                    match journal.await {
                        Ok(j) => {
                            let entries = j
                                .pointer("/data/entries")
                                .or_else(|| j.get("entries"))
                                .and_then(|x| x.as_array())
                                .cloned()
                                .unwrap_or_default();
                            if entries.is_empty() {
                                return view! { <p class="fcs-pad text-[11px] text-stone-500">"No journal entries."</p> }.into_any();
                            }
                            view! {
                                <div class="fcs-pad space-y-1">
                                    <p class="fcs-pad-id">"GET /books/journal — debit/credit counts, not dollars"</p>
                                    {entries.into_iter().map(|e| {
                                        let sq = metric(e.get("seq_no"));
                                        let action = e.get("action").and_then(|x| x.as_str()).unwrap_or("op").to_string();
                                        let actor = e.pointer("/actor/display_name")
                                            .or_else(|| e.pointer("/actor/id"))
                                            .and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                        let outcome = e.get("outcome").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                                        let unit = e.pointer("/debit/unit").and_then(|x| x.as_str()).unwrap_or("count").to_string();
                                        let amt = metric(e.pointer("/debit/amount"));
                                        view! {
                                            <div class="border-b border-stone-800/40 py-1 text-[11px]">
                                                <div class="flex justify-between gap-2">
                                                    <span class="truncate text-stone-200">{format!("#{sq}  {action}")}</span>
                                                    <span class="shrink-0 text-stone-400">{format!("{amt} {unit} · {outcome}")}</span>
                                                </div>
                                                <p class="truncate text-stone-600">{actor}</p>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }
                        Err(e) => view! { <p class="fcs-pad text-xs text-rose-300">{e.message}</p> }.into_any(),
                    }
                })}
            </Suspense>

            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"GET /books/journal/{seq}  ·  /books/receipt/{seq}"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Open one entry"</h4>
                <p class="text-[11px] text-stone-400">
                    "The receipt is the signed proof behind the entry — this is what survives an audit."
                </p>
                <label class="flex flex-col gap-1 max-w-[10rem]">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Sequence no"</span>
                    <input
                        class="fcs-input"
                        placeholder="42"
                        prop:value=move || seq.get()
                        on:input=move |ev| set_seq.set(event_target_value(&ev))
                    />
                </label>
                <div class="flex flex-wrap gap-2">
                    <button type="button" class="fcs-btn" on:click=open_detail("entry")>"ENTRY"</button>
                    <button type="button" class="fcs-btn amber" on:click=open_detail("receipt")>"RECEIPT"</button>
                </div>
                {move || {
                    let d = detail.get();
                    (!d.is_empty()).then(|| view! { <pre class="fcs-pre max-h-72 overflow-auto">{d}</pre> })
                }}
            </section>
        </div>
    }
}

// ── Ledger ───────────────────────────────────────────────────────────────────

#[component]
fn LedgerTab() -> impl IntoView {
    let (account, set_account) = signal(String::new());
    let (out, set_out) = signal(String::new());
    let (busy, set_busy) = signal(false);

    let load = move |kind: &'static str| {
        move |_| {
            let a = account.get().trim().to_string();
            if a.is_empty() {
                set_out.set("Enter an account id.".into());
                return;
            }
            let path = match kind {
                "statement" => format!("/books/statement/{a}"),
                _ => format!("/books/ledger/{a}"),
            };
            set_busy.set(true);
            spawn_local(async move {
                match api::get_value(&path).await {
                    Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                    Err(e) => set_out.set(e.message),
                }
                set_busy.set(false);
            });
        }
    };

    view! {
        <div class="space-y-3">
            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"GET /books/ledger/{account}  ·  /books/statement/{account}"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Account ledger"</h4>
                <p class="text-[11px] text-stone-400">
                    "The ledger is every posting against one account. The statement is the period roll-up of the same postings."
                </p>
                <label class="flex flex-col gap-1 max-w-sm">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Account id"</span>
                    <input
                        class="fcs-input"
                        placeholder="agent-pid, namespace, or account id"
                        prop:value=move || account.get()
                        on:input=move |ev| set_account.set(event_target_value(&ev))
                    />
                </label>
                <div class="flex flex-wrap gap-2">
                    <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=load("ledger")>"LEDGER"</button>
                    <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=load("statement")>"STATEMENT"</button>
                </div>
                {move || {
                    let o = out.get();
                    (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-96 overflow-auto">{o}</pre> })
                }}
            </section>
        </div>
    }
}

// ── Close-out ────────────────────────────────────────────────────────────────

#[component]
fn CloseoutTab() -> impl IntoView {
    let (session, set_session) = signal(String::new());
    let (out, set_out) = signal(String::new());
    let (busy, set_busy) = signal(false);

    let reconcile = move |_| {
        set_busy.set(true);
        set_out.set(String::new());
        spawn_local(async move {
            match api::post_value("/books/reconcile", json!({})).await {
                Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_out.set(e.message),
            }
            set_busy.set(false);
        });
    };

    let close = move |_| {
        let s = session.get().trim().to_string();
        if s.is_empty() {
            set_out.set("Enter the session id to close.".into());
            return;
        }
        set_busy.set(true);
        set_out.set(String::new());
        spawn_local(async move {
            match api::post_value(&format!("/books/close/{s}"), json!({})).await {
                Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_out.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <div class="space-y-3">
            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"POST /books/reconcile"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Reconcile"</h4>
                <p class="text-[11px] text-stone-400">
                    "Recomputes the journal chain and compares it against recorded balances. A mismatch means an entry was written outside the ledger path."
                </p>
                <button type="button" class="fcs-btn go" prop:disabled=move || busy.get() on:click=reconcile>
                    {move || if busy.get() { "RECONCILING…" } else { "RUN RECONCILIATION" }}
                </button>
            </section>

            <section class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"POST /books/close/{session_id}"</p>
                <h4 class="text-xs font-semibold text-stone-100">"Close a session"</h4>
                <p class="text-[11px] text-stone-400">
                    "Seals the period for one session. Postings after a close land in the next period."
                </p>
                <label class="flex flex-col gap-1 max-w-sm">
                    <span class="text-[9px] uppercase tracking-wider text-stone-500">"Session id"</span>
                    <input
                        class="fcs-input"
                        placeholder="session-id"
                        prop:value=move || session.get()
                        on:input=move |ev| set_session.set(event_target_value(&ev))
                    />
                </label>
                <button type="button" class="fcs-btn amber" prop:disabled=move || busy.get() on:click=close>"CLOSE SESSION"</button>
            </section>

            {move || {
                let o = out.get();
                (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-96 overflow-auto">{o}</pre> })
            }}
        </div>
    }
}

// ── Shared ───────────────────────────────────────────────────────────────────

#[component]
fn ReadCard(title: String, desc: String, path: String) -> impl IntoView {
    let (out, set_out) = signal(String::new());
    let (busy, set_busy) = signal(false);
    let p = path.clone();

    let load = move |_| {
        let p = p.clone();
        set_busy.set(true);
        spawn_local(async move {
            match api::get_value(&p).await {
                Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_out.set(e.message),
            }
            set_busy.set(false);
        });
    };

    view! {
        <section class="fcs-pad space-y-2">
            <p class="fcs-pad-id">{format!("GET {path}")}</p>
            <h4 class="text-xs font-semibold text-stone-100">{title}</h4>
            <p class="text-[11px] text-stone-400">{desc}</p>
            <button type="button" class="fcs-btn" prop:disabled=move || busy.get() on:click=load>
                {move || if busy.get() { "READING…" } else { "READ" }}
            </button>
            {move || {
                let o = out.get();
                (!o.is_empty()).then(|| view! { <pre class="fcs-pre max-h-72 overflow-auto">{o}</pre> })
            }}
        </section>
    }
}
