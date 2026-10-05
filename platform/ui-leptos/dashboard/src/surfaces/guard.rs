//! `/guard` — Access Control Tower.
//!
//! Operator surface for the kernel's per-address DAC. The kernel enforces two
//! **different** contracts per address:
//!
//! * `address_rules_contract_v1` — capability allow / block
//! * `address_hitl_contract_v1`  — human gate none / ask / root / block
//!
//! `substrate::identity_stack` refuses augmented actions until both exist, so
//! this page is the only way an operator can clear that state without a shell.
//!
//! Backed by:
//!
//! * `GET  /kernel/address-dac`             — index + posture
//! * `GET  /kernel/address-dac/contract`    — one address, both contracts, seals
//! * `PUT  /kernel/address-dac/rules|hitl`  — mint / replace
//! * `POST /kernel/address-dac/simulate`    — dry run (never seals)
//! * `POST /kernel/address-dac/unseal`      — lift a kernel Block (root passcode)
//! * `GET  /kernel/identity-stack`          — which pillar is blocking an agent

use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::api_state::OpLoadingBlock;
use crate::components::operator::primitives::{OpText, OpTextVariant};

fn csv_to_vec(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn vec_to_csv(v: &[Value]) -> String {
    v.iter()
        .filter_map(|x| x.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn verdict_class(verdict: &str) -> &'static str {
    match verdict {
        "allow" => "fcs-verdict go",
        "ask" => "fcs-verdict ask",
        _ => "fcs-verdict block",
    }
}

#[component]
pub fn GuardCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    crate::components::page_title::use_page_title("Access Control Tower");

    let reload = RwSignal::new(0u32);
    let selected = RwSignal::new(String::new());
    let status = RwSignal::new(String::new());

    let index = LocalResource::new(move || {
        let _ = reload.get();
        async move { api::get_value("/kernel/address-dac").await }
    });

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
                        <span class="truncate">"CONNECTOR OS  ·  ACCESS CONTROL TOWER"</span>
                    </div>
                    <div class="fcs-lights">
                        <span class="fcs-light pwr"><span class="dot"></span>"KERNEL"</span>
                        <span class="fcs-light stby"><span class="dot"></span>"DAC"</span>
                    </div>
                </div>

                <div class="fcs-body space-y-5">
                    <div>
                        <OpText text="ACCESS CONTROL".to_string() variant=OpTextVariant::Title />
                        <p class="mt-1 text-sm text-stone-400 leading-relaxed">
                            "Per-address DAC. RULES decide capability; HITL decides the human gate. They are separate contracts — an agent's own charter cannot substitute for either. Block is kernel-final."
                        </p>
                    </div>

                    <Suspense fallback=move || view! { <OpLoadingBlock /> }>
                        {move || Suspend::new(async move {
                            match index.await {
                                Ok(v) => {
                                    let addrs = v.get("addresses")
                                        .and_then(|x| x.as_array())
                                        .cloned()
                                        .unwrap_or_default();
                                    let count = v.get("address_count").and_then(|x| x.as_u64()).map(|n| n.to_string()).unwrap_or_else(|| "—".into());
                                    let incomplete = v.get("incomplete_count").and_then(|x| x.as_u64()).map(|n| n.to_string()).unwrap_or_else(|| "—".into());
                                    let seals = v.get("total_block_seals").and_then(|x| x.as_u64()).map(|n| n.to_string()).unwrap_or_else(|| "—".into());
                                    let enforced = v.get("identity_stack_enforced").and_then(|x| x.as_bool());
                                    view! {
                                        <div class="fcs-telemetry">
                                            <div class="fcs-telem">
                                                <span class="k">"ADDRESSES"</span>
                                                <span class="v">{count}</span>
                                            </div>
                                            <div class="fcs-telem">
                                                <span class="k">"INCOMPLETE"</span>
                                                <span class="v">{incomplete}</span>
                                            </div>
                                            <div class="fcs-telem">
                                                <span class="k">"BLOCK SEALS"</span>
                                                <span class="v">{seals}</span>
                                            </div>
                                            <div class="fcs-telem">
                                                <span class="k">"STACK GATE"</span>
                                                <span class="v">{match enforced { Some(true) => "ENFORCED", Some(false) => "PERMISSIVE", None => "—" }}</span>
                                            </div>
                                        </div>

                                        <section class="space-y-2">
                                            <h3 class="fcs-section-label">"Address registry"</h3>
                                            {if addrs.is_empty() {
                                                view! {
                                                    <p class="fcs-pad text-xs text-stone-400">
                                                        "No address has a contract yet. Every augmented action stays denied until you mint a RULES and a HITL contract below."
                                                    </p>
                                                }.into_any()
                                            } else {
                                                view! {
                                                    <div class="space-y-1.5">
                                                        {addrs.into_iter().map(|a| {
                                                            let addr = a.get("address").and_then(|x| x.as_str()).unwrap_or_default().to_string();
                                                            let pick = addr.clone();
                                                            let has_rules = a.get("has_rules_contract").and_then(|x| x.as_bool()).unwrap_or(false);
                                                            let has_hitl = a.get("has_hitl_contract").and_then(|x| x.as_bool()).unwrap_or(false);
                                                            let nseals = a.get("block_seal_count").and_then(|x| x.as_u64());
                                                            let seal_label = nseals.map(|n| format!("{n} SEAL")).unwrap_or_else(|| "SEAL —".into());
                                                            let seal_class = match nseals {
                                                                Some(0) | None => "fcs-chip",
                                                                Some(_) => "fcs-chip bad",
                                                            };
                                                            view! {
                                                                <button
                                                                    type="button"
                                                                    class="fcs-pad w-full text-left flex items-center gap-3"
                                                                    on:click=move |_| {
                                                                        selected.set(pick.clone());
                                                                        status.set(String::new());
                                                                    }
                                                                >
                                                                    <span class="fcs-pad-id truncate flex-1">{addr}</span>
                                                                    <span class=if has_rules { "fcs-chip go" } else { "fcs-chip bad" }>"RULES"</span>
                                                                    <span class=if has_hitl { "fcs-chip go" } else { "fcs-chip bad" }>"HITL"</span>
                                                                    <span class=seal_class>
                                                                        {seal_label}
                                                                    </span>
                                                                </button>
                                                            }
                                                        }).collect_view()}
                                                    </div>
                                                }.into_any()
                                            }}
                                        </section>
                                    }.into_any()
                                }
                                Err(e) => view! {
                                    <p class="fcs-pad text-xs text-rose-300">
                                        {format!("Could not read the DAC index: {e}. Admin role required.")}
                                    </p>
                                }.into_any(),
                            }
                        })}
                    </Suspense>

                    <AddressEditor selected=selected reload=reload status=status />
                    <IdentityStackInspector />

                    {move || {
                        let s = status.get();
                        (!s.is_empty()).then(|| view! {
                            <p class="fcs-pad text-xs text-emerald-300">{s}</p>
                        })
                    }}
                </div>

                <div class="fcs-statusbar">
                    <span>"RULES ≠ HITL  ·  BLOCK IS KERNEL-FINAL"</span>
                    <span>"ACCESS CONTROL TOWER"</span>
                </div>
            </div>
        </div>
    }
}

#[component]
fn AddressEditor(
    selected: RwSignal<String>,
    reload: RwSignal<u32>,
    status: RwSignal<String>,
) -> impl IntoView {
    let (addr_input, set_addr_input) = signal(String::new());
    let (default_effect, set_default_effect) = signal("block".to_string());
    let (allowed, set_allowed) = signal(String::new());
    let (denied, set_denied) = signal(String::new());
    let (default_policy, set_default_policy) = signal("ask".to_string());
    let (hitl_tools, set_hitl_tools) = signal(String::new());
    let (sim_tools, set_sim_tools) = signal(String::new());
    let (sim_rows, set_sim_rows) = signal::<Vec<Value>>(Vec::new());
    let (unseal_tool, set_unseal_tool) = signal(String::new());
    let (passcode, set_passcode) = signal(String::new());

    // Selecting an address in the registry hydrates the form from its contracts.
    let detail = LocalResource::new(move || {
        let addr = selected.get();
        let _ = reload.get();
        async move {
            if addr.trim().is_empty() {
                return Ok(Value::Null);
            }
            api::get_value_q("/kernel/address-dac/contract", &[("address", addr.as_str())]).await
        }
    });

    Effect::new(move |_| {
        let a = selected.get();
        if !a.is_empty() {
            set_addr_input.set(a);
        }
    });

    // Hydrate RULES/HITL editors from the selected contract (prevents empty SAVE wipe).
    Effect::new(move |_| {
        let _ = selected.get();
        let _ = reload.get();
        spawn_local(async move {
            let addr = selected.get_untracked();
            if addr.trim().is_empty() {
                return;
            }
            let Ok(v) = api::get_value_q(
                "/kernel/address-dac/contract",
                &[("address", addr.as_str())],
            )
            .await
            else {
                return;
            };
            let summary = v.get("summary").cloned().unwrap_or(Value::Null);
            if summary.is_null() {
                return;
            }
            if let Some(de) = summary.get("default_effect").and_then(|x| x.as_str()) {
                set_default_effect.set(de.to_string());
            }
            if let Some(dp) = summary.get("default_policy").and_then(|x| x.as_str()) {
                set_default_policy.set(dp.to_string());
            }
            if let Some(a) = summary.get("allowed_tools").and_then(|x| x.as_array()) {
                set_allowed.set(vec_to_csv(a));
            }
            if let Some(d) = summary.get("denied_tools").and_then(|x| x.as_array()) {
                set_denied.set(vec_to_csv(d));
            }
            // Per-tool HITL policies from full contract when present.
            if let Some(tools) = v
                .pointer("/hitl_contract/tools")
                .or_else(|| v.pointer("/contracts/hitl/tools"))
                .and_then(|x| x.as_array())
            {
                let pairs: Vec<String> = tools
                    .iter()
                    .filter_map(|t| {
                        let id = t.get("id").and_then(|x| x.as_str())?;
                        let pol = t.get("policy").and_then(|x| x.as_str())?;
                        Some(format!("{id}={pol}"))
                    })
                    .collect();
                if !pairs.is_empty() {
                    set_hitl_tools.set(pairs.join(", "));
                }
            }
            status.set(format!("Hydrated editors from contract for {addr}"));
        });
    });

    let effective_address = move || {
        let typed = addr_input.get();
        if typed.trim().is_empty() {
            selected.get()
        } else {
            typed.trim().to_string()
        }
    };

    let save_rules = move |_| {
        let address = effective_address();
        if address.is_empty() {
            status.set("Enter an address first.".into());
            return;
        }
        if !web_sys::window()
            .and_then(|w| {
                w.confirm_with_message(&format!(
                    "Replace RULES contract for {address}? Empty fields overwrite live allow/deny lists."
                ))
                .ok()
            })
            .unwrap_or(false)
        {
            return;
        }
        let body = json!({
            "address": address,
            "default_effect": default_effect.get(),
            "allowed_tools": csv_to_vec(&allowed.get()),
            "denied_tools": csv_to_vec(&denied.get()),
        });
        spawn_local(async move {
            match api::put_value("/kernel/address-dac/rules", body).await {
                Ok(v) => {
                    if let Some(e) = api::body_error(&v) {
                        status.set(format!("Save failed: {e}"));
                    } else {
                        status.set("RULES contract saved. Existing Block seals are not lifted by this.".into());
                        reload.update(|n| *n += 1);
                    }
                }
                Err(e) => status.set(format!("Save failed: {e}")),
            }
        });
    };

    let save_hitl = move |_| {
        let address = effective_address();
        if address.is_empty() {
            status.set("Enter an address first.".into());
            return;
        }
        if !web_sys::window()
            .and_then(|w| {
                w.confirm_with_message(&format!(
                    "Replace HITL contract for {address}?"
                ))
                .ok()
            })
            .unwrap_or(false)
        {
            return;
        }
        // `tool=policy` pairs, comma separated.
        let tools: Vec<Value> = csv_to_vec(&hitl_tools.get())
            .into_iter()
            .filter_map(|pair| {
                let (id, policy) = pair.split_once('=')?;
                Some(json!({"id": id.trim(), "policy": policy.trim()}))
            })
            .collect();
        let body = json!({
            "address": address,
            "default_policy": default_policy.get(),
            "tools": tools,
        });
        spawn_local(async move {
            match api::put_value("/kernel/address-dac/hitl", body).await {
                Ok(v) => {
                    if let Some(e) = api::body_error(&v) {
                        status.set(format!("Save failed: {e}"));
                    } else {
                        status.set("HITL contract saved. HITL can never lift a kernel Block.".into());
                        reload.update(|n| *n += 1);
                    }
                }
                Err(e) => status.set(format!("Save failed: {e}")),
            }
        });
    };

    let simulate = move |_| {
        let address = effective_address();
        let body = json!({"address": address, "tools": csv_to_vec(&sim_tools.get())});
        spawn_local(async move {
            match api::post_value("/kernel/address-dac/simulate", body).await {
                Ok(v) => {
                    let rows = v
                        .get("results")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default();
                    set_sim_rows.set(rows);
                    status.set("Dry run complete — no seal was written.".into());
                }
                Err(e) => status.set(format!("Simulate failed: {e}")),
            }
        });
    };

    let unseal = move |_| {
        let address = effective_address();
        if !web_sys::window()
            .and_then(|w| {
                w.confirm_with_message(&format!(
                    "Unseal Block for {address}? Requires root passcode."
                ))
                .ok()
            })
            .unwrap_or(false)
        {
            return;
        }
        let body = json!({
            "address": address,
            "tool": unseal_tool.get(),
            "root_passcode": passcode.get(),
        });
        spawn_local(async move {
            match api::post_value("/kernel/address-dac/unseal", body).await {
                Ok(v) => {
                    if v.get("unsealed").and_then(|x| x.as_bool()) == Some(true) {
                        status.set("Seal lifted. The RULES contract decides the next call.".into());
                        reload.update(|n| *n += 1);
                    } else {
                        let msg = v
                            .get("error")
                            .and_then(|x| x.as_str())
                            .unwrap_or("unseal rejected");
                        status.set(format!("Unseal rejected: {msg}"));
                    }
                    set_passcode.set(String::new());
                }
                Err(e) => status.set(format!("Unseal failed: {e}")),
            }
        });
    };

    view! {
        <section class="space-y-3">
            <h3 class="fcs-section-label">"Contract bench"</h3>

            <div class="fcs-pad space-y-2">
                <label class="flex flex-col gap-1">
                    <span class="fcs-pad-id">"ADDRESS"</span>
                    <input
                        class="fcs-input"
                        placeholder="tool:github.create_issue · llm:default · memory:default"
                        prop:value=move || addr_input.get()
                        on:input=move |ev| set_addr_input.set(event_target_value(&ev))
                    />
                </label>
                <Suspense fallback=|| ()>
                    {move || Suspend::new(async move {
                        let v = detail.await.ok().unwrap_or(Value::Null);
                        let summary = v.get("summary").cloned().unwrap_or(Value::Null);
                        let seals = v.get("block_seals").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        if summary.is_null() {
                            return view! { <span></span> }.into_any();
                        }
                        let has_rules = summary.get("has_rules_contract").and_then(|x| x.as_bool()).unwrap_or(false);
                        let has_hitl = summary.get("has_hitl_contract").and_then(|x| x.as_bool()).unwrap_or(false);
                        let de = summary.get("default_effect").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let dp = summary.get("default_policy").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let allow_csv = summary.get("allowed_tools").and_then(|x| x.as_array()).map(|a| vec_to_csv(a)).unwrap_or_default();
                        let deny_csv = summary.get("denied_tools").and_then(|x| x.as_array()).map(|a| vec_to_csv(a)).unwrap_or_default();
                        view! {
                            <div class="grid grid-cols-2 gap-2 text-[11px] text-stone-400">
                                <p>"RULES: "<span class=if has_rules {"text-emerald-300"} else {"text-rose-300"}>{if has_rules {"present"} else {"MISSING"}}</span>" · default "{de}</p>
                                <p>"HITL: "<span class=if has_hitl {"text-emerald-300"} else {"text-rose-300"}>{if has_hitl {"present"} else {"MISSING"}}</span>" · default "{dp}</p>
                                <p class="col-span-2 truncate">"allow: "{allow_csv}</p>
                                <p class="col-span-2 truncate">"deny: "{deny_csv}</p>
                                <p class="col-span-2">"active seals: "{if v.get("block_seals").and_then(|x| x.as_array()).is_some() { seals.len().to_string() } else { "—".into() }}</p>
                            </div>
                        }.into_any()
                    })}
                </Suspense>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div class="fcs-pad space-y-2">
                    <p class="fcs-pad-id">"RULES CONTRACT  ·  CAPABILITY"</p>
                    <label class="flex flex-col gap-1">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Default effect"</span>
                        <select
                            class="fcs-input"
                            on:change=move |ev| set_default_effect.set(event_target_value(&ev))
                        >
                            <option value="block" selected=move || default_effect.get() == "block">"block (deny by default)"</option>
                            <option value="allow" selected=move || default_effect.get() == "allow">"allow"</option>
                        </select>
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Allowed tools (comma separated)"</span>
                        <input
                            class="fcs-input"
                            placeholder="t1, t2, t3"
                            prop:value=move || allowed.get()
                            on:input=move |ev| set_allowed.set(event_target_value(&ev))
                        />
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Denied tools"</span>
                        <input
                            class="fcs-input"
                            placeholder="t9"
                            prop:value=move || denied.get()
                            on:input=move |ev| set_denied.set(event_target_value(&ev))
                        />
                    </label>
                    <button type="button" class="fcs-btn go" on:click=save_rules>"SAVE RULES"</button>
                    <p class="text-[10px] text-stone-500">"Never put 'ask' here — a human gate belongs on the HITL contract."</p>
                </div>

                <div class="fcs-pad space-y-2">
                    <p class="fcs-pad-id">"HITL CONTRACT  ·  HUMAN GATE"</p>
                    <label class="flex flex-col gap-1">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Default policy"</span>
                        <select
                            class="fcs-input"
                            on:change=move |ev| set_default_policy.set(event_target_value(&ev))
                        >
                            <option value="ask" selected=move || default_policy.get() == "ask">"ask"</option>
                            <option value="none" selected=move || default_policy.get() == "none">"none"</option>
                            <option value="root" selected=move || default_policy.get() == "root">"root (human is root)"</option>
                            <option value="block" selected=move || default_policy.get() == "block">"block"</option>
                        </select>
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Per-tool policy (tool=policy, comma separated)"</span>
                        <input
                            class="fcs-input"
                            placeholder="t1=ask, t2=none, t3=ask"
                            prop:value=move || hitl_tools.get()
                            on:input=move |ev| set_hitl_tools.set(event_target_value(&ev))
                        />
                    </label>
                    <button type="button" class="fcs-btn go" on:click=save_hitl>"SAVE HITL"</button>
                    <p class="text-[10px] text-stone-500">"HITL only gates a tool the RULES already allow. It can never lift a Block."</p>
                </div>
            </div>

            <div class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"DRY RUN  ·  NO SEAL WRITTEN"</p>
                <div class="flex flex-wrap gap-2 items-end">
                    <label class="flex flex-col gap-1 flex-1 min-w-[16rem]">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Tools to evaluate"</span>
                        <input
                            class="fcs-input"
                            placeholder="t1, t2, t3"
                            prop:value=move || sim_tools.get()
                            on:input=move |ev| set_sim_tools.set(event_target_value(&ev))
                        />
                    </label>
                    <button type="button" class="fcs-btn" on:click=simulate>"SIMULATE"</button>
                </div>
                {move || {
                    let rows = sim_rows.get();
                    (!rows.is_empty()).then(|| view! {
                        <div class="space-y-1">
                            {rows.into_iter().map(|r| {
                                let tool = r.get("canonical_tool").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                let verdict = r.get("verdict").and_then(|x| x.as_str()).unwrap_or("block").to_string();
                                let reason = r.get("reason").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                let seal = r.get("would_seal").and_then(|x| x.as_bool()).unwrap_or(false);
                                view! {
                                    <div class="flex items-center gap-2 text-[11px]">
                                        <span class=verdict_class(&verdict)>{verdict.to_uppercase()}</span>
                                        <span class="text-stone-200 font-medium">{tool}</span>
                                        <span class="text-stone-500 truncate">{reason}</span>
                                        {seal.then(|| view! { <span class="fcs-chip bad">"WOULD SEAL"</span> })}
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                    })
                }}
            </div>

            <div class="fcs-pad space-y-2">
                <p class="fcs-pad-id">"UNSEAL  ·  KERNEL ROOT ONLY"</p>
                <div class="flex flex-wrap gap-2 items-end">
                    <label class="flex flex-col gap-1 flex-1 min-w-[10rem]">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Tool"</span>
                        <input
                            class="fcs-input"
                            prop:value=move || unseal_tool.get()
                            on:input=move |ev| set_unseal_tool.set(event_target_value(&ev))
                        />
                    </label>
                    <label class="flex flex-col gap-1 flex-1 min-w-[10rem]">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Kernel root passcode"</span>
                        <input
                            type="password"
                            class="fcs-input"
                            prop:value=move || passcode.get()
                            on:input=move |ev| set_passcode.set(event_target_value(&ev))
                        />
                    </label>
                    <button type="button" class="fcs-btn amber" on:click=unseal>"UNSEAL"</button>
                </div>
                <p class="text-[10px] text-stone-500">
                    "Block is kernel-final. No LLM and no HITL approval can lift it — only this passcode, and the RULES contract still decides the next call."
                </p>
            </div>
        </section>
    }
}

#[component]
fn IdentityStackInspector() -> impl IntoView {
    let (pid, set_pid) = signal(String::new());
    let (query, set_query) = signal(String::new());
    let (op, set_op) = signal("llm.chat".to_string());

    let stack = LocalResource::new(move || {
        let p = query.get();
        let o = op.get();
        async move {
            if p.trim().is_empty() {
                return Ok(Value::Null);
            }
            api::get_value_q(
                "/kernel/identity-stack",
                &[("agent_pid", p.as_str()), ("op", o.as_str())],
            )
            .await
        }
    });

    view! {
        <section class="space-y-3">
            <h3 class="fcs-section-label">"Identity stack  ·  preflight"</h3>
            <div class="fcs-pad space-y-2">
                <div class="flex flex-wrap gap-2 items-end">
                    <label class="flex flex-col gap-1 flex-1 min-w-[12rem]">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Agent pid"</span>
                        <input
                            class="fcs-input"
                            prop:value=move || pid.get()
                            on:input=move |ev| set_pid.set(event_target_value(&ev))
                        />
                    </label>
                    <label class="flex flex-col gap-1">
                        <span class="text-[10px] uppercase tracking-wider text-stone-500">"Operation"</span>
                        <select class="fcs-input" on:change=move |ev| set_op.set(event_target_value(&ev))>
                            <option value="llm.chat">"llm.chat"</option>
                            <option value="memory.write">"memory.write"</option>
                        </select>
                    </label>
                    <button
                        type="button"
                        class="fcs-btn"
                        on:click=move |_| set_query.set(pid.get())
                    >
                        "RUN PREFLIGHT"
                    </button>
                </div>

                <Suspense fallback=|| ()>
                    {move || Suspend::new(async move {
                        let v = stack.await.ok().unwrap_or(Value::Null);
                        if v.is_null() {
                            return view! {
                                <p class="text-[11px] text-stone-500">
                                    "Enter an agent pid to see which pillar is denying it."
                                </p>
                            }.into_any();
                        }
                        let pillars = v.get("pillars").and_then(|x| x.as_array()).cloned().unwrap_or_default();
                        let address = v.get("address").and_then(|x| x.as_str()).unwrap_or("—").to_string();
                        let operable = v.get("operable").and_then(|x| x.as_bool()).unwrap_or(false);
                        let quarantined = v.pointer("/control/quarantined").and_then(|x| x.as_bool()).unwrap_or(false);
                        view! {
                            <div class="space-y-2">
                                <p class="text-[11px] text-stone-400">
                                    "address "<span class="text-amber-300">{address}</span>
                                    " · "
                                    <span class=if operable {"text-emerald-300"} else {"text-rose-300"}>
                                        {if operable { "CLEARED" } else { "DENIED" }}
                                    </span>
                                    {quarantined.then(|| view! { <span class="fcs-chip bad ml-2">"QUARANTINED"</span> })}
                                </p>
                                <div class="fcs-checklist">
                                    {pillars.into_iter().map(|p| {
                                        let label = p.get("label").and_then(|x| x.as_str()).unwrap_or("?").to_string();
                                        let ok = p.get("satisfied").and_then(|x| x.as_bool()).unwrap_or(false);
                                        let fix = p.get("fix").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        view! {
                                            <div class=if ok { "fcs-check go" } else { "fcs-check" } title=fix>
                                                <span class="box"></span>{label}
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_any()
                    })}
                </Suspense>
            </div>
        </section>
    }
}
