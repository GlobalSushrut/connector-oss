use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

// ── Signups / Beta Approvals ──────────────────────────────────────────────────
// Lists all registered users. Admin can approve (issues cpk_pilot_* key + email)
// or reject (locks + sends rejection email) directly from this panel.

#[component]
pub fn Signups(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh)     = create_signal(0u32);
    let (flash, set_flash)         = create_signal(Option::<(String, bool)>::None);
    let (filter, set_filter)       = create_signal("all".to_string());
    // Per-row approve form state (seats + days per user_id)
    let (seats_map, set_seats_map) = create_signal(std::collections::HashMap::<String, String>::new());
    let (days_map, set_days_map)   = create_signal(std::collections::HashMap::<String, String>::new());
    let (reject_map, set_reject_map) = create_signal(std::collections::HashMap::<String, String>::new());

    let data = LocalResource::new(move || {
        let _ = refresh.get();
        api::get_value("/admin/signups")
    });

    let do_approve = move |user_id: String| {
        let seats: u32 = seats_map.get().get(&user_id).and_then(|s| s.parse().ok()).unwrap_or(1);
        let days: u64  = days_map.get().get(&user_id).and_then(|s| s.parse().ok()).unwrap_or(90);
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value(
                &format!("/admin/signups/{}/approve", user_id),
                serde_json::json!({ "seats": seats, "duration_days": days }),
            ).await {
                Ok(v)  => {
                    let prefix = v["pilot_key_prefix"].as_str().unwrap_or("—");
                    set_flash.set(Some((format!("✓ Approved — key prefix: {}…", prefix), true)));
                    set_refresh.update(|n| *n += 1);
                }
                Err(e) => set_flash.set(Some((e.message, false))),
            }
        });
    };

    let do_reject = move |user_id: String| {
        let reason = reject_map.get().get(&user_id).cloned().unwrap_or_default();
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value(
                &format!("/admin/signups/{}/reject", user_id),
                serde_json::json!({ "reason": reason }),
            ).await {
                Ok(_)  => {
                    set_flash.set(Some(("Rejected — rejection email sent.".into(), true)));
                    set_refresh.update(|n| *n += 1);
                }
                Err(e) => set_flash.set(Some((e.message, false))),
            }
        });
    };

    view! {
        <div class="p-6 space-y-6">

            // ── Header ──────────────────────────────────────────────────────
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-emerald-400">"Beta access control"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Signups"</h1>
                    <p class="text-sm text-zinc-500">"Review every beta application. Approve to issue a pilot key and notify the user. Reject to block and notify."</p>
                </div>
                <div class="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-3 text-xs text-zinc-500">
                    "Admin: " {move || auth.get().key_hint}
                </div>
            </div>

            // ── Flash ────────────────────────────────────────────────────────
            {move || flash.get().map(|(msg, ok)| {
                let cls = if ok {
                    "rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-2.5 text-sm text-emerald-300"
                } else {
                    "rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-2.5 text-sm text-red-300"
                };
                view! { <div class=cls>{msg}</div> }
            })}

            // ── Filter bar ───────────────────────────────────────────────────
            <div class="flex gap-2">
                {["all", "pending", "approved"].into_iter().map(|f| {
                    let f = f.to_string();
                    let fc = f.clone();
                    view! {
                        <button
                            on:click=move |_| set_filter.set(fc.clone())
                            class=move || if filter.get() == f {
                                "rounded-lg bg-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-50"
                            } else {
                                "rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-400 hover:text-zinc-200"
                            }
                        >{f.clone()}</button>
                    }
                }).collect::<Vec<_>>()}
            </div>

            // ── Table ─────────────────────────────────────────────────────────
            <Suspense fallback=|| view! { <div class="h-64 rounded-xl border border-zinc-800 bg-zinc-900 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let val = data.await;
                    let v   = val.as_ref().ok().unwrap_or(&Value::Null);
                    let all  = v["users"].as_array().cloned().unwrap_or_default();
                    let flt  = filter.get();
                    let rows: Vec<_> = all.iter().filter(|u| {
                        flt == "all" || u["status"].as_str().unwrap_or("") == flt
                    }).cloned().collect();

                    let total   = v["total"].as_u64().unwrap_or(0);
                    let pending = v["pending"].as_u64().unwrap_or(0);
                    let approved= v["approved"].as_u64().unwrap_or(0);

                    view! {
                        <div class="space-y-4">
                            // KPI bar
                            <div class="grid grid-cols-3 gap-4">
                                <div class="rounded-xl border border-zinc-800 bg-zinc-900 p-4 text-center">
                                    <p class="text-2xl font-bold text-zinc-50">{total}</p>
                                    <p class="text-xs text-zinc-500 mt-1">"Total signups"</p>
                                </div>
                                <div class="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 text-center">
                                    <p class="text-2xl font-bold text-amber-300">{pending}</p>
                                    <p class="text-xs text-zinc-500 mt-1">"Pending review"</p>
                                </div>
                                <div class="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-center">
                                    <p class="text-2xl font-bold text-emerald-300">{approved}</p>
                                    <p class="text-xs text-zinc-500 mt-1">"Approved pilots"</p>
                                </div>
                            </div>

                            // User cards
                            {if rows.is_empty() {
                                view! {
                                    <div class="rounded-xl border border-zinc-800 bg-zinc-900 p-12 text-center">
                                        <p class="text-sm text-zinc-500">"No signups match this filter."</p>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="space-y-3">
                                        {rows.into_iter().map(|u| {
                                            let uid     = u["user_id"].as_str().unwrap_or("").to_string();
                                            let email   = u["email"].as_str().unwrap_or("—").to_string();
                                            let name    = u["name"].as_str().unwrap_or("—").to_string();
                                            let status  = u["status"].as_str().unwrap_or("?").to_string();
                                            let role    = u["role"].as_str().unwrap_or("?").to_string();
                                            let tier    = u["tier"].as_str().unwrap_or("?").to_string();
                                            let created = u["created_at"].as_str().unwrap_or("?").to_string();
                                            let nkeys   = u["api_key_count"].as_u64().unwrap_or(0);
                                            let is_pending = status == "pending";

                                            // Use StoredValue so closures can clone freely
                                            let uid_sv = StoredValue::new(uid.clone());

                                            let (show_approve, set_show_approve) = create_signal(false);
                                            let (show_reject, set_show_reject)   = create_signal(false);

                                            view! {
                                                <div class="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
                                                    <div class="flex flex-wrap items-start justify-between gap-4">
                                                        // Left: user info
                                                        <div class="space-y-1 min-w-0">
                                                            <div class="flex items-center gap-2 flex-wrap">
                                                                <span class="text-sm font-semibold text-zinc-100">{name}</span>
                                                                <span class="text-sm text-zinc-400">{email}</span>
                                                                <span class=if is_pending {
                                                                    "rounded-full bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 text-[11px] font-semibold text-amber-300"
                                                                } else {
                                                                    "rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 text-[11px] font-semibold text-emerald-300"
                                                                }>{status}</span>
                                                            </div>
                                                            <div class="flex gap-3 text-xs text-zinc-500 flex-wrap">
                                                                <span>"role: "{role}</span>
                                                                <span>"tier: "{tier}</span>
                                                                <span>"keys: "{nkeys}</span>
                                                                <span>"joined: "{created.chars().take(10).collect::<String>()}</span>
                                                            </div>
                                                            <p class="text-[11px] font-mono text-zinc-600">{uid}</p>
                                                        </div>

                                                        // Right: actions (only for pending)
                                                        {if is_pending {
                                                            view! {
                                                                <div class="flex items-center gap-2 shrink-0">
                                                                    <button on:click=move |_| { set_show_approve.update(|v| *v = !*v); set_show_reject.set(false); }
                                                                        class="rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 transition-colors">
                                                                        "Approve"
                                                                    </button>
                                                                    <button on:click=move |_| { set_show_reject.update(|v| *v = !*v); set_show_approve.set(false); }
                                                                        class="rounded-lg bg-red-500/10 border border-red-500/20 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-500/20 transition-colors">
                                                                        "Reject"
                                                                    </button>
                                                                </div>
                                                            }.into_any()
                                                        } else {
                                                            view! { <span class="text-xs text-zinc-600">"Active"</span> }.into_any()
                                                        }}
                                                    </div>

                                                    // Approve form (inline)
                                                    {move || if show_approve.get() {
                                                        let uid_a = uid_sv.get_value();
                                                        let uid_a2 = uid_sv.get_value();
                                                        let uid_a3 = uid_sv.get_value();
                                                        let uid_a4 = uid_sv.get_value();
                                                        let uid_a5 = uid_sv.get_value();
                                                        view! {
                                                            <div class="mt-4 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-4 space-y-3">
                                                                <p class="text-xs font-semibold text-emerald-300">"Issue pilot key"</p>
                                                                <div class="flex flex-wrap gap-3">
                                                                    <div>
                                                                        <label class="block text-xs text-zinc-500 mb-1">"Seats"</label>
                                                                        <input type="number" min="1" max="50"
                                                                            class="rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1 text-sm text-zinc-100 w-20"
                                                                            prop:value=move || seats_map.get().get(&uid_a).cloned().unwrap_or("1".to_string())
                                                                            on:input=move |ev| {
                                                                                let mut m = seats_map.get();
                                                                                m.insert(uid_a2.clone(), event_target_value(&ev));
                                                                                set_seats_map.set(m);
                                                                            }
                                                                        />
                                                                    </div>
                                                                    <div>
                                                                        <label class="block text-xs text-zinc-500 mb-1">"Duration (days)"</label>
                                                                        <input type="number" min="7" max="365"
                                                                            class="rounded-lg border border-zinc-700 bg-zinc-800 px-2 py-1 text-sm text-zinc-100 w-24"
                                                                            prop:value=move || days_map.get().get(&uid_a3).cloned().unwrap_or("90".to_string())
                                                                            on:input=move |ev| {
                                                                                let mut m = days_map.get();
                                                                                m.insert(uid_a4.clone(), event_target_value(&ev));
                                                                                set_days_map.set(m);
                                                                            }
                                                                        />
                                                                    </div>
                                                                </div>
                                                                <button
                                                                    on:click=move |_| do_approve(uid_a5.clone())
                                                                    class="rounded-lg bg-emerald-500 px-4 py-1.5 text-xs font-semibold text-zinc-950 hover:bg-emerald-400 transition-colors">
                                                                    "Confirm approve + send email"
                                                                </button>
                                                            </div>
                                                        }.into_any()
                                                    } else { view!{ <span /> }.into_any() }}

                                                    // Reject form (inline)
                                                    {move || if show_reject.get() {
                                                        let uid_r  = uid_sv.get_value();
                                                        let uid_r2 = uid_sv.get_value();
                                                        let uid_r3 = uid_sv.get_value();
                                                        view! {
                                                            <div class="mt-4 rounded-lg border border-red-500/20 bg-red-500/5 p-4 space-y-3">
                                                                <p class="text-xs font-semibold text-red-300">"Reject application"</p>
                                                                <div>
                                                                    <label class="block text-xs text-zinc-500 mb-1">"Reason (sent to user — leave blank for default)"</label>
                                                                    <input type="text"
                                                                        class="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-sm text-zinc-100"
                                                                        placeholder="Optional — will appear in email"
                                                                        prop:value=move || reject_map.get().get(&uid_r).cloned().unwrap_or_default()
                                                                        on:input=move |ev| {
                                                                            let mut m = reject_map.get();
                                                                            m.insert(uid_r2.clone(), event_target_value(&ev));
                                                                            set_reject_map.set(m);
                                                                        }
                                                                    />
                                                                </div>
                                                                <button
                                                                    on:click=move |_| do_reject(uid_r3.clone())
                                                                    class="rounded-lg bg-red-500/80 px-4 py-1.5 text-xs font-semibold text-zinc-50 hover:bg-red-500 transition-colors">
                                                                    "Confirm reject + send email"
                                                                </button>
                                                            </div>
                                                        }.into_any()
                                                    } else { view!{ <span /> }.into_any() }}
                                                </div>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </div>
                                }.into_any()
                            }}
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}
