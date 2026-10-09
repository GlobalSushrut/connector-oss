use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Pilots(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh) = create_signal(0u32);
    let (flash, set_flash) = create_signal(Option::<(String, bool)>::None);
    let (show_create, set_show_create) = create_signal(false);
    let (cust_inp, set_cust_inp) = create_signal(String::new());
    let (seats_inp, set_seats_inp) = create_signal("1".to_string());
    let (days_inp, set_days_inp) = create_signal("30".to_string());
    let (note_inp, set_note_inp) = create_signal(String::new());

    let pilots = LocalResource::new(move || { let _ = refresh.get(); api::get_value("/admin/pilots") });

    let do_create = move |_| {
        let customer_id = cust_inp.get();
        if customer_id.is_empty() { set_flash.set(Some(("Customer ID required".into(), false))); return; }
        let seats = seats_inp.get().parse::<u32>().unwrap_or(1);
        let days  = days_inp.get().parse::<u64>().unwrap_or(30);
        let note  = note_inp.get();
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value("/admin/pilots", serde_json::json!({
                "customer_id": customer_id, "seats": seats, "duration_days": days, "note": note
            })).await {
                Ok(v) => {
                    let gid = v["grant_id"].as_str().unwrap_or("?");
                    set_flash.set(Some((format!("Pilot grant created: {gid}"), true)));
                    set_show_create.set(false);
                    set_refresh.update(|v| *v += 1);
                }
                Err(e) => set_flash.set(Some((e.message, false))),
            }
        });
    };

    let do_revoke = move |grant_id: String| {
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value(&format!("/admin/pilots/{grant_id}/revoke"), serde_json::json!({})).await {
                Ok(_)  => { set_flash.set(Some(("Grant revoked".into(), true))); set_refresh.update(|v| *v += 1); }
                Err(e) => set_flash.set(Some((e.message, false))),
            }
        });
    };

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Sales pipeline"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Pilot Grants"</h1>
                    <p class="text-sm text-zinc-500">"Time-limited pilot access grants for prospects. Create, track, and revoke on demand."</p>
                </div>
                <button on:click=move |_| set_show_create.update(|v| *v = !*v)
                    class="rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-2 text-sm font-medium text-red-300 hover:bg-red-500/20 transition-colors">
                    {move || if show_create.get() { "Cancel" } else { "New pilot grant" }}
                </button>
            </div>

            {move || flash.get().map(|(msg, ok)| view! {
                <div class=if ok { "rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300" }
                          else  { "rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300" }>
                    {msg}
                </div>
            })}

            {move || show_create.get().then(|| view! {
                <div class="card space-y-4">
                    <h2 class="text-sm font-semibold text-zinc-200">"Create pilot grant"</h2>
                    <div class="grid gap-3 sm:grid-cols-2">
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Customer ID"</label>
                            <input type="text" prop:value=move || cust_inp.get()
                                on:input=move |e| set_cust_inp.set(event_target_value(&e))
                                placeholder="cust_..."
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500" />
                        </div>
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Seats"</label>
                            <input type="number" prop:value=move || seats_inp.get()
                                on:input=move |e| set_seats_inp.set(event_target_value(&e))
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500" />
                        </div>
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Duration (days)"</label>
                            <input type="number" prop:value=move || days_inp.get()
                                on:input=move |e| set_days_inp.set(event_target_value(&e))
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500" />
                        </div>
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Internal note"</label>
                            <input type="text" prop:value=move || note_inp.get()
                                on:input=move |e| set_note_inp.set(event_target_value(&e))
                                placeholder="e.g. Acme Corp POC — 2 devs"
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500" />
                        </div>
                    </div>
                    <button on:click=do_create
                        class="rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-5 py-2 text-sm font-medium text-emerald-300 hover:bg-emerald-500/20 transition-colors">
                        "Create grant"
                    </button>
                </div>
            })}

            <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = pilots.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let rows = v["grants"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <div class="mb-4">
                                <h2 class="text-lg font-semibold text-zinc-50">"Active grants"</h2>
                                <p class="mt-1 text-sm text-zinc-500">{format!("{} grants", rows.len())}</p>
                            </div>
                            {if rows.is_empty() {
                                view!{ <p class="text-sm text-zinc-600 py-8 text-center">"No pilot grants issued yet."</p> }.into_any()
                            } else {
                                view! {
                                    <table class="min-w-full text-sm">
                                        <thead>
                                            <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                                <th class="px-3 py-3">"Grant ID"</th>
                                                <th class="px-3 py-3">"Customer"</th>
                                                <th class="px-3 py-3">"Seats"</th>
                                                <th class="px-3 py-3">"Expires"</th>
                                                <th class="px-3 py-3">"Status"</th>
                                                <th class="px-3 py-3">"Note"</th>
                                                <th class="px-3 py-3">"Action"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {rows.into_iter().map(|row| {
                                                let gid      = row["grant_id"].as_str().unwrap_or("-").to_string();
                                                let cust     = row["customer_id"].as_str().unwrap_or("—").to_string();
                                                let seats    = row["seats"].as_u64().unwrap_or(0);
                                                let expires  = row["expires_at"].as_str().unwrap_or("—").to_string();
                                                let active   = row["active"].as_bool().unwrap_or(false);
                                                let note     = row["note"].as_str().unwrap_or("").to_string();
                                                let revoke_id = gid.clone();
                                                view! {
                                                    <tr class="border-b border-zinc-900/80 align-top text-zinc-300">
                                                        <td class="px-3 py-4 text-xs font-mono text-zinc-500">{gid}</td>
                                                        <td class="px-3 py-4 text-zinc-200">{cust}</td>
                                                        <td class="px-3 py-4 text-zinc-400">{seats}</td>
                                                        <td class="px-3 py-4 text-xs text-zinc-500">{expires}</td>
                                                        <td class="px-3 py-4">
                                                            <span class=if active { "inline-flex rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300" } else { "inline-flex rounded-full bg-zinc-700 px-2 py-0.5 text-xs font-medium text-zinc-400" }>
                                                                {if active { "Active" } else { "Expired/Revoked" }}
                                                            </span>
                                                        </td>
                                                        <td class="px-3 py-4 text-xs text-zinc-500">{note}</td>
                                                        <td class="px-3 py-4">
                                                            {if active { view!{
                                                                <button on:click=move |_| do_revoke(revoke_id.clone())
                                                                    class="rounded border border-red-500/20 bg-red-500/10 px-2 py-1 text-xs text-red-300 hover:bg-red-500/20 transition-colors">
                                                                    "Revoke"
                                                                </button>
                                                            }.into_any() } else { view!{ <span class="text-xs text-zinc-600">"—"</span> }.into_any() }}
                                                        </td>
                                                    </tr>
                                                }.into_any()
                                            }).collect::<Vec<_>>()}
                                        </tbody>
                                    </table>
                                }.into_any()
                            }}
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}
