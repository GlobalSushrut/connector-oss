use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Keys(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh) = create_signal(0u32);
    let (flash, set_flash) = create_signal(Option::<(String, bool)>::None);
    let (show_issue, set_show_issue) = create_signal(false);
    let (email_inp, set_email_inp) = create_signal(String::new());
    let (name_inp, set_name_inp)   = create_signal(String::new());
    let (tier_inp, set_tier_inp)   = create_signal("community".to_string());
    let (max_act, set_max_act)     = create_signal("3".to_string());

    let keys = LocalResource::new(move || { let _ = refresh.get(); api::get_value("/keys") });

    let do_revoke = move |key_id: String| {
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value(&format!("/keys/revoke"), serde_json::json!({"key_id": key_id})).await {
                Ok(_)  => { set_flash.set(Some(("Key revoked".into(), true))); set_refresh.update(|v| *v += 1); }
                Err(e) => { set_flash.set(Some((e.message, false))); }
            }
        });
    };

    let do_issue = move |_| {
        let email = email_inp.get();
        let name  = name_inp.get();
        let tier  = tier_inp.get();
        let max   = max_act.get().parse::<u32>().unwrap_or(3);
        if email.is_empty() { set_flash.set(Some(("Email required".into(), false))); return; }
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value("/keys/issue", serde_json::json!({
                "customer_email": email, "customer_name": name,
                "tier": tier, "max_activations": max
            })).await {
                Ok(v) => {
                    let kid = v["key_id"].as_str().unwrap_or("?");
                    let secret = v["key_secret"].as_str().unwrap_or("?");
                    set_flash.set(Some((format!("Issued {kid} — secret: {secret}"), true)));
                    set_show_issue.set(false);
                    set_refresh.update(|v| *v += 1);
                }
                Err(e) => { set_flash.set(Some((e.message, false))); }
            }
        });
    };

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"License management"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"License Keys"</h1>
                    <p class="text-sm text-zinc-500">"Issue, inspect, and revoke license keys for all tiers."</p>
                </div>
                <button on:click=move |_| set_show_issue.update(|v| *v = !*v)
                    class="rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-2 text-sm font-medium text-red-300 hover:bg-red-500/20 transition-colors">
                    {move || if show_issue.get() { "Cancel" } else { "Issue new key" }}
                </button>
            </div>

            {move || flash.get().map(|(msg, ok)| view! {
                <div class=if ok { "rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300 font-mono break-all" }
                          else  { "rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300" }>
                    {msg}
                </div>
            })}

            {move || show_issue.get().then(|| view! {
                <div class="card space-y-4">
                    <h2 class="text-sm font-semibold text-zinc-200">"Issue new license key"</h2>
                    <div class="grid gap-3 sm:grid-cols-2">
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Customer email"</label>
                            <input type="email" prop:value=move || email_inp.get()
                                on:input=move |e| set_email_inp.set(event_target_value(&e))
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500" />
                        </div>
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Customer name"</label>
                            <input type="text" prop:value=move || name_inp.get()
                                on:input=move |e| set_name_inp.set(event_target_value(&e))
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500" />
                        </div>
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Tier"</label>
                            <select prop:value=move || tier_inp.get()
                                on:change=move |e| set_tier_inp.set(event_target_value(&e))
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500">
                                <option value="community">"Community"</option>
                                <option value="startup">"Startup"</option>
                                <option value="professional">"Professional"</option>
                                <option value="enterprise">"Enterprise"</option>
                                <option value="ultimate_free">"Ultimate Free"</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-xs text-zinc-500 mb-1">"Max activations"</label>
                            <input type="number" prop:value=move || max_act.get()
                                on:input=move |e| set_max_act.set(event_target_value(&e))
                                class="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-red-500" />
                        </div>
                    </div>
                    <button on:click=do_issue
                        class="rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-5 py-2 text-sm font-medium text-emerald-300 hover:bg-emerald-500/20 transition-colors">
                        "Issue key"
                    </button>
                </div>
            })}

            <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = keys.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let rows = v["keys"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <div class="mb-4">
                                <h2 class="text-lg font-semibold text-zinc-50">"All keys"</h2>
                                <p class="mt-1 text-sm text-zinc-500">{format!("{} keys issued", rows.len())}</p>
                            </div>
                            <table class="min-w-full text-sm">
                                <thead>
                                    <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                        <th class="px-3 py-3">"Customer"</th>
                                        <th class="px-3 py-3">"Tier"</th>
                                        <th class="px-3 py-3">"Key ID"</th>
                                        <th class="px-3 py-3">"Activations"</th>
                                        <th class="px-3 py-3">"Expires"</th>
                                        <th class="px-3 py-3">"Status"</th>
                                        <th class="px-3 py-3">"Action"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {rows.into_iter().map(|row| {
                                        let key_id  = row["key_id"].as_str().unwrap_or("-").to_string();
                                        let email   = row["customer_email"].as_str().unwrap_or("—").to_string();
                                        let name    = row["customer_name"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string());
                                        let tier    = format!("{:?}", row["tier"]).replace('"', "");
                                        let active  = row["active_instances"].as_array().map(|a| a.len()).unwrap_or(0);
                                        let max     = row["max_activations"].as_u64().unwrap_or(0);
                                        let expires = row["expires_at"].as_str().unwrap_or("Never").to_string();
                                        let revoked = row["revoked"].as_bool().unwrap_or(false);
                                        let revoke_id = key_id.clone();
                                        let tier_class = format!("inline-flex rounded-full px-2 py-0.5 text-xs font-medium {}",
                                            if tier.contains("Enterprise") { "bg-violet-500/10 text-violet-300" }
                                            else if tier.contains("Professional") { "bg-sky-500/10 text-sky-300" }
                                            else if tier.contains("Startup") { "bg-blue-500/10 text-blue-300" }
                                            else { "bg-zinc-700 text-zinc-300" });
                                        let act_class = if active >= max as usize { "text-amber-300" } else { "text-zinc-400" };
                                        let status_class = if revoked { "inline-flex rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-300" } else { "inline-flex rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300" };
                                        view! {
                                            <tr class="border-b border-zinc-900/80 align-top text-zinc-300">
                                                <td class="px-3 py-4">
                                                    {name.map(|n| view!{<p class="font-medium text-zinc-100">{n}</p>}.into_any()).unwrap_or(view!{<span/>}.into_any())}
                                                    <p class="text-xs text-zinc-500">{email}</p>
                                                </td>
                                                <td class="px-3 py-4">
                                                    <span class=tier_class>{tier}</span>
                                                </td>
                                                <td class="px-3 py-4 text-xs font-mono text-zinc-500">{key_id}</td>
                                                <td class="px-3 py-4 text-sm">
                                                    <span class=act_class>
                                                        {format!("{}/{}", active, max)}
                                                    </span>
                                                </td>
                                                <td class="px-3 py-4 text-xs text-zinc-500">{expires}</td>
                                                <td class="px-3 py-4">
                                                    <span class=status_class>
                                                        {if revoked { "Revoked" } else { "Active" }}
                                                    </span>
                                                </td>
                                                <td class="px-3 py-4">
                                                    {if !revoked { view!{
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
                        </div>
                    }
                })}
            </Suspense>
        </div>
    }
}
