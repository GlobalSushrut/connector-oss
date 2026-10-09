use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
use serde_json::Value;
use crate::api;
use crate::auth::AuthState;

#[component]
pub fn Payments(auth: ReadSignal<AuthState>) -> impl IntoView {
    let (refresh, set_refresh) = create_signal(0u32);
    let (flash, set_flash) = create_signal(Option::<(String, bool)>::None);

    let revenue = LocalResource::new(move || { let _ = refresh.get(); api::get_value("/payment/revenue") });

    let do_invoice_pdf = move |payment_id: String| {
        set_flash.set(None);
        spawn_local(async move {
            match api::post_value("/payment/invoice-pdf", serde_json::json!({"payment_intent_id": payment_id})).await {
                Ok(v) => {
                    let url = v["pdf_url"].as_str().unwrap_or("#").to_string();
                    set_flash.set(Some((format!("Invoice PDF: {url}"), true)));
                }
                Err(e) => set_flash.set(Some((e.message, false))),
            }
        });
    };

    view! {
        <div class="p-6 space-y-6">
            <div class="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <p class="text-xs font-medium uppercase tracking-wider text-red-400">"Payment operations"</p>
                    <h1 class="text-2xl font-semibold text-zinc-50">"Payments"</h1>
                    <p class="text-sm text-zinc-500">"Transaction history, invoice PDFs, and Stripe reconciliation."</p>
                </div>
                <button on:click=move |_| set_refresh.update(|v| *v += 1)
                    class="rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-700 transition-colors">
                    "Refresh"
                </button>
            </div>

            {move || flash.get().map(|(msg, ok)| view! {
                <div class=if ok { "rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300 break-all" }
                          else  { "rounded-md border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300" }>
                    {msg}
                </div>
            })}

            <Suspense fallback=|| view! { <div class="grid gap-4 md:grid-cols-4"><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/><div class="card h-24 animate-pulse"/></div> }>
                {move || Suspend::new(async move {
                    let value = revenue.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let mrr = v["mrr_display"].as_str().unwrap_or("$0.00").to_string();
                    let arr = v["arr_display"].as_str().unwrap_or("$0.00").to_string();
                    let subs = v["active_subscriptions"].as_u64().unwrap_or(0);
                    let churn = v["churn_pct"].as_f64().unwrap_or(0.0);
                    view! {
                        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"MRR"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{mrr}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"ARR"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{arr}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Active subs"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{subs}</p></div>
                            <div class="card"><p class="text-xs uppercase tracking-wider text-zinc-500">"Churn"</p><p class="mt-2 text-2xl font-semibold text-zinc-50">{format!("{:.1}%", churn)}</p></div>
                        </div>
                    }
                })}
            </Suspense>

            <Suspense fallback=|| view! { <div class="card h-80 animate-pulse" /> }>
                {move || Suspend::new(async move {
                    let value = revenue.await;
                    let v = value.as_ref().ok().unwrap_or(&Value::Null);
                    let transactions = v["recent_transactions"].as_array().cloned().unwrap_or_default();
                    view! {
                        <div class="card overflow-x-auto">
                            <div class="mb-4 flex items-center justify-between">
                                <div>
                                    <h2 class="text-lg font-semibold text-zinc-50">"Recent transactions"</h2>
                                    <p class="mt-1 text-sm text-zinc-500">{format!("{} transactions", transactions.len())}</p>
                                </div>
                            </div>
                            {if transactions.is_empty() {
                                view!{ <p class="text-sm text-zinc-600 py-8 text-center">"No transactions yet — configure Stripe (STRIPE_SECRET_KEY) to see live data."</p> }.into_any()
                            } else {
                                view! {
                                    <table class="min-w-full text-sm">
                                        <thead>
                                            <tr class="border-b border-zinc-800 text-left text-xs uppercase tracking-wider text-zinc-500">
                                                <th class="px-3 py-3">"Customer"</th>
                                                <th class="px-3 py-3">"Amount"</th>
                                                <th class="px-3 py-3">"Status"</th>
                                                <th class="px-3 py-3">"Date"</th>
                                                <th class="px-3 py-3">"Stripe ID"</th>
                                                <th class="px-3 py-3">"Invoice"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {transactions.into_iter().map(|row| {
                                                let customer = row["customer"].as_str().unwrap_or("—").to_string();
                                                let amount   = row["amount_display"].as_str().unwrap_or("—").to_string();
                                                let status   = row["status"].as_str().unwrap_or("—").to_string();
                                                let date     = row["created"].as_str().unwrap_or("—").to_string();
                                                let stripe_id = row["payment_intent_id"].as_str().unwrap_or("").to_string();
                                                let pdf_id   = stripe_id.clone();
                                                let status_class = if status == "succeeded" { "inline-flex rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300" } else if status == "failed" { "inline-flex rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-300" } else { "inline-flex rounded-full bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-300" };
                                                view! {
                                                    <tr class="border-b border-zinc-900/80 text-zinc-300">
                                                        <td class="px-3 py-3 text-zinc-200">{customer}</td>
                                                        <td class="px-3 py-3 font-medium text-zinc-100">{amount}</td>
                                                        <td class="px-3 py-3">
                                                            <span class=status_class>{status}</span>
                                                        </td>
                                                        <td class="px-3 py-3 text-xs text-zinc-500">{date}</td>
                                                        <td class="px-3 py-3 text-xs font-mono text-zinc-600">{stripe_id}</td>
                                                        <td class="px-3 py-3">
                                                            {if !pdf_id.is_empty() { view!{
                                                                <button on:click=move |_| do_invoice_pdf(pdf_id.clone())
                                                                    class="rounded border border-zinc-700 px-2 py-1 text-xs text-zinc-400 hover:text-zinc-200 hover:border-zinc-500 transition-colors">
                                                                    "PDF"
                                                                </button>
                                                            }.into_any() } else { view!{ <span/> }.into_any() }}
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
