//! Seven-backend operational evidence. This is not a Connector Ready board.

use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

use crate::iia_api;

fn rows_of(body: &Value) -> Vec<Value> {
    body.get("backends")
        .or_else(|| body.pointer("/data/backends"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Addresses `./up.sh` uses on first boot. A changed CONNECTOR_OSS_WORK or port moves them.
fn first_boot_address(id: &str) -> &'static str {
    match id {
        "iam" => "Keycloak https://127.0.0.1:18443/ · secrets in /tmp/connector-oss/keycloak.env",
        "spire" => "socket /tmp/connector-oss/spire/agent.sock",
        "openshell" => "gateway http://127.0.0.1:17671/healthz",
        "opa" => "inside the OpenShell gateway",
        "firecracker" => "/tmp/connector-oss/bin/firecracker · binary only, no microvm is started",
        "otel" => "health http://127.0.0.1:13133 · OTLP 127.0.0.1:4317",
        "cosign" => "/tmp/connector-oss/bin/cosign",
        _ => "",
    }
}

fn flag(body: &Value, key: &str) -> Option<bool> {
    body.get(key)
        .or_else(|| body.pointer(&format!("/data/{key}")))
        .and_then(|v| v.as_bool())
}

#[component]
pub fn OperationalEvidencePanel() -> impl IntoView {
    let (body, set_body) = signal(Value::Null);
    let (error, set_error) = signal(String::new());
    let (gateway, set_gateway) = signal(Value::Null);
    let (gateway_error, set_gateway_error) = signal(String::new());
    let (catalog, set_catalog) = signal(Value::Null);
    let (catalog_error, set_catalog_error) = signal(String::new());
    Effect::new(move |_| {
        spawn_local(async move {
            match iia_api::runtime_backends().await {
                Ok(value) => set_catalog.set(value),
                Err(err) => set_catalog_error.set(format!("GET /runtime/backends — {err}")),
            }
            match iia_api::deploy_verify().await {
                Ok(value) => set_body.set(value),
                Err(err) => set_error.set(format!("GET /runtime/deploy-verify — {err}")),
            }
            match iia_api::agentgateway_status().await {
                Ok(value) => set_gateway.set(value),
                Err(err) => set_gateway_error.set(format!("GET /runtime/agentgateway — {err}")),
            }
        });
    });
    view! {
        <section class="mb-6 rounded-xl border border-zinc-800 bg-zinc-950/50 p-5">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"First boot"</p>
            <h2 class="mt-1 text-lg font-semibold text-zinc-50">"Tools behind Connector"</h2>
            <p class="mt-1 text-sm text-zinc-400">"./up.sh downloads, configures, and starts these. You do not need to touch them. Present means this node found the tool. Ready means it did the required operation, not that an effect went through it."</p>
            <p class="mt-2 text-[11px] text-amber-200/80">{move || catalog_error.get()}</p>
            <div class="mt-3 overflow-hidden rounded border border-zinc-800">
                <table class="w-full text-left text-[11px]">
                    <thead class="bg-zinc-900/70 text-zinc-500"><tr><th class="px-2 py-1">"Tool"</th><th>"Present"</th><th>"Ready"</th><th>"Manage at"</th></tr></thead>
                    <tbody>
                        {move || {
                            let rows = rows_of(&catalog.get());
                            if rows.is_empty() {
                                view! { <tr><td colspan="4" class="px-2 py-3 text-zinc-500">"This node returned no tool rows."</td></tr> }.into_any()
                            } else {
                                rows.into_iter().map(|row| {
                                    let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("absent").to_string();
                                    let present = row.get("present").and_then(|v| v.as_bool()).map(|v| v.to_string()).unwrap_or_else(|| "absent".into());
                                    let ready = row.get("ready").and_then(|v| v.as_bool()).map(|v| v.to_string()).unwrap_or_else(|| "absent".into());
                                    let detail = row.get("detail").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let address = first_boot_address(&id);
                                    view! {
                                        <tr class="border-t border-zinc-800/80" title=detail>
                                            <td class="px-2 py-1 text-zinc-100">{id}</td>
                                            <td class="px-2 py-1 font-mono text-zinc-300">{present}</td>
                                            <td class="px-2 py-1 font-mono text-zinc-300">{ready}</td>
                                            <td class="px-2 py-1 font-mono text-zinc-400">{address}</td>
                                        </tr>
                                    }
                                }).collect_view().into_any()
                            }
                        }}
                        <tr class="border-t border-zinc-800/80">
                            <td class="px-2 py-1 text-zinc-100">"agentgateway"</td>
                            <td class="px-2 py-1 font-mono text-zinc-500" colspan="2">"see below"</td>
                            <td class="px-2 py-1 font-mono text-zinc-400">"http://127.0.0.1:4000/ · forwarding is not proven"</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <p class="mt-2 text-[11px] text-zinc-500">"The full list, with ports and secret files, is /tmp/connector-oss/MANAGE.txt."</p>
        </section>
        <section class="mb-6 rounded-xl border border-zinc-800 bg-zinc-950/50 p-5">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Operational evidence"</p>
            <h2 class="mt-1 text-lg font-semibold text-zinc-50">"Seven backends"</h2>
            <p class="mt-1 text-sm text-zinc-400">"A ready row means that backend produced the required operation. It does not admit an effect and it is not Connector Ready."</p>
            <p class="mt-2 text-[11px] text-amber-200/80">{move || error.get()}</p>
            <p class="mt-2 font-mono text-[11px] text-zinc-300">{move || {
                let value = body.get();
                if value.is_null() {
                    return "operational_ready: absent".into();
                }
                let ready = flag(&value, "operational_ready").map(|v| v.to_string()).unwrap_or_else(|| "absent".into());
                let eligible = flag(&value, "production_eligible").map(|v| v.to_string()).unwrap_or_else(|| "absent".into());
                format!("operational_ready: {ready} · production_eligible: {eligible}")
            }}</p>
            <div class="mt-3 overflow-hidden rounded border border-zinc-800">
                <table class="w-full text-left text-[11px]">
                    <thead class="bg-zinc-900/70 text-zinc-500"><tr><th class="px-2 py-1">"Backend"</th><th>"Ready"</th><th>"Detail"</th></tr></thead>
                    <tbody>
                        {move || {
                            let value = body.get();
                            let rows = rows_of(&value);
                            if rows.is_empty() {
                                view! { <tr><td colspan="3" class="px-2 py-3 text-zinc-500">"No backend evidence row was returned."</td></tr> }.into_any()
                            } else {
                                rows.into_iter().map(|row| {
                                    let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("absent").to_string();
                                    let ready = row.get("ready").and_then(|v| v.as_bool()).map(|v| v.to_string()).unwrap_or_else(|| "absent".into());
                                    let detail = row.get("detail").and_then(|v| v.as_str()).unwrap_or("absent").to_string();
                                    view! {
                                        <tr class="border-t border-zinc-800/80">
                                            <td class="px-2 py-1 text-zinc-100">{id}</td>
                                            <td class="px-2 py-1 font-mono text-zinc-300">{ready}</td>
                                            <td class="px-2 py-1 text-zinc-400">{detail}</td>
                                        </tr>
                                    }
                                }).collect_view().into_any()
                            }
                        }}
                    </tbody>
                </table>
            </div>
            <div class="mt-4 rounded border border-zinc-800 p-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Agentgateway"</p>
                <p class="mt-1 text-[11px] text-zinc-400">"Separate from the seven backends. A pinned digest does not install the process. Forwarding stays denied."</p>
                <p class="mt-2 text-[11px] text-amber-200/80">{move || gateway_error.get()}</p>
                <p class="mt-2 font-mono text-[11px] text-zinc-300">{move || {
                    let value = gateway.get();
                    if value.is_null() {
                        return "status: absent".into();
                    }
                    let status = value.get("status").and_then(|item| item.as_str()).unwrap_or("absent");
                    let installed = value.get("installed").and_then(|item| item.as_bool()).map(|item| item.to_string()).unwrap_or_else(|| "absent".into());
                    let ready = value.get("ready").and_then(|item| item.as_bool()).map(|item| item.to_string()).unwrap_or_else(|| "absent".into());
                    let acceptance = value.get("acceptance_passed").and_then(|item| item.as_bool()).map(|item| item.to_string()).unwrap_or_else(|| "absent".into());
                    format!("status: {status} · installed: {installed} · ready: {ready} · acceptance_passed: {acceptance}")
                }}</p>
                <p class="mt-1 break-all font-mono text-[11px] text-zinc-400">{move || {
                    let value = gateway.get();
                    value.get("pinned_reference").and_then(|item| item.as_str()).unwrap_or("pin: absent").to_string()
                }}</p>
            </div>
        </section>
    }
}
