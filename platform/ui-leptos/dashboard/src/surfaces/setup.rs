use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use serde_json::{json, Value};
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::cards::{OpCard, OpCardAccent, OpInstitutionCard};
use crate::components::operator::overlays::gateway_form::OpGatewayGrantForm;
use crate::components::operator::overlays::llm_connect::OpLlmQuickConnect;
use crate::components::operator::primitives::{
    OpButton, OpButtonVariant, OpEmptyState, OpGrid, OpSpinner, OpText, OpTextField, OpTextVariant,
};
use crate::components::operator::overlays::isolation_posture::OpIsolationPosturePanel;
use crate::components::operator::overlays::operational_evidence::OperationalEvidencePanel;
use crate::components::ui::DownloadButton;
use crate::iia_api;
use crate::request_store::bump_reload;
use crate::surfaces::edge_proxies::EdgeProxiesPanel;
use crate::ui_state::{
    open_create_agent, open_create_workflow, open_topic_drawer, open_workflow_drawer, DrawerTopic,
};

#[component]
pub fn SetupCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let navigate = use_navigate();
    let is_admin = Signal::derive(move || {
        auth.get()
            .user
            .as_ref()
            .map(|u| u.role.contains("admin") || u.role == "super_admin")
            .unwrap_or(false)
    });
    let apps = LocalResource::new(|| api::get_value_q("/apps", &[("kind", "plugin")]));
    let plugin_status = LocalResource::new(|| api::get_value("/plugins/status"));
    let templates = LocalResource::new(|| api::get_value("/workflows/reference-templates"));
    let (install_msg, set_install_msg) = signal(Option::<String>::None);

    let go: Arc<dyn Fn(String) + Send + Sync> = {
        let navigate = navigate.clone();
        Arc::new(move |path: String| {
            navigate(&path, Default::default());
        })
    };

    // Pre-build click handlers so <Show> children stay `Fn` (not `FnOnce`).
    let on_first_run = {
        let go = go.clone();
        Arc::new(move |_| go("/setup/first-run".into()))
    };
    let on_connect_tool = {
        let go = go.clone();
        Arc::new(move |_| go("/setup/connect-tool".into()))
    };
    let on_devguard_setup = {
        let go = go.clone();
        Arc::new(move |_| go("/plugins/devguard/setup".into()))
    };
    let on_tracetramp_setup = {
        let go = go.clone();
        Arc::new(move |_| go("/plugins/tracetramp/setup".into()))
    };
    let on_witnessctl_setup = {
        let go = go.clone();
        Arc::new(move |_| go("/plugins/witnessctl/setup".into()))
    };
    let on_invite = {
        let go = go.clone();
        Arc::new(move |_| go("/setup/invite".into()))
    };
    let on_dev = {
        let go = go.clone();
        Arc::new(move |_| go("/dev".into()))
    };
    let on_install_page = {
        let go = go.clone();
        Arc::new(move |_| go("/install".into()))
    };
    let on_watch = {
        let go = go.clone();
        Arc::new(move |_| go("/watch".into()))
    };
    let on_monitor_click = on_watch.clone();

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10">
            <OpText text="SETUP".to_string() variant=OpTextVariant::Title />
            <p class="mt-1 mb-4 text-sm text-zinc-500">
                "Mint what augmented action needs: LLM · identity · DAC (RULES+HITL) · MCP. Then RUN Action."
            </p>

            <section class="mb-6 rounded-xl border border-emerald-800/40 bg-zinc-900/50 p-5">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-emerald-500/90">"Get started"</p>
                <h2 class="mt-1 text-lg font-semibold text-zinc-50">"Two things: connect a model, create an agent"</h2>
                <p class="mt-1 mb-4 text-sm text-zinc-400">
                    "Paste a provider key (vault, not cage). Name the agent. You'll land in Talk / Action."
                </p>
                <OpLlmQuickConnect />
                <div class="mt-4 flex flex-wrap items-center gap-2">
                    <OpButton
                        label="Create an agent".to_string()
                        variant=OpButtonVariant::Primary
                        on_click=Arc::new(move |_| open_create_agent())
                    />
                    <OpButton
                        label="World / edge".to_string()
                        variant=OpButtonVariant::Ghost
                        on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("network".into())))
                    />
                    <a href="/plugins/tracetramp" class="text-[12px] text-zinc-500 hover:text-zinc-300">"Audit (TraceTramp)"</a>
                    <span class="text-zinc-700">"·"</span>
                    <DownloadButton
                        path="/compliance/brief/pdf".to_string()
                        filename="connector-compliance-brief.pdf".to_string()
                        mime="application/pdf".to_string()
                    >
                        "Brief PDF"
                    </DownloadButton>
                </div>
            </section>

            <section class="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <a href="/setup/access" class="rounded-xl border border-amber-900/40 bg-amber-950/20 p-4 hover:border-amber-700/50">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-amber-400/90">"Access · DAC"</p>
                    <p class="mt-1 text-sm font-medium text-zinc-100">"RULES + HITL per address"</p>
                    <p class="mt-1 text-[11px] text-zinc-500">
                        "Identity stack refuses tools until both contracts exist (tool:id / mcp:name / llm:ns)."
                    </p>
                </a>
                <a href="/setup/uplink" class="rounded-xl border border-sky-900/40 bg-sky-950/20 p-4 hover:border-sky-700/50">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-sky-400/90">"Uplink"</p>
                    <p class="mt-1 text-sm font-medium text-zinc-100">"Node connect / mesh"</p>
                    <p class="mt-1 text-[11px] text-zinc-500">"Gateway base, uplink, and host wiring for this node."</p>
                </a>
                <a href="/setup/connect-tool" class="rounded-xl border border-indigo-900/40 bg-indigo-950/20 p-4 hover:border-indigo-700/50">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-indigo-400/90">"MCP · tools"</p>
                    <p class="mt-1 text-sm font-medium text-zinc-100">"Register a bridge"</p>
                    <p class="mt-1 text-[11px] text-zinc-500">
                        "POST /tools/mcp/register then invoke after PATE. Wizard: connect-tool."
                    </p>
                </a>
                <a href="/dev?tab=sdk" class="rounded-xl border border-zinc-700/60 bg-zinc-900/40 p-4 hover:border-zinc-500">
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-400">"SDK"</p>
                    <p class="mt-1 text-sm font-medium text-zinc-100">"DAL · Talk · AGOS"</p>
                    <p class="mt-1 text-[11px] text-zinc-500">"Same action path from outside the UI. Talk never auto-dispatches."</p>
                </a>
            </section>

            <SetupMcpMiniForm />

            <div class="mb-6">
                <OpGatewayGrantForm />
            </div>

            <section class="mb-6 rounded-xl border border-cyan-900/40 bg-zinc-950/50 p-5 space-y-3">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-cyan-400/90">"Isolation · NS FS · ACS"</p>
                <h2 class="mt-1 text-lg font-semibold text-zinc-50">"Per-agent isolation — evidence-bound"</h2>
                <p class="mt-1 text-sm text-zinc-400">
                    "Each intelligence gets ACS (character), NS FS, and a density tier. Landlock, cgroup, nft/eBPF, and microVM/vsock are claimed only when host evidence is present below — not a silent Docker-grade guarantee. MicroVM is high-risk only when selected and measured."
                </p>
                <OpIsolationPosturePanel />
            </section>

            <OperationalEvidencePanel />

            <WorldConnectCard />

            <div class="mb-4 flex flex-wrap gap-2">
                <a class="rounded-md border border-zinc-700 px-3 py-2 text-sm text-zinc-200" href="/setup/uplink">"Connect an existing agent"</a>
                <OpButton label="+ New agent".to_string() variant=OpButtonVariant::Primary on_click=Arc::new(move |_| open_create_agent()) />
                <OpButton label="+ New workflow".to_string() variant=OpButtonVariant::Secondary on_click=Arc::new(move |_| open_create_workflow()) />
            </div>

            <Show when=move || install_msg.get().is_some()>
                <p class="mb-3 rounded-md border border-zinc-800 bg-zinc-900/50 px-3 py-2 text-xs text-zinc-300">
                    {move || install_msg.get().unwrap_or_default()}
                </p>
            </Show>

            // Cloudflare-style edge control plane — first thing on SETUP, not buried below fold
            <EdgeProxiesPanel />

            <section class="mb-6 rounded-xl border border-zinc-800/70 bg-zinc-900/35 p-4 space-y-2">
                <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Hub install · 2A.9 verify"</p>
                <p class="text-xs text-zinc-400">
                    "Install progress is not a fake 30s bar. First-party plugins go through "
                    <code class="text-zinc-300">"connectorctl plugin verify"</code>
                    " (2A.9 certification sections). Hub registry install SLO timing is still open."
                </p>
                <ul class="list-disc space-y-1 pl-4 text-[11px] text-zinc-500">
                    <li>"Verify failures print under 2A.9.1…2A.9.10 headers — human-readable, not a spinner."</li>
                    <li>"Partial MVP: idle / capability / UI bundle sections may skip."</li>
                    <li>
                        "Docs: "
                        <code class="text-zinc-400">"docs/PLUGIN_VERIFY_2A9.md"</code>
                    </li>
                </ul>
                <div class="flex flex-wrap gap-2 pt-1">
                    <OpButton
                        label="Node install commands".to_string()
                        variant=OpButtonVariant::Secondary
                        on_click=on_install_page.clone()
                    />
                </div>
                <p class="font-mono text-[10px] text-zinc-600">
                    "P4.3 — never claim install under 30s until measured; show 2A.9 verify honesty instead."
                </p>
            </section>

            <h2 class="mb-3 text-xs font-semibold uppercase tracking-wide text-zinc-500">"Institutions"</h2>
            <Suspense fallback=move || view! { <div class="flex justify-center py-8"><OpSpinner /></div> }>
                {move || {
                    let go = go.clone();
                    Suspend::new(async move {
                    let apps_res = apps.await;
                    let status_res = plugin_status.await;
                    // Prefer /plugins/status: it carries real lifecycle + status_badge.
                    // /apps is a fallback catalog and must not invent healthy/installed.
                    let mut plugins = status_res.as_ref().ok().map(|v| plugin_cards_from_status(v)).unwrap_or_default();
                    if plugins.is_empty() {
                        plugins = apps_res.as_ref().ok().map(|v| plugin_cards(v)).unwrap_or_default();
                    }
                    if plugins.is_empty() {
                        let err = apps_res
                            .err()
                            .map(|e| e.message)
                            .or_else(|| status_res.err().map(|e| e.message))
                            .unwrap_or_else(|| {
                                "GET /apps?kind=plugin and GET /plugins/status returned no institutions."
                                    .into()
                            });
                        view! {
                            <OpEmptyState
                                title="No institutions from API"
                                description="Health and install state are not invented when the API returns nothing."
                            />
                            <p class="mt-2 font-mono text-[10px] text-amber-200/80">{err}</p>
                        }.into_any()
                    } else {
                        view! {
                            <OpGrid>
                                {plugins.into_iter().map(|(code, name, healthy, installed, href)| {
                                    let go = go.clone();
                                    let path = href.clone();
                                    let path_card = href;
                                    view! {
                                        <OpInstitutionCard
                                            code=code
                                            name=name
                                            healthy=healthy
                                            installed=installed
                                            on_install=Arc::new({
                                                let go = go.clone();
                                                let path = path;
                                                move |_| go(path.clone())
                                            })
                                            on_click=Arc::new(move |_| go(path_card.clone()))
                                        />
                                    }
                                }).collect_view()}
                            </OpGrid>
                        }.into_any()
                    }
                })}}
            </Suspense>

            <h2 class="mb-3 mt-8 text-xs font-semibold uppercase tracking-wide text-zinc-500">"Starter workflows"</h2>
            <Suspense fallback=move || view! { <OpSpinner /> }>
                {move || Suspend::new(async move {
                    let list = templates.await.ok().map(|v| template_rows(&v)).unwrap_or_default();
                    if list.is_empty() {
                        view! {
                            <OpEmptyState
                                title="No templates from API"
                                description="Use + New workflow to open the template installer when the API is available."
                            />
                            <div class="mt-3">
                                <OpButton
                                    label="Open installer".to_string()
                                    variant=OpButtonVariant::Primary
                                    on_click=Arc::new(move |_| open_create_workflow())
                                />
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <OpGrid>
                                {list.into_iter().map(|(id, title, desc)| {
                                    let install = Arc::new({
                                        let tid = id.clone();
                                        move |_| {
                                            let tid = tid.clone();
                                            set_install_msg.set(Some(format!("Installing {tid}…")));
                                            spawn_local(async move {
                                                // One-click install with bundled CCL (do not POST empty cls_source).
                                                match api::post_value(
                                                    &format!("/workflows/reference/{tid}/install"),
                                                    json!({}),
                                                )
                                                .await
                                                {
                                                    Ok(v) => {
                                                        if v.get("ok").and_then(|x| x.as_bool())
                                                            == Some(false)
                                                        {
                                                            set_install_msg
                                                                .set(Some(format_install_error(&v)));
                                                            return;
                                                        }
                                                        let Some(id) = installed_workflow_id(&v) else {
                                                            set_install_msg.set(Some(
                                                                "Install returned ok but no workflow_id — not opening a guessed id.".into(),
                                                            ));
                                                            bump_reload();
                                                            return;
                                                        };
                                                        bump_reload();
                                                        set_install_msg.set(Some(format!(
                                                            "Installed {id}"
                                                        )));
                                                        open_workflow_drawer(id);
                                                    }
                                                    Err(e) => {
                                                        set_install_msg.set(Some(format!(
                                                            "{} — is connector-platform on :9091?",
                                                            e.message
                                                        )));
                                                    }
                                                }
                                            });
                                        }
                                    });
                                    view! {
                                        <OpCard
                                            title=title
                                            subtitle=desc
                                            accent=OpCardAccent::Idle
                                            primary_label="Install".to_string()
                                            on_primary=install.clone()
                                            on_click=install
                                        >
                                            <span class="font-mono text-[10px] text-zinc-600">{id}</span>
                                        </OpCard>
                                    }
                                }).collect_view()}
                            </OpGrid>
                        }.into_any()
                    }
                })}
            </Suspense>

            <h2 class="mb-3 mt-8 text-xs font-semibold uppercase tracking-wide text-zinc-500">"Settings & topics"</h2>
            <OpGrid>
                <OpCard title="Node / runtime".to_string() subtitle="Mode and system".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("node".into())))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("node".into()))) />
                <OpCard title="Network & proxy".to_string() subtitle="Domains · API · edge plane".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("network".into())))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("network".into()))) />
                <OpCard title="LLM routing".to_string() subtitle="Providers & TraceTramp".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("llm".into())))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("llm".into()))) />
                <OpCard title="System".to_string() subtitle="Identity · backup · telemetry".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("system".into())))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Settings("system".into()))) />
                <OpCard title="Secrets".to_string() subtitle="Vault handles".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Secrets))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Secrets)) />
                <OpCard title="Webhooks".to_string() subtitle="Delivery endpoints".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Webhooks))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Webhooks)) />
                <OpCard title="Notifications".to_string() subtitle="Inbox".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Notifications))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Notifications)) />
                <OpCard title="License".to_string() subtitle="Status & machine".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::License))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::License)) />
                <OpCard title="Billing".to_string() subtitle="Entitlements".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Billing))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Billing)) />
                <OpCard title="Memory".to_string() subtitle="Browse & write".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Memory))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Memory)) />
                <OpCard title="Trust".to_string() subtitle="Score & receipts".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Trust))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Trust)) />
                <OpCard title="Books · economy".to_string() subtitle="Tokens · packets · ops (no fake $)".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Cost))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Cost)) />
                <OpCard title="Safety".to_string() subtitle="Graph firewall".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Safety))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Safety)) />
                <OpCard title="Monitor".to_string() subtitle="FinOps · security · load · packets".to_string() accent=OpCardAccent::Idle
                    primary_label="Open live".to_string()
                    on_primary=on_watch
                    on_click=on_monitor_click />
                <OpCard title="Conductor".to_string() subtitle="Multi-agent intelligence".to_string() accent=OpCardAccent::Idle
                    primary_label="Open".to_string()
                    on_primary=Arc::new(move |_| open_topic_drawer(DrawerTopic::Conductor))
                    on_click=Arc::new(move |_| open_topic_drawer(DrawerTopic::Conductor)) />
            </OpGrid>

            <h2 class="mb-3 mt-8 text-xs font-semibold uppercase tracking-wide text-zinc-500">"Tool archetypes"</h2>
            <p class="mb-3 text-xs text-zinc-500">
                "Service tools need a management URL + token. Action tools (DevGuard) bind a coding agent to a local workspace and divert traffic through the gateway — host cage is CLI."
            </p>
            <OpGrid>
                <OpCard
                    title="Action · Connect coding agent".to_string()
                    subtitle="DevGuard session · workspace path · Cursor/Claude".to_string()
                    accent=OpCardAccent::Idle
                    primary_label="Connect tool".to_string()
                    on_primary=on_connect_tool.clone()
                    on_click=on_connect_tool.clone()
                >
                    <span class="font-mono text-[10px] text-zinc-600">"POST /devguard/connect"</span>
                </OpCard>
                <OpCard
                    title="Action · DevGuard workstation".to_string()
                    subtitle="local-profile + CLI cage · not fake /setup".to_string()
                    accent=OpCardAccent::Idle
                    primary_label="DevGuard setup".to_string()
                    on_primary=on_devguard_setup.clone()
                    on_click=on_devguard_setup.clone()
                >
                    <span class="font-mono text-[10px] text-zinc-600">"/plugins/devguard/setup"</span>
                </OpCard>
                <OpCard
                    title="Service · TraceTramp".to_string()
                    subtitle="Management URL + admin token · LLM plane".to_string()
                    accent=OpCardAccent::Idle
                    primary_label="TraceTramp setup".to_string()
                    on_primary=on_tracetramp_setup.clone()
                    on_click=on_tracetramp_setup.clone()
                >
                    <span class="font-mono text-[10px] text-zinc-600">"POST /plugins/tracetramp/configure"</span>
                </OpCard>
                <OpCard
                    title="Service · WitnessCtl".to_string()
                    subtitle="Management URL + admin token · evidence".to_string()
                    accent=OpCardAccent::Idle
                    primary_label="WitnessCtl setup".to_string()
                    on_primary=on_witnessctl_setup.clone()
                    on_click=on_witnessctl_setup.clone()
                >
                    <span class="font-mono text-[10px] text-zinc-600">"POST /plugins/witnessctl/configure"</span>
                </OpCard>
            </OpGrid>

            <h2 class="mb-3 mt-8 text-xs font-semibold uppercase tracking-wide text-zinc-500">"Onboarding"</h2>
            <OpGrid>
                <OpCard
                    title="First-run".to_string()
                    subtitle="Fresh node wizard".to_string()
                    accent=OpCardAccent::Idle
                    primary_label="Start".to_string()
                    on_primary=on_first_run.clone()
                />
                <OpCard
                    title="Invite".to_string()
                    subtitle="Teammate access".to_string()
                    accent=OpCardAccent::Idle
                    primary_label="Invite".to_string()
                    on_primary=on_invite.clone()
                />
            </OpGrid>

            {move || {
                if !is_admin.get() {
                    return view! { <div class="hidden"></div> }.into_any();
                }
                let on_dev = on_dev.clone();
                let on_install_page = on_install_page.clone();
                view! {
                    <div class="mt-8">
                        <h2 class="mb-3 text-xs font-semibold uppercase tracking-wide text-amber-500/80">"Admin"</h2>
                        <OpGrid>
                            <OpCard
                                title="Advanced / Dev".to_string()
                                subtitle="Tools · protocols · infra".to_string()
                                accent=OpCardAccent::Attention
                                primary_label="Open hub".to_string()
                                on_primary=on_dev
                            />
                            <OpCard
                                title="Install / export".to_string()
                                subtitle="Playground session".to_string()
                                accent=OpCardAccent::Idle
                                primary_label="Open".to_string()
                                on_primary=on_install_page
                            />
                        </OpGrid>
                    </div>
                }.into_any()
            }}
        </div>
    }
}

#[component]
fn WorldConnectCard() -> impl IntoView {
    let world = LocalResource::new(|| iia_api::protocol_world());
    view! {
        <section class="mb-6 rounded-xl border border-cyan-900/40 bg-zinc-900/40 p-4">
            <div class="flex flex-wrap items-start justify-between gap-2">
                <div>
                    <p class="text-[10px] font-semibold uppercase tracking-wide text-cyan-500/90">"World connect"</p>
                    <p class="mt-1 text-sm text-zinc-200">"Any chartered agent → secure CNP/CONP → external world"</p>
                </div>
                <a
                    class="rounded-md border border-zinc-700 px-2.5 py-1 text-[11px] text-zinc-300 hover:border-cyan-700 hover:text-zinc-100"
                    href="/setup/connect-tool"
                >
                    "Connect tool wizard"
                </a>
            </div>
            <Suspense fallback=move || view! { <p class="mt-2 text-[11px] text-zinc-600">"Loading GET /protocol/world…"</p> }>
                {move || Suspend::new(async move {
                    match world.await {
                        Ok(v) => {
                            let summary = v
                                .get("summary")
                                .and_then(|x| x.as_str())
                                .unwrap_or("CNP spine + CONP capabilities for world targets.")
                                .to_string();
                            let types = v
                                .get("message_type_count")
                                .and_then(|x| x.as_u64())
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "—".into());
                            let caps = v
                                .get("capability_count")
                                .and_then(|x| x.as_u64())
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "—".into());
                            let targets = v
                                .get("world_target_count")
                                .and_then(|x| x.as_u64())
                                .or_else(|| {
                                    v.get("world_targets")
                                        .and_then(|x| x.as_array())
                                        .map(|a| a.len() as u64)
                                })
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "—".into());
                            let steps: Vec<String> = v
                                .get("operator_quickstart")
                                .and_then(|x| x.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_str())
                                        .map(humanize_world_step)
                                        .take(5)
                                        .collect()
                                })
                                .unwrap_or_default();
                            let has_steps = !steps.is_empty();
                            view! {
                                <p class="mt-2 text-xs text-zinc-400">{summary}</p>
                                <div class="mt-3 flex flex-wrap gap-3 text-[11px] font-mono text-cyan-100/80">
                                    <span class="rounded border border-cyan-900/50 bg-cyan-950/30 px-2 py-1">{format!("{types} CONP types")}</span>
                                    <span class="rounded border border-cyan-900/50 bg-cyan-950/30 px-2 py-1">{format!("{caps} caps")}</span>
                                    <span class="rounded border border-cyan-900/50 bg-cyan-950/30 px-2 py-1">{format!("{targets} world targets")}</span>
                                </div>
                                {
                                    let steps = steps;
                                    has_steps.then(|| view! {
                                        <ul class="mt-3 list-disc space-y-1 pl-4 text-[11px] text-zinc-500">
                                            {steps.into_iter().map(|s| view! { <li>{s}</li> }).collect_view()}
                                        </ul>
                                    })
                                }
                                <p class="mt-2 font-mono text-[10px] text-zinc-600">"GET /api/v1/protocol/world · .cpkg optional after 5-min create"</p>
                            }.into_any()
                        }
                        Err(e) => view! {
                            <p class="mt-2 text-[11px] text-amber-200/80">{format!("World map unavailable: {}", e.message)}</p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </section>
    }
}

fn plugin_cards_from_status(v: &Value) -> Vec<(&'static str, String, bool, bool, String)> {
    let Some(obj) = v.get("plugins").and_then(|x| x.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, row) in obj {
        let code = match id.as_str() {
            "tracetramp" => "TT",
            "witnessctl" => "WC",
            "devguard" => "DG",
            _ => "PL",
        };
        let installed = row
            .pointer("/lifecycle/installed")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let badge = row
            .get("status_badge")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        // Only "healthy" is a measured upstream probe. "enabled" is not health.
        let healthy = badge == "healthy"
            || row.get("upstream_reachable").and_then(|x| x.as_bool()) == Some(true);
        let href = row
            .get("dashboard_path")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("/plugins/{id}"));
        out.push((code, id.to_string(), healthy, installed, href));
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

fn plugin_cards(v: &Value) -> Vec<(&'static str, String, bool, bool, String)> {
    let arr = v
        .get("apps")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    arr.into_iter()
        .filter(|a| a.get("kind").and_then(|k| k.as_str()) == Some("plugin"))
        .filter_map(|a| {
            let id = a.get("id").and_then(|x| x.as_str())?.to_string();
            let code: &'static str = match id.as_str() {
                "tracetramp" => "TT",
                "witnessctl" => "WC",
                "devguard" => "DG",
                _ => "PL",
            };
            let name = a
                .get("display_name")
                .or_else(|| a.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or(&id)
                .to_string();
            let installed = a
                .get("installed")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let healthy = a.get("healthy").and_then(|x| x.as_bool()).unwrap_or(false)
                || a.get("status").and_then(|x| x.as_str()) == Some("healthy");
            let href = a
                .get("dashboard_path")
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("/plugins/{id}"));
            Some((code, name, healthy, installed, href))
        })
        .collect()
}

fn installed_workflow_id(v: &Value) -> Option<String> {
    api::resource_get(v, "workflow_id")
        .and_then(|x| x.as_str())
        .or_else(|| v.pointer("/workflow/workflow_id").and_then(|x| x.as_str()))
        .or_else(|| v.pointer("/data/workflow/workflow_id").and_then(|x| x.as_str()))
        .or_else(|| v.pointer("/workflow/id").and_then(|x| x.as_str()))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Prefer the human-readable install failure, including first CCL diagnostic when present.
fn format_install_error(v: &Value) -> String {
    let base = v
        .get("error")
        .and_then(|x| x.as_str())
        .or_else(|| v.pointer("/cls_compile/error/message").and_then(|x| x.as_str()))
        .unwrap_or("Install failed");
    let diag = v
        .pointer("/cls_compile/error/diagnostics")
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .and_then(|d| {
            let msg = d.get("message").and_then(|m| m.as_str())?;
            let line = d.get("line").and_then(|l| l.as_u64()).unwrap_or(0);
            let col = d.get("column").and_then(|c| c.as_u64()).unwrap_or(0);
            Some(format!(" (line {line}:{col}: {msg})"))
        })
        .unwrap_or_default();
    format!("{base}{diag}")
}

fn template_rows(v: &Value) -> Vec<(String, String, String)> {
    let mut arr = api::resource_array(v, "templates");
    if arr.is_empty() {
        arr = api::resource_array(v, "items");
    }
    if arr.is_empty() {
        arr = v.as_array().cloned().unwrap_or_default();
    }
    arr.into_iter()
        .filter_map(|t| {
            let id = t.get("id").and_then(|x| x.as_str())?.to_string();
            Some((
                id.clone(),
                t.get("name")
                    .or_else(|| t.get("title"))
                    .and_then(|x| x.as_str())
                    .unwrap_or(&id)
                    .to_string(),
                t.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            ))
        })
        .take(8)
        .collect()
}

fn humanize_world_step(raw: &str) -> String {
    let s = raw.trim();
    if s.contains("intelligence/apply") {
        "Create intelligence (~5 min apply)".into()
    } else if s.starts_with("Or:") {
        "Or enhance an existing agent's setup".into()
    } else if s.contains("Link LLM") {
        "Connect LLM, then Start from Control".into()
    } else if s.contains("CONP") {
        "Connect machines / APIs via CONP — bound skills + charter gate".into()
    } else if s.contains(".cpkg") {
        "Optional .cpkg later for custom runtime logic".into()
    } else if s.contains("forensic") {
        "Download forensic package or compliance PDF when you need proof".into()
    } else {
        s.to_string()
    }
}

#[component]
fn SetupMcpMiniForm() -> impl IntoView {
    let (bridge_id, set_bridge_id) = signal(String::new());
    let (url, set_url) = signal(String::new());
    let (agent_pid, set_agent_pid) = signal(String::new());
    let (tools_csv, set_tools_csv) = signal(String::new());
    let (_busy, set_busy) = signal(false);
    let (out, set_out) = signal(String::new());

    view! {
        <section class="mb-6 rounded-xl border border-indigo-900/40 bg-zinc-950/50 p-5 space-y-3">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-indigo-400/90">"MCP · register"</p>
            <h2 class="text-lg font-semibold text-zinc-50">"Register a bridge inline"</h2>
            <p class="text-sm text-zinc-400">
                "POST /tools/mcp/register — egress + L7 + action-binding. Governance Ask lands on FIX. Full wizard: "
                <a class="text-indigo-400 hover:underline" href="/setup/connect-tool">"connect-tool"</a>
                "."
            </p>
            <div class="grid gap-2 sm:grid-cols-2">
                <OpTextField label="Bridge id".to_string() value=bridge_id set_value=set_bridge_id placeholder="github-mcp" />
                <OpTextField label="URL".to_string() value=url set_value=set_url placeholder="https://mcp.example.com" />
                <OpTextField label="Owner agent pid".to_string() value=agent_pid set_value=set_agent_pid placeholder="mcp-bridge (default)" />
                <OpTextField label="Tools (csv)".to_string() value=tools_csv set_value=set_tools_csv placeholder="search, read_file" />
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <OpButton
                    label="Register bridge".to_string()
                    variant=OpButtonVariant::Primary
                    on_click=Arc::new(move |_| {
                        let b = bridge_id.get_untracked();
                        let u = url.get_untracked();
                        let a = agent_pid.get_untracked();
                        let tools: Vec<String> = tools_csv
                            .get_untracked()
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if b.trim().is_empty() || u.trim().is_empty() {
                            set_out.set("Bridge id and URL are required.".into());
                            return;
                        }
                        set_busy.set(true);
                        set_out.set(String::new());
                        spawn_local(async move {
                            let body = json!({
                                "bridge_id": b.trim(),
                                "url": u.trim(),
                                "agent_pid": if a.trim().is_empty() { "mcp-bridge" } else { a.trim() },
                                "tools": tools,
                            });
                            match api::post_value("/tools/mcp/register", body).await {
                                Ok(v) => {
                                    if let Some(e) = api::body_error(&v) {
                                        set_out.set(e);
                                    } else {
                                        set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default());
                                        bump_reload();
                                    }
                                }
                                Err(e) => set_out.set(e.message),
                            }
                            set_busy.set(false);
                        });
                    })
                />
                <a class="text-[12px] text-zinc-500 hover:text-zinc-300" href="/setup/uplink">"Uplink bay →"</a>
            </div>
            <Show when=move || !out.get().is_empty()>
                <pre class="max-h-40 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-400">{move || out.get()}</pre>
            </Show>
        </section>
    }
}
