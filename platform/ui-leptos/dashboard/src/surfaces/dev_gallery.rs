use leptos::prelude::*;

use crate::auth::AuthState;
use crate::components::operator::cards::{
    OpAgentCard, OpCard, OpCardAccent, OpInstitutionCard, OpMetricRow, OpObjectTile,
    OpReceiptCard, OpUsageMeter, OpWorkflowCard,
};
use crate::components::operator::overlays::{
    OpAgentTree, OpConfirm, OpErrorHero, OpExportMenu, OpForensicsPanel, OpModal,
    OpResultSheet, OpSparklineGrid, OpToast,
};
use crate::components::operator::primitives::*;

#[component]
pub fn DevComponentGallery(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    let (tab, set_tab) = signal("primitives".to_string());
    let (modal_open, set_modal_open) = signal(false);
    let (confirm_open, set_confirm_open) = signal(false);
    let (result_open, set_result_open) = signal(false);
    let (text_val, set_text_val) = signal(String::new());
    let (select_val, set_select_val) = signal("run".to_string());
    let (switch_on, set_switch_on) = signal(true);
    let (view_mode, set_view_mode) = signal(OpViewMode::Grid);

    view! {
        <div class="w-full px-6 py-4 pb-10">
            <h1 class="text-lg font-semibold text-zinc-100">"Op* component gallery"</h1>
            <p class="mt-1 text-sm text-zinc-500">"Wave 1–5 — primitives, cards, overlays. Remove /dev/components before production cutover."</p>
            <div class="mt-4">
                <OpFilterTabs
                    tabs=vec![
                        ("primitives", "Primitives"),
                        ("cards", "Cards"),
                        ("overlays", "Overlays"),
                        ("status", "Status"),
                    ]
                    active=tab
                    set_active=set_tab
                />
            </div>
            <div class="mt-6 space-y-8">
                <Show when=move || tab.get() == "primitives">
                    <section class="space-y-4">
                        <h2 class="text-xs font-semibold uppercase tracking-wide text-zinc-500">"Buttons & inputs"</h2>
                        <div class="flex flex-wrap gap-2">
                            <OpButton label="Primary".to_string() />
                            <OpButton label="Secondary".to_string() variant=OpButtonVariant::Secondary />
                            <OpButton label="Ghost".to_string() variant=OpButtonVariant::Ghost />
                            <OpButton label="Danger".to_string() variant=OpButtonVariant::Danger />
                            <OpButton label="Loading".to_string() loading=true />
                        </div>
                        <div class="grid max-w-md gap-4 sm:grid-cols-2">
                            <OpTextField value=text_val set_value=set_text_val label="Text field" placeholder="Type here…" />
                            <OpSelect
                                value=select_val
                                set_value=set_select_val
                                label="Select"
                                options=vec![
                                    ("run".into(), "RUN".into()),
                                    ("watch".into(), "WATCH".into()),
                                    ("fix".into(), "FIX".into()),
                                ]
                            />
                        </div>
                        <OpSwitch checked=switch_on set_checked=set_switch_on label="Developer view".to_string() />
                        <OpViewToggle mode=view_mode set_mode=set_view_mode />
                        <OpKbd keys="⌘K".to_string() />
                    </section>
                    <section class="space-y-4">
                        <h2 class="text-xs font-semibold uppercase tracking-wide text-zinc-500">"Layout & feedback"</h2>
                        <OpSurface class="p-4">
                            <OpStack direction="horizontal" gap="gap-4">
                                <OpSpinner />
                                <OpSkeleton class="h-4 w-48" />
                            </OpStack>
                        </OpSurface>
                        <OpProgress percent=62 />
                        <OpAlertBar message="System maintenance in 2h".to_string() variant="warn" />
                    </section>
                </Show>
                <Show when=move || tab.get() == "cards">
                    <OpGrid cols="grid-cols-1 md:grid-cols-2 xl:grid-cols-3">
                        <OpWorkflowCard
                            workflow_id="hitl-approve".to_string()
                            title="HITL Approve and Audit".to_string()
                            subtitle="Capture → seal → human gate".to_string()
                            state="ENABLED".to_string()
                            accent=OpCardAccent::Running
                        />
                        <OpCard title="Issue example".to_string() subtitle="Missing secret".to_string() accent=OpCardAccent::Attention primary_label="Fix now".to_string()>
                            <span></span>
                        </OpCard>
                        <OpAgentCard name="research-agent".to_string() pid="pid_7f3a".to_string() state="running".to_string() />
                        <OpInstitutionCard code="TT" name="TraceTramp".to_string() healthy=true installed=true />
                        <OpObjectTile label="Secrets".to_string() count=Some(3) />
                    </OpGrid>
                    <OpMetricRow metrics=vec![
                        ("Last run".into(), "2m ago".into()),
                        ("Health".into(), "OK".into()),
                        ("Events".into(), "12".into()),
                        ("Cost".into(), "—".into()),
                    ] />
                    <OpUsageMeter label="Token budget".to_string() used=72 cap=100 />
                    <OpReceiptCard receipt_id="rcpt_abc".to_string() summary="Dry-run sealed".to_string() time="1h ago".to_string() />
                </Show>
                <Show when=move || tab.get() == "overlays">
                    <div class="flex flex-wrap gap-2">
                        <OpButton label="Open modal".to_string() on_click=std::sync::Arc::new(move |_| set_modal_open.set(true)) />
                        <OpButton label="Open confirm".to_string() variant=OpButtonVariant::Danger on_click=std::sync::Arc::new(move |_| set_confirm_open.set(true)) />
                        <OpButton label="Result sheet".to_string() variant=OpButtonVariant::Secondary on_click=std::sync::Arc::new(move |_| set_result_open.set(true)) />
                    </div>
                    <OpErrorHero title="Workflow blocked".to_string() detail="Missing API key for witnessctl".to_string() show_fix=true />
                    <OpSparklineGrid />
                    <OpExportMenu />
                    <OpAgentTree nodes=vec![("pid_root".into(), "parent".into()), ("pid_child".into(), "progeny".into())] />
                    <OpForensicsPanel
                        custody_id="cust_demo".to_string()
                        trace_id="tr_demo".to_string()
                        flow_id="flow_demo".to_string()
                        moment_id="mom_demo".to_string()
                        artifact_id="art_demo".to_string()
                        load_status=false
                    />
                    <OpToast message="Action queued".to_string() variant="success" />
                    <OpModal open=modal_open set_open=set_modal_open title="Example modal".to_string()>
                        <p class="text-sm text-zinc-400">"Centered dialog for rare forms."</p>
                    </OpModal>
                    <OpConfirm
                        open=confirm_open
                        set_open=set_confirm_open
                        title="Terminate subtree?".to_string()
                        message="This stops all child agents immediately.".to_string()
                        on_confirm=move || {}
                    />
                    {
                        let (demo_title, _) = signal("hitl-approve".to_string());
                        let (demo_summary, _) = signal("ok=true · blueprint_ops=3 · events=12".to_string());
                        view! {
                            <OpResultSheet
                                open=result_open
                                set_open=set_result_open
                                title=demo_title
                                summary=demo_summary
                            />
                        }
                    }
                </Show>
                <Show when=move || tab.get() == "status">
                    <div class="flex flex-wrap gap-4 items-center">
                        <OpHealthDot state=OpHealthState::Ok show_label=true />
                        <OpHealthDot state=OpHealthState::Degraded show_label=true />
                        <OpStatChip variant=OpStatVariant::Running count=Some(2) />
                        <OpStatChip variant=OpStatVariant::NeedsYou count=Some(1) />
                        <OpLiveDot />
                        <OpPulseWave />
                        <OpEnvBadge name="prod-eu-1".to_string() />
                        <OpNotifyBell unread=Some(3) />
                    </div>
                    <div class="flex flex-wrap gap-2 mt-4">
                        <OpStatePill state="running".to_string() />
                        <OpDecisionPill decision="allow" />
                        <OpDecisionPill decision="deny" />
                        <OpVerifiedBadge verified=false pending=true />
                        <OpFmtUnknown value=Some("—".to_string()) />
                        <OpTruncMono text="bafybeig…xyz".to_string() />
                    </div>
                </Show>
            </div>
        </div>
    }
}
