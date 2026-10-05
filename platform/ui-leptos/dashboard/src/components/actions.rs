#![allow(dead_code)] // Leptos #[component] props — see cards.rs

use leptos::prelude::*;
use crate::components::icons;

// ═══════════════════════════════════════════════════════════════════════════════
// TOAST NOTIFICATION - Feedback for actions
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, PartialEq)]
pub struct Toast {
    pub message: String,
    pub variant: String,
}

#[component]
pub fn ToastContainer(
    toasts: ReadSignal<Vec<Toast>>,
) -> impl IntoView {
    view! {
        <div class="toast-container">
            <For
                each=move || toasts.get()
                key=|t| t.message.clone()
                children=move |toast| {
                    let variant_class = match toast.variant.as_str() {
                        "success" => "toast toast-success",
                        "error" => "toast toast-error",
                        "warning" => "toast toast-warning",
                        _ => "toast toast-info",
                    };
                    let icon = match toast.variant.as_str() {
                        "success" => icons::ICON_CHECK,
                        "error" => icons::ICON_X,
                        "warning" => icons::ICON_ALERT,
                        _ => icons::ICON_INFO,
                    };
                    view! {
                        <div class=variant_class>
                            <span class="toast-icon" inner_html=icon />
                            <span class="toast-message">{toast.message.clone()}</span>
                        </div>
                    }
                }
            />
        </div>
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HITL APPROVAL CARD - Human-in-the-loop approval UI
// ═══════════════════════════════════════════════════════════════════════════════

#[component]
pub fn HITLApprovalCard(
    #[prop(into)] request_id: String,
    #[prop(into)] agent_pid: String,
    #[prop(into)] action: String,
    #[prop(into)] details: String,
    #[prop(into)] timestamp: String,
) -> impl IntoView {
    view! {
        <div class="hitl-card">
            <div class="hitl-header">
                <div class="flex items-center gap-2">
                    <span class="hitl-badge">"Approval Required"</span>
                    <span class="text-xs text-zinc-500">{timestamp}</span>
                </div>
            </div>
            <div class="hitl-body">
                <div class="flex items-center gap-3 mb-3">
                    <div class="w-8 h-8 rounded-lg bg-amber-500/20 flex items-center justify-center">
                        <span class="text-amber-400" inner_html=icons::ICON_ALERT />
                    </div>
                    <div>
                        <p class="text-sm font-medium text-zinc-200">{action}</p>
                        <p class="text-xs text-zinc-500">"Agent: "{agent_pid}</p>
                    </div>
                </div>
                <p class="text-xs text-zinc-400 bg-zinc-800/50 p-2 rounded-lg font-mono">{details}</p>
                <p class="text-[10px] text-zinc-600 mt-2">"Request ID: "{request_id}</p>
            </div>
        </div>
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMMAND STRUCT - For command palette data
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone, PartialEq)]
pub struct Command {
    pub id: String,
    pub label: String,
    pub icon: &'static str,
    pub category: String,
    pub shortcut: Option<String>,
}
