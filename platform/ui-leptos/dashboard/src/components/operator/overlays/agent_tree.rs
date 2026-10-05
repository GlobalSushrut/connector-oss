use leptos::prelude::*;

/// O13 — progeny tree panel for agent drawer.
#[component]
pub fn OpAgentTree(#[prop(default = Vec::new())] nodes: Vec<(String, String)>) -> impl IntoView {
    view! {
        <div class="space-y-1 rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-3">
            <p class="text-[10px] font-semibold uppercase tracking-wide text-zinc-500">"Agent tree"</p>
            {if nodes.is_empty() {
                view! { <p class="text-xs text-zinc-600">"No progeny yet."</p> }.into_any()
            } else {
                nodes.into_iter().map(|(pid, label)| {
                    view! {
                        <div class="flex items-center gap-2 py-1 text-xs">
                            <span class="font-mono text-zinc-500">{pid}</span>
                            <span class="text-zinc-300">{label}</span>
                        </div>
                    }
                }).collect_view().into_any()
            }}
        </div>
    }
}
