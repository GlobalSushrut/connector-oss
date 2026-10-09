use leptos::prelude::*;
use leptos_router::components::A;
use crate::auth::{AuthState, logout};

struct NavSection {
    label: &'static str,
    items: &'static [(&'static str, &'static str)],
}

#[component]
pub fn Sidebar(auth: ReadSignal<AuthState>, set_auth: WriteSignal<AuthState>) -> impl IntoView {
    let sections: &[NavSection] = &[
        NavSection {
            label: "Overview",
            items: &[("Dashboard", "/admin")],
        },
        NavSection {
            label: "Beta Access",
            items: &[
                ("Signups",     "/admin/signups"),
                ("Pilot Grants", "/admin/pilots"),
            ],
        },
        NavSection {
            label: "Customers",
            items: &[
                ("Customers",    "/admin/customers"),
                ("License Keys", "/admin/keys"),
            ],
        },
        NavSection {
            label: "Finance",
            items: &[
                ("Revenue",  "/admin/revenue"),
                ("Payments", "/admin/payments"),
                ("Dunning",  "/admin/dunning"),
            ],
        },
        NavSection {
            label: "Fleet",
            items: &[
                ("Nodes",        "/admin/instances"),
                ("Surveillance", "/admin/surveillance"),
            ],
        },
        NavSection {
            label: "Playground",
            items: &[
                ("Trial Sessions", "/admin/trial-sessions"),
                ("Plugin Health",  "/admin/plugin-health"),
            ],
        },
        NavSection {
            label: "Distribution",
            items: &[
                ("Releases",  "/admin/distribution"),
            ],
        },
    ];

    view! {
        <aside class="flex w-60 shrink-0 flex-col border-r border-zinc-800 bg-zinc-950 h-screen sticky top-0">
            <div class="flex h-14 items-center gap-2 border-b border-zinc-800 px-4">
                <div class="h-6 w-6 rounded bg-red-500/20 flex items-center justify-center">
                    <span class="text-xs font-bold text-red-400">"C"</span>
                </div>
                <span class="text-sm font-semibold text-zinc-100">"Connector"</span>
                <span class="ml-auto text-[10px] rounded bg-zinc-800 px-1.5 py-0.5 text-zinc-500">"Admin"</span>
            </div>

            <nav class="flex-1 overflow-y-auto py-4 px-3 space-y-5">
                {sections.iter().map(|section| {
                    let section_label = section.label;
                    let items = section.items;
                    view! {
                        <div>
                            <p class="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
                                {section_label}
                            </p>
                            <div class="space-y-0.5">
                                {items.iter().map(|(label, path)| view! {
                                    <A href=*path attr:class="flex items-center rounded-md px-3 py-2 text-sm text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-100 transition-colors [&.active]:bg-zinc-800 [&.active]:text-zinc-100 [&.active]:font-medium">
                                        {*label}
                                    </A>
                                }).collect::<Vec<_>>()}
                            </div>
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </nav>

            <div class="border-t border-zinc-800 p-3 space-y-1">
                <p class="px-2 text-xs text-zinc-600 truncate">{move || auth.get().key_hint}</p>
                <button on:click=move |_| logout(set_auth)
                    class="w-full rounded-md px-3 py-1.5 text-left text-xs text-zinc-500 hover:text-red-400 hover:bg-zinc-800/50 transition-colors">
                    "Sign out"
                </button>
            </div>
        </aside>
    }
}
