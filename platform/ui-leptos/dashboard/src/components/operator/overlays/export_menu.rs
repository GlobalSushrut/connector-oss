use leptos::prelude::*;

/// Export menu — no stub downloads. Wire capability-gated exports later;
/// until then this is an honest empty state (UI_UNIVERSAL_CAPABILITIES K4/K10).
#[component]
pub fn OpExportMenu(
    #[prop(default = true)] allow_pdf: bool,
    #[prop(default = true)] allow_csv: bool,
) -> impl IntoView {
    let _ = (allow_pdf, allow_csv);
    view! {
        <div class="rounded border border-zinc-800/60 bg-zinc-950/40 px-3 py-2">
            <p class="text-[10px] uppercase tracking-wide text-zinc-500">"Exports"</p>
            <p class="mt-1 text-[11px] text-zinc-400">
                "Capability-gated Export is not wired here. Use Evidence: Agent isolation PDF/JSON, system brief/report, or WitnessCtl/TraceTramp plugin consoles."
            </p>
        </div>
    }
}
