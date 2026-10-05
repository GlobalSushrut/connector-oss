use leptos::prelude::*;

/// O08 — ephemeral toast (thin host; full stack still uses global Toaster).
#[component]
pub fn OpToast(
    #[prop(into)] message: String,
    #[prop(default = "info")] variant: &'static str,
) -> impl IntoView {
    let border = match variant {
        "success" => "border-emerald-500/40 text-emerald-200",
        "danger" => "border-red-500/40 text-red-200",
        "warn" => "border-amber-500/40 text-amber-200",
        _ => "border-zinc-700 text-zinc-200",
    };
    view! {
        <div class=format!("rounded-lg border bg-zinc-950/95 px-4 py-3 text-sm shadow-xl backdrop-blur {border}") role="status">
            {message}
        </div>
    }
}
