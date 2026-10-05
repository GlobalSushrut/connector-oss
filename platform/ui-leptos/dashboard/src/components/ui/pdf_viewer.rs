//! PdfViewer — inline PDF preview backed by a blob object URL.
//!
//! The browser's built-in PDF viewer (Chromium, Firefox, Safari) renders
//! a `<iframe src="blob:...">` with `Content-Type: application/pdf`
//! exactly the way a desktop PDF reader does — pagination, search,
//! zoom, save, print all work without us re-implementing them. This
//! primitive owns the lifecycle: it fetches PDF bytes via
//! `api::get_bytes`, wraps them in a blob URL, embeds the iframe, and
//! revokes the URL when the source signal changes or the component
//! unmounts.
//!
//! It has three states:
//!
//! * **Idle** — no source yet; renders an `<EmptyState>` with the
//!   "Generate report" prompt the caller passes in.
//! * **Loading** — fetch is in flight; renders a `<Spinner>` centered
//!   over a placeholder pane.
//! * **Ready** — PDF bytes received; renders the iframe + a small
//!   action bar (Download + Open in new tab + Print).
//!
//! Errors surface via the [`crate::components::toaster`] queue rather
//! than a banner inside the viewer — that's consistent with the rest
//! of the dashboard and keeps the viewer focused on showing the doc.
//!
//! ## Usage
//!
//! ```ignore
//! let bytes = RwSignal::<Option<Vec<u8>>>::new(None);
//! let filename = "connector-compliance-report.pdf".to_string();
//!
//! view! {
//!     <PdfViewer
//!         bytes=bytes.into()
//!         filename=filename
//!         empty_hint="Pick a framework and click Generate."
//!     />
//! }
//! ```
//!
//! Callers fetch bytes once via `api::get_bytes(path).await?` and push
//! them into the `bytes` signal. The viewer takes it from there.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

use crate::components::ui::{Button, ButtonSize, ButtonVariant, EmptyState, OnClick, Spinner};
use crate::utils::{bytes_to_object_url, revoke_object_url, trigger_download_bytes};

/// Inline PDF viewer with download / open-in-tab / print actions.
#[component]
pub fn PdfViewer(
    /// Source bytes. When `None` the viewer renders an empty state with
    /// `empty_hint`. When `Some(bytes)`, the bytes are wrapped in a
    /// blob URL and embedded.
    #[prop(into)]
    bytes: Signal<Option<Vec<u8>>>,
    /// Suggested download filename when the user clicks Download.
    /// Reactive so callers can flip the filename as the focused
    /// resource changes (e.g. per-finding evidence on the Findings
    /// tab) without remounting the viewer. Existing call sites that
    /// pass a plain `String` still work via the `into` coercion —
    /// the resulting constant signal never changes.
    #[prop(into)]
    filename: Signal<String>,
    /// While `bytes` is `None` but `is_loading` is `true`, render a
    /// loading spinner instead of the empty state.
    #[prop(optional, into)]
    is_loading: Signal<bool>,
    /// Sentence rendered in the empty state.
    #[prop(optional, into, default = "Generate the PDF to preview it here.".to_string().into())]
    empty_hint: Signal<String>,
    /// Title shown in the empty state header.
    #[prop(optional, into, default = "No PDF yet".to_string().into())]
    empty_title: Signal<String>,
    /// Iframe height. Defaults to a 700 px tall pane which works on
    /// most desktop viewports without scrolling the page itself.
    #[prop(optional, into, default = "min-h-[700px]".to_string().into())]
    height_class: Signal<String>,
    /// Optional MIME type override. Default is `application/pdf`.
    #[prop(optional, into, default = "application/pdf".to_string().into())]
    mime: Signal<String>,
) -> impl IntoView {
    // Reactive object URL that follows the `bytes` signal. We track the
    // previous URL so we can revoke it on each change — without this,
    // every byte-update would leak the blob.
    let url = RwSignal::new(None::<String>);
    let prev_url = StoredValue::new(None::<String>);

    Effect::new(move |_| {
        let next = bytes.with(|b| b.as_ref().and_then(|v| bytes_to_object_url(v, &mime.get())));
        if let Some(p) = prev_url.get_value() {
            revoke_object_url(&p);
        }
        prev_url.set_value(next.clone());
        url.set(next);
    });

    // Revoke on unmount as well so SPAs that navigate away don't leak.
    on_cleanup(move || {
        if let Some(p) = prev_url.get_value() {
            revoke_object_url(&p);
        }
    });

    let filename_for_dl = filename;
    let mime_for_dl = mime;
    let on_download: OnClick = std::sync::Arc::new(move |_| {
        bytes.with(|b| {
            if let Some(v) = b.as_ref() {
                trigger_download_bytes(
                    v,
                    &filename_for_dl.get_untracked(),
                    &mime_for_dl.get_untracked(),
                );
            }
        });
    });

    let on_open_tab: OnClick = std::sync::Arc::new(move |_| {
        if let Some(u) = url.get_untracked() {
            if let Some(win) = web_sys::window() {
                let _ = win.open_with_url_and_target(&u, "_blank");
            }
        }
    });

    let on_print: OnClick = std::sync::Arc::new(move |_| {
        // Print the iframe contents. Falls back to the surrounding
        // page's print dialog if `contentWindow` isn't reachable
        // (cross-origin object URLs don't expose it in some browsers).
        if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
            if let Some(el) = doc.get_element_by_id("connector-pdf-viewer-iframe") {
                if let Ok(iframe) = el.dyn_into::<web_sys::HtmlIFrameElement>() {
                    if let Ok(Some(content_win)) = iframe.content_window().map(Some).ok_or(()) {
                        let _ = content_win.print();
                        return;
                    }
                }
            }
        }
        if let Some(win) = web_sys::window() {
            let _ = win.print();
        }
    });

    let has_pdf = move || url.get().is_some();

    view! {
        <div class="space-y-3">
            // Action bar — sits above the iframe so the download
            // affordance is always visible without scrolling.
            <Show
                when=has_pdf
                fallback=|| view! { <span class="hidden"></span> }
            >
                <div class="flex items-center justify-between gap-2 flex-wrap">
                    <p class="text-caption text-muted">
                        "Browser PDF viewer · use ⌘/Ctrl+F to search."
                    </p>
                    <div class="flex items-center gap-2">
                        <Button
                            variant=ButtonVariant::Ghost
                            size=ButtonSize::Sm
                            on_click=on_print.clone()
                        >
                            "Print"
                        </Button>
                        <Button
                            variant=ButtonVariant::Outline
                            size=ButtonSize::Sm
                            on_click=on_open_tab.clone()
                        >
                            "Open in new tab"
                        </Button>
                        <Button
                            variant=ButtonVariant::Primary
                            size=ButtonSize::Sm
                            on_click=on_download.clone()
                        >
                            "Download"
                        </Button>
                    </div>
                </div>
            </Show>

            // Viewer body. Renders one of three states:
            //   - Loading → spinner
            //   - Ready → iframe
            //   - Idle → empty state
            <div class=move || {
                let h = height_class.get();
                format!(
                    "rounded-xl border border-zinc-800/60 bg-zinc-950/60 overflow-hidden relative {h}"
                )
            }>
                <Show when=move || url.get().is_some()>
                    <iframe
                        id="connector-pdf-viewer-iframe"
                        title="Compliance report PDF preview"
                        class="w-full h-full block bg-white"
                        src=move || url.get().unwrap_or_default()
                    ></iframe>
                </Show>
                <Show when=move || url.get().is_none() && is_loading.get()>
                    <div class="absolute inset-0 flex flex-col items-center justify-center gap-3 text-muted">
                        <Spinner label="Generating PDF".to_string() />
                        <p class="text-body-sm">"Generating PDF…"</p>
                    </div>
                </Show>
                <Show when=move || url.get().is_none() && !is_loading.get()>
                    <div class="absolute inset-0 flex items-center justify-center p-6">
                        <EmptyState
                            title=empty_title.get()
                            description=empty_hint.get()
                        >
                            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                <polyline points="14 2 14 8 20 8"></polyline>
                                <line x1="9" y1="15" x2="15" y2="15"></line>
                                <line x1="9" y1="11" x2="15" y2="11"></line>
                            </svg>
                        </EmptyState>
                    </div>
                </Show>
            </div>
        </div>
    }
}
