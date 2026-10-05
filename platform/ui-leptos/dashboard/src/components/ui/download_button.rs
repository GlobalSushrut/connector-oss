//! DownloadButton — typed convenience over the binary-download pattern.
//!
//! Every "download X" affordance in the dashboard follows the same
//! recipe:
//!
//! ```ignore
//! match api::get_bytes(path).await {
//!     Ok(bytes) => trigger_download_bytes(&bytes, filename, mime),
//!     Err(e) => toast::error(format!("Download failed: {}", e)),
//! }
//! ```
//!
//! That's mechanical glue that every page re-implements differently.
//! `DownloadButton` collapses it into one composable primitive built on
//! the existing [`crate::components::ui::Button`]. The button manages
//! its own loading state, surfaces errors via the global toaster, and
//! triggers the download via the canonical [`crate::utils::
//! trigger_download_bytes`] helper.

use std::sync::Arc;

use leptos::ev::MouseEvent;
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::components::toaster::toast;
use crate::components::ui::{Button, ButtonSize, ButtonVariant};
use crate::utils::{stamp_download_filename, trigger_download_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadMethod {
    Get,
    Post,
}

impl Default for DownloadMethod {
    fn default() -> Self {
        DownloadMethod::Get
    }
}

/// One-click "fetch + download" button.
///
/// ```ignore
/// view! {
///     <DownloadButton
///         path="/compliance/brief/pdf".to_string()
///         filename="connector-compliance-brief.pdf".to_string()
///         mime="application/pdf".to_string()
///         variant=ButtonVariant::Primary
///     >
///         "Download brief"
///     </DownloadButton>
/// }
/// ```
#[component]
pub fn DownloadButton(
    /// API path (relative to `/api/v1`).
    #[prop(into)]
    path: String,
    /// Suggested filename for the downloaded file.
    #[prop(into)]
    filename: String,
    /// MIME type for the blob. Most callers will pass
    /// `"application/pdf"` or `"application/octet-stream"`.
    #[prop(into, default = "application/octet-stream".to_string())]
    mime: String,
    /// HTTP method. Defaults to GET. Use POST when the endpoint
    /// requires a request body (e.g. evidence-pack generation).
    #[prop(optional, into)]
    method: Signal<DownloadMethod>,
    /// Optional JSON body for POST requests. Ignored on GET.
    #[prop(optional, into, default = serde_json::Value::Null.into())]
    body: Signal<serde_json::Value>,
    /// Visual variant — defaults to `Outline` so the download is
    /// secondary to the primary "Generate" action when both are on
    /// the same row.
    #[prop(optional, into, default = ButtonVariant::Outline.into())]
    variant: Signal<ButtonVariant>,
    #[prop(optional, into)] size: Signal<ButtonSize>,
    /// Optional success toast text. Defaults to nothing (silent
    /// success — the browser's download tray is the confirmation).
    #[prop(optional, into)]
    success_toast: MaybeProp<String>,
    /// When true, insert a UTC stamp into the filename at click time
    /// (`report.pdf` → `report-20260821T163045Z.pdf`) so successive
    /// audit downloads do not overwrite each other.
    #[prop(optional, into, default = true.into())]
    stamp_filename: Signal<bool>,
    /// Optional callback fired after a successful download. Use to
    /// refresh a session-history list, mark "downloaded" state, etc.
    #[prop(optional, into)]
    on_success: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Extra utility classes appended to the button class string.
    #[prop(optional, into)]
    class: MaybeProp<String>,
    children: Children,
) -> impl IntoView {
    let busy = RwSignal::new(false);
    let label_view = children();

    let path = path;
    let filename = filename;
    let mime = mime;

    let on_click: Arc<dyn Fn(MouseEvent) + Send + Sync> = Arc::new(move |_| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let path = path.clone();
        let filename = filename.clone();
        let mime = mime.clone();
        let method = method.get_untracked();
        let body = body.get_untracked();
        let do_stamp = stamp_filename.get_untracked();
        let success_toast = success_toast.get();
        let on_success = on_success.clone();
        spawn_local(async move {
            let result = match method {
                DownloadMethod::Get => api::get_bytes(&path).await,
                DownloadMethod::Post => api::post_bytes(&path, body).await,
            };
            match result {
                Ok(bytes) => {
                    if mime.to_ascii_lowercase().contains("pdf") && !bytes.starts_with(b"%PDF-") {
                        toast::error(
                            "Server did not return a PDF (got JSON or HTML). The control-evidence endpoints must emit %PDF-.".to_string(),
                        );
                    } else {
                        let out_name = if do_stamp {
                            stamp_download_filename(&filename)
                        } else {
                            filename.clone()
                        };
                        trigger_download_bytes(&bytes, &out_name, &mime);
                        if let Some(msg) = success_toast.filter(|s| !s.is_empty()) {
                            toast::success(msg);
                        }
                        if let Some(cb) = on_success.as_ref() {
                            cb();
                        }
                    }
                }
                Err(e) => {
                    toast::error(format!("Download failed: {}", e.message));
                }
            }
            busy.set(false);
        });
    });

    view! {
        <Button
            variant=variant
            size=size
            loading=busy
            on_click=on_click
            class=class
        >
            {label_view}
        </Button>
    }
}
