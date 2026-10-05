//! Dashboard static UI: in **lab / dev** mode, inject `data-dev="1"` on the SPA `index.html` for
//! operators who want an explicit flag. The Leptos login **defaults to showing Dev Bypass** when
//! `data-dev` is absent; set `data-dev="0"` (or `false` / `off` / `no`) on `<html>` to hide it in
//! hardened builds. See [`runtime_control::operator_lab_auth_gate`].

use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use bytes::Bytes;
use std::convert::Infallible;
use std::future::{ready, Ready};
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;

use crate::services::runtime_control;
use crate::state::SharedState;

/// When true, the dashboard SPA fallback serves HTML with `data-dev="1"` on `<html>`.
///
/// Injects the Leptos **Dev Bypass** login control. Normally follows [`runtime_control::operator_lab_auth_gate`].
/// Set **`CONNECTOR_DASHBOARD_LAB_HTML=1`** when your process env is correct but persisted control-plane
/// mode / `connector.yaml` left `CONNECTOR_ENV=production` (so preset cannot `set_if_absent` override),
/// or when the platform is started from an IDE that does not inherit your shell exports.
pub fn dashboard_dev_html_enabled(state: &SharedState) -> bool {
    // Never inject data-dev on playground — it would trigger dev_bypass in the WASM
    // and break the trial email → session → plugin navigation flow.
    if std::env::var("CONNECTOR_PRESET")
        .map(|v| v.eq_ignore_ascii_case("playground"))
        .unwrap_or(false)
    {
        return false;
    }
    if runtime_control::defense_strict_enabled() {
        return false;
    }
    if std::env::var("CONNECTOR_DASHBOARD_LAB_HTML")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return true;
    }
    let mode = *state.runtime_mode.read().unwrap();
    runtime_control::operator_lab_auth_gate(mode)
}

fn html_needs_data_dev(html: &str) -> bool {
    !html.contains("data-dev=\"1\"")
        && !html.contains("data-dev='1'")
        && !html.contains("data-dev=\"true\"")
        && !html.contains("data-dev='true'")
}

/// Insert `data-dev="1"` before the first `>` of the opening `<html` tag (ASCII-safe).
pub(crate) fn ensure_data_dev_html(html: &str) -> String {
    if !html_needs_data_dev(html) {
        return html.to_string();
    }
    let lower = html.to_ascii_lowercase();
    let Some(start) = lower.find("<html") else {
        return html.to_string();
    };
    let after_open = start + "<html".len();
    let rest = &html[after_open..];
    let Some(gt_rel) = rest.find('>') else {
        return html.to_string();
    };
    let insert_at = after_open + gt_rel;
    let mut out = String::with_capacity(html.len() + 24);
    out.push_str(&html[..insert_at]);
    out.push_str(" data-dev=\"1\"");
    out.push_str(&html[insert_at..]);
    out
}

/// [`tower_http::services::ServeDir`] fallback: always returns the patched index bytes.
#[derive(Clone)]
pub struct DevIndexFallback {
    html: Arc<Bytes>,
}

impl DevIndexFallback {
    pub fn new(html: Arc<Bytes>) -> Self {
        Self { html }
    }
}

impl Service<Request<Body>> for DevIndexFallback {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Ready<Result<Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        let res = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(self.html.as_ref().clone()))
            .expect("valid index response");
        ready(Ok(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_data_dev_after_html_open_tag() {
        let raw = "<!DOCTYPE html>\n<html lang=\"en\">\n<head></head></html>";
        let out = ensure_data_dev_html(raw);
        assert!(out.contains("data-dev=\"1\""));
        assert!(out.contains("<html lang=\"en\" data-dev=\"1\">") || out.contains("<html lang=\"en\" data-dev=\"1\""));
    }

    #[test]
    fn idempotent_when_already_set() {
        let raw = "<html lang=\"en\" data-dev=\"1\">";
        assert_eq!(ensure_data_dev_html(raw), raw);
    }
}
