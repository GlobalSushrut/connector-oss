//! Dashboard `dist/` embedded at compile time (Phase 1.5).
//!
//! `build.rs` copies `platform/ui-leptos/dashboard/dist` into `OUT_DIR/dashboard_embed`, or a small
//! tracked stub when dist is absent, so `include_dir!` always succeeds (CI + clean checkouts).

use axum::body::Body;
use axum::http::{header, Method, Request, Response, StatusCode};
use bytes::Bytes;
use include_dir::{include_dir, Dir};
use std::convert::Infallible;
use std::sync::Arc;

static DASHBOARD: Dir<'static> = include_dir!("$OUT_DIR/dashboard_embed");

/// Raw `index.html` bytes from the embedded tree (for dev HTML patching).
pub fn index_html_raw() -> &'static [u8] {
    DASHBOARD
        .get_file("index.html")
        .map(|f| f.contents())
        .unwrap_or_default()
}

/// True when build.rs staged the tracked stub instead of a real Trunk dist.
pub fn is_stub_embed() -> bool {
    let html = std::str::from_utf8(index_html_raw()).unwrap_or("");
    html.contains("Dashboard assets not built") || html.contains("dashboard-embed-stub")
}

/// Operator label: `embedded` or `embedded-stub`.
pub fn embed_mount_label() -> &'static str {
    if is_stub_embed() {
        "embedded-stub"
    } else {
        "embedded"
    }
}

fn mime_for_path(rel: &str) -> &'static str {
    let l = rel.to_ascii_lowercase();
    if l.ends_with(".js") {
        return "application/javascript; charset=utf-8";
    }
    if l.ends_with(".mjs") {
        return "application/javascript; charset=utf-8";
    }
    if l.ends_with(".css") {
        return "text/css; charset=utf-8";
    }
    if l.ends_with(".wasm") {
        return "application/wasm";
    }
    if l.ends_with(".html") {
        return "text/html; charset=utf-8";
    }
    if l.ends_with(".png") {
        return "image/png";
    }
    if l.ends_with(".svg") {
        return "image/svg+xml";
    }
    if l.ends_with(".ico") {
        return "image/x-icon";
    }
    if l.ends_with(".json") {
        return "application/json; charset=utf-8";
    }
    if l.ends_with(".woff2") {
        return "font/woff2";
    }
    if l.ends_with(".txt") {
        return "text/plain; charset=utf-8";
    }
    "application/octet-stream"
}

/// Serve a file from the embedded tree, or the patched SPA `index` for client routes / missing hashed assets policy.
pub async fn serve_embedded_or_spa(
    req: Request<Body>,
    spa_index: Arc<Bytes>,
) -> Result<Response<Body>, Infallible> {
    let method = req.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .unwrap());
    }

    let key = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('?')
        .next()
        .unwrap_or("")
        .to_string();

    let (bytes, ctype, status) = if key.is_empty() {
        (spa_index.as_ref().clone(), "text/html; charset=utf-8", StatusCode::OK)
    } else if let Some(f) = DASHBOARD.get_file(&key) {
        (
            Bytes::copy_from_slice(f.contents()),
            mime_for_path(&key),
            StatusCode::OK,
        )
    } else if key.contains('.') {
        (
            Bytes::from_static(b"Not Found\n"),
            "text/plain; charset=utf-8",
            StatusCode::NOT_FOUND,
        )
    } else {
        (
            spa_index.as_ref().clone(),
            "text/html; charset=utf-8",
            StatusCode::OK,
        )
    };

    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };

    // Hashed assets (filename embeds content hash) get 1-year immutable cache.
    // HTML (SPA index) must never be cached so users always get fresh routing.
    let is_hashed = crate::router::is_content_hashed_asset(&key);
    let cache_control = if is_hashed {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache, no-store, must-revalidate"
    };

    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, ctype)
        .header(header::CACHE_CONTROL, cache_control)
        .body(body)
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_tree_has_index() {
        assert!(
            DASHBOARD.get_file("index.html").is_some(),
            "build.rs must stage index.html into OUT_DIR/dashboard_embed"
        );
    }
}
