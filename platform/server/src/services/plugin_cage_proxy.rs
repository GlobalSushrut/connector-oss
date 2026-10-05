//! Reverse proxy at **`/plugin/<slug>/*`** (Phase 1.4a): rewrites `Host` to the cage hostname,
//! injects the kernel-side admin bearer (same env vars as `/api/v1/plugins/*/…` proxies), and
//! forwards to the address registered in [`crate::internal_dns`] for `<slug>.<CONNECTOR_CAGE_TLD>`.

use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::internal_dns;
use crate::services::plugin_matrix;
use crate::state::SharedState;

fn http_client() -> reqwest::Client {
    static C: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(90))
            .connect_timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("plugin cage reqwest client")
    })
    .clone()
}

fn bearer_for_plugin(slug: &str) -> Option<String> {
    match slug {
        "tracetramp" => std::env::var("CONNECTOR_TRACETRAMP_ADMIN_TOKEN")
            .or_else(|_| std::env::var("TRACETRAMP_ADMIN_TOKEN"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        "witnessctl" => std::env::var("CONNECTOR_WITNESSCTL_ADMIN_TOKEN")
            .or_else(|_| std::env::var("WITNESSCTL_ADMIN_TOKEN"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        "devguard" => None,
        _ => None,
    }
}

fn slug_ok(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// `GET/POST/… /plugin/{*rest}` — `rest` is `tracetramp/admin/stats` after the `/plugin/` nest strip.
pub async fn plugin_cage_forward(
    State(state): State<SharedState>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    if let Err(code) = crate::substrate::cage_security::assert_cage_isolation_grade(state.as_ref())
    {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "isolation_grade_insufficient",
            code,
        );
    }
    let raw_path = uri.path().trim_start_matches('/');
    if raw_path.is_empty() {
        return json_err(
            StatusCode::NOT_FOUND,
            "plugin_cage_missing_slug",
            "Expected /plugin/<slug>/…",
        );
    }
    let (slug, tail) = match raw_path.split_once('/') {
        Some((s, t)) => (s, t),
        None => (raw_path, ""),
    };
    let slug_lc = slug.to_ascii_lowercase();
    if !slug_ok(&slug_lc) {
        return json_err(
            StatusCode::BAD_REQUEST,
            "plugin_cage_bad_slug",
            "Invalid plugin slug",
        );
    }
    if !plugin_matrix::is_gated_plugin_segment(&slug_lc) {
        return json_err(
            StatusCode::NOT_FOUND,
            "plugin_cage_unknown",
            "Unknown first-party plugin slug",
        );
    }
    if !plugin_matrix::is_plugin_enabled(&slug_lc) {
        return json_err(
            StatusCode::FORBIDDEN,
            "plugin_not_in_deployment",
            "Plugin is disabled for this deployment (CONNECTOR_PLUGINS_ENABLED)",
        );
    }

    let claims = match crate::substrate::cage_security::assert_cage_principal_binding(
        &headers, &slug_lc, &method,
    ) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let cage_host = internal_dns::plugin_cage_hostname(&slug_lc);
    let Some(target) = internal_dns::resolve_cage_hostname(&cage_host) else {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "plugin_cage_unresolved",
            "Internal DNS has no socket for this cage host yet",
        );
    };

    let up_path = if tail.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", tail.trim_start_matches('/'))
    };
    let mut url = format!("http://{target}{up_path}");
    if let Some(q) = uri.query() {
        url.push('?');
        url.push_str(q);
    }

    let rb = http_client()
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &url,
        )
        .header("Host", cage_host.as_str());

    let rb = if let Some(tok) = bearer_for_plugin(&slug_lc) {
        rb.header(header::AUTHORIZATION, format!("Bearer {tok}"))
    } else if slug_lc != "devguard" {
        return json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "plugin_cage_no_bearer",
            "Set the CONNECTOR_*_ADMIN_TOKEN env for this plugin on the platform process (same as /api/v1/plugins proxy).",
        );
    } else {
        rb
    };

    let rb = crate::substrate::outbound::stamp_reqwest(
        crate::substrate::cage_security::stamp_cage_upstream(
            rb,
            &claims,
            &slug_lc,
            method.as_str(),
            &up_path,
        ),
        &headers,
    );
    let rb = forward_content_headers(rb, &headers);

    let body_bytes = match axum::body::to_bytes(body, 2 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return json_err(
                StatusCode::BAD_REQUEST,
                "plugin_cage_body",
                &format!("Body read error: {e}"),
            );
        }
    };

    let rb = if body_bytes.is_empty() {
        rb
    } else {
        rb.body(body_bytes.to_vec())
    };

    let mutating = cage_mutation(&method);
    let mut open = if mutating {
        match crate::substrate::pate::require_proceed(
            &state,
            "node",
            "lifecycle",
            "plugin_cage",
            &json!({"method": method.as_str(), "slug": slug_lc.as_str()}),
        ) {
            Ok(atu) => Some(crate::substrate::pate::OpenProceed::arm(&state, &atu)),
            Err(body) => return (StatusCode::OK, Json(body)).into_response(),
        }
    } else {
        None
    };

    let upstream = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            return json_err(
                StatusCode::BAD_GATEWAY,
                "plugin_cage_upstream",
                &e.to_string(),
            );
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut res = Response::builder().status(status);
    for (k, v) in upstream.headers().iter() {
        if is_hop_header(k.as_str()) {
            continue;
        }
        if let Ok(val) = HeaderValue::from_bytes(v.as_bytes()) {
            res = res.header(k.as_str(), val);
        }
    }
    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(e) => {
            if let Some(guard) = open.as_mut() {
                guard.finish_observed(false);
            }
            return json_err(
                StatusCode::BAD_GATEWAY,
                "plugin_cage_read_body",
                &e.to_string(),
            );
        }
    };
    if let Some(guard) = open.as_mut() {
        guard.finish_observed(status.is_success());
    }
    match res.body(Body::from(bytes)) {
        Ok(r) => r.into_response(),
        Err(_) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "plugin_cage_build",
            "response build",
        )
        .into_response(),
    }
}

fn forward_content_headers(
    mut rb: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for key in ["content-type", "accept", "accept-language", "user-agent"] {
        if let Some(v) = headers.get(key) {
            if let Ok(s) = v.to_str() {
                rb = rb.header(key, s);
            }
        }
    }
    rb
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn cage_mutation(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn json_err(status: StatusCode, code: &'static str, message: &str) -> Response {
    let body = json!({
        "ok": false,
        "error": { "code": code, "message": message, "status": status.as_u16() }
    });
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mutations_open_a_cage_task() {
        assert!(cage_mutation(&Method::POST));
        assert!(cage_mutation(&Method::PUT));
        assert!(cage_mutation(&Method::PATCH));
        assert!(cage_mutation(&Method::DELETE));
        assert!(!cage_mutation(&Method::GET));
        assert!(!cage_mutation(&Method::HEAD));
    }
}
