//! Shared HTTP helpers for SOE JSON routes — see `platform/docs/SURFACE_OPERATOR_PLAYBOOK.md` §5.

use axum::http::{header, HeaderMap, HeaderName, HeaderValue};
use connector_engine::surface::{SurfaceType, SurfaceView};

use crate::auth::PlatformRole;

const MAX_SUBJECT_HEADER_LEN: usize = 256;

pub fn surface_type_token(t: SurfaceType) -> &'static str {
    match t {
        SurfaceType::Agent => "agent",
        SurfaceType::Audit => "audit",
        SurfaceType::Memory => "memory",
        SurfaceType::Knowledge => "knowledge",
        SurfaceType::Policy => "policy",
        SurfaceType::Tool => "tool",
        SurfaceType::Contract => "contract",
        SurfaceType::Proof => "proof",
        SurfaceType::Compliance => "compliance",
        SurfaceType::Health => "health",
        SurfaceType::Books => "books",
        SurfaceType::Debug => "debug",
        SurfaceType::Trace => "trace",
        SurfaceType::Inspect => "inspect",
        SurfaceType::Review => "review",
        SurfaceType::Explain => "explain",
        SurfaceType::Monitor => "monitor",
    }
}

pub fn surface_view_token(v: SurfaceView) -> &'static str {
    match v {
        SurfaceView::Summary => "summary",
        SurfaceView::Ops => "ops",
        SurfaceView::Forensic => "forensic",
        SurfaceView::Exec => "exec",
    }
}

pub fn platform_role_token(role: PlatformRole) -> &'static str {
    match role {
        PlatformRole::SuperAdmin => "super_admin",
        PlatformRole::Admin => "admin",
        PlatformRole::Operator => "operator",
        PlatformRole::Developer => "developer",
        PlatformRole::Viewer => "viewer",
        PlatformRole::Service => "service",
    }
}

fn sanitize_subject_for_header(subject_id: &str) -> String {
    let t = subject_id.trim();
    let t: String = t
        .chars()
        .filter(|c| {
            let b = *c as u32;
            (0x20..=0x7e).contains(&b) && *c != '"'
        })
        .take(MAX_SUBJECT_HEADER_LEN)
        .collect();
    if t.is_empty() {
        "_".to_string()
    } else {
        t
    }
}

/// Operator headers on successful SOE JSON responses.
pub fn extend_surface_operator_headers(
    headers: &mut HeaderMap,
    surface_type: &str,
    view: &str,
    subject_id: &str,
    caller_role: &str,
) {
    let subject = sanitize_subject_for_header(subject_id);
    let mut insert = |name: &str, val: &str| {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(val),
        ) {
            headers.insert(name, val);
        }
    };

    insert("x-connector-surface-type", surface_type);
    insert("x-connector-surface-view", view);
    insert("x-connector-surface-subject", &subject);
    insert("x-connector-caller-role", caller_role);

    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// Structured surface error envelope — richer than `error_response` for operator diagnostics.
pub fn surface_error_response(
    status: axum::http::StatusCode,
    code: &str,
    message: &str,
    hint: Option<&str>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let envelope = serde_json::json!({
        "ok": false,
        "error": {
            "code":    code,
            "message": message,
            "status":  status.as_u16(),
            "docs":    format!("https://connector.ai/docs/errors/{}", code),
            "hint":    hint,
        }
    });
    (status, axum::Json(envelope)).into_response()
}

pub fn render_error_to_response(
    e: &connector_engine::surface::RenderError,
) -> axum::response::Response {
    use connector_engine::surface::RenderError;

    let (status, code, hint) = match e {
        RenderError::PolicyDenied(_) => (
            axum::http::StatusCode::FORBIDDEN,
            "surface_policy_denied",
            Some("Check caller role permissions; forensic view requires Auditor or System role."),
        ),
        RenderError::ContractViolation { .. } => (
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "surface_contract_violation",
            Some("The engine produced a surface that fails the contract (e.g. <3 signals). This is a server-side bug — file an issue."),
        ),
        RenderError::SubjectNotFound(_) => (
            axum::http::StatusCode::NOT_FOUND,
            "surface_subject_not_found",
            Some("Verify the subject_id path segment matches a registered agent PID or resource key."),
        ),
        RenderError::TimeRangeInvalid(_) => (
            axum::http::StatusCode::BAD_REQUEST,
            "surface_time_invalid",
            Some("Use a supported time selector: now, @<ts>, since:<ts>, before:<ts>, range:<start>..<end>, last:15m."),
        ),
        RenderError::KernelError(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "surface_kernel_error",
            Some("Internal kernel failure. Retry or check server logs."),
        ),
        RenderError::InternalError(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "surface_internal_error",
            None,
        ),
    };

    surface_error_response(status, code, &e.to_string(), hint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_headers_set_surface_and_cache_control() {
        let mut h = HeaderMap::new();
        extend_surface_operator_headers(&mut h, "agent", "ops", "my-agent", "admin");
        assert_eq!(
            h.get("x-connector-surface-type")
                .and_then(|v| v.to_str().ok()),
            Some("agent")
        );
        assert_eq!(
            h.get("x-connector-surface-view")
                .and_then(|v| v.to_str().ok()),
            Some("ops")
        );
        assert_eq!(
            h.get("x-connector-caller-role")
                .and_then(|v| v.to_str().ok()),
            Some("admin")
        );
        assert_eq!(
            h.get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    #[test]
    fn subject_header_sanitizes_non_ascii() {
        let mut h = HeaderMap::new();
        extend_surface_operator_headers(&mut h, "memory", "summary", "bad\u{1f600}id", "viewer");
        let sub = h
            .get("x-connector-surface-subject")
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(!sub.contains('\u{1f600}'));
    }
}
