//! Request body size limits middleware.
//!
//! Limits (configurable via env):
//!   CONNECTOR_MAX_BODY_SIZE_MB — default 10 MB for general requests
//!   CONNECTOR_MAX_UPLOAD_SIZE_MB — default 100 MB for file uploads
//!
//! Returns 413 Payload Too Large when limit exceeded.

use tower_http::limit::RequestBodyLimitLayer;

/// Default max body size: 10 MB
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Default max upload size: 100 MB (for file imports, memory imports, etc.)
pub const DEFAULT_MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024;

fn size_from_env(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(default)
}

/// Returns a layer that limits request body size to the configured max.
/// Use for general API routes.
pub fn body_limit_layer() -> RequestBodyLimitLayer {
    let max_bytes = size_from_env("CONNECTOR_MAX_BODY_SIZE_MB", DEFAULT_MAX_BODY_SIZE);
    RequestBodyLimitLayer::new(max_bytes)
}

/// Returns a layer for upload routes with higher limits.
/// Use for file upload, memory import, etc.
pub fn upload_limit_layer() -> RequestBodyLimitLayer {
    let max_bytes = size_from_env("CONNECTOR_MAX_UPLOAD_SIZE_MB", DEFAULT_MAX_UPLOAD_SIZE);
    RequestBodyLimitLayer::new(max_bytes)
}

/// Returns the configured limits as a JSON-serializable struct for documentation.
pub fn limits_info() -> BodyLimitsInfo {
    // size_from_env returns bytes, divide by 1MB to get MB
    let body_bytes = size_from_env("CONNECTOR_MAX_BODY_SIZE_MB", DEFAULT_MAX_BODY_SIZE);
    let upload_bytes = size_from_env("CONNECTOR_MAX_UPLOAD_SIZE_MB", DEFAULT_MAX_UPLOAD_SIZE);
    BodyLimitsInfo {
        max_body_size_mb: body_bytes / (1024 * 1024),
        max_upload_size_mb: upload_bytes / (1024 * 1024),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BodyLimitsInfo {
    pub max_body_size_mb: usize,
    pub max_upload_size_mb: usize,
}
