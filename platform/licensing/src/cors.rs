//! Production CORS — restrict to portal, admin, and marketing origins.
use axum::http::{HeaderValue, Method};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

pub fn cors_layer() -> CorsLayer {
    let raw = std::env::var("CONNECTOR_CORS_ORIGINS").unwrap_or_else(|_| {
        [
            "https://portal.cnktros.com",
            "https://admin.cnktros.com",
            "https://api.cnktros.com",
            "https://cnktros.com",
            "https://www.cnktros.com",
            "http://localhost:1420",
            "http://127.0.0.1:1420",
        ]
        .join(",")
    });
    if raw.trim() == "*" {
        return CorsLayer::permissive();
    }
    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();
    if origins.is_empty() {
        return CorsLayer::permissive();
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::any())
}
