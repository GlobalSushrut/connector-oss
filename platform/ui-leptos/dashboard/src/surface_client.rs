use serde_json::Value;

use crate::api::{self, ApiError};

/// Fetch a canonical surface package from `/api/v1/surfaces/:surface/:subject_id`.
pub async fn fetch_surface_value(
    surface: &str,
    subject_id: &str,
    view: Option<&str>,
) -> Result<Value, ApiError> {
    let mut path = format!("/surfaces/{}/{}", surface, subject_id);
    if let Some(v) = view {
        if !v.is_empty() {
            path = format!("{}?view={}", path, v);
        }
    }
    api::get_value(&path).await
}

/// Convenience helper for the default `overview` surface against the `system` subject.
pub async fn overview_system() -> Result<Value, ApiError> {
    fetch_surface_value("overview", "system", None).await
}
