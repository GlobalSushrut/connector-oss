use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use connector_engine::surface::SurfaceType;
use serde::Deserialize;

use crate::{
    auth::{self, PlatformRole},
    error::error_response,
    services::{surface_http, surface_monitor_live},
    state::SharedState,
};

fn default_page() -> usize {
    1
}

fn default_page_size() -> usize {
    50
}

#[derive(Deserialize, Default)]
pub struct SurfaceApiQuery {
    #[serde(default)]
    pub view: Option<String>,
    #[serde(default)]
    pub time: Option<String>,
    #[serde(default = "default_page")]
    pub page: usize,
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    #[serde(default)]
    pub filter: Vec<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub sort: Vec<String>,
}

fn caller(headers: &HeaderMap) -> Option<(String, PlatformRole)> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Some(("dev".to_string(), PlatformRole::SuperAdmin));
    }
    if let Some(api_key) = headers.get("x-api-key").and_then(|h| h.to_str().ok()) {
        if let Ok(user_id) = auth::validate_api_key(api_key) {
            return Some((user_id, PlatformRole::Service));
        }
    }
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))?;
    let claims = auth::verify_token(token).ok()?;
    Some((claims.sub, PlatformRole::from_str(&claims.role)))
}

fn to_surface_role(role: PlatformRole) -> connector_engine::surface::Role {
    match role {
        PlatformRole::SuperAdmin => connector_engine::surface::Role::System,
        PlatformRole::Admin => connector_engine::surface::Role::Auditor,
        PlatformRole::Operator => connector_engine::surface::Role::Operator,
        PlatformRole::Developer => connector_engine::surface::Role::Developer,
        PlatformRole::Viewer => connector_engine::surface::Role::Executive,
        PlatformRole::Service => connector_engine::surface::Role::System,
    }
}

fn parse_surface_type(surface: &str) -> Option<connector_engine::surface::SurfaceType> {
    use connector_engine::surface::SurfaceType;

    match surface.to_ascii_lowercase().as_str() {
        "agent" => Some(SurfaceType::Agent),
        "audit" => Some(SurfaceType::Audit),
        "memory" => Some(SurfaceType::Memory),
        "knowledge" => Some(SurfaceType::Knowledge),
        "policy" => Some(SurfaceType::Policy),
        "tool" => Some(SurfaceType::Tool),
        "contract" => Some(SurfaceType::Contract),
        "proof" | "prove" | "verify" => Some(SurfaceType::Proof),
        "compliance" => Some(SurfaceType::Compliance),
        "health" => Some(SurfaceType::Health),
        "books" => Some(SurfaceType::Books),
        "debug" => Some(SurfaceType::Debug),
        "trace" => Some(SurfaceType::Trace),
        "inspect" => Some(SurfaceType::Inspect),
        "review" | "risk" => Some(SurfaceType::Review),
        "explain" => Some(SurfaceType::Explain),
        "monitor" | "cost" => Some(SurfaceType::Monitor),
        // Dashboard uses GET /surfaces/overview/system — same renderer as Monitor (system cost/ops posture).
        "overview" | "dashboard" => Some(SurfaceType::Monitor),
        _ => None,
    }
}

fn parse_surface_view(
    value: Option<&str>,
    role: connector_engine::surface::Role,
) -> Result<connector_engine::surface::SurfaceView, String> {
    use connector_engine::surface::SurfaceView;

    match value.map(|v| v.to_ascii_lowercase()) {
        None => Ok(role.default_view()),
        Some(v) if v == "summary" => Ok(SurfaceView::Summary),
        Some(v) if v == "ops" => Ok(SurfaceView::Ops),
        Some(v) if v == "forensic" => Ok(SurfaceView::Forensic),
        Some(v) if v == "exec" => Ok(SurfaceView::Exec),
        Some(v) => Err(format!("unsupported view '{}'", v)),
    }
}

fn build_surface_query(
    params: &SurfaceApiQuery,
) -> Result<Option<connector_engine::surface::Query>, String> {
    use connector_engine::surface::{
        Filter, Query as SurfaceQuery, SearchQuery, Sort, SortDirection,
    };

    let explicit = params.page != 1
        || params.page_size != default_page_size()
        || !params.filter.is_empty()
        || params.search.is_some()
        || !params.sort.is_empty();
    if !explicit {
        return Ok(None);
    }

    let mut query = SurfaceQuery::new().paginate(params.page.max(1), params.page_size.max(1));
    if let Some(search) = &params.search {
        query = query.search(SearchQuery::new(search));
    }
    for filter in &params.filter {
        let parsed = Filter::parse(filter)
            .ok_or_else(|| format!("invalid filter expression '{}'", filter))?;
        query = query.filter(parsed);
    }
    for sort in &params.sort {
        let sort = sort.trim();
        let parsed = if let Some(field) = sort.strip_prefix('-') {
            Sort {
                field: field.to_string(),
                direction: SortDirection::Desc,
            }
        } else if let Some((field, direction)) = sort.split_once(':') {
            Sort {
                field: field.to_string(),
                direction: if direction.eq_ignore_ascii_case("desc") {
                    SortDirection::Desc
                } else {
                    SortDirection::Asc
                },
            }
        } else {
            Sort::asc(sort)
        };
        query = query.sort_by(parsed);
    }
    Ok(Some(query))
}

fn parse_surface_time(
    value: Option<&str>,
) -> Result<connector_engine::surface::SurfaceTimeSelector, String> {
    use connector_engine::surface::SurfaceTimeSelector;

    match value {
        None => Ok(SurfaceTimeSelector::Now),
        Some(v) => SurfaceTimeSelector::parse(v)
            .ok_or_else(|| format!("unsupported time selector '{}'", v)),
    }
}

/// GET `/surfaces/:surface/:subject_id`
/// Authenticated, role-aware SOE JSON endpoint for integrations and dashboards.
pub async fn render_surface_json(
    State(state): State<SharedState>,
    Path((surface, subject_id)): Path<(String, String)>,
    Query(params): Query<SurfaceApiQuery>,
    headers: HeaderMap,
) -> Response {
    let (user_id, platform_role) = match caller(&headers) {
        Some(caller) => caller,
        None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "Valid Bearer token or x-api-key required for /surfaces/*",
            )
        }
    };

    let Some(surface_type) = parse_surface_type(&surface) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "surface_type_invalid",
            &format!("Unsupported surface '{}'", surface),
        );
    };

    let surface_role = to_surface_role(platform_role);
    let view = match parse_surface_view(params.view.as_deref(), surface_role) {
        Ok(view) => view,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, "surface_view_invalid", &e),
    };
    let time = match parse_surface_time(params.time.as_deref()) {
        Ok(time) => time,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, "surface_time_invalid", &e),
    };
    let query = match build_surface_query(&params) {
        Ok(query) => query,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, "surface_query_invalid", &e),
    };

    let mut engine = connector_engine::surface::SurfaceEngine::default();
    let mut request = connector_engine::surface::RenderRequest::new(
        surface_type,
        &subject_id,
        "api-surface",
        surface_role,
    )
    .view(view)
    .time(time);
    if let Some(query) = query {
        request = request.query(query);
    }

    let st_token = surface_http::surface_type_token(surface_type);
    let role_label = if crate::services::runtime_control::dev_auth_bypass_allowed() {
        "dev"
    } else {
        surface_http::platform_role_token(platform_role)
    };

    match engine.render(request) {
        Ok(result) => {
            let json_str = result.to_json_with_meta(Some(st_token), Some(role_label));
            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(mut v) => {
                    if surface_type == SurfaceType::Monitor {
                        surface_monitor_live::apply_monitor_surface_live_overlay(
                            &mut v, &state, &user_id,
                        );
                    }
                    let mut res = (StatusCode::OK, Json(v)).into_response();
                    surface_http::extend_surface_operator_headers(
                        res.headers_mut(),
                        st_token,
                        surface_http::surface_view_token(view),
                        &subject_id,
                        role_label,
                    );
                    res
                }
                Err(e) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "surface_json_encode_failed",
                    &e.to_string(),
                ),
            }
        }
        Err(e) => surface_http::render_error_to_response(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_platform_roles_to_surface_roles() {
        assert!(matches!(
            to_surface_role(PlatformRole::Admin),
            connector_engine::surface::Role::Auditor
        ));
        assert!(matches!(
            to_surface_role(PlatformRole::Viewer),
            connector_engine::surface::Role::Executive
        ));
    }

    #[test]
    fn parses_surface_query_components() {
        let params = SurfaceApiQuery {
            page: 2,
            page_size: 10,
            filter: vec!["severity=critical".into()],
            search: Some("policy".into()),
            sort: vec!["-timestamp".into()],
            ..Default::default()
        };
        let query = build_surface_query(&params)
            .expect("query should parse")
            .expect("query should exist");
        assert_eq!(query.page.page, 2);
        assert_eq!(query.page.page_size, 10);
        assert_eq!(query.filters.len(), 1);
        assert_eq!(query.sort.len(), 1);
        assert!(query.search.is_some());
    }
}
