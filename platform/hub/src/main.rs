//! `connector-hub` — minimal HTTP registry for `.cpkg` (Phase 4.3).
//!
//! ```text
//! CONNECTOR_HUB_DATA_DIR=./data/hub CONNECTOR_HUB_BIND=127.0.0.1:19100 CONNECTOR_HUB_PUBLISH_TOKEN=… cargo run --bin connector-hub
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use connector_hub::{hub_data_dir, HubState};
use serde::Deserialize;
use tower_http::trace::TraceLayer;

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
}

#[derive(Deserialize)]
struct CpkgQuery {
    plugin_id: String,
    version: String,
}

#[derive(Deserialize)]
struct LatestQuery {
    plugin_id: String,
}

#[derive(Deserialize)]
struct YankBody {
    plugin_id: String,
    version: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let data_dir = hub_data_dir();
    let _ = tokio::fs::create_dir_all(&data_dir).await;
    let state = HubState::load_or_empty(data_dir).await;

    let expected_publish =
        std::env::var("CONNECTOR_HUB_PUBLISH_TOKEN").ok().filter(|s| !s.is_empty());

    let app = Router::new()
        .route("/health", get(|| async { Json(serde_json::json!({"ok": true, "service": "connector-hub"})) }))
        .route("/v1/search", get(search))
        .route("/v1/latest", get(latest))
        .route("/v1/cpkg", get(download_cpkg))
        .route("/v1/publish", post(publish))
        .route("/v1/yank", post(yank))
        .layer(TraceLayer::new_for_http())
        .with_state((state, expected_publish));

    let bind = std::env::var("CONNECTOR_HUB_BIND").unwrap_or_else(|_| "127.0.0.1:19100".into());
    let addr: SocketAddr = bind.parse().expect("CONNECTOR_HUB_BIND");
    tracing::info!(%addr, "connector-hub listening");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

type AppState = (Arc<HubState>, Option<String>);

async fn search(
    State((hub, _)): State<AppState>,
    Query(q): Query<SearchParams>,
) -> Json<serde_json::Value> {
    let rows = hub.search(q.q.as_deref()).await;
    Json(serde_json::json!({ "ok": true, "packages": rows }))
}

async fn latest(
    State((hub, _)): State<AppState>,
    Query(q): Query<LatestQuery>,
) -> Json<serde_json::Value> {
    let v = hub.latest_version(&q.plugin_id).await;
    Json(serde_json::json!({ "ok": true, "plugin_id": q.plugin_id, "version": v }))
}

async fn download_cpkg(
    State((hub, _)): State<AppState>,
    Query(q): Query<CpkgQuery>,
) -> Result<Bytes, StatusCode> {
    let bytes = hub
        .get_version_bytes(&q.plugin_id, &q.version)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    hub.record_package_download(&q.plugin_id, &q.version).await;
    Ok(Bytes::from(bytes))
}

async fn publish(
    State((hub, token)): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let row = hub
        .publish_cpkg(&body, auth.as_deref(), token.as_deref())
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({ "ok": true, "package": row })))
}

async fn yank(
    State((hub, token)): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<YankBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    match (&token, &auth) {
        (Some(exp), Some(got)) if exp.as_str() != got.as_str() => {
            return Err((StatusCode::UNAUTHORIZED, "invalid publish token".into()));
        }
        (Some(_), None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "hub requires Authorization: Bearer (CONNECTOR_HUB_PUBLISH_TOKEN)".into(),
            ));
        }
        _ => {}
    }
    hub.yank(&body.plugin_id, &body.version)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({"ok": true})))
}
