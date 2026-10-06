//! Regional custody node — receives replicate requests and signs proofs.
//!
//! Usage:
//!   WITNESSCTL_CUSTODY_NODE_SECRET=... WITNESSCTL_CUSTODY_NODE_ID=eu-west-1 \
//!     WITNESSCTL_CUSTODY_NODE_PORT=7444 witnessctl-node

use axum::{routing::post, Json, Router};
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "witnessctl_node=info".into()),
        )
        .init();

    let secret = std::env::var("WITNESSCTL_CUSTODY_NODE_SECRET")
        .or_else(|_| std::env::var("WITNESSCTL_HMAC_SECRET"))
        .map_err(|_| anyhow::anyhow!("set WITNESSCTL_CUSTODY_NODE_SECRET or WITNESSCTL_HMAC_SECRET"))?;
    let node_id = std::env::var("WITNESSCTL_CUSTODY_NODE_ID").unwrap_or_else(|_| "custody-node-1".to_string());
    let region = std::env::var("WITNESSCTL_CUSTODY_NODE_REGION").unwrap_or_else(|_| "local".to_string());
    let port: u16 = std::env::var("WITNESSCTL_CUSTODY_NODE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7444);

    let state = std::sync::Arc::new(NodeState {
        secret,
        node_id: node_id.clone(),
        region,
    });

    let app = Router::new()
        .route("/health", axum::routing::get(health))
        .route("/api/v1/custody/replicate", post(replicate))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("witnessctl-node {} listening on {}", node_id, addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

struct NodeState {
    secret: String,
    node_id: String,
    region: String,
}

async fn health(
    axum::extract::State(st): axum::extract::State<std::sync::Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "witnessctl-node",
        "node_id": st.node_id,
        "region": st.region,
    }))
}

async fn replicate(
    axum::extract::State(st): axum::extract::State<std::sync::Arc<NodeState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<witnessctl::custody_node::ReplicateRequest>,
) -> Result<Json<witnessctl::custody_node::ReplicateResponse>, (axum::http::StatusCode, String)> {
    let provided = headers
        .get("x-witnessctl-custody-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != st.secret {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            "invalid custody secret".to_string(),
        ));
    }
    let proof = witnessctl::custody_node::build_proof_from_request(&body, &st.node_id, &st.secret);
    Ok(Json(witnessctl::custody_node::ReplicateResponse {
        ok: true,
        proof,
    }))
}
