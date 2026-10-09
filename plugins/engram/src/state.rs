//! Shared application state — injected via Axum's `State` extractor.

use sqlx::PgPool;

use crate::connector::ConnectorClient;
use crate::url::EngramUrl;

#[derive(Clone)]
pub struct AppState {
    pub pool:      PgPool,
    pub connector: ConnectorClient,
    pub engram_url: EngramUrl,
}
