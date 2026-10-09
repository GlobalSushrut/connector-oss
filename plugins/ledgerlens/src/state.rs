//! Shared application state passed to every Axum handler.

use sqlx::PgPool;
use crate::connector::ConnectorClient;

#[derive(Clone)]
pub struct AppState {
    pub pool:      PgPool,
    pub connector: ConnectorClient,
}
