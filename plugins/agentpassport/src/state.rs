//! Shared application state — injected via Axum's `State` extractor.

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use uuid::Uuid;

use crate::connector::ConnectorClient;

#[derive(Clone)]
pub struct AppState {
    pub pool:         PgPool,
    pub connector:    ConnectorClient,
    pub http:         reqwest::Client,
    pub signing_key:  SigningKey,
    pub instance_did: String,
    pub key_id:       String,
    pub default_org:  Uuid,
}
