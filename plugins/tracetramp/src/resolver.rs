//! Identity + Tenant Resolver
//!
//! Maps API key → tenant → actor → policy → budget → providers

use sqlx::PgPool;
use tracing::{debug, info};

use crate::{
    connector::ConnectorClient,
    error::AppError,
    types::RequestMode,
};

/// Resolved tenant context for a request
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: String,
    pub tenant_name: String,
    pub actor_id: String,
    pub actor_role: String,
    pub environment: String,
    pub default_mode: RequestMode,
    pub policy_bundle: String,
    pub budget_tier: String,
    pub providers: Vec<String>,
    pub api_key_prefix: String,
}

/// Resolve tenant from API key
pub async fn resolve_tenant(
    _pool: &PgPool,
    connector: &ConnectorClient,
    api_key: &str,
) -> Result<TenantContext, AppError> {
    let prefix = api_key.split('_').take(2).collect::<Vec<_>>().join("_");
    debug!("Resolving tenant identity via Connector agent namespace: {}", prefix);

    let identity = connector.resolve_agent_identity(api_key).await?;
    let ctx = TenantContext {
        tenant_id: identity.tenant_id.clone(),
        tenant_name: "connector-agent".to_string(),
        actor_id: identity.actor_id,
        actor_role: identity.actor_role,
        environment: "production".to_string(),
        // Always Control today; gateway may still downgrade to View only when
        // `TRACETRAMP_ALLOW_VIEW_PIPELINE=1` and the client opts in via header.
        default_mode: RequestMode::Control,
        policy_bundle: "default".to_string(),
        budget_tier: "standard".to_string(),
        providers: vec!["openai".to_string()],
        api_key_prefix: prefix,
    };

    info!("Connector identity resolved: tenant={} actor={}", ctx.tenant_id, ctx.actor_id);
    Ok(ctx)
}

