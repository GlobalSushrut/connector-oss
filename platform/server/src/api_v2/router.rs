//! V2 API Router — Assembles all V2 endpoints

use axum::{
    routing::{get, post, delete, patch},
    Router,
};

use crate::state::SharedState;
use super::{agents, memory, tools, sessions, audit, health, exec, deploy, system, registry, storage, network, dns, tls};

/// Build the V2 API router
pub fn v2_router() -> Router<SharedState> {
    Router::new()
        // Agents
        .route("/agents", post(agents::create_agent))
        .route("/agents", get(agents::list_agents))
        .route("/agents/:id", get(agents::get_agent))
        .route("/agents/:id/start", post(agents::start_agent))
        .route("/agents/:id/stop", post(agents::stop_agent))
        
        // Memory
        .route("/memory", post(memory::write_memory))
        .route("/memory", get(memory::list_memory))
        .route("/memory/:cid", get(memory::get_memory))
        .route("/memory/:cid", delete(memory::delete_memory))
        
        // Tools
        .route("/tools", get(tools::list_tools))
        .route("/tools/:id", get(tools::get_tool))
        .route("/tools/:id/invoke", post(tools::invoke_tool))
        
        // Sessions
        .route("/sessions", post(sessions::create_session))
        .route("/sessions", get(sessions::list_sessions))
        .route("/sessions/:id", get(sessions::get_session))
        .route("/sessions/:id", delete(sessions::close_session))
        
        // Audit
        .route("/audit", get(audit::list_audit))
        .route("/audit/export", get(audit::export_audit))
        .route("/audit/:id", get(audit::get_audit_entry))
        
        // Health
        .route("/health", get(health::get_health))
        .route("/health/maturity", get(health::get_maturity))
        .route("/health/agents", get(health::get_agents_health))
        
        // Execution Management
        .route("/exec/run", post(exec::run_task))
        .route("/exec/schedule", post(exec::schedule_task))
        .route("/exec/queue", post(exec::queue_task))
        .route("/exec/list", get(exec::list_executions))
        .route("/exec/:id/status", get(exec::get_execution_status))
        .route("/exec/:id/logs", get(exec::get_execution_logs))
        .route("/exec/:id/abort", post(exec::abort_execution))
        .route("/exec/:id/retry", post(exec::retry_execution))
        .route("/exec/:id/cost", get(exec::get_execution_cost))
        .route("/exec/:id/resources", get(exec::get_execution_resources))
        .route("/exec/:task/deps", get(exec::get_execution_deps))
        .route("/exec/dry-run", post(exec::dry_run_task))
        .route("/exec/validate", post(exec::validate_task))
        .route("/exec/benchmark", post(exec::benchmark_task))
        
        // Deployment Management
        .route("/deploy/create", post(deploy::create_deployment))
        .route("/deploy/plan", post(deploy::create_deployment_plan))
        .route("/deploy/apply", post(deploy::apply_deployment_plan))
        .route("/deploy/list", get(deploy::list_deployments))
        .route("/deploy/:name/status", get(deploy::get_deployment_status))
        .route("/deploy/:name/rollback", post(deploy::rollback_deployment))
        .route("/deploy/:name/scale", post(deploy::scale_deployment))
        .route("/deploy/:name/logs", get(deploy::get_deployment_logs))
        .route("/deploy/:name/metrics", get(deploy::get_deployment_metrics))
        
        // System Management
        .route("/system/info", get(system::get_system_info))
        .route("/system/health", get(system::get_system_health))
        .route("/system/metrics", get(system::get_system_metrics))
        .route("/system/logs", get(system::get_system_logs))
        .route("/system/backup", post(system::create_backup))
        .route("/system/upgrade", get(system::check_upgrade))
        
        // Registry Management
        .route("/registry/list", get(registry::list_registry))
        .route("/registry/:id", get(registry::get_registry_item))
        .route("/registry/:id", delete(registry::delete_registry))
        .route("/registry/:id/pull", post(registry::pull_registry))
        .route("/registry/push", post(registry::push_registry))
        
        // Storage Management
        .route("/storage/list", get(storage::list_storage))
        .route("/storage/:name", get(storage::get_bucket))
        .route("/storage/sync", post(storage::sync_storage))
        .route("/storage/cleanup", post(storage::cleanup_storage))
        
        // Network Management
        .route("/network/list", get(network::list_networks))
        .route("/network/:name", get(network::inspect_network))
        .route("/network/test", post(network::test_network))
        
        // DNS Management
        .route("/dns/resolve", get(dns::resolve_domain))
        .route("/dns/lookup", get(dns::reverse_lookup))
        .route("/dns/records", get(dns::list_dns_records))
        .route("/dns/propagation", get(dns::check_propagation))
        
        // TLS/Certificate Management
        .route("/tls/check", get(tls::check_tls))
        .route("/tls/cert-info", get(tls::get_cert_info))
        .route("/tls/certificates", get(tls::list_certificates))
        .route("/tls/request", post(tls::request_certificate))
}
