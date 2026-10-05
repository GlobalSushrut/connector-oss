//! Unified workload lifecycle observability (agents + plugins).

use axum::extract::State;
use axum::Json;
use connector_trust::WorkloadLifecycleState;
use serde_json::{json, Value};
use vac_core::types::AgentStatus;

use crate::{
    operator::honesty::operator_envelope,
    services::plugin_lifecycle::{load_plugin_lifecycle_state, PluginLifecycleState},
    state::SharedState,
};

pub fn plugin_workload_state(row: &PluginLifecycleState) -> WorkloadLifecycleState {
    if !row.installed {
        return WorkloadLifecycleState::Terminated;
    }
    match row.last_action.as_str() {
        "disable" => WorkloadLifecycleState::Paused,
        "uninstall" => WorkloadLifecycleState::Terminated,
        "update" => WorkloadLifecycleState::Upgrading,
        "install" if row.enabled => WorkloadLifecycleState::Starting,
        _ if row.enabled => WorkloadLifecycleState::Running,
        _ => WorkloadLifecycleState::Paused,
    }
}

fn agent_workload_state(status: AgentStatus) -> WorkloadLifecycleState {
    match status {
        AgentStatus::Running | AgentStatus::Waiting => WorkloadLifecycleState::Running,
        AgentStatus::Suspended => WorkloadLifecycleState::Paused,
        AgentStatus::Terminated | AgentStatus::Failed | AgentStatus::Completed => {
            WorkloadLifecycleState::Terminated
        }
        AgentStatus::Registered => WorkloadLifecycleState::Starting,
    }
}

/// `GET /api/v1/runtime/lifecycle/summary`
pub async fn get_lifecycle_summary(State(state): State<SharedState>) -> Json<Value> {
    let agents: Vec<Value> = {
        let kernel = state.kernel.lock().unwrap();
        kernel
            .agents()
            .values()
            .map(|a| {
                let wl = agent_workload_state(a.status.clone());
                json!({
                    "kind": "agent",
                    "id": a.agent_pid,
                    "name": a.agent_name,
                    "namespace": a.namespace,
                    "kernel_status": a.status,
                    "lifecycle": wl,
                })
            })
            .collect()
    };

    let plugins: Vec<Value> = crate::services::plugin_matrix::KNOWN_PLUGINS
        .iter()
        .map(|id| {
            let row = load_plugin_lifecycle_state(&state, id);
            let wl = plugin_workload_state(&row);
            json!({
                "kind": "plugin",
                "id": id,
                "installed": row.installed,
                "enabled": row.enabled,
                "version": row.version,
                "last_action": row.last_action,
                "lifecycle": wl,
            })
        })
        .collect();

    let isolation = state.isolation_runtime.read().unwrap();
    Json(operator_envelope(json!({
        "schema": "lifecycle_summary.v1",
        "isolation_declared": isolation.as_str(),
        "isolation_downgrade_allowed": std::env::var("CONNECTOR_ALLOW_ISOLATION_DOWNGRADE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        "agents": agents,
        "plugins": plugins,
        "contract": "connector_trust::WorkloadLifecycleState",
    })))
}
