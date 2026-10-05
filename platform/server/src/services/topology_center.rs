use axum::{extract::State, Json};
use serde_json::json;

use crate::services::{actionlog, cnp_surface, infra, multiagent};
use crate::state::SharedState;

pub async fn get_topology_center(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let cell_status = infra::cross_cell_status(State(state.clone())).await.0;
    let router_cells = infra::router_cells(State(state.clone())).await.0;
    let cross_agent_map = multiagent::cross_agent_map(State(state.clone())).await.0;
    let consensus = infra::bft_status(State(state.clone())).await.0;
    let traces = actionlog::list_traces(
        State(state.clone()),
        axum::extract::Query(actionlog::TraceQuery {
            agent: None,
            limit: Some(20),
            window_h: None,
        }),
    )
    .await
    .0;

    let placements = {
        let agents = {
            let k = state.kernel.lock().unwrap();
            k.all_agents()
                .into_iter()
                .map(|agent| (agent.agent_pid.clone(), agent.namespace.clone()))
                .collect::<Vec<_>>()
        };
        let es = state.engine_store.lock().unwrap();
        agents
            .into_iter()
            .map(|(agent_pid, namespace)| {
                let meta = es
                    .folder_get("agent_meta", &agent_pid)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let cell = meta
                    .get("cell_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("cell:local");
                let status = if meta
                    .get("paused")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "paused"
                } else {
                    "active"
                };
                json!({
                    "agent_pid": agent_pid,
                    "namespace": namespace,
                    "status": status,
                    "cell_id": cell,
                    "placement_state": if status == "active" { "placed" } else { "degraded" }
                })
            })
            .collect::<Vec<_>>()
    };

    let migrations = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("agent_meta", None)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|pid| {
                let meta = es.folder_get("agent_meta", &pid).ok().flatten()?;
                let migrated_at = meta
                    .get("migrated_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—")
                    .to_string();
                let snapshot_cid = meta
                    .get("snapshot_cid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—")
                    .to_string();
                let target_cell = meta
                    .get("cell_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("—")
                    .to_string();
                if migrated_at == "—" && snapshot_cid == "—" {
                    None
                } else {
                    Some(json!({
                        "agent_pid": pid,
                        "migrated_at": migrated_at,
                        "snapshot_cid": snapshot_cid,
                        "target_cell": target_cell,
                    }))
                }
            })
            .collect::<Vec<_>>()
    };

    let cnp_mesh = cnp_surface::cnp_mesh_snapshot(&state);

    Json(json!({
        "ok": true,
        "data": {
            "cell_topology": cell_status,
            "agent_placement": placements,
            "coordination_sessions": cross_agent_map,
            "consensus_state": consensus,
            "trace_replay": traces,
            "migration_views": migrations,
            "router_cells": router_cells,
            "cnp_mesh_control": cnp_mesh,
        }
    }))
}
