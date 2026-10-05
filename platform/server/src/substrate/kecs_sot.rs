//! KECS SoT — live VAC KnotEngine + connector-engine entropic; folder is cache only.

use serde_json::{json, Value};

use connector_engine::entropic::{KecsComputer, KecsWeights};
use vac_core::identity::AgentExpertiseRecord;

use crate::state::PlatformState;

pub const KECS_SOT_SCHEMA: &str = "connector.kecs.sot.v1";

/// Compute KECS from live Knot + expertise; write folder projection as cache.
pub fn live_kecs(state: &PlatformState, agent_pid: &str) -> Value {
    let node_count = state
        .knot
        .lock()
        .map(|k| k.node_count())
        .unwrap_or(0);
    let packet_count = state
        .kernel
        .lock()
        .map(|k| k.packet_count())
        .unwrap_or(0);

    let expertise = AgentExpertiseRecord::new(
        format!("m/{agent_pid}"),
        chrono::Utc::now().timestamp_millis(),
    );
    let weights = KecsWeights::default();
    let result = match state.knot.lock() {
        Ok(knot) => KecsComputer::compute(&knot, &expertise, &weights),
        Err(_) => {
            return json!({
                "schema": KECS_SOT_SCHEMA,
                "agent_pid": agent_pid,
                "kecs": 0.5,
                "error": "knot_lock",
                "honesty": "fallback score — Knot lock failed",
            });
        }
    };

    let body = json!({
        "schema": KECS_SOT_SCHEMA,
        "agent_pid": agent_pid,
        "kecs": result.kecs,
        "k_vn": result.k_vn,
        "s_renyi": result.s_renyi,
        "k_topo": result.k_topo,
        "kecs_points": result.kecs_points,
        "sources": {
            "knot_nodes": node_count,
            "packet_count": packet_count,
            "honesty": "VAC Knot + entropic::KecsComputer are SoT; agent_kecs folder is cache only",
        },
        "at_ms": chrono::Utc::now().timestamp_millis(),
    });

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put("agent_kecs", agent_pid, &body);
        let _ = es.folder_put(
            "kecs_data",
            agent_pid,
            &json!({
                "kecs": result.kecs,
                "k_vn": result.k_vn,
                "s_renyi": result.s_renyi,
                "k_topo": result.k_topo,
                "sot": "knot_entropic_v1",
            }),
        );
    }

    body
}

/// Prefer live compute for runtime gates.
pub fn resolve_kecs(state: &PlatformState, agent_pid: &str) -> f64 {
    live_kecs(state, agent_pid)
        .get("kecs")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.5)
}
