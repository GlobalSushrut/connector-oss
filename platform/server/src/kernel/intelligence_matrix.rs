//! CDMI intelligence matrix — Albus RCS node, not a framework catalog.
//!
//! Kernel = Sensory Processing · World Modeling · Value Judgment · Behavior
//! Generation (app socket). LangGraph/Crew/Talk live in BG as applications.
//! The kernel does not name them.

use serde_json::{json, Value};

use crate::kernel::matrix_host_egress;
use crate::state::PlatformState;

pub const MATRIX_SCHEMA: &str = "connector.intelligence.matrix.v1";

/// Albus 1991/1994 canonical node. Recursive at every hierarchical level.
pub fn albus_node(agent_pid: &str) -> Value {
    json!({
        "schema": MATRIX_SCHEMA,
        "reference": "Albus IEEE SMC 1991 · NISTIR 5502 1994 RCS",
        "I": agent_pid,
        "mu": matrix_host_egress::intelligence_egress_mark_hex(agent_pid),
        "functions": {
            "sensory_processing": {
                "role": "SP",
                "kernel": "Ingress of observations (Talk/CNP/MCP as sensing). Force-pid. Retrieve from WM.",
                "app": false
            },
            "world_modeling": {
                "role": "WM",
                "kernel": "VAC + NS FS /m /k + Knot + grants as pores. SoT for what is true of the world.",
                "app": false
            },
            "value_judgment": {
                "role": "VJ",
                "kernel": "Charter, admission layers, budgets, HITL, forensic. SoT for what may happen.",
                "app": false
            },
            "behavior_generation": {
                "role": "BG",
                "kernel": "App socket only. Kernel admits typed actions A. Does not implement planners.",
                "app": true,
                "honesty": "LangGraph, Crew, MAF, Talk, Relay, CONP loops, PID controllers live here. Kernel does not import them. Minsky 1992: they are methods in a causal-diversity matrix, not the architecture."
            }
        },
        "honesty": "This is the intelligence matrix. Regular, recursive, canonical. Algorithms inside BG may change; the four functions do not. Linux PIDs are membrane material under the node, not identity. CPU and GPU are devices. An LLM is this I thinking, not a core. Newell 1982 knowledge level; Albus 1991; Hawkins 2004."
    })
}

/// Render matrix cell for ACS. Dialect labels are app metadata — kernel ignores them.
pub fn cell(state: &PlatformState, agent_pid: &str) -> Value {
    let pid = agent_pid.trim();
    let spec = crate::kernel::intelligence_spec::load_spec_doc(state, pid);
    let app_note = spec
        .as_ref()
        .and_then(|s| s.pointer("/spec/parameters/reasoner_dialect"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let mut node = albus_node(pid);
    if let Some(obj) = node.as_object_mut() {
        obj.insert(
            "app_layer_note".into(),
            json!({
                "reasoner_dialect_metadata": app_note,
                "kernel_interprets": false,
                "layer": "BG application — ignored by admit_*"
            }),
        );
        obj.insert("ok".into(), json!(true));
        obj.insert(
            "level".into(),
            crate::kernel::operating_layer::level_for(state, pid),
        );
        obj.insert(
            "sockets".into(),
            crate::kernel::operating_layer::spec()["sockets"].clone(),
        );
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_node_has_four_albus_functions_not_langgraph() {
        let n = albus_node("agt_x");
        assert!(n["functions"]["world_modeling"]["app"] == false);
        assert!(n["functions"]["value_judgment"]["app"] == false);
        assert!(n["functions"]["behavior_generation"]["app"] == true);
        let s = n.to_string();
        assert!(!s.contains("StateGraph"));
        assert!(n["functions"]["behavior_generation"]["honesty"]
            .as_str()
            .unwrap()
            .contains("Kernel does not import"));
    }
}
