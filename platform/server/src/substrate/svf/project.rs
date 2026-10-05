//! PROJECT — minimum sufficient model view (S0/S1) for Talk injection.

use connector_trust::{DisclosureLevel, Projection, PROJECTION_SCHEMA};

use crate::state::SharedState;

use super::{broker_epoch, semanticize, store, svf_enabled};

pub const MARKER: &str = "[connector.svf.projection]";

/// Build S0/S1 projections from the agent object store (refresh via SEMANTICIZE first).
pub fn project_objects(state: &SharedState, agent_pid: &str, max: usize) -> Vec<Projection> {
    if !svf_enabled() {
        return Vec::new();
    }
    let _ = semanticize::semanticize_agent(state, agent_pid);
    let epoch = broker_epoch(state, agent_pid);
    let objs = store::list_objects(state, agent_pid);
    objs.into_iter()
        .take(max)
        .map(|o| {
            let level = DisclosureLevel::S1Labels;
            let view_text = format!(
                "{} ({}) handle={} ceiling={}",
                o.object_id,
                o.object_type,
                o.handle.handle,
                o.handle.disclosure_ceiling.as_str()
            );
            Projection {
                schema: PROJECTION_SCHEMA.to_string(),
                object_id: o.object_id,
                level,
                view_text,
                broker_epoch: epoch,
                purpose: Some("talk_project".into()),
            }
        })
        .collect()
}

/// System-block for Talk — alongside agentic_context (who-am-I), not instead of it.
pub fn gateway_injection_block(state: &SharedState, agent_pid: &str) -> Option<String> {
    if !svf_enabled() {
        return None;
    }
    let projections = project_objects(state, agent_pid, 24);
    if projections.is_empty() {
        return Some(format!(
            "{MARKER}\nschema: connector.svf.projection.v1\nbroker_epoch: {}\nobjects: (none yet — SEMANTICIZE on MemWrite/Knot)\nhonesty: SVF labels only; not grants; AffordanceEnvelope shrinks only\n",
            broker_epoch(state, agent_pid)
        ));
    }
    let mut lines = vec![
        MARKER.to_string(),
        "schema: connector.svf.projection.v1".into(),
        format!("broker_epoch: {}", broker_epoch(state, agent_pid)),
        "disclosure: S0/S1 labels only — EXPAND requires purpose + Admit".into(),
        "honesty: handles are not WorldGrants; DIM/usefulness cannot Allow".into(),
        "objects:".into(),
    ];
    for p in &projections {
        lines.push(format!("  - [{}] {}", p.level.as_str(), p.view_text));
    }
    Some(lines.join("\n"))
}
