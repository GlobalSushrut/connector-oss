//! AgentMemoryCapsule builder — hot 8–64 KB runtime context (§6–§7).

use connector_trust::{AgentMemoryCapsule, AMC_SCHEMA};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

use super::context_store;
use super::evidence;
use super::reducer;

pub const CAPSULE_FOLDER: &str = "agent_memory_capsule";
pub const MAX_CAPSULE_BYTES: usize = 64 * 1024;
pub const TARGET_CAPSULE_BYTES: usize = 32 * 1024;

fn capsule_root(amc: &AgentMemoryCapsule) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(amc).unwrap_or_default())
    )
}

pub fn build(
    state: &PlatformState,
    agent_vid: &str,
    execution_epoch: u64,
    current_goal: Option<String>,
    current_plan: Option<String>,
) -> AgentMemoryCapsule {
    let ctx = context_store::load_state(state, agent_vid);
    let ev_root = evidence::evidence_root(state, agent_vid)
        .unwrap_or_else(|| ctx.evidence_root.clone());
    let ctx_ref = context_store::context_ref(state, agent_vid);
    let prev = latest_capsule_root(state, agent_vid);
    let critical = reducer::hot_points(state, agent_vid, 12);
    let decisions = reducer::recent_decision_summaries(state, agent_vid, 8);
    let mut amc = AgentMemoryCapsule {
        schema: AMC_SCHEMA.into(),
        agent_vid: agent_vid.into(),
        execution_epoch,
        context_epoch: ctx.context_epoch,
        memory_root: ctx.context_root.clone(),
        authority_root: ctx.authority_root.clone(),
        evidence_root: ev_root,
        current_goal,
        current_plan,
        critical_facts: critical,
        commitments: vec![],
        unresolved: vec![],
        recent_decisions: decisions,
        recent_actions: vec![],
        entropy: 0.35,
        volatility: 0.25,
        confidence: 0.72,
        autonomous_radius: 0.4,
        previous_capsule_root: prev,
        context_ref: ctx_ref,
    };
    trim_to_budget(&mut amc);
    let root = capsule_root(&amc);
    amc.memory_root = root;
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            CAPSULE_FOLDER,
            agent_vid,
            &serde_json::to_value(&amc).unwrap_or_default(),
        );
    }
    amc
}

pub fn load_cached(state: &PlatformState, agent_vid: &str) -> Option<AgentMemoryCapsule> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(CAPSULE_FOLDER, agent_vid).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn latest_capsule_root(state: &PlatformState, agent_vid: &str) -> Option<String> {
    load_cached(state, agent_vid).map(|a| a.memory_root)
}

fn trim_to_budget(amc: &mut AgentMemoryCapsule) {
    loop {
        let size = serde_json::to_vec(amc).map(|v| v.len()).unwrap_or(MAX_CAPSULE_BYTES + 1);
        if size <= MAX_CAPSULE_BYTES {
            break;
        }
        if !amc.critical_facts.is_empty() {
            amc.critical_facts.pop();
            continue;
        }
        if !amc.recent_decisions.is_empty() {
            amc.recent_decisions.pop();
            continue;
        }
        if !amc.recent_actions.is_empty() {
            amc.recent_actions.pop();
            continue;
        }
        break;
    }
}

pub fn inject_system_block(amc: &AgentMemoryCapsule) -> String {
    serde_json::to_string_pretty(amc).unwrap_or_else(|_| "{}".into())
}

/// Build hot capsule and return system-injection block for gateway Talk.
pub fn gateway_injection_block(
    state: &PlatformState,
    agent_vid: &str,
    execution_epoch: u64,
) -> Result<String, String> {
    let amc = build(state, agent_vid, execution_epoch, None, None);
    enforce_harden(&amc)?;
    Ok(format!(
        "[connector.agent_memory_capsule]\nMemory plane only — bounded runtime context; evidence stays cold.\n{}",
        inject_system_block(&amc)
    ))
}

pub fn enforce_harden(amc: &AgentMemoryCapsule) -> Result<(), String> {
    if !super::harden_cap() {
        return Ok(());
    }
    let size = serde_json::to_vec(amc).map(|v| v.len()).unwrap_or(0);
    if size > MAX_CAPSULE_BYTES {
        return Err(format!(
            "AgentMemoryCapsule {size} bytes exceeds harden cap {MAX_CAPSULE_BYTES}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_reduces_oversized_lists() {
        let mut amc = AgentMemoryCapsule {
            schema: AMC_SCHEMA.into(),
            agent_vid: "a".into(),
            execution_epoch: 1,
            context_epoch: 1,
            memory_root: "m".into(),
            authority_root: "auth".into(),
            evidence_root: "ev".into(),
            current_goal: None,
            current_plan: None,
            critical_facts: (0..5000).map(|i| format!("fact-{i}-{}", "x".repeat(80))).collect(),
            commitments: vec![],
            unresolved: vec![],
            recent_decisions: vec![],
            recent_actions: vec![],
            entropy: 0.5,
            volatility: 0.5,
            confidence: 0.5,
            autonomous_radius: 0.5,
            previous_capsule_root: None,
            context_ref: connector_trust::ContextReference {
                context_root: "r".into(),
                epoch: 1,
            },
        };
        trim_to_budget(&mut amc);
        let size = serde_json::to_vec(&amc).unwrap().len();
        assert!(size <= MAX_CAPSULE_BYTES);
    }
}
