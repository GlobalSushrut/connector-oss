//! AffordanceEnvelope compiler — dynamic reachable consequence space.
//! Compiles from AgentContract, WorldGrant, address DAC, RGO, budgets.
//! Never expands static authority; only shrinks consequence surface.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::kernel::action_binding::ActionBinding;
use crate::kernel::agent_principal;
use crate::kernel::world_gateway;
use crate::state::PlatformState;
use crate::substrate::knot21;
use crate::substrate::rgo::{self, OversightMode, ReversibilityClass};

pub const ENVELOPE_SCHEMA: &str = "connector.affordance_envelope.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffordanceSlot {
    pub address: String,
    pub ops: Vec<String>,
    pub max_class: String,
    pub oversight: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffordanceEnvelope {
    pub schema: String,
    pub agent_pid: String,
    pub slots: Vec<AffordanceSlot>,
    pub budget_tokens: u64,
    pub budget_effects: u32,
    pub knot21_hint: String,
    pub compiled_at_ms: i64,
    pub honesty: String,
}

/// Compile current affordance envelope (read-only projection for LTL / CIP).
pub fn compile(state: &PlatformState, agent_pid: &str) -> AffordanceEnvelope {
    let mut slots = Vec::new();
    if let Some(c) = agent_principal::load_contract(state, agent_pid) {
        for cap in c.capabilities.iter().take(32) {
            slots.push(AffordanceSlot {
                address: cap.clone(),
                ops: vec!["invoke".into()],
                max_class: "R2".into(),
                oversight: format!("{:?}", OversightMode::Hotl),
            });
        }
        for path in c.filesystem_read.iter().take(8) {
            slots.push(AffordanceSlot {
                address: path.clone(),
                ops: vec!["read".into()],
                max_class: "R0".into(),
                oversight: format!("{:?}", OversightMode::Autonomous),
            });
        }
    }
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(world_gateway::GRANT_FOLDER, Some(agent_pid)) {
            for key in keys.into_iter().take(16) {
                if let Ok(Some(grant)) = es.folder_get(world_gateway::GRANT_FOLDER, &key) {
                    let addr = grant
                        .get("address")
                        .and_then(|a| a.as_str())
                        .unwrap_or("")
                        .to_string();
                    if addr.is_empty() {
                        continue;
                    }
                    slots.push(AffordanceSlot {
                        address: addr,
                        ops: vec!["world".into()],
                        max_class: "R2".into(),
                        oversight: format!("{:?}", OversightMode::HitlDigest),
                    });
                }
            }
        }
    }
    let profile = knot21::observe(state, agent_pid);
    if profile.affordance_hint.contains("narrow") && slots.len() > 1 {
        slots.truncate((slots.len() / 2).max(1));
    }
    AffordanceEnvelope {
        schema: ENVELOPE_SCHEMA.into(),
        agent_pid: agent_pid.into(),
        slots,
        budget_tokens: 32_000,
        budget_effects: 64,
        knot21_hint: profile.affordance_hint,
        compiled_at_ms: chrono::Utc::now().timestamp_millis(),
        honesty: "Envelope shrinks consequence; ActionBinding still admits each effect".into(),
    }
}

/// Advisory check whether binding's resource appears in compiled envelope.
pub fn permits(envelope: &AffordanceEnvelope, binding: &ActionBinding) -> bool {
    if envelope.slots.is_empty() {
        return true;
    }
    let res = &binding.target.resource;
    let tool = &binding.target.tool_name;
    envelope
        .slots
        .iter()
        .any(|s| s.address == *res || s.address == *tool || res.starts_with(&s.address))
}

pub fn oversight_for(envelope: &AffordanceEnvelope, class: ReversibilityClass) -> OversightMode {
    let _ = envelope;
    rgo::resolve_oversight(class, rgo::autonomy_tier(), false)
}

pub fn to_json(e: &AffordanceEnvelope) -> Value {
    serde_json::to_value(e).unwrap_or(json!({ "ok": false }))
}
