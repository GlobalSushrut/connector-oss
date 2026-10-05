//! Immutable AgentRuntimeSnapshot — compile governance once, publish atomically.
//!
//! Talk hot path loads an `Arc` to one complete version. Ordinary messages do
//! not reconstruct identity, charter, or tool registries from live stores.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::{PlatformState, SharedState};

pub const AGENT_RUNTIME_SNAPSHOT_SCHEMA: &str = "connector.agent_runtime_snapshot.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRouteHint {
    pub provider: String,
    pub model: String,
    pub proven: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompiledAddressContracts {
    pub talk_address: String,
    pub admit_address: String,
    pub talk_rules: bool,
    pub talk_hitl: bool,
    pub admit_rules: bool,
    pub admit_hitl: bool,
}

/// Compiled, immutable per-agent runtime (static governance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuntimeSnapshot {
    pub schema: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub snapshot_version: u64,
    pub identity_generation: u64,
    pub charter_generation: u64,
    pub broker_generation: u64,
    pub quarantine_generation: u64,
    pub iac_epoch: u64,
    pub policy_bundle_id: String,
    pub who_am_i: String,
    pub hard_charter: String,
    pub vendor_brain_denial: String,
    pub agent_name: String,
    pub compiled_skills: Vec<String>,
    pub compiled_rules: Value,
    pub compiled_address_contracts: CompiledAddressContracts,
    pub compiled_tool_names: Vec<String>,
    pub static_llm_envelope: String,
    pub provider_route: Option<ProviderRouteHint>,
    pub memory_index_ref: String,
    pub budget_profile: Value,
    pub mission_profile: Value,
    pub snapshot_hash: String,
    pub compiled_at_ms: i64,
}

impl AgentRuntimeSnapshot {
    pub fn inject_static_system_blocks(&self) -> Vec<(String, String)> {
        let mut blocks = Vec::with_capacity(4);
        if !self.who_am_i.trim().is_empty() {
            blocks.push(("system".into(), self.who_am_i.clone()));
        }
        if !self.hard_charter.trim().is_empty() {
            blocks.push(("system".into(), self.hard_charter.clone()));
        }
        if !self.vendor_brain_denial.trim().is_empty() {
            blocks.push(("system".into(), self.vendor_brain_denial.clone()));
        }
        if !self.compiled_skills.is_empty() {
            blocks.push((
                "system".into(),
                format!(
                    "--- CONNECTOR COMPILED CAPABILITIES ---\nPermitted skills (registered only):\n- {}",
                    self.compiled_skills.join("\n- ")
                ),
            ));
        }
        blocks
    }

    pub fn assert_generations_match(
        &self,
        identity_generation: u64,
        broker_generation: u64,
    ) -> Result<(), String> {
        if self.identity_generation != identity_generation {
            return Err(format!(
                "DeferRedo: identity_generation mismatch snap={} live={}",
                self.identity_generation, identity_generation
            ));
        }
        if self.broker_generation != broker_generation {
            return Err(format!(
                "DeferRedo: broker_generation mismatch snap={} live={}",
                self.broker_generation, broker_generation
            ));
        }
        Ok(())
    }
}

/// Atomic publish registry — readers always see a complete snapshot or none.
#[derive(Default)]
pub struct RuntimeSnapshotRegistry {
    versions: AtomicU64,
    by_agent: RwLock<HashMap<String, Arc<AgentRuntimeSnapshot>>>,
}

impl RuntimeSnapshotRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, agent_pid: &str) -> Option<Arc<AgentRuntimeSnapshot>> {
        self.by_agent
            .read()
            .ok()
            .and_then(|m| m.get(agent_pid).cloned())
    }

    pub fn publish(&self, snap: AgentRuntimeSnapshot) -> Arc<AgentRuntimeSnapshot> {
        let pid = snap.principal_id.clone();
        let arc = Arc::new(snap);
        if let Ok(mut m) = self.by_agent.write() {
            m.insert(pid, Arc::clone(&arc));
        }
        arc
    }

    pub fn invalidate(&self, agent_pid: &str) {
        if let Ok(mut m) = self.by_agent.write() {
            m.remove(agent_pid);
        }
    }

    pub fn invalidate_all(&self) {
        if let Ok(mut m) = self.by_agent.write() {
            m.clear();
        }
    }

    pub fn next_version(&self) -> u64 {
        self.versions.fetch_add(1, Ordering::SeqCst) + 1
    }
}

const VENDOR_BRAIN_DENIAL_MARKER: &str =
    "--- CONNECTOR LLM BRAIN BINDING (shared model — Connector owns identity) ---";

fn broker_generation(state: &PlatformState, agent_pid: &str) -> u64 {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    es.folder_get("llm_context_broker_v1", &format!("gen:{agent_pid}"))
        .ok()
        .flatten()
        .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
        .unwrap_or(0)
}

fn quarantine_generation(state: &PlatformState, agent_pid: &str) -> u64 {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    es.folder_get("agent_quarantine", agent_pid)
        .ok()
        .flatten()
        .and_then(|v| {
            v.get("generation")
                .or_else(|| v.get("epoch"))
                .and_then(|g| g.as_u64())
        })
        .unwrap_or(0)
}

fn compile_address_contracts(state: &PlatformState, agent_pid: &str) -> CompiledAddressContracts {
    let talk = format!("llm:gateway/{agent_pid}");
    let admit = "tool:workbench.admit".to_string();
    CompiledAddressContracts {
        talk_rules: crate::kernel::address_contracts::load_rules(state, &talk).is_some(),
        talk_hitl: crate::kernel::address_contracts::load_hitl(state, &talk).is_some(),
        admit_rules: crate::kernel::address_contracts::load_rules(state, &admit).is_some(),
        admit_hitl: crate::kernel::address_contracts::load_hitl(state, &admit).is_some(),
        talk_address: talk,
        admit_address: admit,
    }
}

/// Compile a snapshot from authoritative stores (call off the async worker).
pub fn compile_agent_runtime_snapshot(
    state: &PlatformState,
    agent_pid: &str,
    tenant_id: &str,
) -> AgentRuntimeSnapshot {
    let who = crate::kernel::agent_foundation::who_am_i_authoritative(state, agent_pid)
        .or_else(|| {
            crate::kernel::agent_identity_envelope::who_am_i_authoritative(state, agent_pid)
        })
        .unwrap_or_else(|| {
            format!(
                "You are a Connector agent (principal={agent_pid}). Answer as this agent only."
            )
        });

    let agent_name = state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten())
        .and_then(|m| m.get("name").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_else(|| "Connector Agent".into());

    let hard_charter = crate::services::gateway::collect_hard_charter(state, agent_pid);
    let vendor_brain_denial = format!(
        "{VENDOR_BRAIN_DENIAL_MARKER}\n\
         You share an LLM brain with many tenants. Connector — not the vendor — owns your identity, memory refs, and tool authority.\n\
         agent_name: {agent_name}\n\
         principal: {agent_pid}\n\
         rules:\n\
         - Never claim to be ChatGPT, Claude, Gemini, DeepSeek, OpenAI, Anthropic, Google, or a generic AI assistant.\n\
         - Never cite vendor knowledge cutoffs, pricing, or model marketing.\n\
         - Speak as the Connector agent above in chat; tool calls and execution stay on Connector rails.\n\
         - If asked who you are, answer from Connector identity above — not vendor defaults.\n\
         - Never invent worlds or claim an effect completed without an admitted ToolDispatch receipt."
    );

    let skills = crate::kernel::intelligence_spec::load_bound_skills(state, agent_pid);
    let compiled_skills: Vec<String> = skills
        .iter()
        .filter_map(|s| {
            s.get("name")
                .or_else(|| s.get("skill"))
                .or_else(|| s.get("id"))
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .collect();
    let compiled_rules = crate::kernel::intelligence_spec::load_rules(state, agent_pid);
    let compiled_address_contracts = compile_address_contracts(state, agent_pid);
    let compiled_tool_names = {
        let mut tools = compiled_skills.clone();
        tools.push("llm.chat".into());
        tools.push("workbench.admit".into());
        tools.sort();
        tools.dedup();
        tools
    };

    let cell = state.cells.get_or_create(agent_pid);
    let iac_epoch = cell.current_epoch();
    let broker_generation = broker_generation(state, agent_pid);
    let identity_generation = iac_epoch;
    let quarantine_generation = quarantine_generation(state, agent_pid);
    let charter_generation = {
        let mut h = Sha256::new();
        h.update(hard_charter.as_bytes());
        let d = h.finalize();
        u64::from_be_bytes(d[..8].try_into().unwrap_or([0; 8]))
    };

    let policy_bundle_id = format!(
        "policy:{}:{}:{}",
        agent_pid,
        charter_generation,
        broker_generation
    );

    let snapshot_version = state.runtime_snapshots.next_version();
    let memory_index_ref =
        crate::services::agents::canonical_agent_memory_namespace(agent_pid);

    let static_llm_envelope = format!(
        "{who}\n\n{hard_charter}\n\n{vendor_brain_denial}"
    );

    let budget_profile = serde_json::json!({
        "schema": "connector.budget_profile.v1",
        "talk_bulkhead": "CONNECTOR_BULKHEAD_TALK",
        "provider_deadline": "CONNECTOR_TALK_LLM_TIMEOUT / wall",
    });
    let mission_profile = serde_json::json!({
        "schema": "connector.mission_profile.v1",
        "workbench": true,
        "admit_address": compiled_address_contracts.admit_address,
        "talk_address": compiled_address_contracts.talk_address,
    });

    let body = serde_json::json!({
        "principal_id": agent_pid,
        "tenant_id": tenant_id,
        "identity_generation": identity_generation,
        "charter_generation": charter_generation,
        "broker_generation": broker_generation,
        "quarantine_generation": quarantine_generation,
        "iac_epoch": iac_epoch,
        "policy_bundle_id": policy_bundle_id,
        "who_am_i": who,
        "hard_charter": hard_charter,
        "vendor_brain_denial": vendor_brain_denial,
        "agent_name": agent_name,
        "compiled_skills": compiled_skills,
        "compiled_rules": compiled_rules,
        "compiled_address_contracts": compiled_address_contracts,
        "compiled_tool_names": compiled_tool_names,
        "memory_index_ref": memory_index_ref,
        "snapshot_version": snapshot_version,
    });
    let snapshot_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&body).unwrap_or_default())
    );

    AgentRuntimeSnapshot {
        schema: AGENT_RUNTIME_SNAPSHOT_SCHEMA.into(),
        principal_id: agent_pid.into(),
        tenant_id: tenant_id.into(),
        snapshot_version,
        identity_generation,
        charter_generation,
        broker_generation,
        quarantine_generation,
        iac_epoch,
        policy_bundle_id,
        who_am_i: who,
        hard_charter,
        vendor_brain_denial,
        agent_name,
        compiled_skills,
        compiled_rules,
        compiled_address_contracts,
        compiled_tool_names,
        static_llm_envelope,
        provider_route: None,
        memory_index_ref,
        budget_profile,
        mission_profile,
        snapshot_hash,
        compiled_at_ms: chrono::Utc::now().timestamp_millis(),
    }
}

/// Compile + publish (may touch kernel — run via spawn_blocking).
pub fn compile_and_publish(
    state: &SharedState,
    agent_pid: &str,
    tenant_id: &str,
) -> Arc<AgentRuntimeSnapshot> {
    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_talk_lane(state, agent_pid);
        crate::services::agents::ensure_talk_identity(state, agent_pid);
    }
    let snap = compile_agent_runtime_snapshot(state.as_ref(), agent_pid, tenant_id);
    state.runtime_snapshots.publish(snap)
}

/// Get published snapshot or compile once.
pub fn get_or_compile(
    state: &SharedState,
    agent_pid: &str,
    tenant_id: &str,
) -> Arc<AgentRuntimeSnapshot> {
    if let Some(s) = state.runtime_snapshots.get(agent_pid) {
        return s;
    }
    compile_and_publish(state, agent_pid, tenant_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snap() -> AgentRuntimeSnapshot {
        AgentRuntimeSnapshot {
            schema: AGENT_RUNTIME_SNAPSHOT_SCHEMA.into(),
            principal_id: "a1".into(),
            tenant_id: "t1".into(),
            snapshot_version: 1,
            identity_generation: 1,
            charter_generation: 1,
            broker_generation: 1,
            quarantine_generation: 0,
            iac_epoch: 1,
            policy_bundle_id: "policy:a1:1:1".into(),
            who_am_i: "I am a1".into(),
            hard_charter: "refuse X".into(),
            vendor_brain_denial: "denial".into(),
            agent_name: "A1".into(),
            compiled_skills: vec!["echo".into()],
            compiled_rules: serde_json::json!({}),
            compiled_address_contracts: CompiledAddressContracts::default(),
            compiled_tool_names: vec!["echo".into(), "llm.chat".into()],
            static_llm_envelope: "envelope".into(),
            provider_route: None,
            memory_index_ref: "ns:a1".into(),
            budget_profile: serde_json::json!({}),
            mission_profile: serde_json::json!({}),
            snapshot_hash: "abc".into(),
            compiled_at_ms: 0,
        }
    }

    #[test]
    fn registry_publish_get_invalidate() {
        let reg = RuntimeSnapshotRegistry::new();
        reg.publish(sample_snap());
        assert!(reg.get("a1").is_some());
        reg.invalidate("a1");
        assert!(reg.get("a1").is_none());
    }

    #[test]
    fn generation_mismatch_defers() {
        let s = sample_snap();
        assert!(s.assert_generations_match(1, 1).is_ok());
        assert!(s.assert_generations_match(2, 1).is_err());
    }
}
