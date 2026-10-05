//! Production agent memory — MEMORY / EVIDENCE / FORENSICS on VAC substrate.
//!
//! Enable: `CONNECTOR_AGENT_MEMORY=1` (or `CONNECTOR_AUGMENTED_ENV=1` for full path).
//! Docs: platform/docs/arch/CONNECTOR_AGENT_MEMORY.md

pub mod api;
pub mod capsule;
pub mod context_store;
pub mod evidence;
pub mod moment;
pub mod reducer;
pub mod rollup;

use serde_json::{json, Value};

pub fn enabled() -> bool {
    env_on("CONNECTOR_AGENT_MEMORY")
        || crate::substrate::harden_posture::augmented_env_harden()
}

pub fn harden_cap() -> bool {
    env_on("CONNECTOR_AGENT_MEMORY_HARDEN")
        || crate::substrate::harden_posture::harden_refuse_start_enabled()
}

fn env_on(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

pub fn posture_json() -> Value {
    json!({
        "schema": "connector.agent_memory.posture.v1",
        "enabled": enabled(),
        "harden_cap_64kb": harden_cap(),
        "planes": {
            "memory": "AgentMemoryCapsule hot 8-64KB",
            "evidence": "EvidenceRecord append-only hash chain",
            "forensics": "MomentProof + reconstruct @ checkpoint+delta",
        "rollup": "Context Rollup — fade states F0-F3, proof levels P0-P3",
        },
        "flags": {
            "CONNECTOR_AGENT_MEMORY": enabled(),
            "CONNECTOR_AGENT_MEMORY_HARDEN": harden_cap(),
        },
        "docs": "platform/docs/arch/CONNECTOR_AGENT_MEMORY.md",
        "rollup_docs": "platform/docs/arch/CONNECTOR_CONTEXT_ROLLUP.md",
        "rollup": crate::substrate::agent_memory::rollup::posture_json(),
    })
}
