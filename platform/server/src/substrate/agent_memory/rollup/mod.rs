//! Context Rollup — fade score, eligibility, execution, tombstones.
//!
//! Enable: `CONNECTOR_CONTEXT_ROLLUP=1` (or agent memory / augmented env).
//! Docs: platform/docs/arch/CONNECTOR_CONTEXT_ROLLUP.md

pub mod api;
pub mod consolidate;
pub mod demo_c0c10;
pub mod eligibility;
pub mod execute;
pub mod fade;
pub mod metrics;
pub mod policy;
pub mod rehydrate;
pub mod schedule;
pub mod skeleton;
pub mod tombstone;

#[cfg(test)]
mod invariant_tests;

use serde_json::{json, Value};

pub fn enabled() -> bool {
    env_on("CONNECTOR_CONTEXT_ROLLUP")
        || super::enabled()
}

fn env_on(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

pub fn delete_raw_enabled() -> bool {
    env_on("CONNECTOR_ROLLUP_DELETE_RAW")
}

pub fn posture_json() -> Value {
    json!({
        "schema": "connector.context_rollup.posture.v1",
        "enabled": enabled(),
        "delete_raw": delete_raw_enabled(),
        "principle": "Fade information, never fade consequence.",
        "fade_states": ["F0_full", "F1_distilled", "F2_decision", "F3_skeleton"],
        "proof_levels": ["P0_full", "P1_distilled", "P2_contextual", "P3_commitment"],
        "flags": {
            "CONNECTOR_CONTEXT_ROLLUP": enabled(),
            "CONNECTOR_ROLLUP_DELETE_RAW": delete_raw_enabled(),
        },
        "docs": "platform/docs/arch/CONNECTOR_CONTEXT_ROLLUP.md",
    })
}
