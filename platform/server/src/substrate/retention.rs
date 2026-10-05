//! Retention / cold-tier policy (I-23 / P6.9) — policy JSON + honest job stub.
//!
//! Jobs log TTL intent only; they do **not** move B segments to cold tiers yet.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;

pub const RETENTION_POLICY_KEY: &str = "retention_policy";
pub const RETENTION_POLICY_SCHEMA: &str = "retention_policy.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicyV1 {
    #[serde(default = "default_schema")]
    pub schema: String,
    /// Hot object-fabric / moment TTL in days (0 = unlimited).
    #[serde(default = "default_fabric_ttl")]
    pub fabric_ttl_days: u32,
    /// Keep skeleton (S) manifests after B body moves — intent only until cold tier ships.
    #[serde(default = "default_keep_skeletons")]
    pub keep_skeletons: bool,
    /// TraceTramp / WitnessCtl prune-to-CAS intent days.
    #[serde(default = "default_institution_prune")]
    pub institution_prune_days: u32,
    #[serde(default = "default_honesty")]
    pub honesty: String,
}

fn default_schema() -> String {
    RETENTION_POLICY_SCHEMA.into()
}
fn default_fabric_ttl() -> u32 {
    90
}
fn default_keep_skeletons() -> bool {
    true
}
fn default_institution_prune() -> u32 {
    180
}
fn default_honesty() -> String {
    "Policy stored; cold-tier move not yet implemented — jobs log TTL intent only".into()
}

impl Default for RetentionPolicyV1 {
    fn default() -> Self {
        Self {
            schema: RETENTION_POLICY_SCHEMA.into(),
            fabric_ttl_days: 90,
            keep_skeletons: true,
            institution_prune_days: 180,
            honesty: "Policy stored; cold-tier move not yet implemented — jobs log TTL intent only"
                .into(),
        }
    }
}

pub fn default_policy_json() -> Value {
    serde_json::to_value(RetentionPolicyV1::default()).unwrap_or(json!({}))
}

pub fn load_policy(state: &PlatformState) -> RetentionPolicyV1 {
    let es = state.engine_store.lock().unwrap();
    es.folder_get("settings_system", RETENTION_POLICY_KEY)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<RetentionPolicyV1>(v).ok())
        .unwrap_or_default()
}

pub fn save_policy(state: &PlatformState, policy: &RetentionPolicyV1) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "settings_system",
        RETENTION_POLICY_KEY,
        &serde_json::to_value(policy).unwrap_or(json!({})),
    );
}

/// Background job stub — logs TTL intent; does not move cold tiers yet.
pub fn run_retention_job_stub(state: &PlatformState) -> Value {
    let policy = load_policy(state);
    let fabric_count = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(crate::services::object_fabric::OBJECT_FABRIC_FOLDER, None)
            .map(|k| k.len())
            .unwrap_or(0)
    };
    let moment_count = crate::services::moment::moment_count(state);
    tracing::info!(
        schema = RETENTION_POLICY_SCHEMA,
        fabric_ttl_days = policy.fabric_ttl_days,
        institution_prune_days = policy.institution_prune_days,
        keep_skeletons = policy.keep_skeletons,
        fabric_objects = fabric_count,
        moments = moment_count,
        "retention job stub: TTL intent only — not yet moving cold tiers"
    );
    json!({
        "schema": "retention_job_stub.v1",
        "status": "logged_intent",
        "policy": policy,
        "observed": {
            "object_fabric_count": fabric_count,
            "moment_count": moment_count,
        },
        "honesty": "not yet moving cold tiers",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_honest() {
        let p = RetentionPolicyV1::default();
        assert_eq!(p.schema, RETENTION_POLICY_SCHEMA);
        assert!(p.honesty.contains("not yet"));
        assert!(p.keep_skeletons);
    }
}
