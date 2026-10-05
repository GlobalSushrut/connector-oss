//! Sovereign node contract — durable NodeID, boot epoch, capability manifest, posture honesty.
//!
//! The node (not a pod) is the unit of identity, state, and trust. HA/federation are
//! separate topologies and must not be inferred from replica count.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::{PlatformState, SharedState};

pub const SCHEMA: &str = "connector.node_contract.v1";
pub const FOLDER: &str = "_node_contract";
pub const NODE_KEY: &str = "identity";

static BOOT_EPOCH: OnceLock<u64> = OnceLock::new();
static NODE_ID_CACHE: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub schema: String,
    pub node_id: String,
    pub trust_domain_id: String,
    pub cell_id: String,
    pub schema_version: u32,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub identity: bool,
    pub memory: bool,
    pub authority: bool,
    pub effects: bool,
    pub isolation: bool,
    pub evidence: bool,
    pub microvm_measured: bool,
    pub landlock_available: bool,
    pub cfni: bool,
    pub custody: bool,
    pub ha_writer_fencing: bool,
    pub federation: bool,
    pub honesty_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeContract {
    pub schema: String,
    pub identity: NodeIdentity,
    pub boot_epoch: u64,
    pub capability_manifest: CapabilityManifest,
    pub topology: String,
    pub runtime_mode: String,
    pub workload_profile_id: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn generate_node_id(cell_id: &str, data_dir: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cell_id.as_bytes());
    hasher.update(b"|");
    hasher.update(data_dir.as_bytes());
    hasher.update(b"|");
    hasher.update(now_unix().to_le_bytes());
    let dig = hasher.finalize();
    format!("node_{}", hex::encode(&dig[..16]))
}

/// Boot epoch — increments once per process start (not per request).
pub fn boot_epoch() -> u64 {
    *BOOT_EPOCH.get_or_init(now_unix)
}

pub fn load_or_create_identity(state: &PlatformState) -> NodeIdentity {
    if let Some(cached) = NODE_ID_CACHE.get() {
        if let Ok(es) = state.engine_store.lock() {
            if let Ok(Some(v)) = es.folder_get(FOLDER, NODE_KEY) {
                if let Ok(mut id) = serde_json::from_value::<NodeIdentity>(v) {
                    if id.node_id == *cached {
                        return id;
                    }
                    // Prefer durable store if present
                    NODE_ID_CACHE.get_or_init(|| id.node_id.clone());
                    return id;
                }
            }
        }
    }

    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get(FOLDER, NODE_KEY) {
            if let Ok(id) = serde_json::from_value::<NodeIdentity>(v) {
                let _ = NODE_ID_CACHE.set(id.node_id.clone());
                return id;
            }
        }
    }

    let cell_id = std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| state.storage_layout.cell_id.clone());
    let trust_domain = std::env::var("CONNECTOR_TRUST_DOMAIN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("td_{cell_id}"));
    let data_dir = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "data".into());
    let node_id = std::env::var("CONNECTOR_NODE_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| generate_node_id(&cell_id, &data_dir));

    let identity = NodeIdentity {
        schema: SCHEMA.into(),
        node_id: node_id.clone(),
        trust_domain_id: trust_domain,
        cell_id,
        schema_version: 1,
        created_at_unix: now_unix(),
    };

    if let Ok(mut es) = state.engine_store.lock() {
        if let Ok(val) = serde_json::to_value(&identity) {
            let _ = es.folder_put(FOLDER, NODE_KEY, &val);
        }
    }
    let _ = NODE_ID_CACHE.set(node_id);
    identity
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

pub fn capability_manifest(state: &PlatformState) -> CapabilityManifest {
    let isolation = *state.isolation_runtime.read().unwrap();
    let microvm = matches!(
        isolation,
        crate::services::runtime_control::IsolationRuntime::Microvm
    );
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    let landlock_ok = landlock
        .get("kernel_abi_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut notes = vec![
        "ha_writer_fencing=false until Gate E active/passive is proven".into(),
        "federation=false until Gate F signed attenuated tasks are proven".into(),
        "Kubernetes replicaCount must not be read as HA or multi-region".into(),
    ];
    if microvm && !env_flag("CONNECTOR_MICROVM_MEASURED") {
        notes.push(
            "microvm runtime selected but CONNECTOR_MICROVM_MEASURED unset — not advertising measured TEE/MicroCell"
                .into(),
        );
    }

    CapabilityManifest {
        identity: true,
        memory: true,
        authority: true,
        effects: true,
        isolation: true,
        evidence: true,
        microvm_measured: microvm && env_flag("CONNECTOR_MICROVM_MEASURED"),
        landlock_available: landlock_ok,
        cfni: crate::substrate::cfni::cfni_enabled(),
        custody: env_flag("CONNECTOR_CUSTODY_ENABLED"),
        ha_writer_fencing: false,
        federation: false,
        honesty_notes: notes,
    }
}

pub fn build_contract(state: &PlatformState) -> NodeContract {
    let identity = load_or_create_identity(state);
    let profile = crate::substrate::workload_profile::load_active(state);
    let mode = *state.runtime_mode.read().unwrap();
    NodeContract {
        schema: SCHEMA.into(),
        identity,
        boot_epoch: boot_epoch(),
        capability_manifest: capability_manifest(state),
        topology: "sovereign_single_node".into(),
        runtime_mode: mode.as_str().into(),
        workload_profile_id: profile.id,
    }
}

pub fn posture_json(state: &PlatformState) -> Value {
    let c = build_contract(state);
    json!({
        "schema": SCHEMA,
        "contract": c,
        "product_sot": "single_node",
        "ha_claimable": false,
        "federation_claimable": false,
    })
}

pub async fn get_node_contract(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<Value> {
    axum::Json(crate::operator::honesty::operator_envelope(posture_json(
        state.as_ref(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_epoch_stable_in_process() {
        let a = boot_epoch();
        let b = boot_epoch();
        assert_eq!(a, b);
    }

    #[test]
    fn generate_node_id_hex_prefix() {
        let id = generate_node_id("cell_a", "/tmp/data");
        assert!(id.starts_with("node_"));
        assert_eq!(id.len(), 5 + 32);
    }
}
