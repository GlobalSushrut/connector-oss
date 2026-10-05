//! Purge an intelligence: IIA records + NS FS. Kill/terminate must not leave
//! signing keys, charters, or memory trees behind.

use serde_json::{json, Value};

use crate::kernel::{agent_principal, intelligence_spec, nsfs, share_portal};
use crate::state::PlatformState;

const FOLDERS: &[&str] = &[
    agent_principal::IIA_PRINCIPAL_FOLDER,
    agent_principal::IIA_CONTRACT_FOLDER,
    agent_principal::IIA_CONTINUITY_FOLDER,
    agent_principal::IIA_RECEIPT_CHAIN_FOLDER,
    "intelligence_principal_subkey_v2",
    intelligence_spec::SPEC_FOLDER,
    intelligence_spec::SKILLS_FOLDER,
    intelligence_spec::PORTALS_FOLDER,
    intelligence_spec::RULES_FOLDER,
    "agent_setup_spec_v2",
    "agent_activation_profile_v2",
    "docklock_cage_env_v1",
    "docklock_profile_v2",
    "iia_decision_trace_heads",
];

/// Delete per-pid IIA folders and the NS FS tree. Best-effort; returns what ran.
pub fn purge_intelligence(state: &PlatformState, api_pid: &str, kernel_pid: &str) -> Value {
    let pid = api_pid.trim();
    let kpid = kernel_pid.trim();
    let mut deleted_folders = Vec::new();
    if let Ok(mut es) = state.engine_store.lock() {
        for folder in FOLDERS {
            for key in [pid, kpid] {
                if key.is_empty() {
                    continue;
                }
                if es.folder_get(folder, key).ok().flatten().is_some() {
                    let _ = es.folder_delete(folder, key);
                    deleted_folders.push(format!("{folder}/{key}"));
                }
            }
        }
        // Close portals that name this pid.
        if let Ok(keys) = es.folder_keys(share_portal::PORTAL_FOLDER, None) {
            for id in keys {
                if let Ok(Some(p)) = es.folder_get(share_portal::PORTAL_FOLDER, &id) {
                    let from = p.get("from_pid").and_then(|x| x.as_str()).unwrap_or("");
                    let to = p.get("to_pid").and_then(|x| x.as_str()).unwrap_or("");
                    if from == pid || to == pid || from == kpid || to == kpid {
                        let _ = es.folder_delete(share_portal::PORTAL_FOLDER, &id);
                        let _ = es.folder_delete(share_portal::CONTRACT_FOLDER, &id);
                    }
                }
            }
        }
    }
    let mut nsfs_removed = false;
    for key in [pid, kpid] {
        if key.is_empty() {
            continue;
        }
        if let Ok(root) = nsfs::nsfs_root(key) {
            if root.is_dir() {
                if std::fs::remove_dir_all(&root).is_ok() {
                    nsfs_removed = true;
                }
            }
        }
    }
    json!({
        "ok": true,
        "api_pid": pid,
        "kernel_pid": kpid,
        "deleted_folders": deleted_folders,
        "nsfs_removed": nsfs_removed,
        "honesty": "Kill/terminate purges principal, contract, subkey, spec, portals, and NS FS. Not a soft archive.",
    })
}
