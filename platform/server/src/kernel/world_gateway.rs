//! World gateway grants — per (agent × CNP address), owner-authorized with kernel root pass.
//!
//! Linux analogy: root passcode is `/etc/shadow`; each grant is a file ACL on one path.
//! Agent A → address P is independent of Agent A → Q and Agent B → P.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::PlatformState;

pub const ADDR_FOLDER: &str = "iia_world_addresses_v1";
pub const GRANT_FOLDER: &str = "iia_world_grants_v1";
const ROOT_SALT: &str = "connector.kernel.root.v1:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldAddressV1 {
    /// CNP address — URL, EntityId, mqtt topic, machine:arm-1, …
    pub address: String,
    /// One of ~20 world types (http_api, machine, device, mqtt, …).
    #[serde(rename = "type")]
    pub address_type: String,
    #[serde(default)]
    pub label: Option<String>,
    /// Root access parameters for this address (owner-defined).
    #[serde(default)]
    pub params: Value,
    /// CNP capabilities this address can speak (empty = type default).
    #[serde(default)]
    pub cnp_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldGrantV1 {
    pub agent_pid: String,
    pub address: String,
    #[serde(default)]
    pub address_type: String,
    /// Capabilities this agent may use at this address (empty = address catalog).
    #[serde(default)]
    pub access: Vec<String>,
    /// allow | ask | block — default **ask** (Cone). allow requires App justification.
    #[serde(default = "ask_default")]
    pub effect: String,
    /// root | cone | app — default cone (AI suggests, human approves).
    #[serde(default = "cone_default")]
    pub layer: String,
    /// Caps that may run without per-action HITL (App layer). Must be ⊂ access.
    #[serde(default)]
    pub app_allow: Vec<String>,
    /// Caps that stay Cone Ask even if layer=app.
    #[serde(default)]
    pub cone_ask: Vec<String>,
    /// Required when app_allow or layer=app or effect=allow (min 16 chars).
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub note: Option<String>,
}

fn ask_default() -> String {
    "ask".into()
}

fn cone_default() -> String {
    "cone".into()
}

pub fn grant_key(agent_pid: &str, address: &str) -> String {
    format!("{}::{}", agent_pid.trim(), address.trim())
}

fn pass_hash(pass: &str) -> String {
    let mut h = Sha256::new();
    h.update(ROOT_SALT.as_bytes());
    h.update(pass.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn root_path() -> std::path::PathBuf {
    let dir = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into());
    std::path::PathBuf::from(dir)
        .join("keys")
        .join("kernel_root.pass")
}

pub fn root_is_set() -> bool {
    if std::env::var("CONNECTOR_KERNEL_ROOT_PASS")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    root_path().is_file()
}

pub fn set_root_passcode(pass: &str) -> Result<(), String> {
    let p = pass.trim();
    if p.len() < 8 {
        return Err("root_passcode_too_short (min 8)".into());
    }
    let path = root_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, pass_hash(p)).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

static ROOT_FAILS: AtomicU32 = AtomicU32::new(0);
static ROOT_LOCK_UNTIL: AtomicI64 = AtomicI64::new(0);

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn root_fail() -> String {
    let now = now_unix();
    let n = ROOT_FAILS.fetch_add(1, Ordering::Relaxed) + 1;
    if n >= 5 {
        ROOT_LOCK_UNTIL.store(now.saturating_add(30), Ordering::Relaxed);
        ROOT_FAILS.store(0, Ordering::Relaxed);
        "root_passcode_locked: retry in 30s".into()
    } else {
        "root_passcode_mismatch".into()
    }
}

pub fn verify_root_passcode(pass: &str) -> Result<(), String> {
    let p = pass.trim();
    if p.is_empty() {
        return Err("root_passcode_required".into());
    }
    let until = ROOT_LOCK_UNTIL.load(Ordering::Relaxed);
    let now = now_unix();
    if until > now {
        return Err(format!("root_passcode_locked: retry in {}s", until - now));
    }
    if let Ok(env) = std::env::var("CONNECTOR_KERNEL_ROOT_PASS") {
        if !env.trim().is_empty() {
            return if env.trim() == p {
                ROOT_FAILS.store(0, Ordering::Relaxed);
                ROOT_LOCK_UNTIL.store(0, Ordering::Relaxed);
                Ok(())
            } else {
                Err(root_fail())
            };
        }
    }
    let stored = std::fs::read_to_string(root_path()).map_err(|_| "root_passcode_not_initialized")?;
    if stored.trim() == pass_hash(p) {
        ROOT_FAILS.store(0, Ordering::Relaxed);
        ROOT_LOCK_UNTIL.store(0, Ordering::Relaxed);
        Ok(())
    } else {
        Err(root_fail())
    }
}

pub fn put_address(state: &PlatformState, addr: &WorldAddressV1) -> Result<(), String> {
    let a = addr.address.trim();
    if a.is_empty() {
        return Err("address_required".into());
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    es.folder_put(ADDR_FOLDER, a, &serde_json::to_value(addr).unwrap_or(Value::Null))
        .map_err(|e| e.to_string())
}

pub fn put_grant(state: &PlatformState, grant: &WorldGrantV1) -> Result<(), String> {
    if grant.agent_pid.trim().is_empty() || grant.address.trim().is_empty() {
        return Err("agent_pid_and_address_required".into());
    }
    // Dual-write GrantRef + legacy WorldGrant via tenant authority ledger.
    let _ = crate::substrate::authority_repo::mint_world_grant(state, grant, None, None)?;
    let _ = crate::kernel::pore_table::upsert_from_world_grant(state, grant);
    Ok(())
}

/// Compensating undo — tombstone then remove this agent's grant at this address (U7).
pub fn revoke_grant(state: &PlatformState, agent_pid: &str, address: &str) -> Result<Value, String> {
    let _ = crate::kernel::pore_table::revoke(state, agent_pid, address);
    crate::substrate::authority_repo::revoke_world_grant(
        state,
        agent_pid,
        address,
        None,
        "world_gateway.revoke",
    )
}

pub fn list_addresses(state: &PlatformState) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let Ok(keys) = es.folder_keys(ADDR_FOLDER, None) else {
        return vec![];
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(ADDR_FOLDER, &k).ok().flatten())
        .collect()
}

pub fn list_grants(state: &PlatformState, agent_pid: Option<&str>) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let prefix = agent_pid.map(|p| format!("{}::", p.trim()));
    let Ok(keys) = es.folder_keys(GRANT_FOLDER, prefix.as_deref()) else {
        return vec![];
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(GRANT_FOLDER, &k).ok().flatten())
        .collect()
}

pub fn get_grant(state: &PlatformState, agent_pid: &str, address: &str) -> Option<WorldGrantV1> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(GRANT_FOLDER, &grant_key(agent_pid, address))
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

/// Owner grant that covers this world address (exact or prefix, same as admission).
pub fn covering_grant(state: &PlatformState, agent_pid: &str, address: &str) -> Option<WorldGrantV1> {
    if let Some(g) = get_grant(state, agent_pid, address) {
        if !g.effect.eq_ignore_ascii_case("block") {
            return Some(g);
        }
        return None;
    }
    let want = address.trim().to_ascii_lowercase();
    for v in list_grants(state, Some(agent_pid)) {
        let Ok(g) = serde_json::from_value::<WorldGrantV1>(v) else {
            continue;
        };
        if g.effect.eq_ignore_ascii_case("block") {
            continue;
        }
        let addr = g.address.trim().to_ascii_lowercase();
        if addr.is_empty() {
            continue;
        }
        if want == addr || want.starts_with(&addr) || addr.starts_with(&want) {
            return Some(g);
        }
    }
    None
}

/// If this agent has any world grants, entity_id must match one (and capability if listed).
/// Empty grants + a named world address fail closed in production / intelligence hardening.
pub fn assert_grant_allows(
    state: &PlatformState,
    agent_pid: &str,
    entity_id: &str,
    capability: &str,
) -> Result<(), String> {
    let grants = list_grants(state, Some(agent_pid));
    if grants.is_empty() {
        match crate::kernel::admission_layers::admit_empty_grants(entity_id) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    let want = entity_id.trim().to_ascii_lowercase();
    let cap = capability.trim().to_ascii_lowercase();
    for g in &grants {
        let addr = g
            .get("address")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if addr.is_empty() {
            continue;
        }
        let addr_ok = want == addr || want.starts_with(&addr) || addr.starts_with(&want);
        if !addr_ok {
            continue;
        }
        let effect = g
            .get("effect")
            .and_then(|x| x.as_str())
            .unwrap_or("ask")
            .to_ascii_lowercase();
        if effect == "block" {
            return Err(format!("world_grant_blocked: agent={agent_pid} address={entity_id}"));
        }
        let access = g
            .get("access")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        if !access.is_empty() {
            let ok = access.iter().any(|c| {
                c.as_str()
                    .map(|s| {
                        let s = s.to_ascii_lowercase();
                        s == cap || s == "*" || cap.starts_with(&s) || s.starts_with(&cap)
                    })
                    .unwrap_or(false)
            });
            if !ok {
                return Err(format!(
                    "world_grant_capability_denied: agent={agent_pid} address={entity_id} cap={capability}"
                ));
            }
        }
        return Ok(());
    }
    Err(format!(
        "world_grant_missing: agent={agent_pid} has grants but none for address={entity_id} — owner must fill gateway form"
    ))
}

pub fn types_catalog() -> Value {
    json!([
        {"id": "local_host", "what": "This Connector node (loopback / same computer). Isolated identity — not host USER."},
        {"id": "host_fs", "what": "Host filesystem path outside the agent's NS FS"},
        {"id": "host_proc", "what": "Host process / shell / notebook exec on this machine"},
        {"id": "agent_nsfs", "what": "This agent's private NS FS (identity home)"},
        {"id": "http_api", "what": "HTTP / REST API URL"},
        {"id": "browser", "what": "Connector-native web explorer (document GET on a granted origin; recorded + dest-pinned). Not Chromium computer-use."},
        {"id": "machine", "what": "CNC / robot EntityId (machine:…)"},
        {"id": "robot", "what": "Robot / HAL endpoint (robot:…)"},
        {"id": "device", "what": "IoT / generic device"},
        {"id": "sensor", "what": "Sensor telemetry source"},
        {"id": "actuator", "what": "Actuator / effector"},
        {"id": "service", "what": "Microservice"},
        {"id": "mqtt", "what": "MQTT topic / broker"},
        {"id": "mcp_tool", "what": "MCP tool bridge"},
        {"id": "a2a_task", "what": "A2A task endpoint"},
        {"id": "webhook", "what": "Webhook URL"},
        {"id": "cluster_cell", "what": "Mesh / cluster cell"},
        {"id": "network_peer", "what": "CNP L5 peer"},
        {"id": "robot_hal", "what": "Partner robot HAL"},
        {"id": "iot_endpoint", "what": "IoT gateway"},
        {"id": "modbus", "what": "Modbus endpoint"},
        {"id": "composite", "what": "Multi-part cell"},
        {"id": "cpkg_plugin", "what": ".cpkg runtime"},
        {"id": "knowledge_plane", "what": "Knowledge / RAG APIs"},
        {"id": "openai_compat", "what": "OpenAI-compatible LLM"},
        {"id": "agent", "what": "Another chartered agent"},
    ])
}
