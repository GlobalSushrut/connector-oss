//! Cross-agent sharing — isolated by default; a **sharing contract** (what / where /
//! how much / why) is required before a **shared portal** exists.
//!
//! Agents cannot mint skip-HITL (App Allow) or share portals. Only a **human** with
//! kernel root passcode may. Agent A never sees Agent B's NS FS / ACS / memory
//! unless a portal lists them.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::kernel::nsfs;
use crate::state::PlatformState;

pub const CONTRACT_FOLDER: &str = "iia_share_contracts_v1";
pub const PORTAL_FOLDER: &str = "iia_share_portals_v1";
pub const SHARE_SCHEMA: &str = "connector.share.portal.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareContractV1 {
    pub from_pid: String,
    pub to_pid: String,
    /// What is shared (namespace, nsfs tree, knowledge id).
    pub what: String,
    /// Where the grantee may bind it (`/share/{portal_id}` or a namespace).
    pub r#where: String,
    /// How much: bytes, packets, ttl.
    #[serde(default)]
    pub bytes_max: u64,
    #[serde(default)]
    pub packets_max: u64,
    #[serde(default)]
    pub ttl_ms: i64,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub justification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePortalV1 {
    pub portal_id: String,
    pub from_pid: String,
    pub to_pid: String,
    pub what: String,
    pub bind: String,
    pub bytes_max: u64,
    pub packets_max: u64,
    pub expires_at_ms: i64,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub bytes_used: u64,
    #[serde(default)]
    pub packets_used: u64,
}

pub fn portal_id(from_pid: &str, to_pid: &str, what: &str) -> String {
    let mut h = Sha256::new();
    h.update(from_pid.as_bytes());
    h.update(0u8.to_be_bytes());
    h.update(to_pid.as_bytes());
    h.update(0u8.to_be_bytes());
    h.update(what.as_bytes());
    format!("shp_{}", hex::encode(&h.finalize()[..12]))
}

pub fn validate_contract(c: &ShareContractV1) -> Result<(), String> {
    if c.from_pid.trim().is_empty() || c.to_pid.trim().is_empty() {
        return Err("from_pid_and_to_pid_required".into());
    }
    if c.from_pid.trim() == c.to_pid.trim() {
        return Err("share_same_agent_nonsensical".into());
    }
    if c.what.trim().is_empty() {
        return Err("what_required (namespace / nsfs tree / knowledge)".into());
    }
    if c.justification.trim().len() < 16 {
        return Err(
            "share_requires_justification (min 16 chars: what, where, how much, why)"
                .into(),
        );
    }
    Ok(())
}

/// Human root only — agents cannot grant skip-HITL or open share portals.
pub fn require_human_root(headers: &axum::http::HeaderMap, role_rank: u8) -> Result<(), String> {
    if headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(
            "human_root_only — an agent cannot grant App Allow or open a share portal"
                .into(),
        );
    }
    if role_rank < 4 {
        return Err("operator_human_required_for_root_power".into());
    }
    Ok(())
}

pub fn put_portal(state: &PlatformState, contract: &ShareContractV1) -> Result<SharePortalV1, String> {
    validate_contract(contract)?;
    let id = portal_id(&contract.from_pid, &contract.to_pid, &contract.what);
    let now = chrono::Utc::now().timestamp_millis();
    let ttl = if contract.ttl_ms > 0 {
        contract.ttl_ms
    } else {
        7 * 24 * 3600 * 1000
    };
    let bind = if contract.r#where.trim().is_empty() {
        format!("/share/{id}")
    } else {
        contract.r#where.trim().to_string()
    };
    let portal = SharePortalV1 {
        portal_id: id.clone(),
        from_pid: contract.from_pid.trim().to_string(),
        to_pid: contract.to_pid.trim().to_string(),
        what: contract.what.trim().to_string(),
        bind: bind.clone(),
        bytes_max: if contract.bytes_max == 0 {
            1_048_576
        } else {
            contract.bytes_max
        },
        packets_max: if contract.packets_max == 0 {
            100
        } else {
            contract.packets_max
        },
        expires_at_ms: now.saturating_add(ttl),
        permissions: if contract.permissions.is_empty() {
            vec!["read".into()]
        } else {
            contract.permissions.clone()
        },
        bytes_used: 0,
        packets_used: 0,
    };
    let _ = nsfs::ensure_tree(&portal.from_pid);
    let _ = nsfs::ensure_tree(&portal.to_pid);
    if let (Ok(from_root), Ok(to_root)) = (
        nsfs::nsfs_root(&portal.from_pid),
        nsfs::nsfs_root(&portal.to_pid),
    ) {
        let _ = std::fs::create_dir_all(from_root.join("share").join(&id));
        let _ = std::fs::create_dir_all(to_root.join("share").join(&id));
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    es.folder_put(
        CONTRACT_FOLDER,
        &id,
        &serde_json::to_value(contract).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())?;
    es.folder_put(
        PORTAL_FOLDER,
        &id,
        &serde_json::to_value(&portal).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())?;
    Ok(portal)
}

/// Compensating undo — close a share portal (U7). Human+root at HTTP.
pub fn close_portal(state: &PlatformState, portal_id: &str) -> Result<Value, String> {
    let id = portal_id.trim();
    if id.is_empty() {
        return Err("portal_id_required".into());
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let existing = es.folder_get(PORTAL_FOLDER, id).ok().flatten();
    let Some(p) = existing else {
        return Err("portal_not_found".into());
    };
    let from = p.get("from_pid").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let to = p.get("to_pid").and_then(|x| x.as_str()).unwrap_or("").to_string();
    es.folder_delete(PORTAL_FOLDER, id)
        .map_err(|e| e.to_string())?;
    let _ = es.folder_delete(CONTRACT_FOLDER, id);
    drop(es);
    crate::kernel::operating_layer::record(
        crate::kernel::operating_layer::Socket::World,
        &from,
        "world.portal_close",
        true,
        &json!({ "portal_id": id, "to_pid": to }),
    );
    Ok(json!({
        "ok": true,
        "portal_id": id,
        "from_pid": from,
        "to_pid": to,
        "honesty": "Pore closed. Agents are isolated again. Not world rewind."
    }))
}

pub fn list_portals(state: &PlatformState, agent_pid: Option<&str>) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let Ok(keys) = es.folder_keys(PORTAL_FOLDER, None) else {
        return vec![];
    };
    let now = chrono::Utc::now().timestamp_millis();
    keys.into_iter()
        .filter_map(|k| es.folder_get(PORTAL_FOLDER, &k).ok().flatten())
        .filter(|p| {
            let exp = p.get("expires_at_ms").and_then(|x| x.as_i64()).unwrap_or(0);
            if exp > 0 && exp < now {
                return false;
            }
            let Some(want) = agent_pid.map(|s| s.trim()) else {
                return true;
            };
            if want.is_empty() {
                return true;
            }
            p.get("from_pid").and_then(|x| x.as_str()) == Some(want)
                || p.get("to_pid").and_then(|x| x.as_str()) == Some(want)
        })
        .collect()
}

pub fn agents_have_portal(
    state: &PlatformState,
    from_pid: &str,
    to_pid: &str,
    namespace: Option<&str>,
) -> bool {
    if from_pid == to_pid {
        return true;
    }
    let ns = namespace.unwrap_or("").trim();
    list_portals(state, Some(from_pid)).iter().any(|p| {
        let a = p.get("from_pid").and_then(|x| x.as_str()).unwrap_or("");
        let b = p.get("to_pid").and_then(|x| x.as_str()).unwrap_or("");
        let pair = (a == from_pid && b == to_pid) || (a == to_pid && b == from_pid);
        if !pair {
            return false;
        }
        if ns.is_empty() {
            return true;
        }
        let what = p.get("what").and_then(|x| x.as_str()).unwrap_or("");
        let bind = p.get("bind").and_then(|x| x.as_str()).unwrap_or("");
        what == ns || bind == ns || ns.starts_with(what) || what.starts_with(ns)
    })
}

pub fn agent_may_use_portal(state: &PlatformState, agent_pid: &str, target_ns: &str, write: bool) -> bool {
    let t = target_ns.trim();
    list_portals(state, Some(agent_pid)).iter().any(|p| {
        let bind = p.get("bind").and_then(|x| x.as_str()).unwrap_or("");
        let what = p.get("what").and_then(|x| x.as_str()).unwrap_or("");
        let path_ok = t == bind
            || t.starts_with(&format!("{bind}/"))
            || t == what
            || t.starts_with(&format!("{what}/"));
        if !path_ok {
            return false;
        }
        let perms = p
            .get("permissions")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let perm_ok = if write {
            perms.iter().any(|x| x.as_str() == Some("write"))
        } else {
            perms.iter().any(|x| {
                matches!(x.as_str(), Some("read") | Some("write") | Some("*"))
            })
        };
        perm_ok && portal_quota_ok(p)
    })
}

pub fn portal_quota_ok(p: &Value) -> bool {
    let bytes_max = p.get("bytes_max").and_then(|x| x.as_u64()).unwrap_or(0);
    let packets_max = p.get("packets_max").and_then(|x| x.as_u64()).unwrap_or(0);
    let bytes_used = p.get("bytes_used").and_then(|x| x.as_u64()).unwrap_or(0);
    let packets_used = p.get("packets_used").and_then(|x| x.as_u64()).unwrap_or(0);
    (bytes_max == 0 || bytes_used < bytes_max) && (packets_max == 0 || packets_used < packets_max)
}

pub fn record_portal_use(
    state: &PlatformState,
    portal_id: &str,
    bytes: u64,
    packets: u64,
) -> Result<(), String> {
    let id = portal_id.trim();
    if id.is_empty() {
        return Err("portal_id_required".into());
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let mut p = es
        .folder_get(PORTAL_FOLDER, id)
        .ok()
        .flatten()
        .ok_or_else(|| "portal_not_found".to_string())?;
    let bytes_max = p.get("bytes_max").and_then(|x| x.as_u64()).unwrap_or(0);
    let packets_max = p.get("packets_max").and_then(|x| x.as_u64()).unwrap_or(0);
    let bytes_used = p.get("bytes_used").and_then(|x| x.as_u64()).unwrap_or(0);
    let packets_used = p.get("packets_used").and_then(|x| x.as_u64()).unwrap_or(0);
    let next_bytes = bytes_used.saturating_add(bytes);
    let next_packets = packets_used.saturating_add(packets);
    if bytes_max > 0 && next_bytes > bytes_max {
        return Err("portal_bytes_max".into());
    }
    if packets_max > 0 && next_packets > packets_max {
        return Err("portal_packets_max".into());
    }
    p["bytes_used"] = json!(next_bytes);
    p["packets_used"] = json!(next_packets);
    es.folder_put(PORTAL_FOLDER, id, &p)
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn snapshot(state: &PlatformState, agent_pid: &str) -> Value {
    json!({
        "schema": SHARE_SCHEMA,
        "agent_pid": agent_pid,
        "portals": list_portals(state, Some(agent_pid)),
        "honesty": "Isolated by default. Shared portal exists only after a human+root sharing contract (what, where, how much, why). Agent A cannot see Agent B otherwise.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn justification_required() {
        let c = ShareContractV1 {
            from_pid: "a".into(),
            to_pid: "b".into(),
            what: "/m/a".into(),
            r#where: String::new(),
            bytes_max: 0,
            packets_max: 0,
            ttl_ms: 0,
            permissions: vec![],
            justification: "short".into(),
        };
        assert!(validate_contract(&c).is_err());
        let mut d = c;
        d.justification = "share bay telemetry read-only for shift".into();
        assert!(validate_contract(&d).is_ok());
    }
}
