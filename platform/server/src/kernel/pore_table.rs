//! Pore table — iptables-like allowlist for every world address.
//!
//! Default DROP. A row is ACCEPT for one `(agent × address × dest)`.
//! LLM provider traffic uses a Connector-owned system pore, not an agent grant.
//! This is the userspace table; Landlock children enforce dest pin + FS.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::kernel::world_gateway::WorldGrantV1;
use crate::pore_worker::{dest_spec, parse_url_host_port};
use crate::state::PlatformState;

pub const PORE_FOLDER: &str = "landlock_pores_v1";
pub const PORE_SCHEMA: &str = "connector.landlock.pore.v1";
pub const LLM_SYSTEM_AGENT: &str = "_connector";
pub const LLM_PROVIDER_ADDR: &str = "llm:provider";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoreRow {
    pub schema: String,
    pub pore_id: String,
    pub agent_pid: String,
    pub address: String,
    pub address_type: String,
    pub dest_host: String,
    pub dest_port: u16,
    /// network_deny | network_ingress_deny | deny_dangerous
    pub seccomp_intent: String,
    #[serde(default)]
    pub fs_read: String,
    #[serde(default)]
    pub fs_write: String,
    pub status: String,
    pub at_ms: i64,
}

pub fn pore_id(agent_pid: &str, address: &str) -> String {
    format!("{}::{}", agent_pid.trim(), address.trim())
}

pub fn upsert_from_world_grant(state: &PlatformState, grant: &WorldGrantV1) -> Result<PoreRow, String> {
    if grant.effect.eq_ignore_ascii_case("block") {
        revoke(state, &grant.agent_pid, &grant.address)?;
        return Err("pore_blocked_by_grant".into());
    }
    let (host, port, addr_type, seccomp) = classify_grant(grant);
    let row = PoreRow {
        schema: PORE_SCHEMA.into(),
        pore_id: pore_id(&grant.agent_pid, &grant.address),
        agent_pid: grant.agent_pid.clone(),
        address: grant.address.clone(),
        address_type: if grant.address_type.trim().is_empty() {
            addr_type
        } else {
            grant.address_type.clone()
        },
        dest_host: host,
        dest_port: port,
        seccomp_intent: seccomp,
        fs_read: String::new(),
        fs_write: String::new(),
        status: "accept".into(),
        at_ms: chrono::Utc::now().timestamp_millis(),
    };
    put(state, &row)?;
    Ok(row)
}

pub fn upsert_llm_provider(state: &PlatformState, base_url: &str) -> Result<PoreRow, String> {
    let (host, port) = parse_url_host_port(base_url)?;
    let row = PoreRow {
        schema: PORE_SCHEMA.into(),
        pore_id: pore_id(LLM_SYSTEM_AGENT, LLM_PROVIDER_ADDR),
        agent_pid: LLM_SYSTEM_AGENT.into(),
        address: LLM_PROVIDER_ADDR.into(),
        address_type: "llm_provider".into(),
        dest_host: host,
        dest_port: port,
        seccomp_intent: "network_ingress_deny".into(),
        fs_read: String::new(),
        fs_write: String::new(),
        status: "accept".into(),
        at_ms: chrono::Utc::now().timestamp_millis(),
    };
    put(state, &row)?;
    Ok(row)
}

pub fn get(state: &PlatformState, agent_pid: &str, address: &str) -> Option<PoreRow> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(PORE_FOLDER, &pore_id(agent_pid, address))
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

pub fn assert_allows(
    state: &PlatformState,
    agent_pid: &str,
    address: &str,
    dest_host: &str,
    dest_port: u16,
) -> Result<PoreRow, String> {
    let row = get(state, agent_pid, address).ok_or_else(|| {
        format!("pore_missing: agent={agent_pid} address={address} — owner must grant this world address")
    })?;
    if row.status != "accept" {
        return Err(format!("pore_not_accept: {}", row.status));
    }
    if !dest_matches(&row, dest_host, dest_port) {
        return Err(format!(
            "pore_dest_denied: table={}:{} got={}:{}",
            row.dest_host, row.dest_port, dest_host, dest_port
        ));
    }
    Ok(row)
}

/// Empty dest is DROP for network dials — never a wildcard ACCEPT.
pub fn dest_matches(row: &PoreRow, dest_host: &str, dest_port: u16) -> bool {
    if row.dest_host.trim().is_empty() || row.dest_port == 0 {
        return false;
    }
    dest_spec(&row.dest_host, row.dest_port) == dest_spec(dest_host, dest_port)
}

/// Open an ACCEPT pore for this dial only when an owner world grant already covers it.
pub fn ensure_for_dial(
    state: &PlatformState,
    agent_pid: &str,
    address: &str,
    dest_host: &str,
    dest_port: u16,
) -> Result<PoreRow, String> {
    if dest_host.trim().is_empty() || dest_port == 0 {
        return Err("pore_dest_required".into());
    }
    crate::kernel::llm_vendor_cut::deny_agent_vendor_dial(agent_pid, dest_host)?;
    if let Some(row) = get(state, agent_pid, address) {
        return assert_allows(state, agent_pid, address, dest_host, dest_port).map(|_| row);
    }
    let grant = crate::kernel::world_gateway::covering_grant(state, agent_pid, address)
        .ok_or_else(|| {
            format!(
                "pore_missing: agent={agent_pid} address={address} — owner must grant this world address (default DROP)"
            )
        })?;
    let (gh, gp, addr_type, seccomp) = classify_grant(&grant);
    if !gh.is_empty() && gh != dest_host.trim().to_ascii_lowercase() {
        return Err(format!(
            "pore_dest_denied: grant_host={gh} dial_host={dest_host}"
        ));
    }
    if gp != 0 && gp != dest_port {
        return Err(format!(
            "pore_dest_denied: grant_port={gp} dial_port={dest_port}"
        ));
    }
    let row = PoreRow {
        schema: PORE_SCHEMA.into(),
        pore_id: pore_id(agent_pid, address),
        agent_pid: agent_pid.into(),
        address: address.into(),
        address_type: if grant.address_type.trim().is_empty() {
            addr_type
        } else {
            grant.address_type.clone()
        },
        dest_host: dest_host.trim().to_ascii_lowercase(),
        dest_port,
        seccomp_intent: seccomp,
        fs_read: String::new(),
        fs_write: String::new(),
        status: "accept".into(),
        at_ms: chrono::Utc::now().timestamp_millis(),
    };
    put(state, &row)?;
    Ok(row)
}

pub fn revoke(state: &PlatformState, agent_pid: &str, address: &str) -> Result<(), String> {
    let id = pore_id(agent_pid, address);
    if let Some(mut row) = get(state, agent_pid, address) {
        row.status = "drop".into();
        row.at_ms = chrono::Utc::now().timestamp_millis();
        put(state, &row)?;
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let _ = es.folder_delete(PORE_FOLDER, &id);
    Ok(())
}

pub fn list(state: &PlatformState, agent_pid: Option<&str>) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let prefix = agent_pid.map(|p| format!("{}::", p.trim()));
    let Ok(keys) = es.folder_keys(PORE_FOLDER, prefix.as_deref()) else {
        return vec![];
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(PORE_FOLDER, &k).ok().flatten())
        .collect()
}

pub fn posture() -> Value {
    json!({
        "schema": "connector.landlock.pore_table.v1",
        "default": "drop",
        "model": "iptables-like userspace table + Landlock child dest pin",
        "llm": "provider is a Connector system pore; agent cannot dial vendors directly",
        "tool_bypass": "pore worker has no tool dispatcher",
        "folder": PORE_FOLDER,
    })
}

fn put(state: &PlatformState, row: &PoreRow) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    es.folder_put(
        PORE_FOLDER,
        &row.pore_id,
        &serde_json::to_value(row).unwrap_or(Value::Null),
    )
    .map_err(|e| e.to_string())
}

fn classify_grant(grant: &WorldGrantV1) -> (String, u16, String, String) {
    let addr = grant.address.trim();
    for key in ["endpoint", "url", "base_url"] {
        if let Some(ep) = grant.params.get(key).and_then(|v| v.as_str()) {
            if let Ok((h, p)) = parse_url_host_port(ep) {
                let kind = if grant.address_type.trim().is_empty() {
                    "http_api".into()
                } else {
                    grant.address_type.clone()
                };
                return (h, p, kind, "network_ingress_deny".into());
            }
        }
    }
    if let Ok((h, p)) = parse_url_host_port(addr) {
        let kind = if grant.address_type.contains("browser") {
            "browser"
        } else if addr.contains("mcp") || grant.address_type.contains("mcp") {
            "mcp_tool"
        } else if grant.address_type.trim().is_empty() {
            "http_api"
        } else {
            grant.address_type.as_str()
        };
        return (h, p, kind.into(), "network_ingress_deny".into());
    }
    if let Some((h, p)) = addr.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (
                h.trim_start_matches("tcp://")
                    .trim_start_matches("mqtt://")
                    .trim_start_matches("modbus://")
                    .trim_start_matches("ros://")
                    .to_ascii_lowercase(),
                port,
                grant.address_type.clone(),
                "network_ingress_deny".into(),
            );
        }
    }
    let kind = if grant.address_type.trim().is_empty() {
        "host_fs".into()
    } else {
        grant.address_type.clone()
    };
    let seccomp = if kind == "host_fs" || kind == "host_proc" {
        "network_deny"
    } else {
        "network_ingress_deny"
    };
    (String::new(), 0, kind, seccomp.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_url() {
        let g = WorldGrantV1 {
            agent_pid: "a1".into(),
            address: "https://mcp.example:8443/sse".into(),
            address_type: "mcp_tool".into(),
            access: vec![],
            effect: "ask".into(),
            layer: "cone".into(),
            app_allow: vec![],
            cone_ask: vec![],
            justification: None,
            params: json!({}),
            note: None,
        };
        let (h, p, t, s) = classify_grant(&g);
        assert_eq!(h, "mcp.example");
        assert_eq!(p, 8443);
        assert_eq!(t, "mcp_tool");
        assert_eq!(s, "network_ingress_deny");
    }

    #[test]
    fn url_grant_classifies() {
        classify_url();
        assert_eq!(pore_id("ag", "https://x"), "ag::https://x");
    }

    #[test]
    fn empty_dest_is_drop_not_wildcard() {
        let row = PoreRow {
            schema: PORE_SCHEMA.into(),
            pore_id: "a::x".into(),
            agent_pid: "a".into(),
            address: "robot-1".into(),
            address_type: "robot_hal".into(),
            dest_host: String::new(),
            dest_port: 0,
            seccomp_intent: "network_ingress_deny".into(),
            fs_read: String::new(),
            fs_write: String::new(),
            status: "accept".into(),
            at_ms: 0,
        };
        assert!(!dest_matches(&row, "hal.example", 7443));
        let pinned = PoreRow {
            dest_host: "hal.example".into(),
            dest_port: 7443,
            ..row
        };
        assert!(dest_matches(&pinned, "hal.example", 7443));
        assert!(!dest_matches(&pinned, "evil.example", 7443));
        assert!(!dest_matches(&pinned, "hal.example", 80));
    }

    #[test]
    fn params_endpoint_classifies() {
        let g = WorldGrantV1 {
            agent_pid: "a1".into(),
            address: "robot-1".into(),
            address_type: "robot_hal".into(),
            access: vec![],
            effect: "ask".into(),
            layer: "cone".into(),
            app_allow: vec![],
            cone_ask: vec![],
            justification: None,
            params: json!({"endpoint": "tcp://hal.factory:7443"}),
            note: None,
        };
        let (h, p, t, _) = classify_grant(&g);
        assert_eq!(h, "hal.factory");
        assert_eq!(p, 7443);
        assert_eq!(t, "robot_hal");
    }
}
