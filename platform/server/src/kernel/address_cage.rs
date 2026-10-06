//! Address cage — every outer-world target is a typed address; hosted agents
//! keep an isolated identity even on the same machine.
//!
//! The host computer, an HTTP API, an MCP tool, IoT, and a robot are the same
//! kind of thing: an address the owner grants per (agent × address). Same-machine
//! does **not** mean host USER/HOME/uid. The agent's world is `nsfs/{pid}/`.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::kernel::{agent_principal, nsfs};
use crate::state::PlatformState;

pub const CAGE_SCHEMA: &str = "connector.address_cage.v1";
pub const LOCAL_HOST_ADDR: &str = "local:host";
pub const LOCAL_HOST_TYPE: &str = "local_host";

/// Host-login / SSH / sudo identity that must not leak into an agent cage.
pub const HOST_IDENTITY_ENV: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "USERNAME",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "KRB5CCNAME",
    "XDG_RUNTIME_DIR",
    "SUDO_USER",
    "SUDO_UID",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CagedAddress {
    pub address: String,
    pub address_type: String,
    /// True when the target is this Connector node (loopback, host fs, local proc).
    pub same_machine: bool,
    /// True when the target is this agent's own NS FS tree (identity home, not outer world).
    pub self_nsfs: bool,
    /// True when a filesystem path is outside the agent's NS FS.
    pub host_fs: bool,
}

impl CagedAddress {
    fn new(address: String, address_type: &'static str, same_machine: bool, self_nsfs: bool, host_fs: bool) -> Self {
        Self {
            address,
            address_type: address_type.to_string(),
            same_machine,
            self_nsfs,
            host_fs,
        }
    }
}

/// Catalog of cage address types (outer world + same-machine host).
pub fn types_catalog() -> Value {
    json!([
        {"id": "local_host", "what": "This Connector node (loopback / same computer). Isolated identity — not host USER."},
        {"id": "host_fs", "what": "Host filesystem path outside the agent's NS FS"},
        {"id": "host_proc", "what": "Host process / shell / notebook exec on this machine"},
        {"id": "agent_nsfs", "what": "This agent's private NS FS (identity home)"},
        {"id": "http_api", "what": "HTTP / REST API URL"},
        {"id": "browser", "what": "Connector-native web explorer origin"},
        {"id": "mcp_tool", "what": "MCP / tool bridge"},
        {"id": "machine", "what": "CNC / robot EntityId (machine:…)"},
        {"id": "robot_hal", "what": "Partner robot HAL"},
        {"id": "device", "what": "IoT / generic device"},
        {"id": "iot_endpoint", "what": "IoT gateway"},
        {"id": "sensor", "what": "Sensor telemetry source"},
        {"id": "actuator", "what": "Actuator / effector"},
        {"id": "mqtt", "what": "MQTT topic / broker"},
        {"id": "modbus", "what": "Modbus endpoint"},
        {"id": "webhook", "what": "Webhook URL"},
        {"id": "service", "what": "Microservice"},
        {"id": "a2a_task", "what": "A2A task endpoint"},
        {"id": "cpkg_plugin", "what": ".cpkg runtime"},
        {"id": "agent", "what": "Another chartered agent"},
    ])
}

fn param_str(parameters: &Value, keys: &[&str]) -> Option<String> {
    walk_param(parameters, keys, 0)
}

fn walk_param(parameters: &Value, keys: &[&str], depth: usize) -> Option<String> {
    if depth > 6 {
        return None;
    }
    if let Some(obj) = parameters.as_object() {
        for (k, v) in obj {
            let kl = k.to_ascii_lowercase();
            if keys.iter().any(|want| want.eq_ignore_ascii_case(&kl)) {
                if let Some(s) = v.as_str() {
                    let t = s.trim();
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                }
            }
        }
        for v in obj.values() {
            if let Some(s) = walk_param(v, keys, depth + 1) {
                return Some(s);
            }
        }
    } else if let Some(arr) = parameters.as_array() {
        for v in arr.iter().take(8) {
            if let Some(s) = walk_param(v, keys, depth + 1) {
                return Some(s);
            }
        }
    }
    None
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_matches('[').trim_end_matches(']').to_ascii_lowercase();
    matches!(h.as_str(), "localhost" | "localhost." | "127.0.0.1" | "::1" | "0.0.0.0")
        || h.ends_with(".localhost")
        || h.starts_with("127.")
}

fn host_from_url(url: &str) -> Option<String> {
    crate::substrate::egress_policy::parse_host_from_url(url)
}

fn looks_like_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://") || l.contains("://")
}

/// Classify an outer-world or identity-home address for this agent.
pub fn classify_address(raw: &str, agent_pid: &str) -> CagedAddress {
    classify_named(raw, agent_pid)
}

fn classify_named(raw: &str, agent_pid: &str) -> CagedAddress {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("nsfs:") {
        let other = t.get(5..).unwrap_or("").trim();
        if other == agent_pid {
            return CagedAddress::new(
                format!("nsfs:{agent_pid}"),
                "agent_nsfs",
                true,
                true,
                false,
            );
        }
        return CagedAddress::new(t.to_string(), "agent_nsfs", true, false, false);
    }
    if lower.starts_with("file:") || lower.starts_with('/') || lower.starts_with("~/") {
        let rest = t
            .get(5..)
            .filter(|_| lower.starts_with("file:"))
            .unwrap_or(t)
            .trim_start_matches("//");
        return classify_path(rest, agent_pid);
    }
    if looks_like_url(t) {
        if let Some(host) = host_from_url(t) {
            if is_loopback_host(&host) {
                return CagedAddress::new(LOCAL_HOST_ADDR.into(), LOCAL_HOST_TYPE, true, false, false);
            }
        }
        return CagedAddress::new(t.to_string(), "http_api", false, false, false);
    }
    if lower.starts_with("mqtt://") || lower.starts_with("mqtt:") {
        return CagedAddress::new(t.to_string(), "mqtt", false, false, false);
    }
    if lower.starts_with("machine:") {
        return CagedAddress::new(t.to_string(), "machine", false, false, false);
    }
    if lower.starts_with("robot:") || lower.starts_with("robot_hal:") {
        return CagedAddress::new(t.to_string(), "robot_hal", false, false, false);
    }
    if lower.starts_with("device:") {
        return CagedAddress::new(t.to_string(), "device", false, false, false);
    }
    if lower.starts_with("iot:") {
        return CagedAddress::new(t.to_string(), "iot_endpoint", false, false, false);
    }
    if lower.starts_with("modbus:") {
        return CagedAddress::new(t.to_string(), "modbus", false, false, false);
    }
    if lower.starts_with("mcp:") {
        return CagedAddress::new(t.to_string(), "mcp_tool", false, false, false);
    }
    if lower.starts_with("agent:") || lower.starts_with("cnktr:agent:") {
        return CagedAddress::new(t.to_string(), "agent", false, false, false);
    }
    if lower.starts_with("local:") || lower == LOCAL_HOST_ADDR {
        return CagedAddress::new(LOCAL_HOST_ADDR.into(), LOCAL_HOST_TYPE, true, false, false);
    }
    if is_loopback_host(t) {
        return CagedAddress::new(LOCAL_HOST_ADDR.into(), LOCAL_HOST_TYPE, true, false, false);
    }
    CagedAddress::new(t.to_string(), "service", false, false, false)
}

fn classify_path(path: &str, agent_pid: &str) -> CagedAddress {
    let t = path.trim();
    if t.is_empty()
        || (!t.starts_with('/') && !t.starts_with('~') && !t.starts_with("file:"))
    {
        // Relative paths live in the agent's own NS FS — not the host cwd.
        return CagedAddress::new(
            format!("nsfs:{agent_pid}"),
            "agent_nsfs",
            true,
            true,
            false,
        );
    }
    let expanded = if let Some(rest) = t.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home".into());
        format!("{home}/{rest}")
    } else if t == "~" {
        std::env::var("HOME").unwrap_or_else(|_| "/home".into())
    } else {
        t.to_string()
    };
    let p = PathBuf::from(&expanded);
    if let Ok(root) = nsfs::nsfs_root(agent_pid) {
        if path_is_under(&p, &root) {
            return CagedAddress::new(
                format!("nsfs:{agent_pid}"),
                "agent_nsfs",
                true,
                true,
                false,
            );
        }
    }
    CagedAddress::new(format!("file:{}", p.display()), "host_fs", true, false, true)
}

fn http_route_is_node_posture(route: &str) -> bool {
    let route = route.trim().trim_end_matches('/');
    route.ends_with("/runtime/enable-hardening")
}

fn path_is_under(path: &Path, root: &Path) -> bool {
    let canon_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    canon_path.starts_with(&canon_root)
}

/// Resolve any tool invocation to a cage address. Tools without a URL still
/// get `tool:{bridge}/{name}` — there is no ambient host surface.
pub fn resolve_tool_address(
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    parameters: &Value,
) -> CagedAddress {
    let pid = agent_pid.trim();
    // Operator settings (link a model, routing, guardrails) stay on the
    // platform plane. They are not an agent touching an outer address.
    if bridge_id.eq_ignore_ascii_case("settings") {
        return CagedAddress::new(format!("nsfs:{pid}"), "agent_nsfs", true, true, false);
    }
    if let Some(raw) = param_str(
        parameters,
        &[
            "entity_id",
            "address",
            "url",
            "target",
            "endpoint",
            "server_url",
            "base_url",
        ],
    ) {
        return classify_named(&raw, pid);
    }
    let tool_l = tool_name.to_ascii_lowercase();
    let bridge_l = bridge_id.to_ascii_lowercase();
    // The route shell names the HTTP route in `path`. That is not a host file.
    if bridge_l == "lifecycle" && tool_l == "route_mutate" {
        let route = param_str(parameters, &["path"]).unwrap_or_default();
        if http_route_is_node_posture(&route) {
            return CagedAddress::new(format!("nsfs:{pid}"), "agent_nsfs", true, true, false);
        }
        return CagedAddress::new(
            format!("tool:{bridge_id}/{tool_name}"),
            "mcp_tool",
            false,
            false,
            false,
        );
    }
    if let Some(p) = param_str(
        parameters,
        &["path", "file", "filename", "cwd", "directory", "dest", "source"],
    ) {
        return classify_path(&p, pid);
    }
    // A workbench session is this agent's journal, not an outer-world address.
    if bridge_l == "workbench" && tool_l == "create_workbench_session" {
        return CagedAddress::new(format!("nsfs:{pid}"), "agent_nsfs", true, true, false);
    }
    if tool_l.contains("exec")
        || tool_l.contains("shell")
        || tool_l.contains("notebook")
        || bridge_l.contains("notebook")
        || bridge_l.contains("host")
    {
        return CagedAddress::new(
            format!("host_proc:{pid}"),
            "host_proc",
            true,
            false,
            false,
        );
    }
    CagedAddress::new(
        format!("tool:{bridge_id}/{tool_name}"),
        "mcp_tool",
        false,
        false,
        false,
    )
}

fn host_identity_names() -> Vec<String> {
    let mut out = Vec::new();
    for k in ["USER", "LOGNAME", "USERNAME"] {
        if let Ok(v) = std::env::var(k) {
            let t = v.trim().to_ascii_lowercase();
            if !t.is_empty() {
                out.push(t);
            }
        }
    }
    out.push("root".into());
    if let Ok(h) = std::env::var("HOSTNAME") {
        let t = h.trim().to_ascii_lowercase();
        if !t.is_empty() {
            out.push(t);
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let t = h.trim().to_ascii_lowercase();
        if !t.is_empty() {
            out.push(t);
        }
    }
    out
}

/// Agent pid must not be the host login name. Same machine ≠ host identity.
pub fn assert_agent_not_host_identity(agent_pid: &str) -> Result<(), String> {
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return Err("agent_pid_required".into());
    }
    let lower = pid.to_ascii_lowercase();
    if host_identity_names().iter().any(|h| h == &lower) {
        return Err(format!(
            "host_identity_forbidden: agent_pid={pid} collides with host USER/root — mint a Connector principal"
        ));
    }
    Ok(())
}

/// Strip host-login / SSH / home identity from a cage env so the child cannot
/// inherit the operator's account.
pub fn strip_host_identity_env(env: &mut Vec<(String, String)>) -> usize {
    let before = env.len();
    env.retain(|(k, _)| {
        !HOST_IDENTITY_ENV
            .iter()
            .any(|d| k.eq_ignore_ascii_case(d))
    });
    before.saturating_sub(env.len())
}

fn rewrite_cage_bind_path(token: &str, root: &Path) -> String {
    let t = token.trim();
    if t.is_empty() {
        return String::new();
    }
    let stripped = t
        .trim_end_matches("/**")
        .trim_end_matches("/*")
        .trim_end_matches('*');
    let mapped = if stripped == "/workspace" || stripped == "workspace" {
        root.join("workspace")
    } else if let Some(rest) = stripped.strip_prefix("/workspace/") {
        root.join("workspace").join(rest)
    } else if stripped == "/m" || stripped == "m" {
        root.join("m")
    } else if let Some(rest) = stripped.strip_prefix("/m/") {
        root.join("m").join(rest)
    } else if stripped == "/k" || stripped == "k" {
        root.join("k")
    } else if let Some(rest) = stripped.strip_prefix("/k/") {
        root.join("k").join(rest)
    } else if stripped == "/p" || stripped == "p" {
        root.join("p")
    } else if let Some(rest) = stripped.strip_prefix("/p/") {
        root.join("p").join(rest)
    } else if stripped == "/v" || stripped == "v" {
        root.join("v")
    } else if let Some(rest) = stripped.strip_prefix("/v/") {
        root.join("v").join(rest)
    } else if stripped == "/out" || stripped == "out" {
        root.join("out")
    } else if stripped == "/share" || stripped == "share" {
        root.join("share")
    } else {
        PathBuf::from(t)
    };
    mapped.to_string_lossy().to_string()
}

fn rewrite_fs_list(raw: &str, root: &Path) -> String {
    let parts: Vec<String> = raw
        .split(':')
        .map(|s| rewrite_cage_bind_path(s, root))
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        format!(
            "{}:{}",
            root.to_string_lossy(),
            root.join("workspace").display()
        )
    } else {
        parts.join(":")
    }
}

/// Bind Landlock FS to this agent's NS FS (identity home on this machine).
/// In-cage `/workspace` binds become host paths under `nsfs/{pid}/`.
pub fn apply_nsfs_landlock_defaults(agent_pid: &str, env: &mut Vec<(String, String)>) {
    let Ok(_) = nsfs::ensure_tree(agent_pid) else {
        return;
    };
    let Ok(root) = nsfs::nsfs_root(agent_pid) else {
        return;
    };
    let root = root.canonicalize().unwrap_or(root);
    let root_s = root.to_string_lossy().to_string();
    let ws = root.join("workspace");
    let rewrite_key = |env: &mut Vec<(String, String)>, key: &str, root: &Path, fallback: &str| {
        if let Some((_, v)) = env.iter_mut().find(|(k, _)| k == key) {
            *v = rewrite_fs_list(v, root);
        } else {
            env.push((key.to_string(), fallback.to_string()));
        }
    };
    let fallback = format!("{root_s}:{}", ws.display());
    rewrite_key(env, "CONNECTOR_DOCKLOCK_FS_READ", &root, &fallback);
    rewrite_key(env, "CONNECTOR_DOCKLOCK_FS_WRITE", &root, &fallback);
    env.retain(|(k, _)| k != "HOME" && k != "CONNECTOR_AGENT_NSFS");
    env.push(("HOME".into(), ws.to_string_lossy().to_string()));
    env.push(("CONNECTOR_AGENT_NSFS".into(), root_s));
}

pub fn identity_snapshot(state: &PlatformState, agent_pid: &str) -> Value {
    let pid = agent_pid.trim();
    let host_collision = assert_agent_not_host_identity(pid).err();
    let principal = agent_principal::load_principal(state, pid);
    let contract = agent_principal::load_contract(state, pid);
    let ns = nsfs::snapshot(pid);
    json!({
        "schema": CAGE_SCHEMA,
        "agent_pid": pid,
        "host_identity_collision": host_collision,
        "isolated_from_host_login": host_collision.is_none(),
        "principal_id": principal.as_ref().map(|p| &p.principal_id),
        "has_principal": principal.is_some(),
        "has_contract": contract.is_some(),
        "nsfs": ns,
        "honesty": "Hosted on this computer, identity is the Connector principal + NS FS — not host USER/HOME/uid. Outer world (this machine, APIs, tools, IoT, robots) is granted per address.",
    })
}

pub fn cage_snapshot(state: &PlatformState, agent_pid: &str) -> Value {
    let pid = agent_pid.trim();
    let grants = crate::kernel::world_gateway::list_grants(state, Some(pid));
    json!({
        "ok": true,
        "schema": CAGE_SCHEMA,
        "agent_pid": pid,
        "identity": identity_snapshot(state, pid),
        "types": types_catalog(),
        "local_host_address": LOCAL_HOST_ADDR,
        "grant_count": grants.len(),
        "grants": grants,
        "rule": "Same machine is still an address (local:host / host_fs / host_proc). Own NS FS is identity home. Everything else needs an (agent × address) grant.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_local_host_not_ambient() {
        let c = classify_named("https://127.0.0.1:9091/v1", "agt_1");
        assert_eq!(c.address, LOCAL_HOST_ADDR);
        assert!(c.same_machine);
        assert!(!c.self_nsfs);
    }

    #[test]
    fn remote_api_is_http() {
        let c = classify_named("https://api.example.com/v1", "agt_1");
        assert_eq!(c.address_type, "http_api");
        assert!(!c.same_machine);
    }

    #[test]
    fn robot_and_iot_keep_type() {
        assert_eq!(classify_named("machine:arm-1", "a").address_type, "machine");
        assert_eq!(classify_named("robot:bay-3", "a").address_type, "robot_hal");
        assert_eq!(classify_named("iot:sensor-9", "a").address_type, "iot_endpoint");
    }

    #[test]
    fn enable_hardening_is_node_posture_not_a_host_file() {
        let c = resolve_tool_address(
            "node",
            "lifecycle",
            "route_mutate",
            &json!({"method": "POST", "path": "/api/v1/runtime/enable-hardening"}),
        );
        assert!(c.self_nsfs);
        assert!(!c.host_fs);
        assert_eq!(c.address, "nsfs:node");
    }

    #[test]
    fn route_mutate_is_not_a_filesystem_path() {
        let c = resolve_tool_address(
            "node",
            "lifecycle",
            "route_mutate",
            &json!({"method": "POST", "path": "/api/v1/secrets/store"}),
        );
        assert_eq!(c.address, "tool:lifecycle/route_mutate");
        assert!(!c.host_fs);
    }

    #[test]
    fn linking_an_llm_is_the_settings_plane_not_a_world_address() {
        let c = resolve_tool_address(
            "llm-settings",
            "settings",
            "link_llm",
            &json!({"provider": "deepseek", "model": "deepseek-chat", "endpoint": "https://api.deepseek.com/v1"}),
        );
        assert!(c.self_nsfs);
        assert_eq!(c.address_type, "agent_nsfs");
        assert_eq!(c.address, "nsfs:llm-settings");
    }

    fn workbench_session_journal_is_the_agents_own_namespace() {
        let c = resolve_tool_address(
            "agt_1",
            "workbench",
            "create_workbench_session",
            &json!({"agent_pid": "agt_1"}),
        );
        assert!(c.self_nsfs);
        assert_eq!(c.address, "nsfs:agt_1");
    }

    #[test]
    fn unnamed_tool_still_has_address() {
        let c = resolve_tool_address("agt_1", "mcp", "search", &json!({}));
        assert_eq!(c.address, "tool:mcp/search");
        assert_eq!(c.address_type, "mcp_tool");
        assert!(!c.self_nsfs);
    }

    #[test]
    fn nested_url_param_is_http_api() {
        let c = resolve_tool_address(
            "agt_1",
            "mcp",
            "fetch",
            &json!({"request": {"URL": "https://api.example.com/v1"}}),
        );
        assert_eq!(c.address_type, "http_api");
    }

    #[test]
    fn relative_path_is_self_nsfs_not_host_cwd() {
        let c = resolve_tool_address("agt_1", "fs", "read", &json!({"path": "notes.txt"}));
        assert!(c.self_nsfs);
        assert_eq!(c.address, "nsfs:agt_1");
    }

    #[test]
    fn absolute_host_path_is_host_fs() {
        let c = resolve_tool_address("agt_1", "fs", "read", &json!({"path": "/etc/passwd"}));
        assert!(c.host_fs);
        assert_eq!(c.address, "file:/etc/passwd");
        assert!(!c.self_nsfs);
    }

    #[test]
    fn other_agent_nsfs_is_not_self() {
        let c = classify_named("nsfs:agt_b", "agt_a");
        assert!(!c.self_nsfs);
        assert_eq!(c.address_type, "agent_nsfs");
    }

    #[test]
    fn host_user_cannot_be_agent_pid() {
        std::env::set_var("USER", "alice");
        assert!(assert_agent_not_host_identity("alice").is_err());
        assert!(assert_agent_not_host_identity("root").is_err());
        assert!(assert_agent_not_host_identity("agt_alice_1").is_ok());
        std::env::remove_var("USER");
    }

    #[test]
    fn strip_host_env() {
        let mut env = vec![
            ("CONNECTOR_AGENT_PID".into(), "agt_1".into()),
            ("HOME".into(), "/home/alice".into()),
            ("SSH_AUTH_SOCK".into(), "/tmp/ssh".into()),
        ];
        let n = strip_host_identity_env(&mut env);
        assert_eq!(n, 2);
        assert_eq!(env.len(), 1);
    }
}
