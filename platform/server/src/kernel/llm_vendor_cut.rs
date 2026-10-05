//! Direct LLM vendor cut — once a tool is connected, vendors are Connector-only.
//!
//! Cursor / Claude Code / MCP can ignore `ANTHROPIC_BASE_URL`. This table is the
//! lock: DROP tcp/80,443 to vendor IPs unless the packet carries the LLM-cage
//! SO_MARK. Connector Talk still reaches vendors through the Landlock child.

use serde_json::{json, Value};
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::kernel::{matrix_host_egress, pore_table};
use crate::state::PlatformState;
use crate::substrate::egress_policy;

pub const SESSION_FOLDER: &str = "llm_vendor_cut_sessions_v1";
pub const SCHEMA: &str = "connector.llm.vendor_cut.v1";

static ENGAGED: AtomicBool = AtomicBool::new(false);

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

fn env_off(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

/// Fast path: a connected tool session has engaged the vendor exclusive.
pub fn engaged() -> bool {
    if env_off("CONNECTOR_LLM_VENDOR_CUT") {
        return false;
    }
    ENGAGED.load(Ordering::Relaxed) || env_flag("CONNECTOR_LLM_VENDOR_CUT")
}

pub fn cage_mark_hex() -> String {
    matrix_host_egress::intelligence_egress_mark_hex(pore_table::LLM_SYSTEM_AGENT)
}

/// Record a connected tool and apply host DROP of vendor dests except the LLM cage.
pub fn engage(
    state: &PlatformState,
    session_id: &str,
    agent_pid: &str,
    tool: &str,
    reason: &str,
) -> Value {
    if env_off("CONNECTOR_LLM_VENDOR_CUT") {
        return json!({
            "schema": SCHEMA,
            "engaged": false,
            "skipped": "CONNECTOR_LLM_VENDOR_CUT=0",
        });
    }
    let sid = session_id.trim();
    if sid.is_empty() {
        return json!({"schema": SCHEMA, "engaged": false, "error": "session_required"});
    }
    let row = json!({
        "schema": SCHEMA,
        "session_id": sid,
        "agent_pid": agent_pid,
        "tool": tool,
        "reason": reason,
        "at_ms": chrono::Utc::now().timestamp_millis(),
        "status": "active",
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(SESSION_FOLDER, sid, &row);
    }
    ENGAGED.store(true, Ordering::Relaxed);
    if crate::services::playground::is_playground_mode() {
        return json!({
            "schema": SCHEMA,
            "engaged": true,
            "session_id": sid,
            "agent_pid": agent_pid,
            "tool": tool,
            "cage_mark": cage_mark_hex(),
            "kernel": {"applied": false, "skipped": "playground"},
            "honesty": "Playground cannot install host nft. Pore children still deny vendor dests. Dedicated host applies DROP.",
        });
    }
    let kernel = apply_host_cut();
    json!({
        "schema": SCHEMA,
        "engaged": true,
        "session_id": sid,
        "agent_pid": agent_pid,
        "tool": tool,
        "cage_mark": cage_mark_hex(),
        "kernel": kernel,
        "honesty": "Direct vendor HTTPS is DROP except LLM-cage SO_MARK. Tool must use Connector BASE_URL. Not a TLS MITM.",
    })
}

pub fn release(state: &PlatformState, session_id: &str) -> Value {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_delete(SESSION_FOLDER, session_id.trim());
    }
    let remaining = session_count(state);
    if remaining == 0 {
        ENGAGED.store(false, Ordering::Relaxed);
        let cleared = clear_host_cut();
        return json!({
            "schema": SCHEMA,
            "engaged": false,
            "released": session_id,
            "kernel": cleared,
        });
    }
    json!({
        "schema": SCHEMA,
        "engaged": true,
        "released": session_id,
        "remaining": remaining,
    })
}

fn session_count(state: &PlatformState) -> usize {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    es.folder_keys(SESSION_FOLDER, None)
        .ok()
        .map(|k| k.len())
        .unwrap_or(0)
}

pub fn posture(state: Option<&PlatformState>) -> Value {
    let sessions = state
        .map(|s| {
            let Ok(es) = s.engine_store.lock() else {
                return vec![];
            };
            let Ok(keys) = es.folder_keys(SESSION_FOLDER, None) else {
                return vec![];
            };
            keys.into_iter()
                .filter_map(|k| es.folder_get(SESSION_FOLDER, &k).ok().flatten())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "schema": SCHEMA,
        "engaged": engaged(),
        "session_count": sessions.len(),
        "sessions": sessions,
        "cage_mark": cage_mark_hex(),
        "vendors": egress_policy::llm_vendor_dns_names(),
        "kernel_tools": {
            "nft": tool_ok("nft"),
            "iptables": tool_ok("iptables-nft") || tool_ok("iptables"),
        },
        "honesty": "Userspace dest pin + vendor exclusive in the pore child always. Host nft/iptables DROP needs CAP_NET_ADMIN.",
    })
}

fn tool_ok(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn resolve_vendor_ips() -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for host in egress_policy::llm_vendor_dns_names() {
        let Ok(addrs) = format!("{host}:443").to_socket_addrs() else {
            continue;
        };
        for a in addrs {
            match a.ip() {
                IpAddr::V4(ip) => v4.push(ip.to_string()),
                IpAddr::V6(ip) => v6.push(ip.to_string()),
            }
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    (v4, v6)
}

fn apply_host_cut() -> Value {
    let (v4, v6) = resolve_vendor_ips();
    if v4.is_empty() && v6.is_empty() {
        return json!({
            "applied": false,
            "backend": "none",
            "error": "vendor_dns_unresolved",
        });
    }
    if tool_ok("nft") {
        match apply_nft(&v4, &v6) {
            Ok(()) => {
                return json!({
                    "applied": true,
                    "backend": "nftables",
                    "table": "inet connector_llm_vendor",
                    "ipv4": v4.len(),
                    "ipv6": v6.len(),
                    "cage_mark": cage_mark_hex(),
                });
            }
            Err(e) => {
                if let Some(r) = apply_iptables(&v4) {
                    return r;
                }
                return json!({
                    "applied": false,
                    "backend": "nftables",
                    "error": e,
                    "honesty": "Need CAP_NET_ADMIN. Userspace vendor exclusive still denies Connector-spawned children.",
                });
            }
        }
    }
    apply_iptables(&v4).unwrap_or_else(|| {
        json!({
            "applied": false,
            "backend": "none",
            "error": "nft_and_iptables_missing",
            "honesty": "Userspace exclusive still holds for pore children; host Cursor can still hit vendors until nft applies.",
        })
    })
}

fn apply_nft(v4: &[String], v6: &[String]) -> Result<(), String> {
    let mark = cage_mark_hex();
    let bootstrap = r#"
add table inet connector_llm_vendor
add set inet connector_llm_vendor cage_marks { type mark ; }
add set inet connector_llm_vendor vendor4 { type ipv4_addr ; }
add set inet connector_llm_vendor vendor6 { type ipv6_addr ; }
add chain inet connector_llm_vendor output { type filter hook output priority filter ; policy accept ; }
"#;
    run_nft_script(bootstrap)?;
    run_nft(&[
        "add",
        "element",
        "inet",
        "connector_llm_vendor",
        "cage_marks",
        &format!("{{ {mark} }}"),
    ])?;
    if !v4.is_empty() {
        let elems = v4.join(", ");
        run_nft(&[
            "add",
            "element",
            "inet",
            "connector_llm_vendor",
            "vendor4",
            &format!("{{ {elems} }}"),
        ])?;
    }
    if !v6.is_empty() {
        let elems = v6.join(", ");
        run_nft(&[
            "add",
            "element",
            "inet",
            "connector_llm_vendor",
            "vendor6",
            &format!("{{ {elems} }}"),
        ])?;
    }
    ensure_nft_drop_rules()?;
    Ok(())
}

fn ensure_nft_drop_rules() -> Result<(), String> {
    let listed = Command::new("nft")
        .args(["list", "chain", "inet", "connector_llm_vendor", "output"])
        .output()
        .map_err(|e| e.to_string())?;
    let body = String::from_utf8_lossy(&listed.stdout);
    if !body.contains("cage_marks") {
        run_nft(&[
            "add",
            "rule",
            "inet",
            "connector_llm_vendor",
            "output",
            "meta",
            "mark",
            "@cage_marks",
            "accept",
            "comment",
            "connector-llm-cage-accept",
        ])?;
    }
    if !body.contains("vendor4") || !body.contains("drop") {
        run_nft(&[
            "add",
            "rule",
            "inet",
            "connector_llm_vendor",
            "output",
            "ip",
            "daddr",
            "@vendor4",
            "tcp",
            "dport",
            "{ 80, 443 }",
            "drop",
            "comment",
            "connector-llm-vendor-drop4",
        ])?;
    }
    if !body.contains("vendor6") {
        let _ = run_nft(&[
            "add",
            "rule",
            "inet",
            "connector_llm_vendor",
            "output",
            "ip6",
            "daddr",
            "@vendor6",
            "tcp",
            "dport",
            "{ 80, 443 }",
            "drop",
            "comment",
            "connector-llm-vendor-drop6",
        ]);
    }
    Ok(())
}

fn apply_iptables(v4: &[String]) -> Option<Value> {
    let bin = if tool_ok("iptables-nft") {
        "iptables-nft"
    } else if tool_ok("iptables") {
        "iptables"
    } else {
        return None;
    };
    let mark = crate::kernel::matrix_host_egress::intelligence_egress_mark(pore_table::LLM_SYSTEM_AGENT);
    let _ = Command::new(bin)
        .args(["-N", "CONNECTOR_LLM_VENDOR"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new(bin)
        .args(["-F", "CONNECTOR_LLM_VENDOR"])
        .status();
    let chained = Command::new(bin)
        .args(["-C", "OUTPUT", "-j", "CONNECTOR_LLM_VENDOR"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !chained {
        let _ = Command::new(bin)
            .args(["-I", "OUTPUT", "1", "-j", "CONNECTOR_LLM_VENDOR"])
            .status();
    }
    let mark_s = mark.to_string();
    let ok_mark = Command::new(bin)
        .args([
            "-A",
            "CONNECTOR_LLM_VENDOR",
            "-m",
            "mark",
            "--mark",
            &mark_s,
            "-j",
            "RETURN",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let mut dropped = 0usize;
    for ip in v4 {
        for port in ["443", "80"] {
            if Command::new(bin)
                .args([
                    "-A",
                    "CONNECTOR_LLM_VENDOR",
                    "-d",
                    ip,
                    "-p",
                    "tcp",
                    "--dport",
                    port,
                    "-j",
                    "DROP",
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                dropped += 1;
            }
        }
    }
    Some(json!({
        "applied": ok_mark && dropped > 0,
        "backend": bin,
        "chain": "CONNECTOR_LLM_VENDOR",
        "dropped_rules": dropped,
        "cage_mark": cage_mark_hex(),
    }))
}

fn clear_host_cut() -> Value {
    if tool_ok("nft") {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "connector_llm_vendor"])
            .status();
    }
    for bin in ["iptables-nft", "iptables"] {
        if tool_ok(bin) {
            let _ = Command::new(bin)
                .args(["-D", "OUTPUT", "-j", "CONNECTOR_LLM_VENDOR"])
                .status();
            let _ = Command::new(bin)
                .args(["-F", "CONNECTOR_LLM_VENDOR"])
                .status();
            let _ = Command::new(bin)
                .args(["-X", "CONNECTOR_LLM_VENDOR"])
                .status();
        }
    }
    json!({"cleared": true})
}

fn run_nft(args: &[&str]) -> Result<(), String> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| format!("nft spawn: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("File exists") || err.contains("exists") {
        return Ok(());
    }
    Err(format!("nft {}: {}", args.join(" "), err.trim()))
}

fn run_nft_script(script: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft -f spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("nft stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft wait: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("File exists") || err.contains("exists") {
        return Ok(());
    }
    Err(format!("nft -f failed: {}", err.trim()))
}

/// Agent pores may not dial LLM vendors — only `_connector` × `llm:provider`.
pub fn deny_agent_vendor_dial(agent_pid: &str, dest_host: &str) -> Result<(), String> {
    if !egress_policy::is_direct_llm_provider_host(dest_host) {
        return Ok(());
    }
    if agent_pid.trim() == pore_table::LLM_SYSTEM_AGENT {
        return Ok(());
    }
    Err(format!(
        "vendor_exclusive: {dest_host} is a Connector LLM cage dest — agent={agent_pid} must talk through the gateway, not the vendor"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_hosts_are_catalogued() {
        assert!(egress_policy::is_direct_llm_provider_host("api.anthropic.com"));
        assert!(egress_policy::is_direct_llm_provider_host("api.openai.com"));
        assert!(deny_agent_vendor_dial("agent-1", "api.anthropic.com").is_err());
        assert!(deny_agent_vendor_dial(pore_table::LLM_SYSTEM_AGENT, "api.anthropic.com").is_ok());
        assert!(deny_agent_vendor_dial("agent-1", "mcp.example.com").is_ok());
    }

    #[test]
    fn cut_can_be_disabled() {
        let prev = std::env::var("CONNECTOR_LLM_VENDOR_CUT").ok();
        std::env::set_var("CONNECTOR_LLM_VENDOR_CUT", "0");
        ENGAGED.store(true, Ordering::Relaxed);
        assert!(!engaged());
        ENGAGED.store(false, Ordering::Relaxed);
        match prev {
            Some(v) => std::env::set_var("CONNECTOR_LLM_VENDOR_CUT", v),
            None => std::env::remove_var("CONNECTOR_LLM_VENDOR_CUT"),
        }
    }
}
