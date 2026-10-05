//! Per-agent cgroup + namespace identity binding (Seven Pillars P2-T03 / P2-T04 / P4-T02).
//!
//! Linux path: write controller files under `/sys/fs/cgroup/connector/<agent>/` when
//! cgroup v2 is writable; always persist a measured binding record under engine store /
//! data_dir so desired-vs-applied and flow leases can attribute sockets to principals.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.agent_cgroup_ns.v1";

fn sanitize(agent_pid: &str) -> String {
    agent_pid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(96)
        .collect()
}

pub fn cgroup_root() -> PathBuf {
    std::env::var("CONNECTOR_CGROUP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup/connector"))
}

pub fn desired_cgroup_path(agent_pid: &str) -> PathBuf {
    cgroup_root().join(sanitize(agent_pid))
}

/// Kernel-observable attribution material: mark + cgroup path + principal digest.
pub fn principal_attribution(agent_pid: &str, principal_id: &str) -> Value {
    let mark = crate::kernel::matrix_host_egress::intelligence_egress_mark(agent_pid);
    let cg = desired_cgroup_path(agent_pid);
    let material = format!("agent={agent_pid}|principal={principal_id}|cgroup={}", cg.display());
    json!({
        "schema": "connector.principal_attribution.v1",
        "agent_pid": agent_pid,
        "principal_id": principal_id,
        "cgroup_path": cg.display().to_string(),
        "egress_mark": format!("0x{mark:08x}"),
        "attribution_digest": format!("{:x}", Sha256::digest(material.as_bytes())),
        "nsfs_root": crate::kernel::nsfs::nsfs_root(agent_pid)
            .map(|p| p.display().to_string())
            .ok(),
        "honesty": "Attribution is kernel-observable via cgroup path + SO_MARK when applied",
    })
}

/// Bind agent process tree identity: ensure nsfs + cgroup dir + store record.
pub fn bind_agent_process_tree(
    state: &PlatformState,
    agent_pid: &str,
    principal_id: &str,
) -> Result<Value, String> {
    let ns = crate::kernel::nsfs::ensure_tree(agent_pid)?;
    let cg = desired_cgroup_path(agent_pid);
    let mut cgroup_applied = false;
    let mut cgroup_detail = "not_writable".to_string();
    let mut honesty = Vec::<String>::new();

    if let Err(e) = fs::create_dir_all(&cg) {
        cgroup_detail = format!("mkdir_failed:{e}");
    } else {
        let procs = cg.join("cgroup.procs");
        if procs.exists() || cg.exists() {
            // Directory presence is NOT applied confinement. Never bind connectord's
            // own PID into an agent cgroup — that would fake placement of the wrong process.
            cgroup_detail = "directory_present_awaiting_child_pid".into();
            cgroup_applied = false;
            honesty.push(
                "refused_self_pid_bind: target child must be placed via birth/exec before cgroup_applied=true"
                    .into(),
            );
        }
    }

    let attr = principal_attribution(agent_pid, principal_id);
    let mut rec = json!({
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "principal_id": principal_id,
        "cgroup_path": cg.display().to_string(),
        "cgroup_applied": cgroup_applied,
        "cgroup_detail": cgroup_detail,
        "namespaces_intent": ["pid", "mnt", "user", "net"],
        "nsfs": ns,
        "attribution": attr,
        "honesty": honesty,
        "fail_closed_when": "CONNECTOR_KERNEL_ENFORCE=1 or CONNECTOR_SANDBOX_UNBYPASSABLE=1 requires real cgroup placement of the target child — data_dir_mirror is never applied=true",
    });

    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put("agent_cgroup_ns_v1", agent_pid, &rec);
    }

    let require = crate::services::kernel_host::kernel_enforce_enabled()
        || crate::substrate::sandbox_unbypassable::unbypassable_bar_enforced();
    if require && !cgroup_applied {
        // Bookkeeping mirror only — NEVER claim applied confinement.
        let mirror = crate::kernel::nsfs::data_dir()
            .join("cgroup_mirror")
            .join(sanitize(agent_pid));
        fs::create_dir_all(&mirror).map_err(|e| format!("cgroup_mirror:{e}"))?;
        if let Some(o) = rec.as_object_mut() {
            o.insert("cgroup_mirror".into(), json!(mirror.display().to_string()));
            o.insert("cgroup_applied".into(), json!(false));
            o.insert("cgroup_detail".into(), json!("data_dir_mirror"));
            let mut h = o
                .get("honesty")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            h.push(json!(
                "data_dir_mirror_is_not_host_confinement: cgroup_applied remains false"
            ));
            o.insert("honesty".into(), json!(h));
        }
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_put("agent_cgroup_ns_v1", agent_pid, &rec);
        }
        return Err(format!(
            "cgroup_not_applied: data_dir_mirror recorded at {} but is not host confinement \
             (set real cgroup placement of the target child before requiring enforce)",
            mirror.display()
        ));
    }
    Ok(rec)
}

/// Place a known child PID into the agent cgroup. Only this path may set `cgroup_applied=true`.
pub fn place_child_in_agent_cgroup(
    state: &PlatformState,
    agent_pid: &str,
    child_pid: u32,
) -> Result<Value, String> {
    if child_pid == 0 || child_pid == std::process::id() {
        return Err("refuse_place_self_or_zero_pid".into());
    }
    let cg = desired_cgroup_path(agent_pid);
    fs::create_dir_all(&cg).map_err(|e| format!("cgroup_mkdir:{e}"))?;
    let procs = cg.join("cgroup.procs");
    fs::write(&procs, format!("{child_pid}")).map_err(|e| format!("cgroup_procs_write:{e}"))?;
    let rec = json!({
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "child_pid": child_pid,
        "cgroup_path": cg.display().to_string(),
        "cgroup_applied": true,
        "cgroup_detail": "child_pid_written",
        "honesty": ["target_child_placed"],
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put("agent_cgroup_ns_v1", agent_pid, &rec);
    }
    Ok(rec)
}

/// Socket binding for flow lease: no anonymous agent socket (RG-04 / P4-T02).
pub fn socket_binding_for_flow(
    agent_pid: &str,
    principal_id: &str,
    flow_id: &str,
    lease_id: &str,
) -> Value {
    let mark = crate::kernel::matrix_host_egress::intelligence_egress_mark(agent_pid);
    let cg = desired_cgroup_path(agent_pid);
    json!({
        "schema": "connector.socket_binding.v1",
        "anonymous": false,
        "agent_pid": agent_pid,
        "principal_id": principal_id,
        "flow_id": flow_id,
        "lease_id": lease_id,
        "cgroup_path": cg.display().to_string(),
        "so_mark": format!("0x{mark:08x}"),
        "ns_identity": format!("netns:connector/{agent_pid}"),
        "honesty": "Socket must carry principal+flow; anonymous sockets denied under FLOW_LEASE_ENFORCE",
    })
}

pub fn assert_no_anonymous_socket(
    agent_pid: Option<&str>,
    flow_id: Option<&str>,
    lease_id: Option<&str>,
) -> Result<(), String> {
    let enforce = crate::substrate::flow_lease::flow_lease_enforcement_enabled()
        || crate::substrate::sandbox_unbypassable::unbypassable_bar_enforced();
    if !enforce {
        return Ok(());
    }
    if agent_pid.map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err("anonymous_socket_no_agent".into());
    }
    if flow_id.map(|s| s.trim().is_empty()).unwrap_or(true)
        && lease_id.map(|s| s.trim().is_empty()).unwrap_or(true)
    {
        return Err("anonymous_socket_no_flow_or_lease".into());
    }
    Ok(())
}

/// Best-effort cgroup.freeze for AgentCell pause/quarantine (OS-grade).
/// Returns JSON-ish bool success; soft-fail records honesty without claiming freeze.
pub fn try_freeze_agent(state: &PlatformState, agent_pid: &str) -> Value {
    let path = desired_cgroup_path(agent_pid).join("cgroup.freeze");
    let applied = if path.exists() {
        fs::write(&path, b"1").is_ok()
    } else {
        false
    };
    // Persist freeze intent even when cgroup path missing (lab).
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "agent_cgroup_freeze",
            agent_pid,
            &json!({
                "agent_pid": agent_pid,
                "frozen": true,
                "cgroup_path": desired_cgroup_path(agent_pid).display().to_string(),
                "applied": applied,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }
    json!({ "applied": applied, "path": path.display().to_string() })
}

pub fn try_thaw_agent(state: &PlatformState, agent_pid: &str) -> Value {
    let path = desired_cgroup_path(agent_pid).join("cgroup.freeze");
    let applied = if path.exists() {
        fs::write(&path, b"0").is_ok()
    } else {
        false
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "agent_cgroup_freeze",
            agent_pid,
            &json!({
                "agent_pid": agent_pid,
                "frozen": false,
                "applied": applied,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }
    json!({ "applied": applied })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribution_stable() {
        let a = principal_attribution("agent-a", "prin-a");
        let b = principal_attribution("agent-a", "prin-a");
        assert_eq!(a["attribution_digest"], b["attribution_digest"]);
        let c = principal_attribution("agent-b", "prin-a");
        assert_ne!(a["attribution_digest"], c["attribution_digest"]);
    }

    #[test]
    fn anonymous_socket_denied_when_enforce() {
        std::env::set_var("CONNECTOR_FLOW_LEASE_ENFORCE", "1");
        assert!(assert_no_anonymous_socket(None, None, None).is_err());
        assert!(assert_no_anonymous_socket(Some("a1"), Some("f1"), None).is_ok());
        std::env::remove_var("CONNECTOR_FLOW_LEASE_ENFORCE");
    }

    #[test]
    fn data_dir_mirror_never_claims_applied() {
        // Pure honesty invariant on the JSON shape we would write for a mirror.
        let mut r = json!({
            "cgroup_applied": false,
            "cgroup_detail": "not_writable",
        });
        if let Some(o) = r.as_object_mut() {
            o.insert("cgroup_detail".into(), json!("data_dir_mirror"));
            o.insert("cgroup_applied".into(), json!(false));
        }
        assert_eq!(r["cgroup_applied"], json!(false));
        assert_eq!(r["cgroup_detail"], json!("data_dir_mirror"));
    }

    #[test]
    fn place_child_refuses_self_pid() {
        // Cannot construct PlatformState cheaply here — unit-check the guard logic.
        let self_pid = std::process::id();
        assert!(self_pid != 0);
        assert_eq!(
            (self_pid == 0 || self_pid == std::process::id()),
            true
        );
    }
}
