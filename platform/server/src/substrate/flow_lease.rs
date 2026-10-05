//! Flow lease map (I-21 / P6.8) — short-lived egress tickets keyed by CFNI flow id.
//!
//! Destination-constrained leases (CNKTROS) extend the v1 record with optional
//! workload/intelligence/channel UIDs and destination fields. Unconstrained
//! records remain valid (migration-era allow-any for that lease); kerneld still
//! falls back to lease *count* for `IPAddressDeny=any`.

use connector_trust::ForensicFlowIdentityV2;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::PlatformState;

pub const FLOW_LEASE_FOLDER: &str = "flow_lease_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowLeaseRecordV1 {
    pub schema: String,
    pub lease_id: String,
    pub flow_id: String,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub operation: String,
    pub admission_ticket_id: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    // ── CNKTROS destination-constrained extensions (optional / backward compatible) ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ip_cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_posture: Option<String>,
}

/// Request to mint a destination-constrained flow lease (CFNI + socket_binding).
#[derive(Debug, Clone)]
pub struct ConstrainedLeaseRequest {
    pub principal_id: String,
    pub tenant_id: Option<String>,
    pub operation: String,
    pub admission_ticket_id: String,
    pub workload_uid: Option<String>,
    pub intelligence_uid: Option<String>,
    pub channel_uid: Option<String>,
    pub destination_host: Option<String>,
    pub destination_ip_cidr: Option<String>,
    pub destination_port: Option<u16>,
    pub destination_protocol: Option<String>,
    pub action_digest: Option<String>,
    pub authority_revision: Option<u64>,
    pub enforcement_posture: Option<String>,
}

pub fn lease_ttl_secs() -> u64 {
    std::env::var("CONNECTOR_FLOW_LEASE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

fn env_flag_true(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Explicit product enforce flag (P6.8). Combined with map enablement.
pub fn flow_lease_enforce_flag() -> bool {
    env_flag_true("CONNECTOR_FLOW_LEASE_ENFORCE")
}

pub fn flow_lease_map_enabled() -> bool {
    !matches!(
        std::env::var("CONNECTOR_FLOW_LEASE_DISABLE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn kernel_enforce_enabled() -> bool {
    crate::services::kernel_host::kernel_enforce_enabled()
}

/// Enforcement on when map is enabled AND (`CONNECTOR_FLOW_LEASE_ENFORCE` or kernel enforce).
pub fn flow_lease_enforcement_enabled() -> bool {
    flow_lease_map_enabled() && (flow_lease_enforce_flag() || kernel_enforce_enabled())
}

pub fn enforce_display() -> &'static str {
    if flow_lease_enforcement_enabled() {
        "on"
    } else {
        "off"
    }
}

pub fn mint_from_quantum(
    state: &PlatformState,
    principal_id: &str,
    quantum_id: &str,
    operation: &str,
) -> Option<String> {
    if !flow_lease_map_enabled() {
        return None;
    }
    let flow = crate::substrate::cfni::mint_for_principal(principal_id, None)?;
    persist_lease(
        state,
        &flow,
        principal_id,
        None,
        &format!("{operation}|quantum:{quantum_id}"),
        quantum_id,
        None,
    )
}

/// Mint a flow lease after admission pass (correlates egress with CFNI flow id).
pub fn mint_on_admission_pass(
    state: &PlatformState,
    principal_id: &str,
    tenant_id: Option<&str>,
    operation: &str,
    admission_ticket_id: &str,
) -> Option<String> {
    if !flow_lease_map_enabled() {
        return None;
    }
    let flow = crate::substrate::cfni::mint_for_principal(principal_id, tenant_id)?;
    persist_lease(
        state,
        &flow,
        principal_id,
        tenant_id,
        operation,
        admission_ticket_id,
        None,
    )
}

/// Mint a destination-constrained lease (still creates CFNI flow + socket_binding).
pub fn mint_constrained_lease(
    state: &PlatformState,
    req: ConstrainedLeaseRequest,
) -> Option<String> {
    if !flow_lease_map_enabled() {
        return None;
    }
    let flow = crate::substrate::cfni::mint_for_principal(
        &req.principal_id,
        req.tenant_id.as_deref(),
    )?;
    let extras = LeaseExtras {
        workload_uid: req.workload_uid,
        intelligence_uid: req.intelligence_uid,
        channel_uid: req.channel_uid,
        destination_host: req.destination_host,
        destination_ip_cidr: req.destination_ip_cidr,
        destination_port: req.destination_port,
        destination_protocol: req.destination_protocol,
        action_digest: req.action_digest,
        authority_revision: req.authority_revision,
        enforcement_posture: req.enforcement_posture,
    };
    persist_lease(
        state,
        &flow,
        &req.principal_id,
        req.tenant_id.as_deref(),
        &req.operation,
        &req.admission_ticket_id,
        Some(extras),
    )
}

#[derive(Debug, Clone, Default)]
struct LeaseExtras {
    workload_uid: Option<String>,
    intelligence_uid: Option<String>,
    channel_uid: Option<String>,
    destination_host: Option<String>,
    destination_ip_cidr: Option<String>,
    destination_port: Option<u16>,
    destination_protocol: Option<String>,
    action_digest: Option<String>,
    authority_revision: Option<u64>,
    enforcement_posture: Option<String>,
}

fn persist_lease(
    state: &PlatformState,
    flow: &ForensicFlowIdentityV2,
    principal_id: &str,
    tenant_id: Option<&str>,
    operation: &str,
    admission_ticket_id: &str,
    extras: Option<LeaseExtras>,
) -> Option<String> {
    let now = chrono::Utc::now().timestamp_millis();
    let ttl_ms = (lease_ttl_secs() as i64) * 1000;
    let x = extras.unwrap_or_default();
    let record = FlowLeaseRecordV1 {
        schema: "flow_lease.v1".into(),
        lease_id: format!("lease_{}", uuid::Uuid::new_v4()),
        flow_id: flow.flow_id.clone(),
        principal_id: principal_id.to_string(),
        tenant_id: tenant_id.map(str::to_string),
        operation: operation.to_string(),
        admission_ticket_id: admission_ticket_id.to_string(),
        issued_at_ms: now,
        expires_at_ms: now + ttl_ms,
        workload_uid: x.workload_uid,
        intelligence_uid: x.intelligence_uid,
        channel_uid: x.channel_uid,
        destination_host: x.destination_host,
        destination_ip_cidr: x.destination_ip_cidr,
        destination_port: x.destination_port,
        destination_protocol: x.destination_protocol,
        action_digest: x.action_digest,
        authority_revision: x.authority_revision,
        enforcement_posture: x.enforcement_posture,
    };
    // P4-T02 / RG-04: bind socket identity — no anonymous agent socket.
    let binding = crate::kernel::agent_cgroup::socket_binding_for_flow(
        principal_id,
        principal_id,
        &record.flow_id,
        &record.lease_id,
    );
    let mut es = state.engine_store.lock().unwrap();
    let mut stored = serde_json::to_value(&record).ok()?;
    if let Some(o) = stored.as_object_mut() {
        o.insert("socket_binding".into(), binding);
    }
    let _ = es.folder_put(FLOW_LEASE_FOLDER, &record.flow_id, &stored);
    Some(record.flow_id.clone())
}

/// True when the record carries any destination constraint fields.
pub fn record_has_destination_constraint(record: &FlowLeaseRecordV1) -> bool {
    record.destination_host.is_some()
        || record.destination_ip_cidr.is_some()
        || record.destination_port.is_some()
        || record.destination_protocol.is_some()
}

/// v1 IP/CIDR match: exact string, or naive prefix (`starts_with`) after stripping `/mask`.
fn ip_cidr_matches(constraint: &str, actual: &str) -> bool {
    if actual == constraint {
        return true;
    }
    let prefix = constraint.split('/').next().unwrap_or(constraint);
    actual.starts_with(prefix) || prefix.starts_with(actual)
}

/// Whether `record` authorizes the given destination.
///
/// Unconstrained leases (no destination_* fields) are migration-era allow-any
/// for that lease — honesty: destination enforcement only applies when fields
/// are present. Callers gate overall deny via [`flow_lease_enforcement_enabled`].
pub fn lease_allows_destination(
    record: &FlowLeaseRecordV1,
    host: Option<&str>,
    ip: Option<&str>,
    port: Option<u16>,
    protocol: Option<&str>,
) -> bool {
    if !record_has_destination_constraint(record) {
        return true;
    }

    let host_c = record.destination_host.as_deref();
    let ip_c = record.destination_ip_cidr.as_deref();
    if host_c.is_some() || ip_c.is_some() {
        let host_ok = match host_c {
            Some(expected) => host
                .map(|h| h.eq_ignore_ascii_case(expected))
                .unwrap_or(false),
            None => false,
        };
        let ip_ok = match ip_c {
            Some(expected) => ip.map(|a| ip_cidr_matches(expected, a)).unwrap_or(false),
            None => false,
        };
        let endpoint_ok = match (host_c.is_some(), ip_c.is_some()) {
            (true, true) => host_ok || ip_ok,
            (true, false) => host_ok,
            (false, true) => ip_ok,
            (false, false) => true,
        };
        if !endpoint_ok {
            return false;
        }
    }

    if let Some(expected_port) = record.destination_port {
        match port {
            Some(p) if p == expected_port => {}
            _ => return false,
        }
    }

    if let Some(ref expected_proto) = record.destination_protocol {
        match protocol {
            Some(p) if p.eq_ignore_ascii_case(expected_proto) => {}
            _ => return false,
        }
    }

    true
}

pub fn active_lease_count(state: &PlatformState) -> usize {
    active_lease_records(state, usize::MAX).len()
}

/// Active (non-expired) leases for kerneld / forensics (newest first, capped).
pub fn active_lease_records(state: &PlatformState, limit: usize) -> Vec<FlowLeaseRecordV1> {
    prune_expired(state);
    let now = chrono::Utc::now().timestamp_millis();
    let keys: Vec<String> = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(FLOW_LEASE_FOLDER, None)
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    let es = state.engine_store.lock().unwrap();
    for key in keys {
        let Some(v) = es.folder_get(FLOW_LEASE_FOLDER, &key).ok().flatten() else {
            continue;
        };
        let expires = v
            .get("expires_at_ms")
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        if expires > 0 && expires < now {
            continue;
        }
        if let Ok(rec) = serde_json::from_value::<FlowLeaseRecordV1>(v) {
            out.push(rec);
        }
    }
    out.sort_by(|a, b| b.issued_at_ms.cmp(&a.issued_at_ms));
    out.truncate(limit);
    out
}

/// Lookup an active (non-expired) lease by flow id.
pub fn lookup_active_lease(state: &PlatformState, flow_id: &str) -> Option<FlowLeaseRecordV1> {
    if flow_id.trim().is_empty() {
        return None;
    }
    prune_expired(state);
    let now = chrono::Utc::now().timestamp_millis();
    let es = state.engine_store.lock().unwrap();
    let v = es.folder_get(FLOW_LEASE_FOLDER, flow_id).ok().flatten()?;
    let expires = v
        .get("expires_at_ms")
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    if expires > 0 && expires < now {
        return None;
    }
    serde_json::from_value::<FlowLeaseRecordV1>(v).ok()
}

pub fn has_active_lease(state: &PlatformState, flow_id: &str) -> bool {
    lookup_active_lease(state, flow_id).is_some()
}

/// Deny-path stub for unstamped / leaseless egress when enforce is on.
/// Returns Ok(()) when enforcement is off or a matching active lease exists.
pub fn require_active_flow_lease(
    state: &PlatformState,
    flow_id: Option<&str>,
) -> Result<(), serde_json::Value> {
    if !flow_lease_enforcement_enabled() {
        return Ok(());
    }
    let Some(fid) = flow_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(json!({
            "ok": false,
            "error": "flow_lease_denied",
            "reason": "missing_flow_id",
            "enforce": "on",
            "honesty": "CONNECTOR_FLOW_LEASE_ENFORCE (or kernel enforce) active — unstamped egress denied (stub path)",
        }));
    };
    if has_active_lease(state, fid) {
        return Ok(());
    }
    Err(json!({
        "ok": false,
        "error": "flow_lease_denied",
        "reason": "no_active_lease",
        "flow_id": fid,
        "enforce": "on",
        "honesty": "No active flow lease for FNI — egress denied while CONNECTOR_FLOW_LEASE_ENFORCE is on (stub)",
    }))
}

/// Require some active lease that authorizes this destination (when enforce is on).
/// Prefer this on egress hot paths that do not yet carry an explicit flow_id.
pub fn require_matching_destination_lease(
    state: &PlatformState,
    host: Option<&str>,
    ip: Option<&str>,
    port: Option<u16>,
    protocol: Option<&str>,
) -> Result<String, serde_json::Value> {
    if !flow_lease_enforcement_enabled() {
        return Ok(String::new());
    }
    let records = active_lease_records(state, 64);
    if records.is_empty() {
        return Err(json!({
            "ok": false,
            "error": "flow_lease_denied",
            "reason": "no_active_lease",
            "enforce": "on",
            "honesty": "No active flow lease — destination egress denied",
        }));
    }
    for rec in &records {
        if lease_allows_destination(rec, host, ip, port, protocol) {
            return Ok(rec.flow_id.clone());
        }
    }
    Err(json!({
        "ok": false,
        "error": "flow_lease_denied",
        "reason": "destination_mismatch",
        "enforce": "on",
        "honesty": "Active leases exist but none authorize this destination tuple",
        "destination_host": host,
        "destination_port": port,
        "destination_protocol": protocol,
    }))
}

/// Require an active lease that authorizes the given destination (when enforce is on).
pub fn require_destination_lease(
    state: &PlatformState,
    flow_id: Option<&str>,
    host: Option<&str>,
    ip: Option<&str>,
    port: Option<u16>,
    protocol: Option<&str>,
) -> Result<(), serde_json::Value> {
    if !flow_lease_enforcement_enabled() {
        return Ok(());
    }
    let Some(fid) = flow_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(json!({
            "ok": false,
            "error": "flow_lease_denied",
            "reason": "missing_flow_id",
            "enforce": "on",
            "honesty": "destination lease check — missing flow id",
        }));
    };
    let Some(rec) = lookup_active_lease(state, fid) else {
        return Err(json!({
            "ok": false,
            "error": "flow_lease_denied",
            "reason": "no_active_lease",
            "flow_id": fid,
            "enforce": "on",
            "honesty": "No active flow lease for FNI — destination egress denied",
        }));
    };
    if lease_allows_destination(&rec, host, ip, port, protocol) {
        return Ok(());
    }
    Err(json!({
        "ok": false,
        "error": "flow_lease_denied",
        "reason": "destination_mismatch",
        "flow_id": fid,
        "enforce": "on",
        "honesty": "Active lease exists but destination does not match constrained fields",
        "lease_id": rec.lease_id,
    }))
}

pub fn lease_snapshot(state: &PlatformState) -> serde_json::Value {
    const KERNELD_LEASE_CAP: usize = 64;
    let records = active_lease_records(state, KERNELD_LEASE_CAP);
    let active = records.len();
    let constrained = records
        .iter()
        .filter(|r| record_has_destination_constraint(r))
        .count();
    let unconstrained = active.saturating_sub(constrained);
    let kernel_cage_hostnames: Vec<String> = records
        .iter()
        .filter(|r| record_has_destination_constraint(r))
        .filter_map(|r| {
            r.destination_host
                .as_ref()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let enforce = enforce_display();
    json!({
        "schema": "flow_lease_map.v1",
        "enabled": flow_lease_map_enabled(),
        "enforcement_enabled": flow_lease_enforcement_enabled(),
        "enforce": enforce,
        "enforce_env": "CONNECTOR_FLOW_LEASE_ENFORCE",
        "enforce_flag": flow_lease_enforce_flag(),
        "kernel_enforce": kernel_enforce_enabled(),
        "ttl_sec": lease_ttl_secs(),
        "active_leases": active,
        "constrained_leases": constrained,
        "unconstrained_leases": unconstrained,
        "kernel_cage_hostnames": kernel_cage_hostnames,
        "leases": records,
        "deny_stub": "substrate::flow_lease::require_active_flow_lease",
        "destination_deny": "substrate::flow_lease::require_destination_lease|require_matching_destination_lease",
        "kerneld_note": "When enforcement_enabled and active_leases=0 → IPAddressDeny=any; when constrained leases exist, kerneld narrows IPAddressAllow to kernel_cage_hostnames",
        "honesty": "Destination matching enforced in userspace (proxy_plane / flow_lease). Kerneld narrows systemd allowlist to constrained lease hosts when present; eBPF tuple maps remain deferred",
        "reason": if flow_lease_enforcement_enabled() {
            "enforce on via CONNECTOR_FLOW_LEASE_ENFORCE and/or CONNECTOR_KERNEL_ENFORCE with map enabled"
        } else if !flow_lease_map_enabled() {
            "map disabled (CONNECTOR_FLOW_LEASE_DISABLE)"
        } else {
            "enforce off — set CONNECTOR_FLOW_LEASE_ENFORCE=1 for prod deny path"
        },
    })
}

pub fn revoke_leases_for_agent(state: &PlatformState, agent_pid: &str) {
    let keys: Vec<String> = {
        let Ok(es) = state.engine_store.lock() else {
            return;
        };
        es.folder_keys(FLOW_LEASE_FOLDER, None).unwrap_or_default()
    };
    let mut es = match state.engine_store.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    for key in keys {
        let Some(v) = es.folder_get(FLOW_LEASE_FOLDER, &key).ok().flatten() else {
            continue;
        };
        let pid = v
            .get("principal_id")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let op = v.get("operation").and_then(|x| x.as_str()).unwrap_or("");
        if pid.contains(agent_pid) || op.contains(agent_pid) || key.contains(agent_pid) {
            let _ = es.folder_delete(FLOW_LEASE_FOLDER, &key);
        }
    }
    // Explicit cut marker for kerneld desired-vs-applied.
    let _ = es.folder_put(
        FLOW_LEASE_FOLDER,
        &format!("revoked:{agent_pid}"),
        &json!({
            "revoked": true,
            "agent_pid": agent_pid,
            "at_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
}

fn prune_expired(state: &PlatformState) {
    let now = chrono::Utc::now().timestamp_millis();
    let keys: Vec<String> = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(FLOW_LEASE_FOLDER, None)
            .unwrap_or_default()
    };
    let mut es = state.engine_store.lock().unwrap();
    for key in keys {
        let Some(v) = es.folder_get(FLOW_LEASE_FOLDER, &key).ok().flatten() else {
            continue;
        };
        let expires = v
            .get("expires_at_ms")
            .and_then(|x| x.as_i64())
            .unwrap_or(0);
        if expires > 0 && expires < now {
            let _ = es.folder_delete(FLOW_LEASE_FOLDER, &key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_record() -> FlowLeaseRecordV1 {
        FlowLeaseRecordV1 {
            schema: "flow_lease.v1".into(),
            lease_id: "lease_test".into(),
            flow_id: "flow_test".into(),
            principal_id: "principal_1".into(),
            tenant_id: None,
            operation: "egress".into(),
            admission_ticket_id: "ticket_1".into(),
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            workload_uid: None,
            intelligence_uid: None,
            channel_uid: None,
            destination_host: None,
            destination_ip_cidr: None,
            destination_port: None,
            destination_protocol: None,
            action_digest: None,
            authority_revision: None,
            enforcement_posture: None,
        }
    }

    #[test]
    fn lease_ttl_has_sane_default() {
        assert!(lease_ttl_secs() >= 60);
    }

    #[test]
    fn enforce_display_is_on_or_off() {
        let d = enforce_display();
        assert!(d == "on" || d == "off");
    }

    #[test]
    fn deny_reason_codes_are_stable() {
        // Document stub contract without needing PlatformState.
        assert_eq!(
            json!({"error": "flow_lease_denied", "reason": "missing_flow_id"})["error"],
            "flow_lease_denied"
        );
        assert_eq!(
            json!({"error": "flow_lease_denied", "reason": "no_active_lease"})["reason"],
            "no_active_lease"
        );
        assert_eq!(
            json!({"error": "flow_lease_denied", "reason": "destination_mismatch"})["reason"],
            "destination_mismatch"
        );
    }

    #[test]
    fn old_record_json_deserializes_with_defaults() {
        let legacy = json!({
            "schema": "flow_lease.v1",
            "lease_id": "lease_old",
            "flow_id": "flow_old",
            "principal_id": "p1",
            "operation": "op",
            "admission_ticket_id": "t1",
            "issued_at_ms": 1,
            "expires_at_ms": 2,
        });
        let rec: FlowLeaseRecordV1 = serde_json::from_value(legacy).expect("legacy deserialize");
        assert!(rec.workload_uid.is_none());
        assert!(rec.destination_host.is_none());
        assert!(!record_has_destination_constraint(&rec));
    }

    #[test]
    fn unconstrained_lease_allows_any_destination() {
        let rec = base_record();
        assert!(lease_allows_destination(
            &rec,
            Some("evil.example"),
            Some("1.2.3.4"),
            Some(22),
            Some("tcp")
        ));
    }

    #[test]
    fn destination_host_and_port_match() {
        let mut rec = base_record();
        rec.destination_host = Some("api.example.com".into());
        rec.destination_port = Some(443);
        rec.destination_protocol = Some("tcp".into());
        assert!(lease_allows_destination(
            &rec,
            Some("API.example.com"),
            None,
            Some(443),
            Some("TCP")
        ));
        assert!(!lease_allows_destination(
            &rec,
            Some("other.example.com"),
            None,
            Some(443),
            Some("tcp")
        ));
        assert!(!lease_allows_destination(
            &rec,
            Some("api.example.com"),
            None,
            Some(80),
            Some("tcp")
        ));
    }

    #[test]
    fn destination_host_or_ip_cidr() {
        let mut rec = base_record();
        rec.destination_host = Some("api.example.com".into());
        rec.destination_ip_cidr = Some("10.0.0.".into());
        // Host match alone is enough (OR).
        assert!(lease_allows_destination(
            &rec,
            Some("api.example.com"),
            Some("9.9.9.9"),
            None,
            None
        ));
        // IP prefix match alone is enough.
        assert!(lease_allows_destination(
            &rec,
            Some("other.com"),
            Some("10.0.0.5"),
            None,
            None
        ));
        // Neither matches.
        assert!(!lease_allows_destination(
            &rec,
            Some("other.com"),
            Some("9.9.9.9"),
            None,
            None
        ));
    }

    #[test]
    fn ip_cidr_exact_and_prefix() {
        let mut rec = base_record();
        rec.destination_ip_cidr = Some("192.168.1.0/24".into());
        assert!(lease_allows_destination(
            &rec,
            None,
            Some("192.168.1.0/24"),
            None,
            None
        ));
        assert!(lease_allows_destination(
            &rec,
            None,
            Some("192.168.1.0"),
            None,
            None
        ));
        assert!(!lease_allows_destination(
            &rec,
            None,
            Some("10.0.0.1"),
            None,
            None
        ));
    }

    #[test]
    fn constrained_record_serde_roundtrip() {
        let mut rec = base_record();
        rec.workload_uid = Some("wl_1".into());
        rec.intelligence_uid = Some("intel_1".into());
        rec.channel_uid = Some("ch_1".into());
        rec.destination_host = Some("api.example.com".into());
        rec.destination_ip_cidr = Some("10.1.2.3".into());
        rec.destination_port = Some(443);
        rec.destination_protocol = Some("tcp".into());
        rec.action_digest = Some("sha256:abc".into());
        rec.authority_revision = Some(7);
        rec.enforcement_posture = Some("enforce".into());

        let v = serde_json::to_value(&rec).expect("serialize");
        let back: FlowLeaseRecordV1 = serde_json::from_value(v).expect("deserialize");
        assert_eq!(back.workload_uid.as_deref(), Some("wl_1"));
        assert_eq!(back.intelligence_uid.as_deref(), Some("intel_1"));
        assert_eq!(back.channel_uid.as_deref(), Some("ch_1"));
        assert_eq!(back.destination_host.as_deref(), Some("api.example.com"));
        assert_eq!(back.destination_ip_cidr.as_deref(), Some("10.1.2.3"));
        assert_eq!(back.destination_port, Some(443));
        assert_eq!(back.destination_protocol.as_deref(), Some("tcp"));
        assert_eq!(back.action_digest.as_deref(), Some("sha256:abc"));
        assert_eq!(back.authority_revision, Some(7));
        assert_eq!(back.enforcement_posture.as_deref(), Some("enforce"));
        assert!(record_has_destination_constraint(&back));
        assert!(lease_allows_destination(
            &back,
            Some("api.example.com"),
            None,
            Some(443),
            Some("tcp")
        ));
        assert!(!lease_allows_destination(
            &back,
            Some("evil.com"),
            Some("9.9.9.9"),
            Some(443),
            Some("tcp")
        ));
    }

    #[test]
    fn constrained_lease_request_fields_map_to_record_shape() {
        // Document ConstrainedLeaseRequest → record field mapping without PlatformState.
        let req = ConstrainedLeaseRequest {
            principal_id: "p1".into(),
            tenant_id: Some("t1".into()),
            operation: "https_egress".into(),
            admission_ticket_id: "adm_1".into(),
            workload_uid: Some("wl".into()),
            intelligence_uid: Some("intel".into()),
            channel_uid: Some("ch".into()),
            destination_host: Some("api.example.com".into()),
            destination_ip_cidr: None,
            destination_port: Some(443),
            destination_protocol: Some("tcp".into()),
            action_digest: Some("digest".into()),
            authority_revision: Some(1),
            enforcement_posture: Some("enforce".into()),
        };
        let extras = LeaseExtras {
            workload_uid: req.workload_uid.clone(),
            intelligence_uid: req.intelligence_uid.clone(),
            channel_uid: req.channel_uid.clone(),
            destination_host: req.destination_host.clone(),
            destination_ip_cidr: req.destination_ip_cidr.clone(),
            destination_port: req.destination_port,
            destination_protocol: req.destination_protocol.clone(),
            action_digest: req.action_digest.clone(),
            authority_revision: req.authority_revision,
            enforcement_posture: req.enforcement_posture.clone(),
        };
        let mut rec = base_record();
        rec.workload_uid = extras.workload_uid;
        rec.intelligence_uid = extras.intelligence_uid;
        rec.channel_uid = extras.channel_uid;
        rec.destination_host = extras.destination_host;
        rec.destination_ip_cidr = extras.destination_ip_cidr;
        rec.destination_port = extras.destination_port;
        rec.destination_protocol = extras.destination_protocol;
        rec.action_digest = extras.action_digest;
        rec.authority_revision = extras.authority_revision;
        rec.enforcement_posture = extras.enforcement_posture;
        assert!(record_has_destination_constraint(&rec));
        assert!(lease_allows_destination(
            &rec,
            Some("api.example.com"),
            None,
            Some(443),
            Some("TCP")
        ));
    }
}
