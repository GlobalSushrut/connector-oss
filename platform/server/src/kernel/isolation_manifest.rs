//! ConnectorIsolationManifest — desired vs measured isolation (Seven Pillars §6).

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const ISOLATION_MANIFEST_SCHEMA: &str = "connector.isolation_manifest.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectorIsolationManifestV1 {
    pub schema: String,
    pub agent_pid: String,
    pub principal_id: String,
    pub tier: IsolationTierName,
    pub cgroup_path: Option<String>,
    pub namespaces: Vec<String>,
    pub allowed_mounts: Vec<String>,
    pub seccomp_profile: String,
    pub allowed_devices: Vec<String>,
    pub network_posture: String,
    pub vsock_endpoints: Vec<String>,
    pub microvm_kernel_digest: Option<String>,
    pub microvm_rootfs_digest: Option<String>,
    pub vm_id: Option<String>,
    pub resource_limits: serde_json::Value,
    pub digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IsolationTierName {
    Light,
    Medium,
    High,
    Physical,
}

impl IsolationTierName {
    pub fn from_runtime(runtime: &str) -> Self {
        match runtime {
            "microvm" => Self::High,
            "docker_lab" => Self::Medium,
            "subprocess" | "internal" => Self::Light,
            _ => Self::Light,
        }
    }

    /// Map tier promise to Linux/VM primitives (Pillar 2 / 6).
    pub fn linux_primitives(&self) -> &'static [&'static str] {
        match self {
            Self::Light => &["cgroup", "namespaces", "seccomp", "landlock"],
            Self::Medium => &["cgroup", "namespaces", "seccomp", "landlock", "docker_lab"],
            Self::High => &["microvm", "vsock_only", "deny_all_guest_net", "seccomp"],
            Self::Physical => &[
                "microvm",
                "vsock_only",
                "deny_all_guest_net",
                "governed_device_channel",
            ],
        }
    }
}

pub fn file_sha256_hex(path: &str) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(format!("{:x}", Sha256::digest(&bytes)))
}

/// Build desired isolation manifest for an agent from runtime env + optional VM assets.
pub fn build_desired(
    agent_pid: &str,
    principal_id: &str,
    vm_id: Option<String>,
) -> ConnectorIsolationManifestV1 {
    let runtime = std::env::var("CONNECTOR_ISOLATION_RUNTIME")
        .or_else(|_| std::env::var("CONNECTOR_PLUGIN_RUN_BACKEND"))
        .unwrap_or_else(|_| "subprocess".into());
    let tier = IsolationTierName::from_runtime(runtime.trim());
    let kernel_path = std::env::var("CONNECTOR_MICROVM_KERNEL").ok();
    let rootfs_path = std::env::var("CONNECTOR_MICROVM_ROOTFS").ok();
    let kernel_digest = kernel_path.as_deref().and_then(file_sha256_hex);
    let rootfs_digest = rootfs_path.as_deref().and_then(file_sha256_hex);
    let network = match tier {
        IsolationTierName::High | IsolationTierName::Physical => "deny_all_vsock_only",
        IsolationTierName::Medium => "docker_network_none",
        IsolationTierName::Light => "host_governed",
    };
    let mut m = ConnectorIsolationManifestV1 {
        schema: ISOLATION_MANIFEST_SCHEMA.into(),
        agent_pid: agent_pid.into(),
        principal_id: principal_id.into(),
        tier,
        cgroup_path: Some(format!("/connector/agents/{agent_pid}")),
        namespaces: vec!["pid".into(), "mnt".into(), "user".into(), "net".into()],
        allowed_mounts: vec!["/m".into(), "/k".into(), "/p".into()],
        seccomp_profile: "connector-default".into(),
        allowed_devices: vec![],
        network_posture: network.into(),
        vsock_endpoints: vec!["vsock:connector-broker".into()],
        microvm_kernel_digest: kernel_digest,
        microvm_rootfs_digest: rootfs_digest,
        vm_id,
        resource_limits: json!({ "cpu_shares": 1024, "memory_mb": 512 }),
        digest_hex: String::new(),
    };
    m.digest_hex = manifest_digest(&m);
    m
}

fn manifest_digest(m: &ConnectorIsolationManifestV1) -> String {
    let mut copy = m.clone();
    copy.digest_hex.clear();
    let bytes = serde_json::to_vec(&copy).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

/// Persist desired + compare measured; drift is a security event.
pub fn apply_and_check_drift(
    state: &PlatformState,
    desired: &ConnectorIsolationManifestV1,
    measured: &ConnectorIsolationManifestV1,
) -> Result<(), String> {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "isolation_manifest_v1",
            &format!("desired:{}", desired.agent_pid),
            &serde_json::to_value(desired).unwrap_or(json!({})),
        );
        let _ = es.folder_put(
            "isolation_manifest_v1",
            &format!("measured:{}", desired.agent_pid),
            &serde_json::to_value(measured).unwrap_or(json!({})),
        );
    }

    if desired.tier != measured.tier
        || desired.network_posture != measured.network_posture
        || desired.microvm_kernel_digest != measured.microvm_kernel_digest
        || desired.microvm_rootfs_digest != measured.microvm_rootfs_digest
        || desired.vm_id != measured.vm_id
    {
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_put(
                "isolation_manifest_v1",
                &format!("drift:{}", desired.agent_pid),
                &json!({
                    "desired_digest": desired.digest_hex,
                    "measured_digest": measured.digest_hex,
                }),
            );
        }
        crate::substrate::atomic_revoke::revoke_agent_authority(
            state,
            &desired.agent_pid,
            "isolation_drift",
        );
        return Err("isolation_manifest_drift".into());
    }
    Ok(())
}

/// Verify microVM assets at launch (fail closed when required).
pub fn assert_microvm_assets_measured() -> Result<(Option<String>, Option<String>), String> {
    let require = matches!(
        std::env::var("CONNECTOR_ISOLATION_RUNTIME")
            .or_else(|_| std::env::var("CONNECTOR_PLUGIN_RUN_BACKEND"))
            .ok()
            .as_deref()
            .map(|s| s.trim()),
        Some("microvm")
    ) || crate::substrate::effect_exclusivity::effect_exclusivity_enforced();

    let kernel = std::env::var("CONNECTOR_MICROVM_KERNEL").ok();
    let rootfs = std::env::var("CONNECTOR_MICROVM_ROOTFS").ok();
    if require {
        let k = kernel
            .as_deref()
            .ok_or_else(|| "CONNECTOR_MICROVM_KERNEL missing".to_string())?;
        let r = rootfs
            .as_deref()
            .ok_or_else(|| "CONNECTOR_MICROVM_ROOTFS missing".to_string())?;
        let kd = file_sha256_hex(k).ok_or_else(|| "kernel_unreadable".to_string())?;
        let rd = file_sha256_hex(r).ok_or_else(|| "rootfs_unreadable".to_string())?;
        // Optional pinned digests
        if let Ok(expect) = std::env::var("CONNECTOR_MICROVM_KERNEL_SHA256") {
            if !expect.is_empty() && expect != kd {
                return Err("microvm_kernel_digest_mismatch".into());
            }
        }
        if let Ok(expect) = std::env::var("CONNECTOR_MICROVM_ROOTFS_SHA256") {
            if !expect.is_empty() && expect != rd {
                return Err("microvm_rootfs_digest_mismatch".into());
            }
        }
        return Ok((Some(kd), Some(rd)));
    }
    Ok((
        kernel.as_deref().and_then(file_sha256_hex),
        rootfs.as_deref().and_then(file_sha256_hex),
    ))
}

/// Whether vsock tickets are required (prod / unbypassable bar).
pub fn vsock_ticket_required() -> bool {
    let allow_unauth = matches!(
        std::env::var("CONNECTOR_ALLOW_UNAUTH_VSOCK")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    );
    if allow_unauth {
        return false;
    }
    matches!(
        std::env::var("CONNECTOR_VSOCK_TICKET_REQUIRE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    ) || matches!(
        std::env::var("CONNECTOR_SANDBOX_UNBYPASSABLE")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    ) || crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
}

fn vsock_hmac_key() -> Vec<u8> {
    if let Ok(k) = std::env::var("CONNECTOR_VSOCK_HMAC_KEY") {
        if !k.trim().is_empty() {
            return k.into_bytes();
        }
    }
    // Derived lab key — production must set CONNECTOR_VSOCK_HMAC_KEY.
    b"connector-vsock-dev-key-change-me".to_vec()
}

/// Mint an HMAC ticket binding principal × channel × op × expiry.
pub fn mint_vsock_ticket(
    agent_pid: &str,
    principal_id: &str,
    channel_id: &str,
    op_class: &str,
    ttl_secs: u64,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_add(ttl_secs);
    let nonce = format!("{:x}", Sha256::digest(
        format!("{agent_pid}:{channel_id}:{exp}").as_bytes(),
    ));
    let payload = format!(
        "v1|{agent_pid}|{principal_id}|{channel_id}|{op_class}|{exp}|{}",
        &nonce[..16.min(nonce.len())]
    );
    let mut mac = HmacSha256::new_from_slice(&vsock_hmac_key()).expect("hmac key");
    mac.update(payload.as_bytes());
    let sig = format!("{:x}", mac.finalize().into_bytes());
    format!("{payload}|{sig}")
}

/// Verify ticket; fail closed when required.
pub fn verify_vsock_ticket(
    state: &PlatformState,
    agent_pid: &str,
    ticket: &str,
) -> Result<(), String> {
    if crate::substrate::atomic_revoke::is_agent_authority_revoked(state, agent_pid) {
        return Err("vsock_authority_revoked".into());
    }
    if let Ok(es) = state.engine_store.lock() {
        if es
            .folder_get("vsock_channel_v1", &format!("revoke_all:{agent_pid}"))
            .ok()
            .flatten()
            .is_some()
        {
            return Err("vsock_channels_revoked".into());
        }
    }
    if ticket.is_empty() {
        if vsock_ticket_required() {
            return Err("vsock_ticket_missing".into());
        }
        return Ok(());
    }
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let parts: Vec<&str> = ticket.split('|').collect();
    if parts.len() != 8 || parts[0] != "v1" {
        return Err("vsock_ticket_malformed".into());
    }
    if parts[1] != agent_pid {
        return Err("vsock_ticket_agent_mismatch".into());
    }
    let exp: u64 = parts[5].parse().map_err(|_| "vsock_ticket_exp")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now > exp {
        return Err("vsock_ticket_expired".into());
    }
    let payload = parts[..7].join("|");
    let mut mac = HmacSha256::new_from_slice(&vsock_hmac_key()).map_err(|_| "hmac")?;
    mac.update(payload.as_bytes());
    let expect = format!("{:x}", mac.finalize().into_bytes());
    if expect != parts[7] {
        return Err("vsock_ticket_bad_sig".into());
    }
    Ok(())
}

/// Authenticate vsock channel binding to principal + op class (HMAC ticket).
pub fn authorize_vsock_channel(
    state: &PlatformState,
    agent_pid: &str,
    principal_id: &str,
    channel_id: &str,
    op_class: &str,
) -> Result<String, String> {
    if channel_id.is_empty() {
        return Err("vsock_channel_missing".into());
    }
    if crate::substrate::atomic_revoke::is_agent_authority_revoked(state, agent_pid) {
        return Err("vsock_authority_revoked".into());
    }
    let ticket = mint_vsock_ticket(agent_pid, principal_id, channel_id, op_class, 300);
    verify_vsock_ticket(state, agent_pid, &ticket)?;
    let rec = json!({
        "principal_id": principal_id,
        "op_class": op_class,
        "channel_id": channel_id,
        "authorized": true,
        "ticket_fingerprint": format!("{:x}", Sha256::digest(ticket.as_bytes())),
        "no_host_network_escape": true,
        "auth": "hmac_sha256_vsock_ticket_v1",
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "vsock_channel_v1",
            &format!("{agent_pid}:{channel_id}"),
            &rec,
        );
    }
    Ok(ticket)
}

pub fn revoke_vsock_channels(state: &PlatformState, agent_pid: &str) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "vsock_channel_v1",
            &format!("revoke_all:{agent_pid}"),
            &json!({ "revoked": true }),
        );
    }
}

/// Bind DockLock quantum to isolation instance ids.
pub fn docklock_instance_binding_material(
    quantum_id: &str,
    agent_pid: &str,
    vm_id: Option<&str>,
    cgroup_path: Option<&str>,
) -> String {
    let raw = format!(
        "quantum={quantum_id}|agent={agent_pid}|vm={}|cgroup={}",
        vm_id.unwrap_or("-"),
        cgroup_path.unwrap_or("-")
    );
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_ticket_roundtrip() {
        std::env::set_var("CONNECTOR_VSOCK_HMAC_KEY", "test-key");
        let t = mint_vsock_ticket("a1", "p1", "ch1", "local_io", 60);
        // verify without store — empty revoke
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let parts: Vec<&str> = t.split('|').collect();
        assert_eq!(parts.len(), 8);
        let payload = parts[..7].join("|");
        let mut mac = HmacSha256::new_from_slice(b"test-key").unwrap();
        mac.update(payload.as_bytes());
        assert_eq!(format!("{:x}", mac.finalize().into_bytes()), parts[7]);
    }
}
