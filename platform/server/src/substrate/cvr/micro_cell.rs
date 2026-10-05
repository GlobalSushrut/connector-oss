//! MicroCell instance management — real Firecracker lifecycle via MicrovmHost.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use connector_microvm::{
    BootSource, Drive, FirecrackerVmConfig, GuestMachineConfig, MicrovmHost, VsockConfig,
};

use super::host_probe::probe_host;
use super::runtime_bundle::RuntimeBundlePosture;
use crate::state::PlatformState;

pub const MICROCELL_FOLDER: &str = "cvr_microcells";
pub const MICROCELL_SCHEMA: &str = "connector.cvr.microcell.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroCellInstance {
    pub schema: String,
    pub microcell_id: String,
    pub agent_pid: String,
    pub dedicated: bool,
    pub backend: String,
    pub vm_id: String,
    pub api_socket_path: String,
    pub log_path: String,
    pub vsock_path: Option<String>,
    pub guest_cid: Option<u32>,
    pub pid: Option<u32>,
    pub jailed: bool,
    pub state: String,
    pub kernel_path: String,
    pub rootfs_path: String,
    pub kernel_sha256: Option<String>,
    pub rootfs_sha256: Option<String>,
    pub boot_nonce: String,
    #[serde(default)]
    pub resource_profile: String,
    #[serde(default)]
    pub vcpu_count: u8,
    #[serde(default)]
    pub mem_mib: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl MicroCellInstance {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({}))
    }
}

fn state_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CONNECTOR_MICROVM_STATE_DIR") {
        return PathBuf::from(p);
    }
    PathBuf::from("/var/lib/connector/microvm/instances")
}

fn build_host() -> MicrovmHost {
    let probe = probe_host();
    MicrovmHost::new(None)
        .with_firecracker_bin(probe.firecracker_bin.map(PathBuf::from))
        .with_jailer_bin(probe.jailer_bin.map(PathBuf::from))
}

fn jailer_required() -> bool {
    matches!(
        std::env::var("CONNECTOR_MICROCELL_JAILER_REQUIRED")
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    ) || crate::kernel::agent_principal::intelligence_hardening_on()
        || std::env::var("CONNECTOR_AUGMENTED_ENV")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
}

fn guest_cid_for(microcell_id: &str) -> u32 {
    let base = std::env::var("CONNECTOR_MICROVM_GUEST_CID_BASE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(52_000u32);
    let mut h: u32 = 2166136261;
    for b in microcell_id.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    base.saturating_add(h % 8_000)
}

/// Create + start a MicroCell (Firecracker). Fails closed when probe incomplete.
pub fn create_and_start(
    state: &PlatformState,
    microcell_id: &str,
    agent_pid: &str,
    dedicated: bool,
) -> Result<MicroCellInstance, Value> {
    create_and_start_with_resources(
        state,
        microcell_id,
        agent_pid,
        dedicated,
        super::resources::ResourceProfile::Default,
    )
}

/// Create + start with an explicit resource envelope (Phase E4).
pub fn create_and_start_with_resources(
    state: &PlatformState,
    microcell_id: &str,
    agent_pid: &str,
    dedicated: bool,
    resource: super::resources::ResourceProfile,
) -> Result<MicroCellInstance, Value> {
    let probe = probe_host();
    if !probe.microcell_ready() {
        return Err(json!({
            "ok": false,
            "error": "START_REFUSED",
            "denial_reason": "microcell_runtime_unavailable",
            "host_probe": probe.to_json(),
        }));
    }
    let use_jailer = jailer_required();
    if use_jailer && probe.jailer_bin.is_none() {
        return Err(json!({
            "ok": false,
            "error": "START_REFUSED",
            "denial_reason": "jailer_required_unavailable",
            "honesty": "Hardened MicroCell requires jailer — refusing silent non-jailed Firecracker",
        }));
    }

    let kernel = probe.guest_kernel.clone().ok_or_else(|| {
        json!({"ok": false, "error": "START_REFUSED", "denial_reason": "kernel_missing"})
    })?;
    let rootfs = probe.guest_rootfs.clone().ok_or_else(|| {
        json!({"ok": false, "error": "START_REFUSED", "denial_reason": "rootfs_missing"})
    })?;

    let bundle = RuntimeBundlePosture::discover();
    let dir = state_dir().join(microcell_id);
    std::fs::create_dir_all(&dir).map_err(|e| {
        json!({"ok": false, "error": "io", "detail": e.to_string()})
    })?;

    let vm_id = microcell_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect::<String>();
    let api_socket = dir.join("firecracker.sock");
    let log_path = dir.join("firecracker.log");
    let vsock_path = dir.join("vsock");
    let guest_cid = guest_cid_for(microcell_id);
    let boot_nonce = uuid::Uuid::new_v4().simple().to_string();
    let (vcpu_count, mem_mib) = resource.machine(dedicated);

    // Fresh identity in boot args — no reusable authority in base image.
    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off connector.agent_pid={agent_pid} connector.microcell_id={microcell_id} connector.boot_nonce={boot_nonce} connector.dedicated={} connector.resources={}",
        if dedicated { "1" } else { "0" },
        resource.as_str(),
    );

    let cfg = FirecrackerVmConfig {
        vm_id: vm_id.clone(),
        api_socket_path: api_socket.display().to_string(),
        log_path: log_path.display().to_string(),
        machine_config: GuestMachineConfig {
            vcpu_count,
            mem_mib,
            smt: false,
            track_dirty_pages: false,
        },
        boot_source: BootSource {
            kernel_image_path: kernel.clone(),
            boot_args: Some(boot_args),
            initrd_path: None,
        },
        drives: vec![Drive {
            drive_id: "rootfs".into(),
            path_on_host: rootfs.clone(),
            is_root_device: true,
            is_read_only: true,
        }],
        network_iface: None, // World Gateway only — no unrestricted TAP by default
        vsock: Some(VsockConfig {
            guest_cid,
            uds_path: vsock_path.display().to_string(),
        }),
        metrics_path: None,
    };

    let host = build_host();
    let started = if super::microd_client::microd_socket_present() {
        match super::microd_client::start_vm(&cfg, use_jailer) {
            Ok(v) => v,
            Err(e) => {
                if use_jailer || super::microd_client::microd_verified_ready() {
                    tracing::warn!(error = %e, "microd start failed; attempting in-process fallback");
                }
                host.start_with_options(&cfg, use_jailer).map_err(|e2| {
                    json!({
                        "ok": false,
                        "error": "START_REFUSED",
                        "denial_reason": "firecracker_start_failed",
                        "microd_error": e,
                        "detail": e2.to_string(),
                        "jailed_requested": use_jailer,
                    })
                })?
            }
        }
    } else {
        host.start_with_options(&cfg, use_jailer).map_err(|e| {
            json!({
                "ok": false,
                "error": "START_REFUSED",
                "denial_reason": "firecracker_start_failed",
                "detail": e.to_string(),
                "jailed_requested": use_jailer,
                "hint": "Start connector-microd for privileged VMM path",
            })
        })?
    };

    let now = chrono::Utc::now().timestamp_millis();
    let inst = MicroCellInstance {
        schema: MICROCELL_SCHEMA.into(),
        microcell_id: microcell_id.to_string(),
        agent_pid: agent_pid.to_string(),
        dedicated,
        backend: "firecracker".into(),
        vm_id,
        api_socket_path: api_socket.display().to_string(),
        log_path: log_path.display().to_string(),
        vsock_path: Some(vsock_path.display().to_string()),
        guest_cid: Some(guest_cid),
        pid: started.get("pid").and_then(|v| v.as_u64()).map(|p| p as u32),
        jailed: started
            .get("jailed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        state: "RUNNING".into(),
        kernel_path: kernel,
        rootfs_path: rootfs,
        kernel_sha256: bundle.kernel_sha256.clone(),
        rootfs_sha256: bundle.rootfs_sha256.clone(),
        boot_nonce,
        resource_profile: resource.as_str().into(),
        vcpu_count,
        mem_mib,
        created_at_ms: now,
        updated_at_ms: now,
    };
    persist(state, &inst)?;
    super::deployment_verify::record_firecracker_stage(
        state,
        microcell_id,
        "create_start",
    );
    Ok(inst)
}

/// Index only the agent → microcell mapping (shared pool attach).
pub fn persist_agent_index(
    state: &PlatformState,
    agent_pid: &str,
    inst: &MicroCellInstance,
) -> Result<(), Value> {
    let mut es = state.engine_store.lock().map_err(|e| {
        json!({"ok": false, "error": "lock", "detail": format!("{e}")})
    })?;
    es.folder_put(
        MICROCELL_FOLDER,
        &format!("agent:{agent_pid}"),
        &inst.to_json(),
    )
    .map_err(|e| json!({"ok": false, "error": "persist", "detail": format!("{e}")}))?;
    Ok(())
}

pub fn persist(state: &PlatformState, inst: &MicroCellInstance) -> Result<(), Value> {
    let mut es = state.engine_store.lock().map_err(|e| {
        json!({"ok": false, "error": "lock", "detail": format!("{e}")})
    })?;
    es.folder_put(MICROCELL_FOLDER, &inst.microcell_id, &inst.to_json())
        .map_err(|e| json!({"ok": false, "error": "persist", "detail": format!("{e}")}))?;
    es.folder_put(
        MICROCELL_FOLDER,
        &format!("agent:{}", inst.agent_pid),
        &inst.to_json(),
    )
    .map_err(|e| json!({"ok": false, "error": "persist", "detail": format!("{e}")}))?;
    Ok(())
}

pub fn load(state: &PlatformState, microcell_id: &str) -> Option<MicroCellInstance> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(MICROCELL_FOLDER, microcell_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn load_for_agent(state: &PlatformState, agent_pid: &str) -> Option<MicroCellInstance> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(MICROCELL_FOLDER, &format!("agent:{agent_pid}"))
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

pub fn pause(state: &PlatformState, microcell_id: &str) -> Value {
    let Some(mut inst) = load(state, microcell_id) else {
        return json!({"ok": false, "error": "microcell_not_found"});
    };
    let vmm = if super::microd_client::microd_socket_present() {
        super::microd_client::pause(&inst.api_socket_path).or_else(|e| {
            tracing::warn!(error = %e, "microd pause failed; in-process fallback");
            build_host()
                .pause(&inst.api_socket_path)
                .map_err(|e2| e2.to_string())
        })
    } else {
        build_host()
            .pause(&inst.api_socket_path)
            .map_err(|e| e.to_string())
    };
    match vmm {
        Ok(r) => {
            inst.state = "PAUSED".into();
            inst.updated_at_ms = chrono::Utc::now().timestamp_millis();
            let _ = persist(state, &inst);
            super::deployment_verify::record_firecracker_stage(
                state,
                microcell_id,
                "pause",
            );
            json!({"ok": true, "microcell_id": microcell_id, "vmm": r, "state": "PAUSED"})
        }
        Err(e) => json!({
            "ok": false,
            "error": "microvm_pause_failed",
            "detail": e,
            "api_socket_exists": Path::new(&inst.api_socket_path).exists(),
        }),
    }
}

pub fn resume(state: &PlatformState, microcell_id: &str) -> Value {
    let Some(mut inst) = load(state, microcell_id) else {
        return json!({"ok": false, "error": "microcell_not_found"});
    };
    let vmm = if super::microd_client::microd_socket_present() {
        super::microd_client::resume(&inst.api_socket_path).or_else(|e| {
            tracing::warn!(error = %e, "microd resume failed; in-process fallback");
            build_host()
                .resume(&inst.api_socket_path)
                .map_err(|e2| e2.to_string())
        })
    } else {
        build_host()
            .resume(&inst.api_socket_path)
            .map_err(|e| e.to_string())
    };
    match vmm {
        Ok(r) => {
            inst.state = "RUNNING".into();
            inst.updated_at_ms = chrono::Utc::now().timestamp_millis();
            let _ = persist(state, &inst);
            json!({"ok": true, "microcell_id": microcell_id, "vmm": r, "state": "RUNNING"})
        }
        Err(e) => json!({"ok": false, "error": "microvm_resume_failed", "detail": e}),
    }
}

pub fn stop(state: &PlatformState, microcell_id: &str) -> Value {
    let Some(mut inst) = load(state, microcell_id) else {
        return json!({"ok": false, "error": "microcell_not_found"});
    };
    let vmm = if super::microd_client::microd_socket_present() {
        super::microd_client::stop(&inst.api_socket_path, inst.pid).or_else(|e| {
            tracing::warn!(error = %e, "microd stop failed; in-process fallback");
            build_host()
                .stop(&inst.api_socket_path, inst.pid)
                .map_err(|e2| e2.to_string())
        })
    } else {
        build_host()
            .stop(&inst.api_socket_path, inst.pid)
            .map_err(|e| e.to_string())
    };
    match vmm {
        Ok(r) => {
            inst.state = "STOPPED".into();
            inst.updated_at_ms = chrono::Utc::now().timestamp_millis();
            let _ = persist(state, &inst);
            super::deployment_verify::record_firecracker_stage(
                state,
                microcell_id,
                "destroy",
            );
            json!({"ok": true, "microcell_id": microcell_id, "vmm": r, "state": "STOPPED"})
        }
        Err(e) => json!({"ok": false, "error": "microvm_stop_failed", "detail": e}),
    }
}
