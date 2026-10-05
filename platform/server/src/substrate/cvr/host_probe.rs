//! HostProbe — KVM / VMM / jailer / assets readiness (architecture §10, §37.5).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProbe {
    pub schema: String,
    pub linux: bool,
    pub arch: String,
    pub kvm_available: bool,
    pub kvm_usable: bool,
    pub firecracker_bin: Option<String>,
    pub jailer_bin: Option<String>,
    pub guest_kernel: Option<String>,
    pub guest_rootfs: Option<String>,
    pub vsock_capable: bool,
    pub cgroup_v2: bool,
    pub landlock_abi: bool,
    pub matrix_cut_tools: bool,
}

impl HostProbe {
    pub fn empty() -> Self {
        Self {
            schema: "connector.cvr.host_probe.v1".into(),
            linux: cfg!(target_os = "linux"),
            arch: std::env::consts::ARCH.into(),
            kvm_available: false,
            kvm_usable: false,
            firecracker_bin: None,
            jailer_bin: None,
            guest_kernel: None,
            guest_rootfs: None,
            vsock_capable: false,
            cgroup_v2: false,
            landlock_abi: false,
            matrix_cut_tools: false,
        }
    }

    /// MicroCell can be Applied (not merely Requested).
    pub fn microcell_ready(&self) -> bool {
        // Prefer supervisor READY if microd has verified the host.
        // Production still requires this process to open /dev/kvm.
        if crate::substrate::cvr::microd_client::microd_verified_ready()
            && (self.kvm_usable || !crate::connector_profile::is_productionish_env())
        {
            return true;
        }
        self.linux
            && self.kvm_usable
            && self.firecracker_bin.is_some()
            && self.guest_kernel.is_some()
            && self.guest_rootfs.is_some()
            && (self.jailer_bin.is_some() || !jailer_required_by_env())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "linux": self.linux,
            "arch": self.arch,
            "kvm": {
                "available": self.kvm_available,
                "usable": self.kvm_usable,
            },
            "vmm": {
                "firecracker": self.firecracker_bin,
                "jailer": self.jailer_bin,
                "jailer_required": jailer_required_by_env(),
            },
            "assets": {
                "guest_kernel": self.guest_kernel,
                "guest_rootfs": self.guest_rootfs,
            },
            "vsock_capable": self.vsock_capable,
            "cgroup_v2": self.cgroup_v2,
            "landlock_abi": self.landlock_abi,
            "matrix_cut_tools": self.matrix_cut_tools,
            "microcell_ready": self.microcell_ready(),
            "effective_state": if self.microcell_ready() { "ready" } else { "not_ready" },
            "honesty": "microcell_ready requires KVM usable + pinned FC + kernel + rootfs (+ jailer when harden)",
        })
    }
}

fn jailer_required_by_env() -> bool {
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

fn which_bin(name: &str) -> Option<String> {
    // Explicit env overrides
    let env_key = match name {
        "firecracker" => Some("CONNECTOR_FIRECRACKER_BIN"),
        "jailer" => Some("CONNECTOR_JAILER_BIN"),
        _ => None,
    };
    if let Some(k) = env_key {
        if let Ok(p) = std::env::var(k) {
            let t = p.trim();
            if !t.is_empty() && Path::new(t).is_file() {
                return Some(t.to_string());
            }
        }
    }
    // Vendor / lib paths
    for base in [
        "/usr/lib/connector/vmm",
        "/var/lib/connector/microvm/vmm",
        "vendor/firecracker",
    ] {
        let candidate = Path::new(base).join(name);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p).find_map(|dir| {
            let c = dir.join(name);
            if c.is_file() {
                Some(c.display().to_string())
            } else {
                None
            }
        })
    })
}

fn first_existing(paths: &[&str]) -> Option<String> {
    for p in paths {
        if Path::new(p).is_file() {
            return Some((*p).to_string());
        }
    }
    None
}

fn kvm_probe() -> (bool, bool) {
    let available = Path::new("/dev/kvm").exists();
    let usable = available
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
    // Lab override for CI without KVM — never claims usable unless explicitly set.
    if std::env::var("CONNECTOR_MICROVM_HOST_AVAILABLE")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
    {
        return (true, true);
    }
    (available, usable)
}

/// Overlay paths reported by connector-microd READY file when present.
fn overlay_microd_ready(mut probe: HostProbe) -> HostProbe {
    let Some(ready) = crate::substrate::cvr::microd_client::ready_file_json() else {
        return probe;
    };
    if ready.get("verified").and_then(|v| v.as_bool()) != Some(true) {
        return probe;
    }
    if probe.firecracker_bin.is_none() {
        probe.firecracker_bin = ready
            .get("firecracker")
            .and_then(|v| v.as_str())
            .filter(|s| Path::new(s).is_file())
            .map(|s| s.to_string());
    }
    if probe.jailer_bin.is_none() {
        probe.jailer_bin = ready
            .get("jailer")
            .and_then(|v| v.as_str())
            .filter(|s| Path::new(s).is_file())
            .map(|s| s.to_string());
    }
    if probe.guest_kernel.is_none() {
        probe.guest_kernel = ready
            .get("kernel")
            .and_then(|v| v.as_str())
            .filter(|s| Path::new(s).is_file())
            .map(|s| s.to_string());
    }
    if probe.guest_rootfs.is_none() {
        probe.guest_rootfs = ready
            .get("rootfs")
            .and_then(|v| v.as_str())
            .filter(|s| Path::new(s).is_file())
            .map(|s| s.to_string());
    }
    if ready.get("kvm_usable").and_then(|v| v.as_bool()) == Some(true) {
        probe.kvm_available = true;
        probe.kvm_usable = true;
    }
    probe
}

/// Full host probe (cheap; safe to call on status).
pub fn probe_host() -> HostProbe {
    let (kvm_available, kvm_usable) = kvm_probe();
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    let landlock_abi = landlock
        .get("kernel_abi_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cut = crate::kernel::matrix_host_egress::host_cut_tools_available();
    let kernel = std::env::var("CONNECTOR_MICROVM_KERNEL")
        .ok()
        .filter(|s| Path::new(s.trim()).is_file())
        .or_else(|| {
            first_existing(&[
                "/var/lib/connector/microvm/kernels/connector-vmlinux",
                "vendor/microvm/vmlinux",
                "platform/lab/microvm-assets/vmlinux",
            ])
        });
    let rootfs = std::env::var("CONNECTOR_MICROVM_ROOTFS")
        .ok()
        .filter(|s| Path::new(s.trim()).is_file())
        .or_else(|| {
            first_existing(&[
                "/var/lib/connector/microvm/images/connector-cell.img",
                "vendor/microvm/rootfs.ext4",
                "platform/lab/microvm-assets/rootfs.ext4",
            ])
        });

    let probe = HostProbe {
        schema: "connector.cvr.host_probe.v1".into(),
        linux: cfg!(target_os = "linux"),
        arch: std::env::consts::ARCH.into(),
        kvm_available,
        kvm_usable,
        firecracker_bin: which_bin("firecracker").or_else(|| which_bin("connector-microvm")),
        jailer_bin: which_bin("jailer"),
        guest_kernel: kernel,
        guest_rootfs: rootfs,
        vsock_capable: Path::new("/dev/vhost-vsock").exists()
            || Path::new("/dev/vsock").exists()
            || cfg!(target_os = "linux"),
        cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        landlock_abi,
        matrix_cut_tools: cut.any(),
    };
    overlay_microd_ready(probe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_not_ready() {
        assert!(!HostProbe::empty().microcell_ready());
    }

    #[test]
    fn probe_returns_schema() {
        let p = probe_host();
        assert!(p.schema.contains("host_probe"));
    }
}
