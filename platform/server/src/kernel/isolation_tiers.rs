//! TG-6 — Isolation tier claim ladder (honest applied_truth).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::kernel::docklock;
use crate::kernel::matrix_host_egress;
use crate::kernel::matrix_isolation;
use crate::kernel::membrane_posture;
use crate::state::PlatformState;
use crate::substrate::cage_security;

pub const ISOLATION_SCHEMA: &str = "connector.isolation.tier.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationTier {
    ProcessLandlock,
    DockerLab,
    MicroVm,
    HostSimulated,
}

impl IsolationTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessLandlock => "process_landlock",
            Self::DockerLab => "docker_lab",
            Self::MicroVm => "micro_vm",
            Self::HostSimulated => "host_simulated",
        }
    }
}

/// Docker-grade Linux materials without Docker daemon or Firecracker.
/// Default density path: max agents on one node.
pub fn light_isolation_profile() -> Value {
    json!({
        "id": "light_ns",
        "title": "Docker-grade materials, shared kernel",
        "default_for": "max_agents",
        "grade": "docker_equivalent",
        "materials": [
            "landlock_fs",
            "seccomp",
            "cgroup_v2",
            "nsfs",
            "docklock_cage",
            "matrix_mark_cut",
            "no_new_privs"
        ],
        "linux_namespaces_equivalent": ["mnt (via Landlock+NSFS)", "pid (private at spawn)", "uts", "ipc", "net (deny-default + mark)"],
        "not_default": ["docker_daemon", "firecracker_microvm", "guest_kernel"],
        "compute": "No guest kernel, no docker dind, no per-agent VM. Shared host kernel + tiny cgroup. Density path for hundreds of agents.",
        "escalate_to_microvm": "Only high-risk untrusted .cpkg / untrusted code class — explicit IsolationRuntime::Microvm.",
        "escalate_to_docker_lab": "Dev convenience only — not the tenant boundary, not the density path.",
        "honesty": "Same isolation primitives Docker uses (FS, syscalls, cgroups, net deny). Not a Docker container. Not a VM. light_ns is the default so a complex secure system still runs max agents."
    })
}

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

/// Seven Pillars L1/L2/L3 map — each guarantee tied to a Linux primitive.
pub fn l1_l2_l3_linux_map() -> Value {
    json!({
        "schema": "connector.isolation.l1_l2_l3.v1",
        "L1_light": {
            "tier": "light",
            "primitives": ["cgroup_v2", "namespaces", "seccomp-BPF", "landlock"],
            "network": "host_governed_or_deny",
            "maps_to": IsolationTier::ProcessLandlock.as_str(),
        },
        "L2_medium": {
            "tier": "medium",
            "primitives": ["cgroup_v2", "namespaces", "seccomp-BPF", "landlock", "docker_lab"],
            "network": "network_none",
            "maps_to": IsolationTier::DockerLab.as_str(),
        },
        "L3_high": {
            "tier": "high",
            "primitives": ["microvm", "vsock_only", "deny_all_guest_net", "measured_rootfs"],
            "network": "vsock_broker_only",
            "maps_to": IsolationTier::MicroVm.as_str(),
        },
        "ebpf": {
            "status": "IMPLEMENTED_GATED",
            "honesty": "connector-kerneld ebpf-load pins cgroup/skb mark-deny; ebpf_loaded only when /sys/fs/bpf/connector pins exist",
            "commands": ["ebpf-load", "ebpf-status", "ebpf-deny-mark", "ebpf-unload"],
        },
    })
}

/// Resolve declared tier from runtime (MicroVM only when operator selected it).
pub fn resolve_tier(state: &PlatformState) -> IsolationTier {
    use crate::services::runtime_control::IsolationRuntime;
    let declared = *state.isolation_runtime.read().unwrap();
    match declared {
        IsolationRuntime::Microvm => IsolationTier::MicroVm,
        IsolationRuntime::DockerLab => IsolationTier::DockerLab,
        IsolationRuntime::Wasm
        | IsolationRuntime::Subprocess
        | IsolationRuntime::Internal => {
            if docklock::ring1_enforce_enabled()
                || docklock::docklock_enforce_enabled()
                || env_flag("CONNECTOR_DOCKLOCK_LANDLOCK")
            {
                IsolationTier::ProcessLandlock
            } else {
                IsolationTier::HostSimulated
            }
        }
    }
}

/// Per-agent isolation posture for operators.
pub fn isolation_for_agent(state: &PlatformState, agent_pid: &str) -> Value {
    let tier = resolve_tier(state);
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    let applied = membrane_posture::applied_truth_snapshot(state);
    let matrix = matrix_isolation::status_for_agent(state, agent_pid);
    let cut_tools = matrix_host_egress::host_cut_tools_available();
    let cage = cage_security::cage_security_status(state);
    let soft_fail = landlock
        .get("mode")
        .and_then(|v| v.as_str())
        == Some("soft_fail");
    let microvm_selected = matches!(tier, IsolationTier::MicroVm);
    let ebpf_probe = matrix_host_egress::probe_ebpf_pins(Some(agent_pid));
    let ebpf_active = env_flag("CONNECTOR_EBPF_HOST_ACTIVE") || ebpf_probe;
    let ebpf_honesty = if ebpf_probe {
        "bpffs pins present — real eBPF load/attach path"
    } else if env_flag("CONNECTOR_EBPF_HOST_ACTIVE") {
        "flag_set_requires_real_attach_backend — pins not found"
    } else {
        "off"
    };

    json!({
        "ok": true,
        "schema": ISOLATION_SCHEMA,
        "agent_pid": agent_pid,
        "tier": tier.as_str(),
        "tier_enum": tier,
        "landlock": landlock,
        "matrix": matrix,
        "soft_fail": soft_fail,
        "applied_truth": applied,
        "cage_security": cage,
        "matrix_cut_tools": {
            "nft": cut_tools.nft,
            "iptables": cut_tools.iptables,
        },
        "microvm": {
            "selected": microvm_selected,
            "usable_for_high_risk": microvm_selected,
            "default_claim": false,
            "honesty": if microvm_selected {
                "MicroVM selected via POST /runtime/isolation — Firecracker backend may still be stub; not silent default"
            } else {
                "Not selected — high-risk uses ProcessLandlock/DockerLab; never silent MicroVM claim"
            },
        },
        "ebpf_host_active": {
            "flag": env_flag("CONNECTOR_EBPF_HOST_ACTIVE"),
            "ebpf_probe_ok": ebpf_probe,
            "applied_truth": if ebpf_probe {
                "pins_present"
            } else if ebpf_active {
                "unknown_until_attach_probe"
            } else {
                "not_applied"
            },
            "honesty": ebpf_honesty,
        },
        "density": light_isolation_profile(),
        "l1_l2_l3": l1_l2_l3_linux_map(),
        "nsfs": crate::kernel::nsfs::snapshot(agent_pid),
        "harden_refuse": membrane_posture::assert_membrane_ready_for_effects(agent_pid).err(),
        "honesty": "Default density is light_ns (docker-grade Linux materials, shared kernel). Docker daemon is lab. MicroVM is high-risk only. Isolation + NS FS + ACS are top-level — not plugin settings.",
    })
}
