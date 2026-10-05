//! Phase 5.1–5.6 — pluggable **plugin** isolation (`Subprocess`, `DockerLab`, `Microvm`, **`Wasm`** / Wasmtime + WASI preview1).
//!
//! The platform kernel selects a backend from persisted [`IsolationRuntime`](crate::IsolationRuntime)
//! (mirrored in `connector-platform` `runtime_control::IsolationRuntime` — keep discriminant strings in sync).
//!
//! **Docker lab egress (Phase 5.7.2):** set **`CONNECTOR_DOCKER_LAB_EGRESS`** to `deny_all` for
//! **`docker run --network none`**, or `allowlist_strict` so an empty [`SpawnRequest::egress_allowlist`]
//! maps to **no network**. Non-empty allowlist uses the default bridge unless
//! **`CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables`** (Linux, root / `CAP_NET_ADMIN`): **`iptables`** /
//! **`ip6tables`** rules in **`DOCKER-USER`** for resolved TCP destinations (IPv4 + IPv6) plus optional DNS to
//! **`/etc/resolv.conf`** (`CONNECTOR_DOCKER_LAB_ALLOW_RESOLVER_DNS`, default on). The lab bridge is created with
//! **`fd00:c0ff:ee99::/64`** when IPv6 is needed; existing **`connector_plugin_lab`** without IPv6 must be
//! **`docker network rm`**’d once. Manifest caps may use **`network.outbound:[2001:db8::1]:443`**. Foreground runs
//! drop rules when **`docker run`** exits; detached runs use a background **`docker wait`**.
//! Set **`workspace_host_mount`** to the rollout `files` dir; use **`docker_run_detached: false`** for blocking
//! **`connectorctl plugin run --dev`** (`CONNECTOR_PLUGIN_RUN_BACKEND=docker_lab`).
//!
//! **Subprocess hardening (Phase 5.9 partial, Linux):** **`CONNECTOR_PLUGIN_SUBPROCESS_NO_NEW_PRIVS=1`** →
//! **`PR_SET_NO_NEW_PRIVS`**; **`CONNECTOR_PLUGIN_SUBPROCESS_NOT_DUMPABLE=1`** → **`PR_SET_DUMPABLE`** (in
//! **`pre_exec`** after **`setpgid`**). Seccomp supports **`strict`** and **`deny_dangerous`** (x86_64/aarch64):
//! a BPF filter that denies selected high-risk syscalls (e.g. `bpf`, `perf_event_open`, `userfaultfd`,
//! keyring syscalls, `clone3`, `unshare`) with `EPERM`; and **`network_deny`** that denies socket-family
//! network syscalls (`socket`, `connect`, `accept`, `bind`, `listen`, `sendto`, …). **`network_ingress_deny`**
//! blocks inbound server-style syscalls (`bind`, `listen`, `accept`/`accept4`) while leaving outbound client
//! networking (`socket` + `connect`) available.
//!
//! **Cgroup v2 (Phase 5.8 partial, Linux subprocess):** delegated **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT`**
//! + optional **`memory.max`** / **`memory.high`** (**`CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_HIGH_BYTES`**) /
//! **`memory.swap.max`** (**`CONNECTOR_PLUGIN_SUBPROCESS_MEMORY_SWAP_MAX_BYTES`**, **`0`** = no swap) / **`cpu.max`**;
//! optional **`cpu.weight`** (**`CONNECTOR_PLUGIN_SUBPROCESS_CPU_WEIGHT`**, **`1..=10_000`**);
//! optional **`pids.max`** via **`CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PIDS_MAX`**
//! when the parent cgroup exposes the **`pids`** controller (otherwise a skip note is recorded in **`cgroup.limits`**);
//! optional **`io.max`** either explicit via
//! **`CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX`** or auto-derived from workspace/cwd device using
//! **`CONNECTOR_PLUGIN_SUBPROCESS_IO_MAX_AUTO=1`** plus **`*_RBPS`** / **`*_WBPS`** / **`*_RIOPS`** / **`*_WIOPS`**;
//! **`CONNECTOR_PLUGIN_TIER_CGROUP_SCAN=1`** samples **`runner-*`**
//! children for **`GET …/plugin-tier-scheduler`** (with **`usage_usec`** from **`cpu.stat`**).
//! Optional **cgroup-accelerated idle demotion** (**Phase 5.4.3**): when
//! **`CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE=1`** and **`CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS`** > 0,
//! the platform tier scheduler may demote Warm/Hot → Cold before the full idle window if aggregate
//! **`runner-<plugin>-*`** CPU usage growth stays below **`CONNECTOR_PLUGIN_TIER_CGROUP_DEMOTE_MAX_USEC_PER_WALL_SEC`**
//! (see server `plugin_tier_scheduler` env parsing).
//!
//! **MicroVM egress (Phase 5.7.2 partial, Linux Firecracker):** **`CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables`**
//! with **`CONNECTOR_MICROVM_EGRESS_MODE`** ≠ **`deny_all`** and a non-empty allowlist creates a host TAP,
//! adds **`ip=`** to the guest kernel cmdline, **`PUT`s** `/network-interfaces/eth0`, and installs **`iptables`**
//! / **`ip6tables` `FORWARD`** rules (TCP to resolved IPv4 / IPv6 + optional DNS). **`MASQUERADE`** /
//! NAT6 on the WAN requires host forwarding sysctl + routable IPv6 when caps resolve to **`AAAA`**.
//!
//! **Wasm (Phase 5.6):** **`IsolationRuntime::Wasm`** loads **`SpawnRequest::program`** as a **`.wasm`** module (or `\0asm` prefix), links **WASI preview1** via **`wasmtime-wasi` `p1`**, disables WASI TCP/UDP on the context builder, optionally preopens **`workspace_host_mount`** / **`cwd`** read-only at **`.`**, and runs **`_start`** or **`main`**. Optional **`CONNECTOR_WASM_FUEL_UNITS`** enables **fuel** metering.
//!
//! **Windows / WSL2:** the same **`CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables`** path runs **`connector-microvm-wsl-egress-apply.py`**
//! **inside** the configured distro (needs **`iptables`**, **`ip`**, and **`ip6tables`** when **`AAAA`** caps resolve); receipt includes **`microvm_egress_cleanup_watcher`** when a PID-exit helper is started.
//!
//! **Tier idle + vsock (Phase 5.4.3 partial):** when **`CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS`** > 0,
//! microVM boot args include **`connector.plugin_idle_suspend_after_ms=…`** and **`connector.vsock_agent_port=…`**
//! for **`connector-vm-agent`**. On Linux Firecracker, the host listens on **`{uds_path}_{port}`** (guest-initiated vsock);
//! optional **`CONNECTOR_MICROVM_VSOCK_TIER_SIGNAL=1`** replies with **`tier_signal`** JSON (see **`CONNECTOR_MICROVM_TIER_STATE_FILE`** —
//! when **`connector-platform`** sets that path, it periodically writes **`vendor/slug` → `cold`|`warm`** from the tier scheduler).
//! **`SpawnReceipt.detail.tier_idle_suspend_policy_ms_for_guest`** mirrors idle policy ms on Linux, macOS sidecar, and WSL2.

mod docker;
mod docker_egress;
mod error;
pub mod isolation_membrane;
pub mod linux_cgroup;
pub mod linux_hardening;
mod microvm_egress_linux;
mod microvm_egress_wsl;
mod microvm_vsock_agent;
mod microvm_backend;
mod subprocess_disk;
mod subprocess;
mod wasm_backend;
mod types;

pub use docker::DockerLabBackend;
pub use error::PluginRuntimeError;
pub use isolation_membrane::{
    force_guest_deny_all, is_forbidden_guest_env_key, membrane_enforced, membrane_status,
    sanitize_guest_env,
};
pub use microvm_backend::MicrovmPluginBackend;
pub use subprocess::SubprocessPluginBackend;
pub use wasm_backend::WasmPluginBackend;
pub use types::{IsolationRuntime, SpawnReceipt, SpawnRequest};

use async_trait::async_trait;

#[async_trait]
pub trait PluginIsolationBackend: Send + Sync {
    fn kind(&self) -> IsolationRuntime;

    /// Best-effort spawn — returns structured receipt (PID / container id / stub marker).
    async fn spawn(&self, req: SpawnRequest) -> Result<SpawnReceipt, PluginRuntimeError>;
}

/// True for production / prod / staging / defense-strict. Shared by spawn fail-closed gates.
pub fn productionish_env() -> bool {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let defense = std::env::var("CONNECTOR_DEFENSE_STRICT")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    matches!(
        env.as_str(),
        "production" | "prod" | "staging" | "pilots" | "pilot"
    ) || defense
}

/// MicroVM spawn must observe a guest vsock heartbeat before returning Ok.
pub fn microvm_require_heartbeat() -> bool {
    productionish_env()
        || matches!(
            std::env::var("CONNECTOR_MICROVM_REQUIRE_HEARTBEAT")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "true" | "yes" | "on"
        )
}

pub fn backend_for(
    runtime: IsolationRuntime,
    docker_image: Option<String>,
    microvm_socket: Option<std::path::PathBuf>,
) -> Box<dyn PluginIsolationBackend> {
    match runtime {
        IsolationRuntime::Internal | IsolationRuntime::Subprocess => {
            Box::new(SubprocessPluginBackend::default())
        }
        IsolationRuntime::DockerLab => Box::new(DockerLabBackend::new(docker_image)),
        IsolationRuntime::Microvm => Box::new(MicrovmPluginBackend::new(microvm_socket)),
        IsolationRuntime::Wasm => Box::new(WasmPluginBackend::new()),
    }
}
