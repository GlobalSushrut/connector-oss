//! Linux sandbox unbypassable bar — microVM/vsock + FS Landlock + nft/eBPF (Seven Pillars §2/§6)
//! + LLM broker lane (same fail-closed posture as Linux kernel paths).
//!
//! Under effect exclusivity / kernel enforce / productionish profiles, LLM/agent effects must not
//! rely on userspace-only checks. This module is the single gate that asserts:
//! - measured microVM assets when tools-in-microvm / isolation=microvm
//! - FS allowlists present when Landlock fail-closed
//! - host Active apply + (nft/iptables or eBPF pins) under CONNECTOR_KERNEL_ENFORCE
//! - LLM broker lane open (per-agent sandbox) when broker unbypassable
//! - no revoked agent authority

use serde_json::{json, Value};

use crate::state::PlatformState;

pub const SCHEMA: &str = "connector.sandbox_unbypassable.v1";

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

pub fn unbypassable_bar_enforced() -> bool {
    // Hosted playground (Fly shared VM): no Landlock/Firecracker bar unless explicitly opted in.
    // CONNECTOR_ENV=pilots alone must not block Talk with fs_allowlist_required.
    if crate::services::playground::is_playground_mode()
        && !env_flag("CONNECTOR_SANDBOX_UNBYPASSABLE")
    {
        return false;
    }
    env_flag("CONNECTOR_SANDBOX_UNBYPASSABLE")
        || env_flag("CONNECTOR_LLM_BROKER_UNBYPASSABLE")
        || crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
        || crate::services::kernel_host::kernel_enforce_enabled()
        || (crate::connector_profile::is_productionish_env()
            && crate::substrate::probabilistic_llm::distrust_enforced())
}

fn fs_allowlists_present() -> bool {
    let read = std::env::var("CONNECTOR_DOCKLOCK_FS_READ").unwrap_or_default();
    let write = std::env::var("CONNECTOR_DOCKLOCK_FS_WRITE").unwrap_or_default();
    !read.trim().is_empty() || !write.trim().is_empty()
}

fn refuse(agent_pid: &str, code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "status": 499,
        "message": "sorry, you are not allowed — need human approval",
        "error": "sandbox_unbypassable_refuse",
        "denial_reason": code,
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "human_approval": true,
        "detail": message,
        "honesty": "Userspace L7 alone is not enough — Linux FS/net/VM + LLM broker lane must be applied like kernel paths",
        "remediation": {
            "fs": "CONNECTOR_DOCKLOCK_FS_READ/WRITE + CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED=1",
            "net": "connector-kerneld Active + nft/iptables matrix cut or ebpf-load",
            "vm": "CONNECTOR_ISOLATION_RUNTIME=microvm + measured KERNEL/ROOTFS + vsock tickets",
            "llm_broker": "CONNECTOR_LLM_BROKER_UNBYPASSABLE=1 — per-agent sandbox slot + seal plane",
            "cgroup": "CONNECTOR_CGROUP_ROOT writable cgroup v2 under /sys/fs/cgroup/connector/<agent>",
            "master": "CONNECTOR_SANDBOX_UNBYPASSABLE=1",
        }
    })
}

/// Fail-closed gate for effects / tool dispatch / LLM world actions — Linux + broker.
pub fn assert_sandbox_unbypassable(state: &PlatformState, agent_pid: &str) -> Result<(), Value> {
    if crate::substrate::atomic_revoke::is_agent_authority_revoked(state, agent_pid) {
        return Err(refuse(
            agent_pid,
            "authority_revoked",
            "Agent authority revoked (quantum/flow/vsock/egress) — all effects denied",
        ));
    }

    if !unbypassable_bar_enforced() {
        return Ok(());
    }

    // FS: Landlock fail-closed requires non-empty path allowlists (otherwise no restrict).
    if connector_plugin_runtime::linux_hardening::landlock_fail_closed_enabled()
        && !fs_allowlists_present()
    {
        return Err(refuse(
            agent_pid,
            "fs_allowlist_required",
            "Landlock fail-closed is on but CONNECTOR_DOCKLOCK_FS_READ/WRITE are empty — FS would be unrestricted",
        ));
    }

    // Net: under kernel enforce, require real host Active AND nft/iptables or eBPF pins.
    if crate::services::kernel_host::kernel_enforce_enabled() {
        let apply = state.kernel_host.lock().ok().and_then(|kh| {
            kh.agent_attachment(agent_pid)
                .map(|a| a.host_apply_state.is_host_ready())
        });
        let ready = apply.unwrap_or(false);
        if !ready {
            return Err(refuse(
                agent_pid,
                "kernel_host_not_active",
                "CONNECTOR_KERNEL_ENFORCE requires HostApplyState::Active from connector-kerneld",
            ));
        }
        let tools = crate::kernel::matrix_host_egress::host_cut_tools_available();
        let ebpf = crate::kernel::matrix_host_egress::probe_ebpf_pins(Some(agent_pid));
        if !tools.any() && !ebpf {
            return Err(refuse(
                agent_pid,
                "linux_net_cut_missing",
                "Need nft/iptables matrix cut tools or eBPF pins (connector-kerneld ebpf-load)",
            ));
        }
    }

    // VM: tools/world in microVM must have measured assets.
    if crate::substrate::microvm_tool_plane::tools_in_microvm_enforced()
        || crate::substrate::microvm_tool_plane::world_channel_via_microvm()
        || matches!(
            std::env::var("CONNECTOR_ISOLATION_RUNTIME")
                .ok()
                .as_deref()
                .map(|s| s.trim()),
            Some("microvm")
        )
    {
        if let Err(e) = crate::kernel::isolation_manifest::assert_microvm_assets_measured() {
            return Err(refuse(
                agent_pid,
                "microvm_unmeasured",
                &format!("MicroVM assets not measured: {e}"),
            ));
        }
        if !crate::kernel::isolation_manifest::vsock_ticket_required()
            && crate::connector_profile::is_productionish_env()
        {
            if !env_flag("CONNECTOR_VSOCK_TICKET_REQUIRE")
                && !env_flag("CONNECTOR_ALLOW_UNAUTH_VSOCK")
            {
                return Err(refuse(
                    agent_pid,
                    "vsock_ticket_required",
                    "Set CONNECTOR_VSOCK_TICKET_REQUIRE=1 (or CONNECTOR_ALLOW_UNAUTH_VSOCK=1 break-glass)",
                ));
            }
        }
    }

    // Break-glass host paths closed.
    if env_flag("CONNECTOR_ALLOW_IN_PROCESS_EFFECTS")
        && !env_flag("CONNECTOR_ALLOW_IN_PROCESS_EFFECTS_ACK")
    {
        return Err(refuse(
            agent_pid,
            "in_process_effects_break_glass",
            "CONNECTOR_ALLOW_IN_PROCESS_EFFECTS requires CONNECTOR_ALLOW_IN_PROCESS_EFFECTS_ACK=1",
        ));
    }

    // LLM broker lane — same fail-closed class as Landlock/eBPF (cannot skip 409/499).
    if crate::substrate::llm_broker_gate::broker_unbypassable() {
        if crate::substrate::llm_sealed_context::agent_brain_quarantined_platform(state, agent_pid)
        {
            return Err(refuse(
                agent_pid,
                "llm_broker_brain_quarantined",
                "LLM broker brain quarantined — Linux path will not expand seals; need human approval",
            ));
        }
        // Require cgroup/nsfs bind record so slot is kernel-attributable.
        let principal = format!("agent:{agent_pid}");
        if let Err(e) =
            crate::kernel::agent_cgroup::bind_agent_process_tree(state, agent_pid, &principal)
        {
            if crate::services::kernel_host::kernel_enforce_enabled()
                || env_flag("CONNECTOR_CGROUP_REQUIRE")
            {
                return Err(refuse(
                    agent_pid,
                    "cgroup_bind_required",
                    &format!("Per-agent cgroup/nsfs bind failed: {e}"),
                ));
            }
        }
    }

    Ok(())
}

pub fn posture_json(state: &PlatformState, agent_pid: Option<&str>) -> Value {
    let pid = agent_pid.unwrap_or("-");
    let gate = assert_sandbox_unbypassable(state, pid);
    let tools = crate::kernel::matrix_host_egress::host_cut_tools_available();
    json!({
        "schema": SCHEMA,
        "enforced": unbypassable_bar_enforced(),
        "gate_ok": gate.is_ok(),
        "gate_error": gate.err(),
        "fs_allowlists_present": fs_allowlists_present(),
        "landlock_fail_closed": connector_plugin_runtime::linux_hardening::landlock_fail_closed_enabled(),
        "kernel_enforce": crate::services::kernel_host::kernel_enforce_enabled(),
        "nft": tools.nft,
        "iptables": tools.iptables,
        "ebpf_pins": crate::kernel::matrix_host_egress::probe_ebpf_pins(agent_pid),
        "vsock_ticket_required": crate::kernel::isolation_manifest::vsock_ticket_required(),
        "tools_in_microvm": crate::substrate::microvm_tool_plane::tools_in_microvm_enforced(),
        "world_channel_via_microvm": crate::substrate::microvm_tool_plane::world_channel_via_microvm(),
        "llm_broker_unbypassable": crate::substrate::llm_broker_gate::broker_unbypassable(),
        "llm_agent_sandbox": crate::substrate::llm_agent_sandbox::status(),
        "honesty": "Unbypassable = Linux Landlock + nft/eBPF + microVM/vsock + LLM broker sandbox lane — not app L7 alone",
    })
}
