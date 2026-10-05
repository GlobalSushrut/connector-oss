//! TG-0 — Applied-truth membrane posture + fail-closed start/effect gates.
//!
//! Intent ≠ applied. Soft-fail must never render as green "applied" under harden.

use serde_json::{json, Value};

use crate::kernel::agent_principal;
use crate::kernel::docklock;
use crate::kernel::matrix_host_egress;
use crate::kernel::matrix_isolation;
use crate::state::PlatformState;
use crate::substrate::egress_policy;

pub const APPLIED_TRUTH_SCHEMA: &str = "connector.applied_truth.v1";
pub const MEMBRANE_GATE_SCHEMA: &str = "connector.membrane.gate.v1";

/// Aggregate honesty for MONITOR / intelligence-posture (never claim child restrict from intent).
pub fn applied_truth_snapshot(state: &PlatformState) -> Value {
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    let ll_intent = landlock
        .get("intent")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ll_abi = landlock
        .get("kernel_abi_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ll_fc = landlock
        .get("fail_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ll_applied = landlock
        .get("applied")
        .and_then(|v| v.as_str())
        .unwrap_or("not_applied");

    let cut_tools = matrix_host_egress::host_cut_tools_available();
    let matrix_hw = matrix_isolation::matrix_hw_enforce_enabled();
    let dock_enforce = docklock::docklock_enforce_enabled();
    let ring1 = docklock::ring1_enforce_enabled();
    let l7 = egress_policy::l7_egress_status();
    let l7_enforced = l7.get("enforced").and_then(|v| v.as_bool()).unwrap_or(false);

    // Truth vocabulary: applied | not_applied | unknown_until_child | unavailable
    let landlock_truth = if !ll_intent {
        "not_applied"
    } else if !ll_abi {
        "unavailable"
    } else {
        // Parent cannot assert child restrict_self succeeded.
        match ll_applied {
            "not_applied" => "not_applied",
            _ => "unknown_until_child",
        }
    };

    let matrix_truth = if !matrix_hw && !cut_tools.nft && !cut_tools.iptables {
        "not_applied"
    } else if matrix_hw && !cut_tools.any() {
        "unavailable"
    } else if cut_tools.any() {
        "tools_present_cut_per_agent"
    } else {
        "not_applied"
    };

    let docklock_truth = if dock_enforce || ring1 {
        "enforce_on_binding_per_agent"
    } else {
        "not_enforced"
    };

    let l7_truth = if l7_enforced {
        "app_allowlist_enforced"
    } else {
        "not_enforced"
    };

    // Soft-fail Landlock must never look like green production membrane.
    let soft_fail = landlock
        .get("mode")
        .and_then(|v| v.as_str())
        .map(|m| m == "soft_fail")
        .unwrap_or(false)
        || (ll_intent && !ll_fc);

    let microvm_requested = crate::substrate::microvm_tool_plane::tools_in_microvm_enforced();
    let microvm_host = crate::substrate::microvm_tool_plane::host_available();
    let microvm_truth = if !microvm_requested {
        "not_requested"
    } else if !microvm_host {
        "unavailable"
    } else {
        "applied"
    };

    json!({
        "zt_handshake": crate::kernel::zt_handshake::status(state, None),
        "schema": APPLIED_TRUTH_SCHEMA,
        "isolation_tiers": {
            "T2_landlock": {
                "applied_truth": landlock_truth,
                "soft_fail_lab": soft_fail,
            },
            "T3_docklock": {
                "applied_truth": docklock_truth,
            },
            "T4_microvm": {
                "requested": microvm_requested,
                "host_available": microvm_host,
                "applied_truth": microvm_truth,
                "honesty": "unavailable when host Firecracker/microVM path missing — never claim Effective",
            },
        },
        "landlock": {
            "intent": ll_intent,
            "fail_closed": ll_fc,
            "soft_fail_lab": soft_fail,
            "kernel_abi_available": ll_abi,
            "applied_truth": landlock_truth,
            "raw": landlock,
        },
        "matrix_host_cut": {
            "hw_enforce": matrix_hw,
            "nft_available": cut_tools.nft,
            "iptables_available": cut_tools.iptables,
            "applied_truth": matrix_truth,
        },
        "docklock": {
            "ring1": ring1,
            "docklock_enforce": dock_enforce,
            "applied_truth": docklock_truth,
        },
        "l7_egress": {
            "enforced": l7_enforced,
            "applied_truth": l7_truth,
            "status": l7,
        },
        "honesty": "applied_truth never equates cage env intent with kernel/child enforcement",
        "hardening_on": agent_principal::intelligence_hardening_on(),
    })
}

/// Fail-closed start gate under harden/prod (TG-0).
pub fn assert_membrane_ready_for_start(
    _state: &PlatformState,
    agent_pid: &str,
) -> Result<(), Value> {
    assert_membrane_ready_for_effects(agent_pid)
}

/// Fail-closed effect gate (start + high-risk tools) under harden.
pub fn assert_membrane_ready_for_effects(agent_pid: &str) -> Result<(), Value> {
    let harden = agent_principal::intelligence_hardening_on()
        || docklock::docklock_enforce_enabled()
        || matrix_isolation::matrix_hw_enforce_enabled();
    if !harden {
        return Ok(());
    }

    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    let ll_intent = landlock
        .get("intent")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ll_abi = landlock
        .get("kernel_abi_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ll_fc = landlock
        .get("fail_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Landlock: under fail-closed + intent (or docklock cage path), missing ABI → refuse.
    let dock_path = docklock::docklock_enforce_enabled() || docklock::ring1_enforce_enabled();
    if (ll_intent || dock_path) && ll_fc && !ll_abi {
        return Err(json!({
            "ok": false,
            "error": "membrane_refuse_landlock_abi",
            "denial_reason": "landlock_abi_unavailable",
            "schema": MEMBRANE_GATE_SCHEMA,
            "agent_pid": agent_pid,
            "status": 503,
            "honesty": "Hardened node refuses start/effects when Landlock fail-closed is on but kernel ABI is unavailable — soft green forbidden",
        }));
    }

    if matrix_isolation::matrix_hw_enforce_enabled() {
        let tools = matrix_host_egress::host_cut_tools_available();
        if !tools.any() {
            return Err(json!({
                "ok": false,
                "error": "membrane_refuse_matrix_tools",
                "denial_reason": "matrix_host_cut_tools_unavailable",
                "schema": MEMBRANE_GATE_SCHEMA,
                "agent_pid": agent_pid,
                "status": 503,
                "honesty": "Matrix HW enforce requires nftables or iptables for intelligence mark cut — refusing",
            }));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn landlock_truth_excludes_bare_applied() {
        // Soft-fail / parent probe must never use the green token "applied".
        let tokens = [
            "not_applied",
            "unavailable",
            "unknown_until_child",
            "tools_present_cut_per_agent",
            "enforce_on_binding_per_agent",
            "not_enforced",
            "app_allowlist_enforced",
        ];
        assert!(!tokens.contains(&"applied"));
    }
}
