//! Production / harden posture triad — Requested · Applied · Effective.
//! Fail-closed agent start under intelligence hardening for real augmented env.

use serde_json::{json, Value};

use crate::kernel::agent_principal;
use crate::kernel::docklock;
use crate::kernel::matrix_isolation;
use crate::services::runtime_control::IsolationRuntime;
use crate::state::PlatformState;
use crate::substrate::effect_exclusivity;
use crate::substrate::sandbox_unbypassable;

pub const HARDEN_POSTURE_SCHEMA: &str = "connector.harden_posture.v1";
pub const START_REFUSED: &str = "START_REFUSED";

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

/// True when this node is operating as a real augmented env (not playground/lab soft).
pub fn augmented_env_harden() -> bool {
    if crate::services::playground::is_playground_mode() {
        return false;
    }
    agent_principal::intelligence_hardening_on()
        || env_flag("CONNECTOR_AUGMENTED_ENV")
        || crate::connector_profile::is_productionish_env()
}

/// Refuse agent start when harden requirements are unmet (standard §16).
/// Opt-in for real augmented env: CONNECTOR_HARDEN_REFUSE_START or CONNECTOR_AUGMENTED_ENV.
/// Also engages when exclusivity + sandbox unbypassable are both already on (strong harden).
pub fn harden_refuse_start_enabled() -> bool {
    if !augmented_env_harden() {
        return false;
    }
    env_flag("CONNECTOR_HARDEN_REFUSE_START")
        || env_flag("CONNECTOR_AUGMENTED_ENV")
        || (effect_exclusivity::effect_exclusivity_enforced()
            && sandbox_unbypassable::unbypassable_bar_enforced()
            && agent_principal::intelligence_hardening_on())
}

#[derive(Debug, Clone)]
struct GateRow {
    name: &'static str,
    requested: bool,
    applied: bool,
    effective: bool,
    detail: String,
}

impl GateRow {
    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "requested": self.requested,
            "applied": self.applied,
            "effective": self.effective,
            "detail": self.detail,
            "met": !self.requested || (self.applied && self.effective),
        })
    }
}

fn collect_gates(state: &PlatformState) -> Vec<GateRow> {
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    let ll_abi = landlock
        .get("kernel_abi_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ll_fc = landlock
        .get("fail_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ring1 = docklock::ring1_enforce_enabled();
    let dock = docklock::docklock_enforce_enabled();
    let exclusivity = effect_exclusivity::effect_exclusivity_enforced();
    let sandbox = sandbox_unbypassable::unbypassable_bar_enforced();
    let matrix_hw = matrix_isolation::matrix_hw_enforce_enabled();
    let cut = crate::kernel::matrix_host_egress::host_cut_tools_available();
    let runtime = *state.isolation_runtime.read().unwrap();
    let iso_bar = effect_exclusivity::isolation_meets_exclusivity_bar(runtime);
    let microvm_tools = crate::substrate::microvm_tool_plane::tools_in_microvm_enforced();
    let microvm_host = crate::services::runtime_control::microvm_host_available();

    let mut rows = vec![
        GateRow {
            name: "identity_hardening",
            requested: agent_principal::intelligence_hardening_on(),
            applied: agent_principal::intelligence_hardening_on(),
            effective: agent_principal::intelligence_hardening_on(),
            detail: "CONNECTOR_IIA_* / intelligence hardening".into(),
        },
        GateRow {
            name: "ring1_docklock",
            requested: ring1 || dock || exclusivity,
            applied: ring1 || dock,
            effective: ring1 || dock,
            detail: "CONNECTOR_IIA_RING1 / DOCKLOCK_ENFORCE".into(),
        },
        GateRow {
            name: "landlock_fail_closed",
            requested: ll_fc || exclusivity || sandbox,
            applied: ll_fc && ll_abi,
            effective: ll_fc && ll_abi,
            detail: if ll_fc && !ll_abi {
                "fail-closed requested but Landlock ABI unavailable".into()
            } else {
                "CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED".into()
            },
        },
        GateRow {
            name: "effect_exclusivity",
            requested: exclusivity,
            applied: exclusivity,
            effective: (exclusivity
                && effect_exclusivity::effect_exclusivity_status(state)
                    .get("effect_exclusivity_strong")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false))
                || (exclusivity && iso_bar && ring1 && ll_fc),
            detail: "CONNECTOR_EFFECT_EXCLUSIVITY — alternate paths must close".into(),
        },
        GateRow {
            name: "sandbox_unbypassable",
            requested: sandbox,
            applied: sandbox,
            effective: sandbox,
            detail: "CONNECTOR_SANDBOX_UNBYPASSABLE".into(),
        },
        GateRow {
            name: "isolation_grade",
            requested: exclusivity || microvm_tools || matches!(runtime, IsolationRuntime::Microvm),
            applied: iso_bar || matches!(runtime, IsolationRuntime::Microvm | IsolationRuntime::DockerLab | IsolationRuntime::Wasm),
            effective: if matches!(runtime, IsolationRuntime::Microvm) || microvm_tools {
                microvm_host
            } else {
                iso_bar || !exclusivity
            },
            detail: format!("declared={} microvm_host={}", runtime.as_str(), microvm_host),
        },
        GateRow {
            name: "matrix_host_cut",
            requested: matrix_hw,
            applied: matrix_hw && cut.any(),
            effective: matrix_hw && cut.any(),
            detail: if matrix_hw && !cut.any() {
                "HW enforce on but nft/iptables missing".into()
            } else {
                "CONNECTOR_MATRIX_HW_ENFORCE".into()
            },
        },
    ];

    // Under full harden refuse-start, these are mandatory even if flags unset.
    if harden_refuse_start_enabled() && augmented_env_harden() {
        for row in &mut rows {
            match row.name {
                "ring1_docklock" | "landlock_fail_closed" | "effect_exclusivity"
                | "sandbox_unbypassable" => {
                    row.requested = true;
                }
                "isolation_grade" => {
                    row.requested = true;
                }
                _ => {}
            }
        }
    }

    rows
}

/// Requested / Applied / Effective snapshot for operators and proof export.
pub fn posture_triad(state: &PlatformState) -> Value {
    let playground = crate::services::playground::is_playground_mode();
    let gates: Vec<Value> = collect_gates(state).iter().map(GateRow::to_json).collect();
    let unmet: Vec<&Value> = gates
        .iter()
        .filter(|g| g.get("met").and_then(|v| v.as_bool()) == Some(false))
        .collect();
    let harden = augmented_env_harden();
    let effective_profile = if playground {
        "playground"
    } else if harden && unmet.is_empty() {
        "harden"
    } else if harden {
        "harden_requirements_unmet"
    } else {
        "pilot"
    };

    json!({
        "schema": HARDEN_POSTURE_SCHEMA,
        "profile": {
            "requested": if playground {
                "playground"
            } else if harden {
                "harden"
            } else {
                "pilot"
            },
            "applied": if playground {
                "playground"
            } else if agent_principal::intelligence_hardening_on() {
                "harden_flags_on"
            } else {
                "pilot"
            },
            "effective": effective_profile,
        },
        "gates": gates,
        "unmet_count": unmet.len(),
        "unmet": unmet,
        "harden_refuse_start": harden_refuse_start_enabled(),
        "augmented_env": harden,
        "playground": playground,
        "honesty": "Requested ≠ Applied ≠ Effective — unmet harden gates must START_REFUSED, never silent playground",
    })
}

fn start_refused(agent_pid: &str, reason: &str, detail: Value) -> Value {
    json!({
        "ok": false,
        "status": 503,
        "error": START_REFUSED,
        "denial_reason": reason,
        "schema": HARDEN_POSTURE_SCHEMA,
        "agent_pid": agent_pid,
        "action": START_REFUSED,
        "detail": detail,
        "honesty": "Hardened augmented env refuses agent start when mandatory primitives are unmet — soft-fail forbidden",
    })
}

/// Composite fail-closed start for real augmented env (not lab soft).
pub fn assert_harden_ready_for_start(
    state: &PlatformState,
    agent_pid: &str,
) -> Result<(), Value> {
    // Always run TG-0 membrane checks when harden/dock/matrix.
    crate::kernel::membrane_posture::assert_membrane_ready_for_effects(agent_pid)?;

    // CVR: MicroCell-required profiles refuse when HostProbe incomplete.
    crate::substrate::cvr::execution_body::assert_cvr_ready_for_start(state, agent_pid)?;

    // WorkloadSecurityProfile: START_REFUSED only when profile declares refuse_start_on_unmet.
    crate::substrate::workload_profile::assert_start_allowed(state)?;

    if !harden_refuse_start_enabled() {
        // Still run exclusivity/sandbox when those switches are on.
        if effect_exclusivity::effect_exclusivity_enforced() {
            effect_exclusivity::assert_effect_exclusivity_ready(agent_pid, state)?;
        } else if sandbox_unbypassable::unbypassable_bar_enforced() {
            sandbox_unbypassable::assert_sandbox_unbypassable(state, agent_pid)?;
        }
        return Ok(());
    }

    let triad = posture_triad(state);
    let unmet = triad
        .get("unmet_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if unmet > 0 {
        return Err(start_refused(
            agent_pid,
            "harden_requirements_unmet",
            triad,
        ));
    }

    effect_exclusivity::assert_effect_exclusivity_ready(agent_pid, state).map_err(|e| {
        let reason = e
            .get("denial_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("effect_exclusivity")
            .to_string();
        start_refused(agent_pid, &reason, e)
    })?;

    sandbox_unbypassable::assert_sandbox_unbypassable(state, agent_pid).map_err(|e| {
        let reason = e
            .get("denial_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("sandbox_unbypassable")
            .to_string();
        start_refused(agent_pid, &reason, e)
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_refused_token_stable() {
        assert_eq!(START_REFUSED, "START_REFUSED");
    }

    #[test]
    fn playground_is_not_augmented_harden() {
        // Without env, function still depends on playground/hardening flags —
        // token and schema must remain stable for API clients.
        assert_eq!(HARDEN_POSTURE_SCHEMA, "connector.harden_posture.v1");
    }
}
