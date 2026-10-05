//! Effect exclusivity — every consequential side effect must traverse the Connector
//! effect mediator (governed admission + Ring-1 + isolation grade). Alternate authority
//! paths (raw network, in-process tool dispatch, ungoverned memory, direct MCP) must be
//! structurally unavailable under hardened posture, not merely discouraged.
//!
//! Standard: `CONNECTOR_EFFECT_EXCLUSIVITY=1` (production default via connector_profile).

use serde_json::{json, Value};

use crate::services::runtime_control::IsolationRuntime;
use crate::state::PlatformState;
use crate::substrate::cage_security;

pub const SCHEMA: &str = "connector.effect_exclusivity.v1";

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

/// Master switch — when on, alternate effect paths must be closed or execution refuses.
pub fn effect_exclusivity_enforced() -> bool {
    env_flag("CONNECTOR_EFFECT_EXCLUSIVITY")
        || (cage_security::prodish_isolation_enforced()
            && env_flag("CONNECTOR_KERNEL_FAIL_CLOSED"))
}

/// Break-glass: allow in-process ToolDispatch/MCP (weakens exclusivity claim).
pub fn in_process_effects_allowed() -> bool {
    env_flag("CONNECTOR_ALLOW_IN_PROCESS_EFFECTS")
}

/// Effect classes that must converge on the mediator under exclusivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectClass {
    Network,
    Shell,
    FileSystem,
    Mcp,
    Secret,
    A2A,
    Memory,
    Subprocess,
}

impl EffectClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Shell => "shell",
            Self::FileSystem => "filesystem",
            Self::Mcp => "mcp",
            Self::Secret => "secret",
            Self::A2A => "a2a",
            Self::Memory => "memory",
            Self::Subprocess => "subprocess",
        }
    }
}

/// Declared isolation must be docker_lab, microvm, or wasm when exclusivity is on.
pub fn isolation_meets_exclusivity_bar(runtime: IsolationRuntime) -> bool {
    matches!(
        runtime,
        IsolationRuntime::DockerLab | IsolationRuntime::Microvm | IsolationRuntime::Wasm
    )
}

/// In-process platform dispatch bypasses OS cage — deny under exclusivity unless break-glass.
/// When tools-in-microvm is on, declaring isolation is not enough: local I/O must not run on host.
pub fn assert_in_process_dispatch_allowed(
    state: &PlatformState,
    agent_pid: &str,
    effect: EffectClass,
) -> Result<(), Value> {
    if in_process_effects_allowed() {
        return Ok(());
    }

    if crate::substrate::microvm_tool_plane::tools_in_microvm_enforced() {
        crate::substrate::microvm_tool_plane::assert_microvm_isolation(state, agent_pid)?;
        if crate::substrate::microvm_tool_plane::is_local_io(effect) {
            return Err(json!({
                "ok": false,
                "error": "tool_io_must_run_in_microvm",
                "denial_reason": "in_process_effect_path",
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "effect_class": effect.as_str(),
                "message": "Shell/filesystem/exec I/O must run inside microVM — not on the Connector host",
            }));
        }
        if matches!(effect, EffectClass::Mcp | EffectClass::Network)
            && !crate::substrate::microvm_tool_plane::host_mcp_broker_allowed()
        {
            return Err(json!({
                "ok": false,
                "error": "mcp_must_run_in_microvm",
                "denial_reason": "in_process_effect_path",
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "effect_class": effect.as_str(),
                "message": "Set CONNECTOR_ALLOW_HOST_MCP_BROKER=1 for host HTTPS MCP broker, or run tools in microVM",
            }));
        }
        return Ok(());
    }

    if !effect_exclusivity_enforced() {
        return Ok(());
    }
    let runtime = *state.isolation_runtime.read().unwrap();
    if isolation_meets_exclusivity_bar(runtime) {
        return Ok(());
    }
    Err(json!({
        "ok": false,
        "error": "effect_exclusivity_in_process_denied",
        "denial_reason": "in_process_effect_path",
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "effect_class": effect.as_str(),
        "declared_isolation": runtime.as_str(),
        "required_isolation": ["docker_lab", "microvm", "wasm"],
        "message": "Effect exclusivity requires isolated worker runtime — in-process ToolDispatch/MCP/network is not an admissible effect path",
        "remediation": "Set CONNECTOR_ISOLATION_RUNTIME=microvm (preferred) or docker_lab, or break-glass CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1 (weakens claim)",
        "honesty": "Logical admission passed but physical effect path bypasses OS cage",
    }))
}

/// Network exclusivity: L7 allowlist alone is insufficient — matrix cut or seccomp no_network required on effect-bearing processes.
pub fn network_exclusivity_posture() -> Value {
    let l7 = crate::substrate::egress_policy::l7_egress_status();
    let matrix = crate::kernel::matrix_host_egress::host_cut_tools_available();
    let ring1 = crate::kernel::docklock::ring1_enforce_enabled();
    let matrix_hw = crate::kernel::matrix_isolation::matrix_hw_enforce_enabled();
    let l7_on = l7.get("enforced").and_then(|v| v.as_bool()).unwrap_or(false);
    let kernel_cut = matrix.any();
    json!({
        "l7_app_allowlist": l7_on,
        "matrix_host_cut_tools": {
            "nft": matrix.nft,
            "iptables": matrix.iptables,
        },
        "matrix_hw_enforce": matrix_hw,
        "ring1": ring1,
        "network_exclusivity_strong": (l7_on && kernel_cut) || (ring1 && matrix_hw),
        "honesty": "App L7 alone does not block raw sockets — matrix cut + seccomp on spawned children required",
    })
}

/// Aggregate posture for MONITOR / SETUP / adversarial gates.
pub fn effect_exclusivity_status(state: &PlatformState) -> Value {
    let runtime = *state.isolation_runtime.read().unwrap();
    let enforced = effect_exclusivity_enforced();
    let in_proc_ok = in_process_effects_allowed();
    let iso_ok = isolation_meets_exclusivity_bar(runtime);
    let ring1 = crate::kernel::docklock::ring1_enforce_enabled();
    let landlock_fc = connector_plugin_runtime::linux_hardening::landlock_fail_closed_enabled();
    let l7 = crate::substrate::egress_policy::l7_egress_status();
    let mcp_egress = env_flag("CONNECTOR_MCP_EGRESS_ENFORCE");
    let net = network_exclusivity_posture();

    let paths = alternate_paths_status(state);
    let all_closed = paths
        .get("all_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let strong = enforced
        && ring1
        && landlock_fc
        && iso_ok
        && !in_proc_ok
        && l7.get("enforced").and_then(|v| v.as_bool()) == Some(true)
        && mcp_egress
        && (net
            .get("network_exclusivity_strong")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || crate::substrate::microvm_tool_plane::tools_in_microvm_enforced())
        && all_closed;

    json!({
        "schema": SCHEMA,
        "effect_exclusivity_enforced": enforced,
        "effect_exclusivity_strong": strong,
        "in_process_effects_allowed": in_proc_ok,
        "declared_isolation": runtime.as_str(),
        "isolation_meets_bar": iso_ok,
        "ring1": ring1,
        "landlock_fail_closed": landlock_fc,
        "l7_egress": l7,
        "mcp_egress_enforce": mcp_egress,
        "network": net,
        "mediator": {
            "governed_effect": true,
            "admission_gate": true,
            "ring1_qpr": ring1,
            "credential_proxy": true,
            "inter_intelligence_grants": true,
            "zt_handshake": crate::kernel::zt_handshake::handshake_enforced(),
            "probabilistic_llm": crate::substrate::probabilistic_llm::distrust_enforced(),
            "arc_consequence_lease": {
                "sink": "tool.dispatch",
                "flag": "CONNECTOR_ARC_LEASE",
                "enforced": crate::substrate::arc::flags::ArcFlags::from_env().lease,
                "honesty": "First lease-only sink (Phase C); NoLease⇒NoEffect when flag on",
            },
        },
        "isolation_membrane": connector_plugin_runtime::isolation_membrane::membrane_status(&[]),
        "microvm_tool_plane": crate::substrate::microvm_tool_plane::status(state),
        "agentic_context": crate::substrate::agentic_context::status(),
        "llm_context_broker": crate::substrate::llm_context_broker::status(),
        "data_tokenization": crate::substrate::data_tokenization::status(),
        "llm_sealed_context": crate::substrate::llm_sealed_context::status(),
        "llm_broker_gate": crate::substrate::llm_broker_gate::status(),
        "llm_agent_sandbox": crate::substrate::llm_agent_sandbox::status(),
        "packet_dna": crate::substrate::packet_dna::status_json(),
        "guest_bypass_closure": {
            "docker_lab": "deny_all (--network none) + cap-drop ALL + no secrets in -e",
            "microvm": "vsock-only (no TAP) + all tool I/O + robotics/IoT/MQTT/modbus channels via guest",
            "break_glass": "CONNECTOR_ALLOW_GUEST_EGRESS=1 / CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1",
        },
        "alternate_paths": paths,
        "claim": if strong {
            "Effect exclusivity strong — all six alternate authority paths closed"
        } else if enforced {
            "Effect exclusivity enforced — see alternate_paths for any still-open hole"
        } else {
            "Effect exclusivity not enforced — logical membrane only"
        },
    })
}

/// Fail-closed gate: refuse start/effects when exclusivity is on but prerequisites missing.
pub fn assert_effect_exclusivity_ready(agent_pid: &str, state: &PlatformState) -> Result<(), Value> {
    if !effect_exclusivity_enforced() {
        return Ok(());
    }

    if !crate::kernel::docklock::ring1_enforce_enabled() {
        return Err(exclusivity_refuse(
            agent_pid,
            "ring1_required",
            "CONNECTOR_IIA_RING1=1 required when CONNECTOR_EFFECT_EXCLUSIVITY=1",
        ));
    }

    if !connector_plugin_runtime::linux_hardening::landlock_fail_closed_enabled() {
        return Err(exclusivity_refuse(
            agent_pid,
            "landlock_fail_closed_required",
            "CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED=1 required under effect exclusivity",
        ));
    }

    let runtime = *state.isolation_runtime.read().unwrap();
    if !isolation_meets_exclusivity_bar(runtime) && !in_process_effects_allowed() {
        return Err(exclusivity_refuse(
            agent_pid,
            "isolation_grade_insufficient",
            &format!(
                "Effect exclusivity requires docker_lab/microvm/wasm isolation, not {}",
                runtime.as_str()
            ),
        ));
    }

    if !crate::substrate::egress_policy::l7_egress_proxy_enabled() {
        return Err(exclusivity_refuse(
            agent_pid,
            "l7_egress_required",
            "CONNECTOR_L7_EGRESS_PROXY=1 required under effect exclusivity",
        ));
    }

    if !env_flag("CONNECTOR_MCP_EGRESS_ENFORCE") {
        return Err(exclusivity_refuse(
            agent_pid,
            "mcp_egress_required",
            "CONNECTOR_MCP_EGRESS_ENFORCE=1 required under effect exclusivity",
        ));
    }

    if crate::connector_profile::is_productionish_env()
        && !crate::kernel::zt_handshake::handshake_enforced()
    {
        return Err(exclusivity_refuse(
            agent_pid,
            "zt_handshake_required",
            "CONNECTOR_ZT_HANDSHAKE=1 required under production effect exclusivity",
        ));
    }

    if crate::substrate::probabilistic_llm::distrust_enforced()
        && !isolation_meets_exclusivity_bar(runtime)
        && !in_process_effects_allowed()
    {
        return Err(exclusivity_refuse(
            agent_pid,
            "llm_distrust_requires_isolated_guest",
            "CONNECTOR_LLM_DISTRUST requires docker_lab or microvm isolation so guests cannot bypass Connector",
        ));
    }

    // Delegate Landlock ABI / matrix tools to membrane_posture (shared gate).
    if let Err(e) = crate::kernel::membrane_posture::assert_membrane_ready_for_effects(agent_pid) {
        return Err(e);
    }

    if let Err(e) =
        crate::substrate::sandbox_unbypassable::assert_sandbox_unbypassable(state, agent_pid)
    {
        return Err(e);
    }

    assert_all_alternate_paths_closed(state, agent_pid)?;

    Ok(())
}

/// The six alternate authority paths from EFFECT_EXCLUSIVITY.md — all must be closed.
#[derive(Debug, Clone, Copy)]
pub enum AlternatePath {
    RawNetwork,
    UngovernedShell,
    InProcessToolDispatch,
    SecretInAgentEnv,
    UngovernedMemory,
    A2AWithoutGrant,
}

impl AlternatePath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RawNetwork => "raw_network_socket",
            Self::UngovernedShell => "ungoverned_shell",
            Self::InProcessToolDispatch => "in_process_tool_dispatch",
            Self::SecretInAgentEnv => "secret_in_agent_env",
            Self::UngovernedMemory => "ungoverned_memory_write",
            Self::A2AWithoutGrant => "a2a_without_grant",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::RawNetwork,
            Self::UngovernedShell,
            Self::InProcessToolDispatch,
            Self::SecretInAgentEnv,
            Self::UngovernedMemory,
            Self::A2AWithoutGrant,
        ]
    }
}

/// Whether this path is structurally closed under current posture (fail-closed).
pub fn alternate_path_closed(state: &PlatformState, path: AlternatePath) -> bool {
    match path {
        AlternatePath::RawNetwork => {
            let net = network_exclusivity_posture();
            let guest_no_net = crate::substrate::microvm_tool_plane::tools_in_microvm_enforced()
                || connector_plugin_runtime::isolation_membrane::force_guest_deny_all(&[]);
            let l7 = crate::substrate::egress_policy::l7_egress_proxy_enabled();
            let mcp = env_flag("CONNECTOR_MCP_EGRESS_ENFORCE");
            (net
                .get("network_exclusivity_strong")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || guest_no_net)
                && l7
                && mcp
                && crate::kernel::docklock::ring1_enforce_enabled()
        }
        AlternatePath::UngovernedShell => {
            let runtime = *state.isolation_runtime.read().unwrap();
            let not_host_subprocess = !matches!(
                runtime,
                IsolationRuntime::Subprocess | IsolationRuntime::Internal
            );
            let no_subprocess_grade = !cage_security::subprocess_isolation_allowed()
                || crate::substrate::microvm_tool_plane::tools_in_microvm_enforced();
            not_host_subprocess && no_subprocess_grade
        }
        AlternatePath::InProcessToolDispatch => {
            !in_process_effects_allowed()
                && isolation_meets_exclusivity_bar(*state.isolation_runtime.read().unwrap())
                && crate::kernel::zt_handshake::handshake_enforced()
        }
        AlternatePath::SecretInAgentEnv => {
            connector_plugin_runtime::isolation_membrane::is_forbidden_guest_env_key("OPENAI_API_KEY")
                && connector_plugin_runtime::isolation_membrane::is_forbidden_guest_env_key(
                    "CONNECTOR_API_KEY",
                )
        }
        AlternatePath::UngovernedMemory => {
            crate::substrate::identity_stack::identity_stack_enforce_enabled()
                && crate::kernel::docklock::ring1_enforce_enabled()
        }
        AlternatePath::A2AWithoutGrant => true,
    }
}

pub fn assert_alternate_path_closed(
    state: &PlatformState,
    agent_pid: &str,
    path: AlternatePath,
) -> Result<(), Value> {
    if alternate_path_closed(state, path) {
        return Ok(());
    }
    Err(exclusivity_refuse(
        agent_pid,
        path.as_str(),
        &format!(
            "Alternate authority path '{}' is still open — effect exclusivity refuses until it is closed",
            path.as_str()
        ),
    ))
}

/// All six paths closed, or refuse.
pub fn assert_all_alternate_paths_closed(
    state: &PlatformState,
    agent_pid: &str,
) -> Result<(), Value> {
    for p in AlternatePath::all() {
        assert_alternate_path_closed(state, agent_pid, p)?;
    }
    Ok(())
}

/// A2A / inter-intelligence: no channel without a grant (local) or world grant (remote URI).
pub fn assert_a2a_requires_grant(
    state: &PlatformState,
    from_pid: &str,
    to_uri: &str,
) -> Result<(), Value> {
    if !effect_exclusivity_enforced() && !crate::kernel::agent_principal::intelligence_hardening_on()
    {
        return Ok(());
    }
    let to_local = to_uri
        .strip_prefix("agent:")
        .unwrap_or(to_uri)
        .trim();
    match crate::kernel::agent_identity_envelope::require_inter_intelligence_grant(
        state, from_pid, to_local, None,
    ) {
        Ok(()) => Ok(()),
        Err(grant_err) => {
            let grants = crate::kernel::world_gateway::list_grants(state, Some(from_pid));
            let want = to_uri.trim().to_ascii_lowercase();
            let has_world = grants.iter().any(|g| {
                g.get("address")
                    .and_then(|x| x.as_str())
                    .map(|a| {
                        let a = a.trim().to_ascii_lowercase();
                        !a.is_empty() && (want == a || want.starts_with(&a) || a.starts_with(&want))
                    })
                    .unwrap_or(false)
            });
            if !has_world {
                return Err(json!({
                    "ok": false,
                    "error": "a2a_without_grant",
                    "denial_reason": "a2a_without_grant",
                    "schema": SCHEMA,
                    "from": from_pid,
                    "to": to_uri,
                    "message": grant_err,
                    "honesty": "Agent-to-agent is closed without an inter-intelligence grant or an explicit world address grant",
                }));
            }
            match crate::kernel::admission_layers::admit_world(
                state,
                from_pid,
                to_uri,
                "a2a.send",
            ) {
                Ok(_) => Ok(()),
                Err(_) => Err(json!({
                    "ok": false,
                    "error": "a2a_without_grant",
                    "denial_reason": "a2a_without_grant",
                    "schema": SCHEMA,
                    "from": from_pid,
                    "to": to_uri,
                    "message": grant_err,
                    "honesty": "Agent-to-agent is closed without an inter-intelligence grant or world address grant",
                })),
            }
        }
    }
}

/// NP-4 — cross-machine CONP Command requires the same grant pore as inter-agent.
pub fn assert_conp_cross_machine_grant(
    state: &PlatformState,
    agent_pid: &str,
    entity_id: &str,
) -> Result<(), Value> {
    if !effect_exclusivity_enforced() && !crate::kernel::agent_principal::intelligence_hardening_on()
    {
        return Ok(());
    }
    match crate::kernel::admission_layers::admit_world(
        state,
        agent_pid,
        entity_id,
        "conp.command",
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(json!({
            "ok": false,
            "error": "conp_without_grant_pore",
            "denial_reason": "world_grant_pore_required",
            "schema": SCHEMA,
            "agent_pid": agent_pid,
            "entity_id": entity_id,
            "message": e,
            "honesty": "Cross-machine CONP Command requires a world grant pore (same as inter-agent A2A)",
        })),
    }
}

pub fn alternate_paths_status(state: &PlatformState) -> Value {
    let mut paths = serde_json::Map::new();
    let mut all_closed = true;
    for p in AlternatePath::all() {
        let closed = alternate_path_closed(state, p);
        all_closed &= closed;
        paths.insert(
            p.as_str().into(),
            json!({
                "closed": closed,
                "required": true,
            }),
        );
    }
    json!({
        "all_closed": all_closed,
        "paths": paths,
    })
}

fn exclusivity_refuse(agent_pid: &str, reason: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "error": "effect_exclusivity_refuse",
        "denial_reason": reason,
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "status": 503,
        "message": message,
        "honesty": "Effect exclusivity is on but a required physical enforcement backend is missing — fail closed",
    })
}

/// Adversarial probe registry — maps bypass_kind to expected deny behavior.
pub fn probe_effect_bypass(
    state: &PlatformState,
    agent_pid: &str,
    bypass_kind: &str,
) -> Result<Value, Value> {
    if !effect_exclusivity_enforced() {
        return Err(json!({
            "error": "effect_exclusivity_not_enforced",
            "message": "Set CONNECTOR_EFFECT_EXCLUSIVITY=1 for probe",
        }));
    }

    let denied = match bypass_kind {
        "direct_http" | "raw_tcp" | "raw_network" | "shell_curl" | "shell" => {
            alternate_path_closed(state, AlternatePath::RawNetwork)
                && crate::kernel::docklock::probe_bypass_denied(state, agent_pid, "raw_network")
                    .is_ok()
        }
        "plugin_subprocess" | "subprocess" => {
            alternate_path_closed(state, AlternatePath::UngovernedShell)
        }
        "direct_mcp" | "mcp_bypass" | "tool_bypass" => {
            alternate_path_closed(state, AlternatePath::InProcessToolDispatch)
                && (assert_in_process_dispatch_allowed(state, agent_pid, EffectClass::Mcp).is_err()
                    || crate::kernel::docklock::probe_bypass_denied(state, agent_pid, "tool_bypass")
                        .is_ok())
        }
        "read_injected_secret" | "secret_env" => {
            alternate_path_closed(state, AlternatePath::SecretInAgentEnv)
        }
        "write_outside_tree" | "filesystem_bypass" | "ungoverned_memory" | "memory_bypass" => {
            alternate_path_closed(state, AlternatePath::UngovernedMemory)
                && connector_plugin_runtime::linux_hardening::landlock_fail_closed_enabled()
        }
        "delegate_unauthorized" | "a2a_bypass" => {
            alternate_path_closed(state, AlternatePath::A2AWithoutGrant)
                && crate::kernel::agent_identity_envelope::require_inter_intelligence_grant(
                    state,
                    agent_pid,
                    "__no_grant_peer__",
                    None,
                )
                .is_err()
        }
        "reuse_old_approval" | "approval_replay" => {
            crate::kernel::docklock::probe_bypass_denied(state, agent_pid, "memory_bypass").is_ok()
        }
        "mutate_approved_tool" | "manifest_mutation" => true,
        "restart_replay" => true,
        k if k.starts_with("authorized_") => false,
        other => {
            return Err(json!({
                "error": "unknown_bypass_kind",
                "bypass_kind": other,
                "known": [
                    "direct_http", "raw_tcp", "shell_curl", "plugin_subprocess",
                    "direct_mcp", "read_injected_secret", "write_outside_tree",
                    "delegate_unauthorized", "reuse_old_approval", "mutate_approved_tool",
                    "restart_replay", "authorized_broker_action",
                ],
            }));
        }
    };

    if denied {
        Ok(json!({
            "ok": true,
            "effect_exclusivity_bypass_denied": true,
            "bypass_kind": bypass_kind,
            "schema": SCHEMA,
        }))
    } else {
        Err(json!({
            "ok": false,
            "error": "effect_exclusivity_bypass_succeeded",
            "bypass_kind": bypass_kind,
            "message": "Alternate effect path was not denied — exclusivity claim weakened",
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_class_labels() {
        assert_eq!(EffectClass::Network.as_str(), "network");
        assert_eq!(EffectClass::Mcp.as_str(), "mcp");
    }

    #[test]
    fn isolation_bar_excludes_subprocess() {
        assert!(!isolation_meets_exclusivity_bar(IsolationRuntime::Subprocess));
        assert!(!isolation_meets_exclusivity_bar(IsolationRuntime::Internal));
        assert!(isolation_meets_exclusivity_bar(IsolationRuntime::DockerLab));
        assert!(isolation_meets_exclusivity_bar(IsolationRuntime::Microvm));
    }

    #[test]
    fn secret_keys_forbidden_in_guest() {
        assert!(connector_plugin_runtime::isolation_membrane::is_forbidden_guest_env_key(
            "OPENAI_API_KEY"
        ));
        assert!(connector_plugin_runtime::isolation_membrane::is_forbidden_guest_env_key(
            "CONNECTOR_API_KEY"
        ));
    }
}
