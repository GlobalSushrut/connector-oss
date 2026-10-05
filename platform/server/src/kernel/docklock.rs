//! DockLock Ring-1 kernel — mandatory QPR quantum + **volatile intelligence cage**
//! before any effect.
//!
//! When `CONNECTOR_IIA_RING1=1` (or production / defense-strict), **no valid execution
//! without a valid, single-use ExecutionQuantum** bound to the agent principal.
//! Bypass paths (shell, raw network, SDK side-door) fail closed.
//!
//! DockLock is **not** a long-lived process sandbox. It is docker-grade security for a
//! **volatile intelligence execution plane**:
//! - OS communication — brokered / no ambient host IPC
//! - Hardware management — devices/GPU/USB/block/DMA deny by default
//! - Intelligence isolation — quantum-bound, matrix mark, no ambient authority
//! - Network — deny-by-default + contract allowlist (docker/`nft` plane)

use axum::http::HeaderMap;
use base64::Engine;
use connector_trust::{ContinuityStateV2, ExecutionQuantumV2};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::kernel::{agent_principal, forensics};
use crate::quanta_polar;
use crate::state::PlatformState;

pub const QUANTUM_HEADER: &str = "x-connector-execution-quantum";
pub const DOCKLOCK_BINDING_HEADER: &str = "x-connector-docklock-binding";
pub const CPO_HEADER: &str = "x-connector-cpo-id";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockLockBindingV1 {
    pub schema: String,
    pub quantum_id: String,
    pub principal_id: String,
    pub operation: String,
    pub cage_profile: serde_json::Value,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub binding_mac: String,
}

/// Leaf env flags only — never call other enforce helpers (avoids ring1↔qpr recursion).
fn qpr_env_flag() -> bool {
    env_flag("CONNECTOR_IIA_QPR_ENFORCE")
}

fn docklock_env_flag() -> bool {
    env_flag("CONNECTOR_IIA_DOCKLOCK_ENFORCE")
}

fn ring1_env_flag() -> bool {
    env_flag("CONNECTOR_IIA_RING1")
}

/// Military-grade Ring-1: QPR + DockLock enforce (fail-closed on all effects).
///
/// Uses leaf env flags only in the `(QPR && DockLock)` conjunction so this never
/// recurses through [`qpr_enforce_enabled`] / [`docklock_enforce_enabled`].
///
/// Hosted playground uses `CONNECTOR_ENV=pilots` (productionish) but has no Landlock
/// cage — do not inherit Ring-1 from pilots alone unless explicitly opted in.
pub fn ring1_enforce_enabled() -> bool {
    if playground_env() && !ring1_env_flag() {
        return false;
    }
    ring1_env_flag()
        || crate::substrate::cage_security::prodish_isolation_enforced()
        || (qpr_env_flag() && docklock_env_flag())
}

pub fn docklock_enforce_enabled() -> bool {
    if playground_env() && !docklock_env_flag() && !ring1_env_flag() {
        return false;
    }
    docklock_env_flag()
        || ring1_enforce_enabled()
        || crate::substrate::cage_security::prodish_isolation_enforced()
}

fn playground_env() -> bool {
    env_flag("CONNECTOR_PLAYGROUND")
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

fn ring1_strict_operation_bind() -> bool {
    env_flag("CONNECTOR_IIA_RING1_STRICT")
        || crate::substrate::cage_security::prodish_isolation_enforced()
}

/// Quantum action must authorize the admission operation (prevents read-quantum → write escalation).
pub fn quantum_allows_operation(quantum: &ExecutionQuantumV2, operation: &str) -> bool {
    if !ring1_strict_operation_bind() && !ring1_enforce_enabled() {
        return true;
    }
    let action = quantum.action.to_ascii_lowercase();
    if action == "*" || action == "any" || action == "effect" {
        return true;
    }
    match operation {
        "llm.chat" => {
            action.contains("chat")
                || action.contains("llm")
                || action.contains("cognize")
                || action == "read"
        }
        "memory.write" => action.contains("write") || action.contains("memory"),
        "tool.dispatch" => {
            action.contains("tool")
                || action.contains("dispatch")
                || action.contains("exec")
                || action.contains("shell")
        }
        "mcp.call" => {
            action.contains("mcp")
                || action.contains("tool")
                || action.contains("egress")
                || action.contains("network")
        }
        "pipeline.step" => action.contains("pipeline") || action.contains("step"),
        "shell" | "sdk_bypass" | "raw_network" | "memory_bypass" | "tool_bypass" | "debug_bypass"
        | "mcp_bypass" => false,
        _ => action == operation.to_ascii_lowercase(),
    }
}

pub const IIA_CAGE_ENV_FOLDER: &str = "docklock_cage_env_v1";
pub const IIA_CAGE_RUNTIME_LOG_FOLDER: &str = "iia_cage_runtime_log";

/// Append a cage/runtime line distinct from kernel audit (TG-0 Control stream).
pub fn append_cage_runtime_log(state: &PlatformState, agent_pid: &str, kind: &str, detail: &str) {
    let ms = chrono::Utc::now().timestamp_millis();
    let dig = format!("{:x}", Sha256::digest(format!("{agent_pid}|{kind}|{detail}|{ms}").as_bytes()));
    let key = format!("{}_{}", ms, &dig[..12]);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            IIA_CAGE_RUNTIME_LOG_FOLDER,
            &key,
            &json!({
                "schema": "connector.cage.runtime_log.v1",
                "agent_pid": agent_pid,
                "kind": kind,
                "detail": detail,
                "at_ms": ms,
                "honesty": "Cage/runtime plane — not kernel audit activity",
            }),
        );
    }
}

/// Recent cage/runtime lines for an agent (newest last).
pub fn list_cage_runtime_log(state: &PlatformState, agent_pid: &str, limit: usize) -> Vec<serde_json::Value> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let keys = es
        .folder_keys(IIA_CAGE_RUNTIME_LOG_FOLDER, None)
        .unwrap_or_default();
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(IIA_CAGE_RUNTIME_LOG_FOLDER, &k) {
            if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid) {
                rows.push(v);
            }
        }
    }
    rows.sort_by_key(|v| v.get("at_ms").and_then(|x| x.as_i64()).unwrap_or(0));
    let skip = rows.len().saturating_sub(limit);
    rows.into_iter().skip(skip).collect()
}

/// Env vars injected into plugin/subprocess cages when Ring-1 binds a quantum.
pub fn cage_env_for_quantum(quantum_id: &str, principal_id: &str) -> Vec<(String, String)> {
    cage_env_for_intelligence(quantum_id, principal_id, principal_id)
}

/// Network posture derived from agent contract (deny default = intelligence isolated).
#[derive(Debug, Clone)]
pub struct IntelligenceNetworkPolicy {
    pub network_default: String,
    pub network_allow: Vec<String>,
}

impl IntelligenceNetworkPolicy {
    pub fn from_contract(contract: Option<&connector_trust::AgentContractV2>) -> Self {
        match contract {
            Some(c) => Self {
                network_default: c.network_default.clone(),
                network_allow: c.network_allow.clone(),
            },
            None => Self {
                network_default: "deny".into(),
                network_allow: vec![],
            },
        }
    }

    /// Maps to `CONNECTOR_DOCKER_LAB_EGRESS` consumed by plugin-runtime docker_lab.
    pub fn docker_egress_mode(&self) -> &'static str {
        let deny = self.network_default.eq_ignore_ascii_case("deny")
            || self.network_default.eq_ignore_ascii_case("deny_all")
            || self.network_default.is_empty();
        if deny && self.network_allow.is_empty() {
            "deny_all"
        } else if !self.network_allow.is_empty() {
            "allowlist_strict"
        } else {
            "deny_all"
        }
    }
}

/// Cage env for an intelligence execution quantum (agent-scoped matrix mark).
pub fn cage_env_for_intelligence(
    quantum_id: &str,
    principal_id: &str,
    agent_pid: &str,
) -> Vec<(String, String)> {
    cage_env_for_intelligence_with_policy(
        quantum_id,
        principal_id,
        agent_pid,
        &IntelligenceNetworkPolicy::from_contract(None),
    )
}

/// Full volatile intelligence cage env: OS / hardware / isolation / network.
pub fn cage_env_for_intelligence_with_policy(
    quantum_id: &str,
    principal_id: &str,
    agent_pid: &str,
    net: &IntelligenceNetworkPolicy,
) -> Vec<(String, String)> {
    let ring1 = ring1_enforce_enabled();
    let docker_egress = net.docker_egress_mode();
    let mut env: Vec<(String, String)> = vec![
        ("CONNECTOR_EXECUTION_QUANTUM".into(), quantum_id.into()),
        (
            "CONNECTOR_DOCKLOCK_RING1".into(),
            if ring1 { "1".into() } else { "0".into() },
        ),
        ("CONNECTOR_PRINCIPAL_ID".into(), principal_id.into()),
        ("CONNECTOR_AGENT_PID".into(), agent_pid.into()),
        // Volatile intelligence plane — quantum-bound, no ambient host authority.
        ("CONNECTOR_INTELLIGENCE_EXECUTION_PLANE".into(), "1".into()),
        ("CONNECTOR_DOCKLOCK_VOLATILE".into(), "1".into()),
        (
            "CONNECTOR_DOCKLOCK_SECURITY_GRADE".into(),
            "docker_intelligence".into(),
        ),
        // Docker-grade container security (honored by plugin-runtime docker_lab).
        ("CONNECTOR_DOCKLOCK_DOCKER_SECURITY".into(), "1".into()),
        // OS communication: no ambient host IPC / privileged sockets.
        ("CONNECTOR_DOCKLOCK_OS_COMMS".into(), "brokered".into()),
        ("CONNECTOR_DOCKLOCK_IPC".into(), "none".into()),
        // Hardware management: deny devices unless contract later grants.
        ("CONNECTOR_DOCKLOCK_HARDWARE".into(), "deny".into()),
        ("CONNECTOR_DOCKLOCK_GPU".into(), "deny".into()),
        ("CONNECTOR_DOCKLOCK_DEVICES".into(), "none".into()),
        // Network plane for intelligence (not process-PID firewalling).
        ("CONNECTOR_DOCKER_LAB_EGRESS".into(), docker_egress.into()),
        (
            "CONNECTOR_DOCKLOCK_NETWORK_DEFAULT".into(),
            net.network_default.clone(),
        ),
        (
            "CONNECTOR_DOCKLOCK_NETWORK_ALLOW".into(),
            net.network_allow.join(","),
        ),
    ];
    // Probabilistic LLM distrust → guest broker-only (docker_lab / microvm membrane).
    if crate::substrate::probabilistic_llm::distrust_enforced()
        || crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
    {
        env.push(("CONNECTOR_LLM_DISTRUST".into(), "1".into()));
        env.push(("CONNECTOR_EFFECT_EXCLUSIVITY".into(), "1".into()));
        env.push(("CONNECTOR_ZT_HANDSHAKE".into(), "1".into()));
        env.push(("CONNECTOR_BROKER_ONLY".into(), "1".into()));
        env.push(("CONNECTOR_MICROVM_EGRESS_MODE".into(), "deny_all".into()));
        for (k, v) in env.iter_mut() {
            match k.as_str() {
                "CONNECTOR_DOCKER_LAB_EGRESS" => *v = "deny_all".into(),
                "CONNECTOR_DOCKLOCK_NETWORK_ALLOW" => *v = String::new(),
                "CONNECTOR_DOCKLOCK_NETWORK_DEFAULT" => *v = "deny".into(),
                _ => {}
            }
        }
    }
    if docker_egress == "allowlist_strict"
        && ring1
        && !crate::substrate::probabilistic_llm::distrust_enforced()
        && !crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
    {
        // Prefer host DOCKER-USER cut when allowlist is non-empty under Ring-1.
        env.push((
            "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE".into(),
            "iptables".into(),
        ));
    }
    // Default Linux spawn hardening for intelligence workers.
    if std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT").is_err()
        && std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP").is_err()
    {
        let intent = if ring1
            || docker_egress == "deny_all"
            || crate::substrate::probabilistic_llm::distrust_enforced()
        {
            "no_network"
        } else {
            "safe_default"
        };
        env.push((
            "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT".into(),
            intent.into(),
        ));
    }
    // Intelligence-plane mark for nftables `connector_matrix` / iptables-nft cut.
    env.push((
        "CONNECTOR_MATRIX_EGRESS_MARK".into(),
        crate::kernel::matrix_host_egress::intelligence_egress_mark_hex(agent_pid),
    ));
    // Landlock FS intent (plugin-runtime applies when CONNECTOR_DOCKLOCK_LANDLOCK=1).
    env.push(("CONNECTOR_DOCKLOCK_LANDLOCK".into(), "1".into()));
    env
}

/// Enrich cage env with contract FS paths for Landlock (B40).
pub fn cage_env_with_contract_fs(
    quantum_id: &str,
    principal_id: &str,
    agent_pid: &str,
    contract: Option<&connector_trust::AgentContractV2>,
) -> Vec<(String, String)> {
    let net = IntelligenceNetworkPolicy::from_contract(contract);
    let mut env =
        cage_env_for_intelligence_with_policy(quantum_id, principal_id, agent_pid, &net);
    if let Some(c) = contract {
        if !c.filesystem_read.is_empty() {
            env.push((
                "CONNECTOR_DOCKLOCK_FS_READ".into(),
                c.filesystem_read.join(":"),
            ));
        }
        if !c.filesystem_write.is_empty() {
            env.push((
                "CONNECTOR_DOCKLOCK_FS_WRITE".into(),
                c.filesystem_write.join(":"),
            ));
        }
    }
    crate::kernel::address_cage::strip_host_identity_env(&mut env);
    crate::kernel::address_cage::apply_nsfs_landlock_defaults(agent_pid, &mut env);
    env
}

/// Persist cage env for a quantum so spawners / tools can load it (B23).
pub fn persist_cage_env(
    state: &PlatformState,
    quantum_id: &str,
    principal_id: &str,
    agent_pid: &str,
    contract: Option<&connector_trust::AgentContractV2>,
) {
    let env = cage_env_with_contract_fs(quantum_id, principal_id, agent_pid, contract);
    let net = IntelligenceNetworkPolicy::from_contract(contract);
    let map: serde_json::Map<String, serde_json::Value> = env
        .into_iter()
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect();
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            IIA_CAGE_ENV_FOLDER,
            quantum_id,
            &json!({
                "quantum_id": quantum_id,
                "principal_id": principal_id,
                "agent_pid": agent_pid,
                "volatile": true,
                "security_grade": "docker_intelligence",
                "network_default": net.network_default,
                "network_allow": net.network_allow,
                "env": map,
            }),
        );
    }
}

/// Load persisted cage env for subprocess spawners.
pub fn load_cage_env(state: &PlatformState, quantum_id: &str) -> Option<Vec<(String, String)>> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(IIA_CAGE_ENV_FOLDER, quantum_id).ok().flatten()?;
    let env = v.get("env")?.as_object()?;
    Some(
        env.iter()
            .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
    )
}

fn synthesize_intelligence_cage(quantum_id: &str, principal_id: &str) -> Vec<(String, String)> {
    // Matrix mark is keyed by intelligence agent_pid, not OS process id.
    let agent_pid = std::env::var("CONNECTOR_AGENT_PID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| principal_id.to_string());
    let net = IntelligenceNetworkPolicy {
        network_default: std::env::var("CONNECTOR_DOCKLOCK_NETWORK_DEFAULT")
            .unwrap_or_else(|_| "deny".into()),
        network_allow: std::env::var("CONNECTOR_DOCKLOCK_NETWORK_ALLOW")
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    };
    cage_env_for_intelligence_with_policy(quantum_id, principal_id, &agent_pid, &net)
}

/// B23: apply cage env onto a subprocess `Command` (persisted → else synthesize).
pub fn apply_cage_env_to_command(
    state: &PlatformState,
    cmd: &mut std::process::Command,
    quantum_id: Option<&str>,
    principal_id: Option<&str>,
) {
    let pairs = match quantum_id {
        Some(qid) => load_cage_env(state, qid).unwrap_or_else(|| {
            synthesize_intelligence_cage(qid, principal_id.unwrap_or("unknown"))
        }),
        None => {
            // Fall back to ambient process quantum if present.
            match std::env::var("CONNECTOR_EXECUTION_QUANTUM") {
                Ok(qid) if !qid.is_empty() => load_cage_env(state, &qid).unwrap_or_else(|| {
                    synthesize_intelligence_cage(
                        &qid,
                        &std::env::var("CONNECTOR_PRINCIPAL_ID")
                            .unwrap_or_else(|_| "unknown".into()),
                    )
                }),
                _ => return,
            }
        }
    };
    let mut pairs = pairs;
    let stripped = crate::kernel::credential_proxy::strip_secret_env_keys(&mut pairs);
    if stripped > 0 {
        tracing::warn!(
            stripped,
            "DI-3: refused to inject API-key env vars into intelligence cage"
        );
    }
    crate::kernel::address_cage::strip_host_identity_env(&mut pairs);
    let agent_pid = pairs
        .iter()
        .find(|(k, _)| k == "CONNECTOR_AGENT_PID")
        .map(|(_, v)| v.clone())
        .filter(|s| !s.trim().is_empty());
    if let Some(pid) = agent_pid.as_deref() {
        crate::kernel::address_cage::apply_nsfs_landlock_defaults(pid, &mut pairs);
    }
    for key in crate::kernel::address_cage::HOST_IDENTITY_ENV {
        cmd.env_remove(key);
    }
    for (k, v) in pairs {
        cmd.env(k, v);
    }
}

fn ring1_secret() -> Vec<u8> {
    std::env::var("CONNECTOR_DOCKLOCK_RING1_SECRET")
        .or_else(|_| std::env::var("CONNECTOR_CAGE_CAP_SECRET"))
        .or_else(|_| std::env::var("CONNECTOR_CFNI_SECRET"))
        .unwrap_or_else(|_| "connector-docklock-ring1-dev-only".into())
        .into_bytes()
}

pub fn extract_quantum_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(QUANTUM_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Compile Ring-1 **volatile intelligence** cage from quantum + optional contract (B7/B39).
///
/// Docker-grade security model for intelligence execution (not a persistent VM):
/// OS brokered comms, hardware deny, intelligence isolation, network deny-default.
pub fn compile_cage_profile(
    quantum: &ExecutionQuantumV2,
    contract: Option<&connector_trust::AgentContractV2>,
) -> serde_json::Value {
    let (fs_read, fs_write, net) = if let Some(c) = contract {
        let write = if quantum.action.to_ascii_lowercase().contains("write")
            || quantum.action.to_ascii_lowercase().contains("memory")
        {
            c.filesystem_write.clone()
        } else {
            vec![]
        };
        (
            c.filesystem_read.clone(),
            write,
            IntelligenceNetworkPolicy::from_contract(Some(c)),
        )
    } else {
        (
            vec!["/workspace/**".into()],
            if quantum.action.contains("write") {
                vec!["/workspace/out/**".into()]
            } else {
                vec![]
            },
            IntelligenceNetworkPolicy::from_contract(None),
        )
    };
    let docker_egress = net.docker_egress_mode();
    json!({
        "schema": "connector.docklock.intelligence.v2",
        "quantum_id": quantum.quantum_id,
        "principal_id": quantum.principal_id,
        "action": quantum.action,
        "target": quantum.target,
        "volatile": true,
        "security_grade": "docker_intelligence",
        "lifetime": "quantum_bound",
        "ambient_authority": false,
        "bypass_denied": true,
        "contract_bound": contract.is_some(),
        // --- filesystem (contract) ---
        "filesystem_read": fs_read,
        "filesystem_write": fs_write,
        // --- network (intelligence plane) ---
        "network": {
            "default": net.network_default.clone(),
            "allow": net.network_allow.clone(),
            "docker_egress_mode": docker_egress,
            "matrix_mark_cut": true,
        },
        // legacy flat keys (compat)
        "network_default": net.network_default,
        "network_allow": net.network_allow,
        // --- OS communication ---
        "os_communication": {
            "mode": "brokered",
            "host_ipc": "none",
            "privileged_sockets": "deny",
            "docker": {
                "ipc": "none",
                "pid": "private",
                "uts": "private",
            },
        },
        // --- hardware management ---
        "hardware_management": {
            "gpu": "deny",
            "pcie_passthrough": "deny",
            "usb_mass_storage": "deny",
            "raw_block_devices": "deny",
            "dma_untrusted": "deny",
            "devices": "none",
            "tpm_quote_required": crate::kernel::matrix_isolation::matrix_hw_enforce_enabled(),
        },
        // compat stamp
        "hardware_access": {
            "gpu": "deny",
            "pcie_passthrough": "deny",
            "usb_mass_storage": "deny",
            "raw_block_devices": "deny",
            "dma_untrusted": "deny",
            "tpm_quote_required": crate::kernel::matrix_isolation::matrix_hw_enforce_enabled(),
        },
        // --- intelligence isolation ---
        "intelligence_isolation": {
            "plane": "cdmi_intelligence",
            "quantum_single_use": quantum.single_use,
            "matrix_egress_mark": true,
            "seccomp_intent": if ring1_enforce_enabled() || docker_egress == "deny_all" {
                "no_network"
            } else {
                "safe_default"
            },
        },
        // --- docker-grade container posture (applied when backend=docker_lab) ---
        "docker_grade": {
            "read_only_rootfs": true,
            "cap_drop": ["ALL"],
            "no_new_privileges": true,
            "privileged": false,
            "rm_on_exit": true,
            "tmpfs": ["/tmp"],
            "pids_limit": 256,
            "security_opt": ["no-new-privileges:true"],
        },
        "process_allow_declared": ["connector-agent", "connector-platform"],
        "syscall_filter_declared": "seccomp-bpf",
        // Honest: admission + cage env + docker_lab/subprocess pre_exec + matrix nft.
        "enforcement": "admission_env_docker_or_seccomp_matrix",
        "matrix_hw_enforce": crate::kernel::matrix_isolation::matrix_hw_enforce_enabled(),
    })
}

pub const IIA_DOCKLOCK_PROFILE_FOLDER: &str = "docklock_profile_v2";

/// B10: persist per-agent DockLock profile at activate (derived from contract).
pub fn bind_docklock_profile_at_activate(
    state: &PlatformState,
    api_pid: &str,
) -> Result<String, String> {
    let contract = agent_principal::load_contract(state, api_pid)
        .ok_or_else(|| "contract_not_found".to_string())?;
    let principal_id = agent_principal::load_principal(state, api_pid)
        .map(|p| p.principal_id)
        .unwrap_or_else(|| contract.agent_id.clone());
    let profile_id = format!(
        "dlp_{}",
        &hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}",
                api_pid, contract.contract_digest_sha256, contract.contract_version
            )
            .as_bytes()
        ))[..16]
    );
    let net = IntelligenceNetworkPolicy::from_contract(Some(&contract));
    let profile = json!({
        "schema": "connector.docklock.profile.v3",
        "profile_id": profile_id,
        "agent_pid": api_pid,
        "principal_id": principal_id,
        "security_grade": "docker_intelligence",
        "volatile": true,
        "contract_digest_sha256": contract.contract_digest_sha256,
        "contract_version": contract.contract_version,
        "filesystem_read": contract.filesystem_read,
        "filesystem_write": contract.filesystem_write,
        "network_allow": contract.network_allow,
        "network_default": contract.network_default,
        "docker_egress_mode": net.docker_egress_mode(),
        "receipt_required": contract.receipt_required,
        "os_communication": "brokered",
        "hardware_management": "deny",
        "intelligence_isolation": true,
        "enforcement": "admission_env_docker_or_seccomp_matrix",
        "os_seccomp_applied": cfg!(target_os = "linux"),
        "os_seccomp_path": "plugin_subprocess_pre_exec_via_CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT",
        "docker_security_path": "plugin_runtime_docker_lab_CONNECTOR_DOCKLOCK_DOCKER_SECURITY",
        "bound_at_ms": chrono::Utc::now().timestamp_millis(),
    });
    let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    es.folder_put(IIA_DOCKLOCK_PROFILE_FOLDER, api_pid, &profile)
        .map_err(|e| format!("{e:?}"))?;
    Ok(profile_id)
}

pub fn load_docklock_profile(state: &PlatformState, api_pid: &str) -> Option<serde_json::Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(IIA_DOCKLOCK_PROFILE_FOLDER, api_pid)
        .ok()
        .flatten()
}

fn binding_mac(quantum_id: &str, principal_id: &str, operation: &str, expires_at_ms: i64) -> String {
    let payload = format!("{quantum_id}|{principal_id}|{operation}|{expires_at_ms}");
    let mut mac = HmacSha256::new_from_slice(&ring1_secret()).expect("hmac key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn mint_binding(
    quantum: &ExecutionQuantumV2,
    operation: &str,
    contract: Option<&connector_trust::AgentContractV2>,
) -> DockLockBindingV1 {
    let binding = DockLockBindingV1 {
        schema: "connector.docklock.binding.v1".into(),
        quantum_id: quantum.quantum_id.clone(),
        principal_id: quantum.principal_id.clone(),
        operation: operation.into(),
        cage_profile: compile_cage_profile(quantum, contract),
        issued_at_ms: quantum.issued_at_ms,
        expires_at_ms: quantum.expires_at_ms,
        binding_mac: binding_mac(
            &quantum.quantum_id,
            &quantum.principal_id,
            operation,
            quantum.expires_at_ms,
        ),
    };
    binding
}

pub fn verify_binding(binding: &DockLockBindingV1) -> bool {
    let expected = binding_mac(
        &binding.quantum_id,
        &binding.principal_id,
        &binding.operation,
        binding.expires_at_ms,
    );
    expected == binding.binding_mac
}

pub fn binding_header_value(binding: &DockLockBindingV1) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        serde_json::to_string(binding).unwrap_or_default(),
    )
}

/// Ring-1 gate — call after classic admission passes.
pub fn enforce_ring1(
    state: &PlatformState,
    agent_pid: &str,
    operation: &str,
    quantum_id: Option<&str>,
) -> Result<(), crate::error::ConnectorError> {
    // B24: even with Ring-1 off, contracts that require receipts must mint a signed one.
    let contract_early = agent_principal::load_contract(state, agent_pid);
    let receipt_required = contract_early
        .as_ref()
        .map(|c| c.receipt_required)
        .unwrap_or(false);

    if !ring1_enforce_enabled() {
        if receipt_required {
            require_effect_receipt(
                state,
                agent_pid,
                None,
                None,
                Some("connector.receipt_required.v1"),
                &format!("op|{operation}|{agent_pid}"),
            )?;
        }
        return Ok(());
    }

    if let Err(reason) = crate::kernel::matrix_isolation::assert_hardware_reality_bound(state) {
        return Err(ring1_deny(
            agent_pid,
            operation,
            "hardware_reality_unbound",
            &format!("Matrix hardware gate: {reason}"),
        ));
    }

    // Principal + continuity (kernel truth, not model self-report).
    let principal = agent_principal::load_principal(state, agent_pid).ok_or_else(|| {
        ring1_deny(agent_pid, operation, "principal_not_found", "Register agent under IIA spine")
    })?;
    let continuity = agent_principal::load_continuity(state, agent_pid).ok_or_else(|| {
        ring1_deny(agent_pid, operation, "continuity_missing", "Continuity record required")
    })?;
    if continuity.state == ContinuityStateV2::Broken {
        return Err(ring1_deny(
            agent_pid,
            operation,
            "continuity_broken",
            "Continuity BROKEN — revoke quanta and isolate",
        ));
    }

    let qid = quantum_id.ok_or_else(|| {
        ring1_deny(
            agent_pid,
            operation,
            "qpr_required",
            &format!("Ring-1 requires header {QUANTUM_HEADER}"),
        )
    })?;

    quanta_polar::require_quantum_header(state, agent_pid, Some(qid)).map_err(|j| {
        let reason = j
            .get("denial_reason")
            .or_else(|| j.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("quantum_invalid");
        ring1_deny(agent_pid, operation, reason, "Invalid or replayed execution quantum")
    })?;

    let quantum = quanta_polar::load_quantum(state, qid).ok_or_else(|| {
        ring1_deny(agent_pid, operation, "quantum_not_found", "Execution quantum missing")
    })?;

    if quantum.principal_id != principal.principal_id {
        return Err(ring1_deny(
            agent_pid,
            operation,
            "quantum_principal_mismatch",
            "Quantum not bound to this principal",
        ));
    }

    if !quantum_allows_operation(&quantum, operation) {
        return Err(ring1_deny(
            agent_pid,
            operation,
            "quantum_operation_mismatch",
            "Execution quantum action does not authorize this operation",
        ));
    }

    // Contracts are keyed by API pid (admission passes api_pid).
    let contract = contract_early.or_else(|| agent_principal::load_contract(state, agent_pid));
    let binding = mint_binding(&quantum, operation, contract.as_ref());
    persist_cage_env(
        state,
        &quantum.quantum_id,
        &quantum.principal_id,
        agent_pid,
        contract.as_ref(),
    );

    let _ = crate::substrate::flow_lease::mint_from_quantum(
        state,
        agent_pid,
        &quantum.quantum_id,
        operation,
    );

    let receipt = forensics::append_receipt(
        state,
        forensics::AppendReceiptParams {
            agent_pid: agent_pid.to_string(),
            cpo_id: Some(quantum.cpo_id.clone()),
            quantum_id: Some(quantum.quantum_id.clone()),
            docklock_profile_id: Some(binding.schema.clone()),
            effect_digest: binding.binding_mac.clone(),
        },
    );
    // B24: receipt_required ⇒ signed intelligence receipt or deny the effect.
    if receipt_required && receipt.signature.is_none() {
        return Err(ring1_deny(
            agent_pid,
            operation,
            "receipt_required",
            "Contract requires a signed intelligence receipt for this effect",
        ));
    }

    Ok(())
}

fn require_effect_receipt(
    state: &PlatformState,
    agent_pid: &str,
    cpo_id: Option<String>,
    quantum_id: Option<String>,
    docklock_profile_id: Option<&str>,
    effect_digest: &str,
) -> Result<(), crate::error::ConnectorError> {
    let receipt = forensics::append_receipt(
        state,
        forensics::AppendReceiptParams {
            agent_pid: agent_pid.to_string(),
            cpo_id,
            quantum_id,
            docklock_profile_id: docklock_profile_id.map(str::to_string),
            effect_digest: effect_digest.to_string(),
        },
    );
    if receipt.signature.is_none() {
        return Err(ring1_deny(
            agent_pid,
            "effect",
            "receipt_required",
            "Contract requires a signed intelligence receipt for this effect",
        ));
    }
    Ok(())
}

fn ring1_deny(
    agent_pid: &str,
    operation: &str,
    reason: &str,
    message: &str,
) -> crate::error::ConnectorError {
    tracing::warn!(
        agent_pid = %agent_pid,
        operation = %operation,
        reason = %reason,
        "DOCKLOCK Ring-1 DENY"
    );
    crate::error::ConnectorError::new(crate::error::DenialReason::PolicyDenied, message)
        .with_denied_resource(operation)
        .with_agent_scope(agent_pid)
}

/// Bypass probe — shell / SDK / raw network without quantum must fail when Ring-1 on.
pub fn probe_bypass_denied(
    state: &PlatformState,
    agent_pid: &str,
    bypass_kind: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    if !ring1_enforce_enabled() {
        return Err(serde_json::json!({
            "error": "ring1_not_enforced",
            "message": "Set CONNECTOR_IIA_RING1=1 for bypass probe",
        }));
    }
    match enforce_ring1(state, agent_pid, bypass_kind, None) {
        Err(_) => Ok(serde_json::json!({
            "ok": true,
            "docklock_bypass_denied": true,
            "bypass_kind": bypass_kind,
            "denial_reason": "qpr_required",
        })),
        Ok(()) => Err(serde_json::json!({
            "ok": false,
            "error": "bypass_succeeded",
            "message": "Ring-1 bypass probe failed — effect allowed without quantum",
        })),
    }
}

pub fn status_snapshot(state: &PlatformState) -> serde_json::Value {
    let landlock = connector_plugin_runtime::linux_hardening::landlock_posture_snapshot();
    json!({
        "ring1_enforce": ring1_enforce_enabled(),
        "docklock_enforce": docklock_enforce_enabled(),
        "qpr_enforce": quanta_polar::qpr_enforce_enabled(),
        "quantum_header": QUANTUM_HEADER,
        "docklock_binding_header": DOCKLOCK_BINDING_HEADER,
        "bypass_fail_closed": ring1_enforce_enabled(),
        "ring1_strict_operation_bind": ring1_strict_operation_bind(),
        "matrix_hw_enforce": crate::kernel::matrix_isolation::matrix_hw_enforce_enabled(),
        "landlock": landlock,
        "security_grade": "docker_intelligence",
        "volatile": true,
        "planes": ["os_communication", "hardware_management", "intelligence_isolation", "network"],
        "cage_env_keys": [
            "CONNECTOR_EXECUTION_QUANTUM",
            "CONNECTOR_DOCKLOCK_RING1",
            "CONNECTOR_PRINCIPAL_ID",
            "CONNECTOR_AGENT_PID",
            "CONNECTOR_DOCKLOCK_VOLATILE",
            "CONNECTOR_DOCKLOCK_SECURITY_GRADE",
            "CONNECTOR_DOCKLOCK_DOCKER_SECURITY",
            "CONNECTOR_DOCKLOCK_OS_COMMS",
            "CONNECTOR_DOCKLOCK_HARDWARE",
            "CONNECTOR_DOCKER_LAB_EGRESS",
            "CONNECTOR_MATRIX_EGRESS_MARK",
            "CONNECTOR_INTELLIGENCE_EXECUTION_PLANE",
            "CONNECTOR_DOCKLOCK_LANDLOCK",
            "CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED",
        ],
        "cage_env_persist_folder": IIA_CAGE_ENV_FOLDER,
        "node_witness_pubkey_hex": state.signing_key.public_key_hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_mac_round_trip() {
        let q = ExecutionQuantumV2 {
            schema: "x".into(),
            quantum_id: "q_test".into(),
            cpo_id: "c".into(),
            principal_id: "cnktr:agent:a".into(),
            contract_digest_sha256: "d".into(),
            action: "read".into(),
            target: "/workspace/x".into(),
            nonce: "n".into(),
            issued_at_ms: 1,
            expires_at_ms: 90_000,
            single_use: true,
            consumed: false,
            signature: None,
        };
        let b = mint_binding(&q, "llm.chat", None);
        assert!(verify_binding(&b));
    }

    #[test]
    fn ring1_enforce_all_flags_off_does_not_recurse() {
        // Must return without stack overflow when IIA env flags unset.
        let _ = ring1_enforce_enabled();
        let _ = docklock_enforce_enabled();
        let _ = quanta_polar::qpr_enforce_enabled();
    }

    #[test]
    fn cage_profile_uses_contract_fs() {
        let q = ExecutionQuantumV2 {
            schema: "x".into(),
            quantum_id: "q_c".into(),
            cpo_id: "c".into(),
            principal_id: "cnktr:agent:a".into(),
            contract_digest_sha256: "d".into(),
            action: "write".into(),
            target: "/data".into(),
            nonce: "n".into(),
            issued_at_ms: 1,
            expires_at_ms: 90_000,
            single_use: true,
            consumed: false,
            signature: None,
        };
        let contract = connector_trust::AgentContractV2 {
            schema: "s".into(),
            agent_id: "cnktr:agent:a".into(),
            issuer: "i".into(),
            purpose: vec![],
            capabilities: vec!["write".into()],
            denied_operations: vec![],
            filesystem_read: vec!["/m/a/**".into()],
            filesystem_write: vec!["/m/a/out/**".into()],
            network_allow: vec!["api.example.com".into()],
            network_default: "deny".into(),
            receipt_required: true,
            contract_digest_sha256: "cd".into(),
            contract_version: 2,
        };
        let cage = compile_cage_profile(&q, Some(&contract));
        assert_eq!(cage["filesystem_read"][0], "/m/a/**");
        assert_eq!(cage["filesystem_write"][0], "/m/a/out/**");
        assert_eq!(cage["network_allow"][0], "api.example.com");
        assert_eq!(cage["contract_bound"], true);
        assert_eq!(cage["volatile"], true);
        assert_eq!(cage["security_grade"], "docker_intelligence");
        assert_eq!(cage["network"]["docker_egress_mode"], "allowlist_strict");
        assert_eq!(cage["os_communication"]["mode"], "brokered");
        assert_eq!(cage["hardware_management"]["devices"], "none");
        assert_eq!(cage["docker_grade"]["cap_drop"][0], "ALL");
    }

    #[test]
    fn intelligence_network_deny_maps_to_docker_deny_all() {
        let net = IntelligenceNetworkPolicy {
            network_default: "deny".into(),
            network_allow: vec![],
        };
        assert_eq!(net.docker_egress_mode(), "deny_all");
        let env = cage_env_for_intelligence_with_policy("q1", "p1", "agent_a", &net);
        let map: std::collections::HashMap<_, _> = env.into_iter().collect();
        assert_eq!(map.get("CONNECTOR_DOCKLOCK_VOLATILE").map(String::as_str), Some("1"));
        assert_eq!(
            map.get("CONNECTOR_DOCKLOCK_SECURITY_GRADE").map(String::as_str),
            Some("docker_intelligence")
        );
        assert_eq!(
            map.get("CONNECTOR_DOCKER_LAB_EGRESS").map(String::as_str),
            Some("deny_all")
        );
        assert_eq!(
            map.get("CONNECTOR_DOCKLOCK_OS_COMMS").map(String::as_str),
            Some("brokered")
        );
        assert_eq!(
            map.get("CONNECTOR_DOCKLOCK_HARDWARE").map(String::as_str),
            Some("deny")
        );
    }

    #[test]
    fn read_quantum_cannot_authorize_memory_write() {
        let q = ExecutionQuantumV2 {
            schema: "x".into(),
            quantum_id: "q_rw".into(),
            cpo_id: "c".into(),
            principal_id: "cnktr:agent:a".into(),
            contract_digest_sha256: "d".into(),
            action: "read".into(),
            target: "/workspace/x".into(),
            nonce: "n".into(),
            issued_at_ms: 1,
            expires_at_ms: 90_000,
            single_use: true,
            consumed: false,
            signature: None,
        };
        assert!(quantum_allows_operation(&q, "llm.chat"));
        assert!(!quantum_allows_operation(&q, "memory.write"));
    }
}
