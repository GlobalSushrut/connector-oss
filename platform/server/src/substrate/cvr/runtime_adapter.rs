//! ConnectorRuntime — one adapter over Firecracker, containers, the lab subprocess,
//! and NVIDIA OpenShell.
//!
//! OpenShell is probed, not invented. A missing binary is `not_installed`.
//! Policy text compiled here is a projection of [`AgentContractV2`]. It is stored
//! on cease. It is not pushed into a supervisor that is not present.
//!
//! See `platform/docs/arch/CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md`.

use std::path::PathBuf;

use connector_trust::AgentContractV2;
use serde_json::{json, Value};

use super::backend::{FirecrackerBackend, MicroVmBackend};
use super::micro_cell;
use crate::state::PlatformState;

pub const POLICY_GEN_FOLDER: &str = "cvr_policy_generation";
pub const MEMORY_EPOCH_FOLDER: &str = "cvr_memory_epoch";
pub const PROJECTION_SCHEMA: &str = "connector.openshell_policy_projection.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    Firecracker,
    Container,
    SubprocessLab,
    OpenShell,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Container => "container",
            Self::SubprocessLab => "subprocess_lab",
            Self::OpenShell => "openshell",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeProbe {
    pub kind: RuntimeKind,
    pub present: bool,
    pub ready: bool,
    pub detail: String,
}

/// Host probes for the four runtimes. Ready is never implied from a name.
pub fn probe_all() -> Vec<RuntimeProbe> {
    vec![
        probe_firecracker(),
        probe_container(),
        probe_subprocess_lab(),
        probe_openshell(),
    ]
}

pub fn probe_firecracker() -> RuntimeProbe {
    let p = FirecrackerBackend.probe();
    RuntimeProbe {
        kind: RuntimeKind::Firecracker,
        present: p.ok,
        ready: p.ok,
        detail: p.detail,
    }
}

pub fn probe_container() -> RuntimeProbe {
    match bin_on_path("docker", "CONNECTOR_DOCKER_BIN") {
        Some(p) => RuntimeProbe {
            kind: RuntimeKind::Container,
            present: true,
            ready: false,
            detail: format!(
                "docker binary at {} — plugin DockerLab cage exists; not yet an OpenShell OCI driver",
                p.display()
            ),
        },
        None => RuntimeProbe {
            kind: RuntimeKind::Container,
            present: false,
            ready: false,
            detail: "docker binary not on PATH".into(),
        },
    }
}

pub fn probe_subprocess_lab() -> RuntimeProbe {
    RuntimeProbe {
        kind: RuntimeKind::SubprocessLab,
        present: true,
        ready: true,
        detail: "lab tier: plugin subprocess + linux_hardening Landlock/seccomp. Weaker than OpenShell or Firecracker. SOAS playground stays this posture.".into(),
    }
}

pub fn probe_openshell() -> RuntimeProbe {
    match bin_on_path("openshell", "CONNECTOR_OPENSHELL_BIN") {
        Some(p) => match run_cli(&p, &["--version".into()], std::time::Duration::from_secs(5)) {
            Ok(out) if out.success => RuntimeProbe {
                kind: RuntimeKind::OpenShell,
                present: true,
                ready: false,
                detail: format!(
                    "openshell --version ok at {} — supervisor bind requires CONNECTOR_OPENSHELL_SANDBOX and a successful `openshell policy set`. stdout: {}",
                    p.display(),
                    truncate(&out.stdout)
                ),
            },
            Ok(out) => RuntimeProbe {
                kind: RuntimeKind::OpenShell,
                present: true,
                ready: false,
                detail: format!(
                    "openshell at {} exited {} — {}",
                    p.display(),
                    out.code,
                    truncate(&out.stderr)
                ),
            },
            Err(e) => RuntimeProbe {
                kind: RuntimeKind::OpenShell,
                present: true,
                ready: false,
                detail: format!("openshell at {} failed to run: {e}", p.display()),
            },
        },
        None => RuntimeProbe {
            kind: RuntimeKind::OpenShell,
            present: false,
            ready: false,
            detail: "not_installed: set CONNECTOR_OPENSHELL_BIN or place openshell on PATH. Connector does not vendor or emulate the supervisor.".into(),
        },
    }
}

/// Create a sandbox with the real `openshell sandbox create --policy` CLI.
/// The command after `--` is `sleep 20`. `true` exits before the supervisor relay
/// and OpenShell marks the sandbox MainProcessExited. A named
/// `CONNECTOR_OPENSHELL_SANDBOX` is left to `policy set`. Exit 0 is created, not a military claim.
pub fn create_openshell_sandbox(yaml: Option<&str>) -> Value {
    let Some(bin) = bin_on_path("openshell", "CONNECTOR_OPENSHELL_BIN") else {
        return json!({"created": false, "ready": false, "reason": "not_installed"});
    };
    let Some(yaml) = yaml.filter(|s| !s.trim().is_empty()) else {
        return json!({"created": false, "ready": false, "reason": "no_contract_projection"});
    };
    if let Some(sandbox) = std::env::var("CONNECTOR_OPENSHELL_SANDBOX")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return json!({
            "created": false,
            "ready": false,
            "sandbox": sandbox,
            "reason": "CONNECTOR_OPENSHELL_SANDBOX already set; use policy set",
            "command": "openshell sandbox create --no-tty --no-auto-providers --policy <file> -- sleep 20",
        });
    }
    let path = std::env::temp_dir().join(format!(
        "connector-openshell-policy-{}.yaml",
        chrono::Utc::now().timestamp_millis()
    ));
    if let Err(e) = std::fs::write(&path, yaml) {
        return json!({"created": false, "ready": false, "reason": format!("write policy: {e}")});
    }
    let result = run_cli(
        &bin,
        &[
            "sandbox".into(),
            "create".into(),
            "--no-tty".into(),
            "--no-auto-providers".into(),
            "--policy".into(),
            path.display().to_string(),
            "--".into(),
            "sleep".into(),
            "20".into(),
        ],
        std::time::Duration::from_secs(90),
    );
    let _ = std::fs::remove_file(&path);
    match result {
        Ok(out) => json!({
            "created": out.success,
            "ready": out.success,
            "exit_code": out.code,
            "stdout": truncate(&out.stdout),
            "stderr": truncate(&out.stderr),
            "command": "openshell sandbox create --no-tty --no-auto-providers --policy <file> -- sleep 20",
            "honesty": "The sandbox id in stdout is a runtime handle, not the agent. Filesystem rules lock at create. Network rules can still be replaced with policy set.",
        }),
        Err(e) => json!({"created": false, "ready": false, "reason": e}),
    }
}

/// Apply the compiled contract with the real `openshell policy set` CLI.
/// No sandbox name means the policy is not pushed. A non-zero exit is not ready.
pub fn push_openshell_policy(yaml: Option<&str>) -> Value {
    let Some(bin) = bin_on_path("openshell", "CONNECTOR_OPENSHELL_BIN") else {
        return json!({
            "pushed": false,
            "ready": false,
            "reason": "not_installed",
        });
    };
    let Some(yaml) = yaml.filter(|s| !s.trim().is_empty()) else {
        return json!({
            "pushed": false,
            "ready": false,
            "reason": "no_contract_projection",
        });
    };
    let sandbox = std::env::var("CONNECTOR_OPENSHELL_SANDBOX")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(sandbox) = sandbox else {
        return json!({
            "pushed": false,
            "ready": false,
            "reason": "CONNECTOR_OPENSHELL_SANDBOX unset",
            "command": "openshell policy set <sandbox> --policy <file> --wait --timeout 20",
        });
    };
    let path = std::env::temp_dir().join(format!(
        "connector-openshell-policy-{}.yaml",
        chrono::Utc::now().timestamp_millis()
    ));
    if let Err(e) = std::fs::write(&path, yaml) {
        return json!({"pushed": false, "ready": false, "reason": format!("write policy: {e}")});
    }
    let result = run_cli(
        &bin,
        &[
            "policy".into(),
            "set".into(),
            sandbox.clone(),
            "--policy".into(),
            path.display().to_string(),
            "--wait".into(),
            "--timeout".into(),
            "20".into(),
        ],
        std::time::Duration::from_secs(25),
    );
    let _ = std::fs::remove_file(&path);
    match result {
        Ok(out) => json!({
            "pushed": out.success,
            "ready": out.success,
            "sandbox": sandbox,
            "exit_code": out.code,
            "stdout": truncate(&out.stdout),
            "stderr": truncate(&out.stderr),
            "command": "openshell policy set <sandbox> --policy <file> --wait --timeout 20",
            "honesty": "OPA inside the OpenShell supervisor evaluates this bundle. Connector does not run a second policy engine.",
        }),
        Err(e) => json!({
            "pushed": false,
            "ready": false,
            "sandbox": sandbox,
            "reason": e,
        }),
    }
}

struct CmdOut {
    success: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(bin: &std::path::Path, args: &[String], timeout: std::time::Duration) -> Result<CmdOut, String> {
    let mut child = std::process::Command::new(bin)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = read_pipe(child.stdout.take());
                let stderr = read_pipe(child.stderr.take());
                return Ok(CmdOut {
                    success: status.success(),
                    code: status.code().unwrap_or(-1),
                    stdout,
                    stderr,
                });
            }
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} timed out after {}s", bin.display(), timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn read_pipe(pipe: Option<impl std::io::Read>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = String::new();
    let _ = std::io::Read::read_to_string(&mut pipe, &mut buf);
    buf
}

fn truncate(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() > 400 {
        let end = t.char_indices().nth(400).map(|(i, _)| i).unwrap_or(t.len());
        format!("{}…", &t[..end])
    } else {
        t.to_string()
    }
}

/// Sigstore cosign. `ready` is true only after `cosign verify-blob` exits 0.
pub fn cosign_status() -> Value {
    let Some(bin) = bin_on_path("cosign", "CONNECTOR_COSIGN_BIN") else {
        return json!({
            "present": false,
            "verified": false,
            "reason": "not_installed",
            "standard": "Sigstore cosign",
            "command": "cosign verify-blob --signature <sig> <blob>",
        });
    };
    let version = run_cli(&bin, &["version".into()], std::time::Duration::from_secs(5));
    let blob = std::env::var("CONNECTOR_COSIGN_BLOB").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let sig = std::env::var("CONNECTOR_COSIGN_SIGNATURE").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let (Some(blob), Some(sig)) = (blob, sig) else {
        return json!({
            "present": true,
            "verified": false,
            "binary": bin.display().to_string(),
            "version": version.as_ref().ok().map(|o| truncate(&o.stdout)),
            "reason": "CONNECTOR_COSIGN_BLOB and CONNECTOR_COSIGN_SIGNATURE unset",
            "standard": "Sigstore cosign",
            "command": "cosign verify-blob --signature <sig> <blob>",
        });
    };
    let mut args = vec!["verify-blob".into(), "--signature".into(), sig];
    if let Some(key) = std::env::var("CONNECTOR_COSIGN_KEY").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        args.push("--key".into());
        args.push(key);
    } else if let Some(cert) = std::env::var("CONNECTOR_COSIGN_CERTIFICATE").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        args.push("--certificate".into());
        args.push(cert);
    }
    args.push(blob);
    match run_cli(&bin, &args, std::time::Duration::from_secs(20)) {
        Ok(out) => json!({
            "present": true,
            "verified": out.success,
            "exit_code": out.code,
            "stdout": truncate(&out.stdout),
            "stderr": truncate(&out.stderr),
            "standard": "Sigstore cosign",
            "command": "cosign verify-blob --signature <sig> [--key <pub>|--certificate <cert>] <blob>",
            "honesty": "verified is the CLI exit code. It is not a release certificate and not a court signature.",
        }),
        Err(e) => json!({
            "present": true,
            "verified": false,
            "reason": e,
            "standard": "Sigstore cosign",
        }),
    }
}

pub fn catalog() -> Value {
    let probes: Vec<Value> = probe_all()
        .into_iter()
        .map(|p| {
            json!({
                "runtime": p.kind.as_str(),
                "present": p.present,
                "ready": p.ready,
                "detail": p.detail,
            })
        })
        .collect();
    json!({
        "schema": "connector.runtime_adapter.v1",
        "ops": ["probe", "create", "exec", "push_policy", "pause", "destroy", "measure"],
        "honesty": "Firecracker create/pause/stop delegate to FirecrackerBackend. OpenShell create runs `openshell sandbox create --no-tty --no-auto-providers --policy <file> -- sleep 20` only when CONNECTOR_OPENSHELL_CREATE=1. policy set runs when CONNECTOR_OPENSHELL_SANDBOX is set. ready=false is not a failure of the report.",
        "runtimes": probes,
    })
}

/// Project [`AgentContractV2`] into an OpenShell policy document (`version: 1`).
/// Comments carry the contract digest and cease generation. OpenShell ignores
/// comments. PATE still admits intent. OPA inside the supervisor evaluates this file.
pub fn compile_openshell_projection(contract: &AgentContractV2, generation: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("# schema: {PROJECTION_SCHEMA}\n"));
    out.push_str("# OpenShell policy schema version 1. Not pushed until `openshell policy set` or `openshell sandbox create --policy` exits 0.\n");
    out.push_str("# authority: Connector PATE admitted the intent. OPA inside OpenShell evaluates this file at the socket.\n");
    out.push_str(&format!("# generation: \"{}\"\n", yaml_escape(generation)));
    out.push_str(&format!(
        "# contract_digest_sha256: \"{}\"\n",
        yaml_escape(&contract.contract_digest_sha256)
    ));
    out.push_str(&format!(
        "# network_default: \"{}\"\n",
        yaml_escape(&contract.network_default)
    ));
    out.push_str(&format!(
        "# denied_operations: {}\n",
        contract
            .denied_operations
            .iter()
            .map(|s| yaml_escape(s))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str("# denied_operations are enforced by the Connector contract. OpenShell process policy has no field for them.\n");
    out.push_str("version: 1\n");
    out.push_str("filesystem_policy:\n");
    let reads = openshell_paths(&contract.filesystem_read);
    let writes = openshell_paths(&contract.filesystem_write);
    if reads.is_empty() {
        out.push_str("  read_only: []\n");
    } else {
        out.push_str("  read_only:\n");
        push_yaml_list(&mut out, &reads);
    }
    if writes.is_empty() {
        out.push_str("  read_write: []\n");
    } else {
        out.push_str("  read_write:\n");
        push_yaml_list(&mut out, &writes);
    }
    out.push_str("network_policies:\n");
    if contract.network_allow.is_empty() {
        out.push_str("  {}\n");
    } else {
        out.push_str("  contract_allow:\n");
        out.push_str("    name: connector-contract\n");
        out.push_str("    endpoints:\n");
        for host in &contract.network_allow {
            let (name, port) = split_host_port(host);
            out.push_str(&format!("      - host: \"{}\"\n", yaml_escape(&name)));
            out.push_str(&format!("        port: {port}\n"));
        }
        out.push_str("    binaries:\n");
        out.push_str("      - path: /usr/bin/**\n");
        out.push_str("      - path: /usr/local/bin/**\n");
        out.push_str("# binaries are not on AgentContractV2. These two prefixes are the supervisor allow until the contract names executables.\n");
    }
    out
}

fn openshell_paths(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|p| {
            let t = p.trim().trim_end_matches("/**").trim_end_matches("**").trim_end_matches('/');
            if t.starts_with('/') && !t.contains("..") && t != "/" {
                Some(t.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn split_host_port(raw: &str) -> (String, u16) {
    let t = raw.trim();
    let t = t.strip_prefix("https://").or_else(|| t.strip_prefix("http://")).unwrap_or(t);
    let t = t.split('/').next().unwrap_or(t);
    if let Some((host, port)) = t.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            if !host.is_empty() {
                return (host.to_string(), p);
            }
        }
    }
    (t.to_string(), 443)
}

fn push_yaml_list(out: &mut String, items: &[String]) {
    if items.is_empty() {
        out.push_str("    []\n");
        return;
    }
    for item in items {
        out.push_str(&format!("    - \"{}\"\n", yaml_escape(item)));
    }
}

fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Cease fan-out. Context-token invalidation already happened in `kernel_cease`.
/// This function seals the memory epoch, stores the policy generation, and pauses
/// a Firecracker MicroCell when one is bound to the agent.
pub fn fanout_cease(state: &PlatformState, agent_pid: &str, generation_next: &str) -> Value {
    let memory = seal_memory_epoch(state, agent_pid, generation_next);
    let pause = pause_microcell_if_bound(state, agent_pid);
    let openshell = probe_openshell();
    let contract = crate::kernel::agent_principal::load_contract(state, agent_pid);
    let projection = contract
        .as_ref()
        .map(|c| compile_openshell_projection(c, generation_next));
    let contract_digest = contract.as_ref().map(|c| c.contract_digest_sha256.clone());
    let create = if std::env::var("CONNECTOR_OPENSHELL_CREATE")
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
    {
        create_openshell_sandbox(projection.as_deref())
    } else {
        json!({
            "created": false,
            "ready": false,
            "reason": "CONNECTOR_OPENSHELL_CREATE unset",
            "command": "openshell sandbox create --no-tty --no-auto-providers --policy <file> -- sleep 20",
        })
    };
    let push = push_openshell_policy(projection.as_deref());
    let logs = read_openshell_sandbox_logs();
    if let Some(line) = logs.get("denial").and_then(|v| v.as_str()) {
        record_openshell_deny_if_pate_proceeded(state, agent_pid, line);
    }
    let projection_stored = store_policy_generation(
        state,
        agent_pid,
        generation_next,
        &openshell,
        &pause,
        projection.as_deref(),
        contract_digest.as_deref(),
        &push,
    );
    json!({
        "schema": "connector.cease_fanout.v1",
        "agent_pid": agent_pid,
        "generation_next": generation_next,
        "context_tokens": "voided_by_kernel_cease",
        "pate": "stale_generation_refused_by_existing_admit_fence",
        "memory_epoch": memory,
        "openshell": {
            "present": openshell.present,
            "ready": openshell.ready,
            "policy": if push.get("pushed").and_then(|v| v.as_bool()) == Some(true) {
                "set_on_supervisor"
            } else if create.get("created").and_then(|v| v.as_bool()) == Some(true) {
                "created_with_policy"
            } else if openshell.present {
                "compiled_not_pushed"
            } else {
                "not_installed"
            },
            "create": create,
            "push": push,
            "logs": logs,
            "tunnels": if push.get("pushed").and_then(|v| v.as_bool()) == Some(true) {
                "policy_generation_reload_requested"
            } else if create.get("created").and_then(|v| v.as_bool()) == Some(true) {
                "sandbox_created_with_this_policy"
            } else {
                "not_cut_no_supervisor_session"
            },
            "detail": openshell.detail,
        },
        "firecracker_pause": pause,
        "policy_generation_stored": projection_stored,
        "contract_digest_sha256": contract_digest,
        "policy_projection_stored": projection.is_some() && projection_stored,
        "honesty": "Operator JWT jti is a separate fence and is not revoked here. Tunnel cut waits on a bound OpenShell supervisor.",
    })
}

/// NVIDIA documents `openshell logs --source sandbox` as the denied-request log.
/// A line is an OpenShell policy denial only when it says `denied` and `by policy`.
pub fn openshell_policy_denial_line(log: &str) -> Option<String> {
    for line in log.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("denied") && lower.contains("by policy") {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub fn read_openshell_sandbox_logs() -> Value {
    let Some(bin) = bin_on_path("openshell", "CONNECTOR_OPENSHELL_BIN") else {
        return json!({
            "read": false,
            "denial": Value::Null,
            "reason": "not_installed",
            "command": "openshell logs --source sandbox",
        });
    };
    match run_cli(
        &bin,
        &["logs".into(), "--source".into(), "sandbox".into()],
        std::time::Duration::from_secs(5),
    ) {
        Ok(out) => {
            let denial = openshell_policy_denial_line(&out.stdout).or_else(|| openshell_policy_denial_line(&out.stderr));
            json!({
                "read": out.success,
                "exit_code": out.code,
                "denial": denial,
                "stdout": truncate(&out.stdout),
                "stderr": truncate(&out.stderr),
                "command": "openshell logs --source sandbox",
                "honesty": "openshell_opa is recorded only from a line that says denied by policy, and only when the latest PATE verdict is proceed.",
            })
        }
        Err(e) => json!({
            "read": false,
            "denial": Value::Null,
            "reason": e,
            "command": "openshell logs --source sandbox",
        }),
    }
}

fn record_openshell_deny_if_pate_proceeded(state: &PlatformState, agent_pid: &str, line: &str) {
    let atu = {
        let Ok(es) = state.engine_store.lock() else {
            return;
        };
        es.folder_get(crate::substrate::pate::ATU_FOLDER, &format!("latest:{agent_pid}"))
            .ok()
            .flatten()
    };
    let Some(atu) = atu else {
        return;
    };
    if atu.get("verdict").and_then(|v| v.as_str()) != Some("proceed") {
        return;
    }
    let task_id = atu.get("task_id").and_then(|v| v.as_str()).unwrap_or("pate_unknown");
    let digest = atu.get("action_digest").and_then(|v| v.as_str()).unwrap_or("");
    crate::substrate::pate::note_runtime_deny_after_admit(
        state,
        agent_pid,
        task_id,
        digest,
        "openshell",
        "openshell_policy_denied",
        line,
    );
}

fn pause_microcell_if_bound(state: &PlatformState, agent_pid: &str) -> Value {
    let Some(inst) = micro_cell::load_for_agent(state, agent_pid) else {
        return json!({
            "attempted": false,
            "result": "no_microcell",
        });
    };
    let result = micro_cell::pause(state, &inst.microcell_id);
    json!({
        "attempted": true,
        "microcell_id": inst.microcell_id,
        "result": result,
    })
}

pub fn seal_memory_epoch(state: &PlatformState, agent_pid: &str, generation_next: &str) -> Value {
    let rec = json!({
        "schema": "connector.memory_epoch_seal.v1",
        "agent_pid": agent_pid,
        "sealed_generation": generation_next,
        "sealed_at_ms": chrono::Utc::now().timestamp_millis(),
        "honesty": "Bytes may remain. Capsule injection is refused while the live broker generation equals sealed_generation.",
    });
    let stored = match state.engine_store.lock() {
        Ok(mut es) => es
            .folder_put(MEMORY_EPOCH_FOLDER, agent_pid, &rec)
            .is_ok(),
        Err(_) => false,
    };
    json!({
        "sealed": stored,
        "sealed_generation": generation_next,
    })
}

fn store_policy_generation(
    state: &PlatformState,
    agent_pid: &str,
    generation_next: &str,
    openshell: &RuntimeProbe,
    pause: &Value,
    projection: Option<&str>,
    contract_digest: Option<&str>,
    push: &Value,
) -> bool {
    let rec = json!({
        "schema": PROJECTION_SCHEMA,
        "agent_pid": agent_pid,
        "generation": generation_next,
        "contract_digest_sha256": contract_digest,
        "projection": projection,
        "openshell_present": openshell.present,
        "openshell_ready": push.get("ready").and_then(|v| v.as_bool()).unwrap_or(false),
        "pushed": push.get("pushed").and_then(|v| v.as_bool()).unwrap_or(false),
        "push": push,
        "firecracker_pause": pause,
        "issued_at_ms": chrono::Utc::now().timestamp_millis(),
        "honesty": "Projection is stored. It is not loaded into an OpenShell supervisor.",
    });
    match state.engine_store.lock() {
        Ok(mut es) => es
            .folder_put(POLICY_GEN_FOLDER, &format!("latest:{agent_pid}"), &rec)
            .is_ok(),
        Err(_) => false,
    }
}

/// Privileged capsule text must not be injected as live context for a sealed generation.
pub fn injection_allowed(state: &crate::state::SharedState, agent_pid: &str) -> bool {
    let live = crate::substrate::llm_context_broker::current_generation(state, agent_pid).to_string();
    let Ok(es) = state.engine_store.lock() else {
        return true;
    };
    let Ok(Some(v)) = es.folder_get(MEMORY_EPOCH_FOLDER, agent_pid) else {
        return true;
    };
    let sealed = v
        .get("sealed_generation")
        .and_then(|g| g.as_str())
        .unwrap_or("");
    sealed != live
}

fn bin_on_path(name: &str, env_key: &str) -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var(env_key) {
        let p = PathBuf::from(explicit.trim());
        if p.is_file() {
            return Some(p);
        }
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contract() -> AgentContractV2 {
        AgentContractV2 {
            schema: "connector.iia.v2".into(),
            agent_id: "cnktr:agent:test".into(),
            issuer: "test".into(),
            purpose: vec!["demo".into()],
            capabilities: vec!["read".into()],
            denied_operations: vec!["ambient_shell".into(), "modify_contract".into()],
            filesystem_read: vec!["/workspace/**".into()],
            filesystem_write: vec!["/workspace/out/**".into()],
            network_allow: vec!["api.example.com".into()],
            network_default: "deny".into(),
            receipt_required: true,
            contract_digest_sha256: "abc123".into(),
            contract_version: 2,
        }
    }

    #[test]
    fn projection_carries_digest_generation_and_deny_default() {
        let yaml = compile_openshell_projection(&sample_contract(), "42");
        assert!(yaml.contains("version: 1"));
        assert!(yaml.contains("# contract_digest_sha256: \"abc123\""));
        assert!(yaml.contains("# generation: \"42\""));
        assert!(yaml.contains("api.example.com"));
        assert!(yaml.contains("port: 443"));
        assert!(yaml.contains("ambient_shell"));
        assert!(yaml.contains("# network_default: \"deny\""));
        assert!(yaml.contains("filesystem_policy:"));
        assert!(yaml.contains("/workspace"));
        assert!(yaml.contains("Not pushed"));
    }

    #[test]
    #[test]
    #[test]
    fn cosign_unconfigured_is_not_verified() {
        let blob = std::env::var("CONNECTOR_COSIGN_BLOB").ok().filter(|s| !s.trim().is_empty());
        let sig = std::env::var("CONNECTOR_COSIGN_SIGNATURE").ok().filter(|s| !s.trim().is_empty());
        if blob.is_some() && sig.is_some() {
            return;
        }
        let v = cosign_status();
        assert_eq!(v.get("verified").and_then(|b| b.as_bool()), Some(false));
        assert_eq!(v.get("standard").and_then(|s| s.as_str()), Some("Sigstore cosign"));
    }

    #[test]
    #[test]
    fn openshell_denial_line_requires_the_policy_phrase() {
        assert_eq!(
            openshell_policy_denial_line("proxy: denied connection to evil.example.com:443 by policy\n"),
            Some("proxy: denied connection to evil.example.com:443 by policy".into())
        );
        assert!(openshell_policy_denial_line("request denied by user\n").is_none());
        assert!(openshell_policy_denial_line("policy loaded\n").is_none());
    }

    #[test]
    fn sandbox_create_does_not_report_success_without_a_policy_file() {
        let v = create_openshell_sandbox(None);
        assert_eq!(v.get("created").and_then(|b| b.as_bool()), Some(false));
        assert_eq!(v.get("ready").and_then(|b| b.as_bool()), Some(false));
    }

    #[test]
    fn policy_push_does_not_report_success_without_a_live_set() {
        let v = push_openshell_policy(None);
        assert_eq!(v.get("pushed").and_then(|b| b.as_bool()), Some(false));
        assert_eq!(v.get("ready").and_then(|b| b.as_bool()), Some(false));
    }

    #[test]
    fn openshell_ready_is_false_even_when_binary_exists() {
        let p = probe_openshell();
        assert!(!p.ready);
        if !p.present {
            assert!(p.detail.contains("not_installed"));
        }
    }

    #[test]
    fn catalog_lists_four_runtimes() {
        let c = catalog();
        let runtimes = c.get("runtimes").and_then(|v| v.as_array()).unwrap();
        assert_eq!(runtimes.len(), 4);
        let names: Vec<&str> = runtimes
            .iter()
            .filter_map(|r| r.get("runtime").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"openshell"));
        assert!(names.contains(&"firecracker"));
        assert!(names.contains(&"container"));
        assert!(names.contains(&"subprocess_lab"));
    }
}
