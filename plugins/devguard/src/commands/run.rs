//! `devguard run` — bind a local process to native origin-binding APIs, then exec.
//!
//! Thin stub: stamps CONNECTOR_* UIDs into the child environment. Does not redistribute
//! Cursor (or any editor). Full cgroup/pidfd birth control is M1 WIP.

use anyhow::{Context, Result};
use crate::connector_client::ConnectorClient;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

pub const DEFAULT_CONTRACT: &str = "dev-agent-v1";
pub const DEFAULT_COMMAND: &str = "cursor";
pub const DEFAULT_PRINCIPAL: &str = "local-principal";
pub const DEFAULT_TENANT: &str = "local";

#[derive(Debug, Clone)]
pub struct RunArgs {
    pub birth_controlled: bool,
    pub contract: Option<String>,
    pub agent_pid: Option<String>,
    pub dry_bind: bool,
    pub command: Vec<String>,
}

/// Resolve argv; empty → default `cursor`.
pub fn resolve_command(args: &[String]) -> Vec<String> {
    if args.is_empty() {
        vec![DEFAULT_COMMAND.to_string()]
    } else {
        args.to_vec()
    }
}

/// Contract flag or `dev-agent-v1`.
pub fn resolve_contract(contract: Option<&str>) -> String {
    contract
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_CONTRACT)
        .to_string()
}

/// Declared software name from the executable (basename of argv[0]).
pub fn declared_name_from_command(command: &[String]) -> String {
    command
        .first()
        .map(|c| {
            Path::new(c)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(c.as_str())
                .to_string()
        })
        .unwrap_or_else(|| DEFAULT_COMMAND.to_string())
}

pub fn resolve_principal() -> String {
    std::env::var("CONNECTOR_PRINCIPAL")
        .or_else(|_| std::env::var("DEVGUARD_IDENTITY"))
        .or_else(|_| std::env::var("CONNECTOR_AGENT_IDENTITY"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_PRINCIPAL.to_string())
}

pub fn resolve_tenant() -> String {
    std::env::var("CONNECTOR_TENANT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_TENANT.to_string())
}

/// Gateway from `CONNECTOR_URL`, else `.devguard/connector.json`, else CLI fallback.
pub fn resolve_gateway_base(cli_fallback: &str) -> String {
    if let Ok(url) = std::env::var("CONNECTOR_URL") {
        let t = url.trim();
        if !t.is_empty() {
            return t.trim_end_matches('/').to_string();
        }
    }
    if let Some(path) = find_connector_link() {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                if let Some(base) = v.get("gateway_base").and_then(|x| x.as_str()) {
                    let t = base.trim();
                    if !t.is_empty() {
                        return t.trim_end_matches('/').to_string();
                    }
                }
            }
        }
    }
    cli_fallback.trim_end_matches('/').to_string()
}

fn find_connector_link() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..8 {
        let p = dir.join(".devguard/connector.json");
        if p.is_file() {
            return Some(p);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

pub fn build_soft_bind_body(
    declared_name: &str,
    executable_selector: &str,
    contract_ref: &str,
    agent_pid: Option<&str>,
    tenant: &str,
) -> Value {
    let mut body = json!({
        "tenant": tenant,
        "declared_name": declared_name,
        "executable_selector": executable_selector,
        "contract_ref": contract_ref,
        "mode": "attached",
        "adapters": [],
        "enforcement_requirements": [],
    });
    if let Some(pid) = agent_pid.map(str::trim).filter(|s| !s.is_empty()) {
        body["agent_pid"] = json!(pid);
    }
    body
}

pub fn build_workload_body(
    software_uid: &str,
    birth_controlled: bool,
    agent_pid: Option<&str>,
) -> Value {
    let mut body = json!({
        "software_uid": software_uid,
        "birth_controlled": birth_controlled,
    });
    if let Some(pid) = agent_pid.map(str::trim).filter(|s| !s.is_empty()) {
        body["agent_pid"] = json!(pid);
    }
    body
}

pub fn build_intelligence_body(
    workload_uid: &str,
    principal: &str,
    contract_ref: &str,
    agent_pid: Option<&str>,
) -> Value {
    let mut body = json!({
        "workload_uid": workload_uid,
        "principal": principal,
        "contract_ref": contract_ref,
    });
    if let Some(pid) = agent_pid.map(str::trim).filter(|s| !s.is_empty()) {
        body["agent_pid"] = json!(pid);
    }
    body
}

/// Client-facing posture: never claim TransportEnforced without a future kernel confirm.
pub fn client_claimed_posture(_birth_controlled: bool) -> &'static str {
    "advisory"
}

pub fn honesty_note(birth_controlled: bool) -> String {
    if birth_controlled {
        "birth_controlled requested but host confinement (cgroup/pidfd) is M1 WIP; \
         TransportEnforced is not claimed without kernel birth confirm"
            .into()
    } else {
        "Attached bind defaults to Advisory; TransportEnforced requires proven birth control"
            .into()
    }
}

pub fn build_summary(
    software_uid: &str,
    workload_uid: &str,
    intelligence_uid: &str,
    birth_controlled: bool,
    registered_posture: Option<&str>,
) -> Value {
    let mut summary = json!({
        "software_uid": software_uid,
        "workload_uid": workload_uid,
        "intelligence_uid": intelligence_uid,
        "enforcement_posture": client_claimed_posture(birth_controlled),
        "birth_controlled": birth_controlled,
        "honesty": honesty_note(birth_controlled),
    });
    if let Some(p) = registered_posture.map(str::trim).filter(|s| !s.is_empty()) {
        summary["workload_registered_posture"] = json!(p);
    }
    summary
}

fn extract_uid(resp: &Value, object_key: &str, uid_key: &str) -> Result<String> {
    if let Some(err) = resp.get("error").and_then(|v| v.as_str()) {
        anyhow::bail!("{} failed: {}", object_key, err);
    }
    resp.get(object_key)
        .and_then(|o| o.get(uid_key))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            resp.get(uid_key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .with_context(|| format!("missing {uid_key} in {object_key} response"))
}

fn extract_registered_posture(resp: &Value) -> Option<String> {
    resp.get("workload")
        .and_then(|w| w.get("enforcement_posture"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub async fn run(client_fallback_url: &str, args: RunArgs) -> Result<()> {
    let command = resolve_command(&args.command);
    let contract_ref = resolve_contract(args.contract.as_deref());
    let declared_name = declared_name_from_command(&command);
    let executable_selector = command.first().cloned().unwrap_or_else(|| DEFAULT_COMMAND.into());
    let principal = resolve_principal();
    let tenant = resolve_tenant();
    let agent_pid = args.agent_pid.as_deref();

    let gateway = resolve_gateway_base(client_fallback_url);
    let mut client = ConnectorClient::new(&gateway);
    if let Ok(token) = std::env::var("CONNECTOR_AGENT_TOKEN")
        .or_else(|_| std::env::var("DEVGUARD_TOKEN"))
    {
        if token.trim().starts_with("cg_") {
            client.set_bearer_token(Some(token));
        }
    }

    let soft_body = build_soft_bind_body(
        &declared_name,
        &executable_selector,
        &contract_ref,
        agent_pid,
        &tenant,
    );
    let soft_resp = client
        .native_bind_software(&soft_body)
        .await
        .with_context(|| "POST /api/v1/native/software/bind")?;
    let software_uid = extract_uid(&soft_resp, "software", "software_uid")?;

    let wl_body = build_workload_body(&software_uid, args.birth_controlled, agent_pid);
    let wl_resp = client
        .native_register_workload(&wl_body)
        .await
        .with_context(|| "POST /api/v1/native/workloads")?;
    let workload_uid = extract_uid(&wl_resp, "workload", "workload_uid")?;
    let registered_posture = extract_registered_posture(&wl_resp);

    let intel_body =
        build_intelligence_body(&workload_uid, &principal, &contract_ref, agent_pid);
    let intel_resp = client
        .native_register_intelligence(&intel_body)
        .await
        .with_context(|| "POST /api/v1/native/intelligence")?;
    let intelligence_uid = extract_uid(&intel_resp, "intelligence", "intelligence_uid")?;

    let summary = build_summary(
        &software_uid,
        &workload_uid,
        &intelligence_uid,
        args.birth_controlled,
        registered_posture.as_deref(),
    );
    println!("{}", serde_json::to_string_pretty(&summary)?);

    if args.dry_bind {
        return Ok(());
    }

    if args.birth_controlled {
        eprintln!(
            "warning: --birth-controlled: full cgroup/pidfd confinement is M1 WIP; \
             currently execs with stamped env only. Host confinement is not yet proven."
        );
    }

    exec_with_stamps(&command, &software_uid, &workload_uid, &intelligence_uid, &contract_ref)
}

fn exec_with_stamps(
    command: &[String],
    software_uid: &str,
    workload_uid: &str,
    intelligence_uid: &str,
    contract_ref: &str,
) -> Result<()> {
    let (prog, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty command"))?;

    let mut cmd = Command::new(prog);
    cmd.args(args);
    cmd.env("CONNECTOR_SOFTWARE_UID", software_uid);
    cmd.env("CONNECTOR_WORKLOAD_UID", workload_uid);
    cmd.env("CONNECTOR_INTELLIGENCE_UID", intelligence_uid);
    cmd.env("CONNECTOR_CONTRACT_REF", contract_ref);
    cmd.env("CONNECTOR_ENFORCEMENT_POSTURE", client_claimed_posture(false));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow::Error::new(err).context(format!("exec {prog}")))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("spawn {prog}"))?;
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!("{prog} exited with {status}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_command_is_cursor() {
        assert_eq!(resolve_command(&[]), vec!["cursor"]);
        assert_eq!(
            resolve_command(&[String::from("code"), String::from(".")]),
            vec!["code", "."]
        );
    }

    #[test]
    fn default_contract_is_dev_agent_v1() {
        assert_eq!(resolve_contract(None), "dev-agent-v1");
        assert_eq!(resolve_contract(Some("")), "dev-agent-v1");
        assert_eq!(resolve_contract(Some("  ")), "dev-agent-v1");
        assert_eq!(resolve_contract(Some("my-contract")), "my-contract");
    }

    #[test]
    fn declared_name_uses_basename() {
        assert_eq!(
            declared_name_from_command(&[String::from("/usr/bin/cursor")]),
            "cursor"
        );
        assert_eq!(
            declared_name_from_command(&[String::from("windsurf")]),
            "windsurf"
        );
    }

    #[test]
    fn soft_bind_body_is_attached_mode() {
        let body = build_soft_bind_body("cursor", "cursor", "dev-agent-v1", Some("agent_1"), "local");
        assert_eq!(body["mode"], "attached");
        assert_eq!(body["declared_name"], "cursor");
        assert_eq!(body["contract_ref"], "dev-agent-v1");
        assert_eq!(body["agent_pid"], "agent_1");
        assert_eq!(body["tenant"], "local");
    }

    #[test]
    fn workload_body_defaults_birth_controlled_false() {
        let body = build_workload_body("sw_abc", false, None);
        assert_eq!(body["software_uid"], "sw_abc");
        assert_eq!(body["birth_controlled"], false);
        assert!(body.get("agent_pid").is_none());
    }

    #[test]
    fn intelligence_body_carries_principal_and_contract() {
        let body = build_intelligence_body("wl_1", "local-principal", "dev-agent-v1", None);
        assert_eq!(body["workload_uid"], "wl_1");
        assert_eq!(body["principal"], "local-principal");
        assert_eq!(body["contract_ref"], "dev-agent-v1");
    }

    #[test]
    fn summary_never_claims_transport_enforced() {
        let with_bc = build_summary("sw", "wl", "intel", true, Some("transport_enforced"));
        assert_eq!(with_bc["enforcement_posture"], "advisory");
        assert_eq!(with_bc["workload_registered_posture"], "transport_enforced");
        assert!(with_bc["honesty"]
            .as_str()
            .unwrap()
            .contains("not claimed"));

        let without = build_summary("sw", "wl", "intel", false, Some("advisory"));
        assert_eq!(without["enforcement_posture"], "advisory");
        assert!(without["honesty"]
            .as_str()
            .unwrap()
            .contains("Advisory"));
    }
}
