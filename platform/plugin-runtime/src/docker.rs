use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use serde_json::json;

#[cfg(target_os = "linux")]
use crate::docker_egress::EgressDockerUserGuard;
use crate::docker_egress::{self, LAB_NETWORK};
use crate::error::PluginRuntimeError;
use crate::types::{IsolationRuntime, SpawnReceipt, SpawnRequest};
use crate::PluginIsolationBackend;

#[derive(Debug, Clone)]
pub struct DockerLabBackend {
    image: String,
}

impl DockerLabBackend {
    pub fn new(image: Option<String>) -> Self {
        Self {
            image: image.unwrap_or_else(|| "alpine:3.20".to_string()),
        }
    }
}

fn container_wants_ipv4(tcp_dests: &[(IpAddr, u16)], dns: &[IpAddr]) -> bool {
    tcp_dests.iter().any(|(a, _)| a.is_ipv4())
        || (docker_egress::allow_resolver_dns_from_env() && dns.iter().any(|a| a.is_ipv4()))
}

fn container_wants_ipv6(tcp_dests: &[(IpAddr, u16)], dns: &[IpAddr]) -> bool {
    tcp_dests.iter().any(|(a, _)| a.is_ipv6())
        || (docker_egress::allow_resolver_dns_from_env() && dns.iter().any(|a| a.is_ipv6()))
}

/// Static **`--ip` / `--ip6`** on **`connector_plugin_lab`** for enforce mode.
fn lab_enforce_extra_ips(
    want_v4: bool,
    want_v6: bool,
) -> Result<(Vec<String>, Option<String>, Option<String>), PluginRuntimeError> {
    if !want_v4 && !want_v6 {
        return Err(PluginRuntimeError::DockerLab(
            "egress enforce: no IPv4/IPv6 path (empty allowlist resolution?)".into(),
        ));
    }
    let mut extra = vec!["--network".into(), LAB_NETWORK.into()];
    let mut ip4 = None;
    let mut ip6 = None;
    if want_v4 {
        let s = docker_egress::random_lab_container_ipv4().to_string();
        extra.extend(["--ip".into(), s.clone()]);
        ip4 = Some(s);
    }
    if want_v6 {
        let s = docker_egress::random_lab_container_ipv6().to_string();
        extra.extend(["--ip6".into(), s.clone()]);
        ip6 = Some(s);
    }
    Ok((extra, ip4, ip6))
}

fn normalize_docker_lab_egress_mode(raw: &str) -> String {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || s == "unrestricted" || s == "open" {
        return "unrestricted".into();
    }
    if matches!(s.as_str(), "deny_all" | "deny-all" | "none" | "isolated") {
        return "deny_all".into();
    }
    if matches!(s.as_str(), "allowlist_strict" | "allowlist-strict" | "manifest_strict") {
        return "allowlist_strict".into();
    }
    "unrestricted".into()
}

fn req_env_get<'a>(req: &'a SpawnRequest, key: &str) -> Option<&'a str> {
    req.env
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn env_truthy_val(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// DockLock volatile intelligence plane → docker-grade container security.
fn docklock_docker_security_enabled(req: &SpawnRequest) -> bool {
    if crate::isolation_membrane::membrane_enforced(&req.env) {
        return true;
    }
    for key in [
        "CONNECTOR_DOCKLOCK_DOCKER_SECURITY",
        "CONNECTOR_DOCKLOCK_VOLATILE",
        "CONNECTOR_INTELLIGENCE_EXECUTION_PLANE",
    ] {
        if req_env_get(req, key).map(env_truthy_val).unwrap_or(false) {
            return true;
        }
        if std::env::var(key).map(|v| env_truthy_val(&v)).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Docker CLI args: cap-drop, no-new-privileges, read-only, no devices, private IPC —
/// docker-level security for volatile intelligence (not a persistent process jail).
fn docklock_intelligence_security_args(req: &SpawnRequest) -> Vec<String> {
    if !docklock_docker_security_enabled(req) {
        return vec![];
    }
    // Hardware deny: never pass --privileged / --gpus / --device (implicit by omission).
    let _ = req_env_get(req, "CONNECTOR_DOCKLOCK_HARDWARE");
    vec![
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--read-only".into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,size=64m".into(),
        "--pids-limit".into(),
        "256".into(),
        "--ipc".into(),
        "none".into(),
    ]
}

/// `CONNECTOR_DOCKER_LAB_EGRESS`: prefer SpawnRequest cage env (DockLock), then process env.
/// Under isolation membrane (LLM distrust / exclusivity), force `deny_all` unless break-glass.
/// `unrestricted` (default), `deny_all` (`--network none`),
/// `allowlist_strict` (empty egress_allowlist → `none`; non-empty → bridge, or iptables when enforced).
fn docker_lab_egress_mode(req: Option<&SpawnRequest>) -> String {
    let req_env = req.map(|r| r.env.as_slice()).unwrap_or(&[]);
    if crate::isolation_membrane::force_guest_deny_all(req_env) {
        return "deny_all".into();
    }
    if let Some(req) = req {
        if let Some(v) = req_env_get(req, "CONNECTOR_DOCKER_LAB_EGRESS") {
            return normalize_docker_lab_egress_mode(v);
        }
    }
    let raw = std::env::var("CONNECTOR_DOCKER_LAB_EGRESS").unwrap_or_default();
    normalize_docker_lab_egress_mode(&raw)
}

fn merge_docker_args(security: &[String], extra: &[String]) -> Vec<String> {
    let mut out = security.to_vec();
    out.extend(extra.iter().cloned());
    out
}

fn enrich_egress_allowlist(req: &mut SpawnRequest) {
    if !req.egress_allowlist.is_empty() {
        return;
    }
    let Some(raw) = req_env_get(req, "CONNECTOR_DOCKLOCK_NETWORK_ALLOW").map(str::to_string) else {
        return;
    };
    for part in raw.split(',') {
        let h = part.trim();
        if h.is_empty() {
            continue;
        }
        // Manifest-style capability string for resolve_allowlist_tcp_dests.
        if h.contains("network.outbound:") {
            req.egress_allowlist.push(h.to_string());
        } else if h.contains(':') {
            req.egress_allowlist
                .push(format!("network.outbound:{h}"));
        } else {
            req.egress_allowlist
                .push(format!("network.outbound:{h}:443"));
        }
    }
}

fn container_exe_under_mount(program: &Path, mount: &Path) -> Result<PathBuf, PluginRuntimeError> {
    let rel = program.strip_prefix(mount).map_err(|_| {
        PluginRuntimeError::DockerLab(format!(
            "program {} is not under workspace mount {}",
            program.display(),
            mount.display()
        ))
    })?;
    Ok(PathBuf::from("/connector-plugin").join(rel))
}

fn docker_stderr_suggests_ip_conflict(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("address already in use")
        || s.contains("user specified ip address is supported only if connecting to network with a user configured subnet")
        || s.contains("invalid ip")
        || s.contains("invalid ip address")
}

fn apply_docker_cli_args(cmd: &mut tokio::process::Command, extra_docker_args: &[String]) {
    // Args may be pairs (--flag value) or bare flags; pass through in order.
    for a in extra_docker_args {
        cmd.arg(a);
    }
}

async fn run_docker_lab_foreground(
    image: &str,
    req: &SpawnRequest,
    exe: &str,
    network_none: bool,
    extra_docker_args: &[String],
    guest_env: &[(String, String)],
) -> Result<std::process::Output, PluginRuntimeError> {
    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("run").arg("--rm");
    if let Some(m) = &req.workspace_host_mount {
        cmd.arg("-v")
            .arg(format!("{}:/connector-plugin:ro", m.display()))
            .arg("-w")
            .arg("/connector-plugin");
    }
    apply_docker_cli_args(&mut cmd, extra_docker_args);
    if network_none {
        cmd.arg("--network").arg("none");
    }
    // Guest env must use docker -e (host process env does not enter the container).
    for (k, v) in guest_env {
        cmd.arg("-e").arg(format!("{k}={v}"));
    }
    if let Ok(uds) = std::env::var("CONNECTOR_BROKER_UDS") {
        let uds = uds.trim();
        if !uds.is_empty() && Path::new(uds).exists() {
            cmd.arg("-v").arg(format!("{uds}:/run/connector-broker.sock"));
            cmd.arg("-e").arg("CONNECTOR_BROKER_UDS=/run/connector-broker.sock");
        }
    }
    cmd.arg(image).arg(exe);
    for a in &req.args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::null());
    cmd.output()
        .await
        .map_err(|e| PluginRuntimeError::DockerLab(format!("docker run: {e}")))
}

async fn run_docker_lab_detached_output(
    image: &str,
    req: &SpawnRequest,
    exe: &str,
    network_none: bool,
    extra_docker_args: &[String],
    guest_env: &[(String, String)],
) -> Result<std::process::Output, PluginRuntimeError> {
    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("run").arg("--rm").arg("-d");
    if let Some(m) = &req.workspace_host_mount {
        cmd.arg("-v")
            .arg(format!("{}:/connector-plugin:ro", m.display()))
            .arg("-w")
            .arg("/connector-plugin");
    }
    apply_docker_cli_args(&mut cmd, extra_docker_args);
    if network_none {
        cmd.arg("--network").arg("none");
    }
    for (k, v) in guest_env {
        cmd.arg("-e").arg(format!("{k}={v}"));
    }
    if let Ok(uds) = std::env::var("CONNECTOR_BROKER_UDS") {
        let uds = uds.trim();
        if !uds.is_empty() && Path::new(uds).exists() {
            cmd.arg("-v").arg(format!("{uds}:/run/connector-broker.sock"));
            cmd.arg("-e").arg("CONNECTOR_BROKER_UDS=/run/connector-broker.sock");
        }
    }
    cmd.arg(image).arg(exe);
    for a in &req.args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::null());
    cmd.output()
        .await
        .map_err(|e| PluginRuntimeError::DockerLab(format!("docker run: {e}")))
}

#[async_trait]
impl PluginIsolationBackend for DockerLabBackend {
    fn kind(&self) -> IsolationRuntime {
        IsolationRuntime::DockerLab
    }

    async fn spawn(&self, req: SpawnRequest) -> Result<SpawnReceipt, PluginRuntimeError> {
        let mut req = req;
        let membrane = crate::isolation_membrane::membrane_enforced(&req.env);
        if membrane {
            // Guest cannot hold allowlist destinations — broker-only.
            req.egress_allowlist.clear();
        } else {
            enrich_egress_allowlist(&mut req);
        }
        let guest_env = crate::isolation_membrane::sanitize_guest_env(&req.env);
        req.env = guest_env.clone();
        let mode = docker_lab_egress_mode(Some(&req));
        let security = docklock_intelligence_security_args(&req);
        let network_none = match mode.as_str() {
            "deny_all" => true,
            "allowlist_strict" => req.egress_allowlist.is_empty(),
            _ => false,
        };
        if membrane && !network_none {
            return Err(PluginRuntimeError::DockerLab(
                "isolation membrane refused docker_lab spawn with guest network — set CONNECTOR_ALLOW_GUEST_EGRESS=1 to break-glass".into(),
            ));
        }
        let allowlist_bridge_note =
            mode.as_str() == "allowlist_strict" && !req.egress_allowlist.is_empty();
        if allowlist_bridge_note
            && !docker_egress::egress_enforce_iptables_requested()
            && !req_env_get(&req, "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE")
                .map(|v| {
                    let s = v.trim();
                    s.eq_ignore_ascii_case("iptables")
                        || s.eq_ignore_ascii_case("iptables_docker_user")
                        || s.eq_ignore_ascii_case("docker_user")
                })
                .unwrap_or(false)
            && std::env::var("CONNECTOR_ENV")
                .map(|e| {
                    matches!(
                        e.trim().to_ascii_lowercase().as_str(),
                        "production" | "prod" | "staging" | "hardened"
                    )
                })
                .unwrap_or(false)
        {
            return Err(PluginRuntimeError::DockerLab(
                "allowlist_strict without CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables is open bridge — refused in production".into(),
            ));
        }

        let docklock_iptables = req_env_get(&req, "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE")
            .map(|v| {
                let s = v.trim();
                s.eq_ignore_ascii_case("iptables")
                    || s.eq_ignore_ascii_case("iptables_docker_user")
                    || s.eq_ignore_ascii_case("docker_user")
            })
            .unwrap_or(false);
        let try_iptables = (docker_egress::egress_enforce_iptables_requested() || docklock_iptables)
            && allowlist_bridge_note;

        let exe = match &req.workspace_host_mount {
            Some(m) => container_exe_under_mount(&req.program, m)?.to_string_lossy().into_owned(),
            None => req.program.to_string_lossy().to_string(),
        };

        if try_iptables && !req.docker_run_detached {
            #[cfg(target_os = "linux")]
            {
                let tcp_dests =
                    docker_egress::resolve_allowlist_tcp_dests(&req.egress_allowlist).await?;
                let dns: Vec<_> = if docker_egress::allow_resolver_dns_from_env() {
                    docker_egress::resolv_conf_nameservers()
                } else {
                    vec![]
                };
                let want_v4 = container_wants_ipv4(&tcp_dests, &dns);
                let want_v6 = container_wants_ipv6(&tcp_dests, &dns);
                docker_egress::ensure_lab_bridge_network(want_v6).await?;

                const MAX_IP_TRIES: u32 = 12;
                for attempt in 0..MAX_IP_TRIES {
                    let (extra, ip4_s, ip6_s) = lab_enforce_extra_ips(want_v4, want_v6)?;
                    let docker_args = merge_docker_args(&security, &extra);
                    let guard = EgressDockerUserGuard::apply(
                        ip4_s.as_deref(),
                        ip6_s.as_deref(),
                        &tcp_dests,
                        &dns,
                    )?;
                    let out = run_docker_lab_foreground(
                        &self.image,
                        &req,
                        &exe,
                        false,
                        &docker_args,
                        &guest_env,
                    )
                    .await;
                    drop(guard);
                    let out = match out {
                        Ok(o) => o,
                        Err(e) => return Err(e),
                    };
                    if out.status.success() {
                        let note = "docklock intelligence + allowlist_strict + iptables DOCKER-USER (foreground)";
                        return Ok(SpawnReceipt {
                            backend: "docker_lab".into(),
                            plugin_id: req.plugin_id,
                            detail: json!({
                                "image": self.image,
                                "phase": "5.7.2",
                                "egress_mode": mode,
                                "docklock_docker_security": !security.is_empty(),
                                "security_grade": "docker_intelligence",
                                "network_isolated": false,
                                "egress_allowlist_len": req.egress_allowlist.len(),
                                "egress_enforce": "iptables_docker_user",
                                "lab_network": LAB_NETWORK,
                                "container_ipv4": ip4_s,
                                "container_ipv6": ip6_s,
                                "foreground": true,
                                "exit_code": out.status.code(),
                                "note": note,
                            }),
                        });
                    }
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if attempt + 1 < MAX_IP_TRIES && docker_stderr_suggests_ip_conflict(&stderr) {
                        continue;
                    }
                    return Err(PluginRuntimeError::DockerLab(format!(
                        "docker run exit {:?}: {}",
                        out.status.code(),
                        stderr
                    )));
                }
                return Err(PluginRuntimeError::DockerLab(
                    "docker_lab: exhausted retries for static --ip/--ip6 (address collisions)".into(),
                ));
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(PluginRuntimeError::DockerLab(
                    "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables requires a Linux host".into(),
                ));
            }
        }

        if try_iptables && req.docker_run_detached {
            #[cfg(target_os = "linux")]
            {
                let tcp_dests =
                    docker_egress::resolve_allowlist_tcp_dests(&req.egress_allowlist).await?;
                let dns: Vec<_> = if docker_egress::allow_resolver_dns_from_env() {
                    docker_egress::resolv_conf_nameservers()
                } else {
                    vec![]
                };
                let want_v4 = container_wants_ipv4(&tcp_dests, &dns);
                let want_v6 = container_wants_ipv6(&tcp_dests, &dns);
                docker_egress::ensure_lab_bridge_network(want_v6).await?;

                const MAX_IP_TRIES: u32 = 12;
                for attempt in 0..MAX_IP_TRIES {
                    let (extra, ip4_s, ip6_s) = lab_enforce_extra_ips(want_v4, want_v6)?;
                    let docker_args = merge_docker_args(&security, &extra);
                    let out = run_docker_lab_detached_output(
                        &self.image,
                        &req,
                        &exe,
                        false,
                        &docker_args,
                        &guest_env,
                    )
                    .await?;
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        if attempt + 1 < MAX_IP_TRIES && docker_stderr_suggests_ip_conflict(&stderr)
                        {
                            continue;
                        }
                        return Err(PluginRuntimeError::DockerLab(format!(
                            "docker run -d exit {:?}: {}",
                            out.status.code(),
                            stderr
                        )));
                    }
                    let cid = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if cid.is_empty() {
                        return Err(PluginRuntimeError::DockerLab(
                            "docker run -d returned empty container id".into(),
                        ));
                    }
                    let guard = match EgressDockerUserGuard::apply(
                        ip4_s.as_deref(),
                        ip6_s.as_deref(),
                        &tcp_dests,
                        &dns,
                    ) {
                        Ok(g) => g,
                        Err(e) => {
                            let _ = tokio::process::Command::new("docker")
                                .args(["rm", "-f", &cid])
                                .status()
                                .await;
                            return Err(e);
                        }
                    };
                    let note = "docklock intelligence + allowlist_strict + iptables DOCKER-USER (detached)";
                    let cid_wait = cid.clone();
                    tokio::spawn(async move {
                        let _g = guard;
                        let _ = tokio::process::Command::new("docker")
                            .args(["wait", &cid_wait])
                            .status()
                            .await;
                    });
                    return Ok(SpawnReceipt {
                        backend: "docker_lab".into(),
                        plugin_id: req.plugin_id,
                        detail: json!({
                            "container_id": cid,
                            "container_handle": cid,
                            "image": self.image,
                            "phase": "5.7.2",
                            "egress_mode": mode,
                            "docklock_docker_security": !security.is_empty(),
                            "security_grade": "docker_intelligence",
                            "network_isolated": false,
                            "egress_allowlist_len": req.egress_allowlist.len(),
                            "egress_enforce": "iptables_docker_user",
                            "lab_network": LAB_NETWORK,
                            "container_ipv4": ip4_s,
                            "container_ipv6": ip6_s,
                            "foreground": false,
                            "note": note,
                        }),
                    });
                }
                return Err(PluginRuntimeError::DockerLab(
                    "docker_lab: exhausted retries for detached static --ip/--ip6".into(),
                ));
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(PluginRuntimeError::DockerLab(
                    "CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables requires a Linux host".into(),
                ));
            }
        }

        let note: String = if membrane {
            "isolation membrane: --network none + docker-grade caps; guest has no ambient egress; effects via Connector broker only".into()
        } else if !security.is_empty() {
            "DockLock volatile intelligence cage: docker-grade caps/read-only/ipc=none + egress mode".into()
        } else if allowlist_bridge_note {
            "allowlist_strict: non-empty manifest allowlist uses default bridge; set CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE=iptables on Linux for DOCKER-USER enforcement (foreground or detached)".into()
        } else {
            "Lab-only convenience; CONNECTOR_DOCKER_LAB_EGRESS controls docker --network".into()
        };

        if req.docker_run_detached {
            let out = run_docker_lab_detached_output(
                &self.image,
                &req,
                &exe,
                network_none,
                &security,
                &guest_env,
            )
            .await?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                return Err(PluginRuntimeError::DockerLab(format!(
                    "docker run -d exit {:?}: {}",
                    out.status.code(),
                    stderr
                )));
            }
            let cid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if cid.is_empty() {
                return Err(PluginRuntimeError::DockerLab(
                    "docker run -d returned empty container id".into(),
                ));
            }
            Ok(SpawnReceipt {
                backend: "docker_lab".into(),
                plugin_id: req.plugin_id,
                detail: json!({
                    "container_id": cid,
                    "container_handle": cid,
                    "image": self.image,
                    "phase": "5.2",
                    "egress_mode": mode,
                    "docklock_docker_security": !security.is_empty(),
                    "security_grade": if security.is_empty() { "lab" } else { "docker_intelligence" },
                    "network_isolated": network_none,
                    "egress_allowlist_len": req.egress_allowlist.len(),
                    "foreground": false,
                    "isolation_membrane": crate::isolation_membrane::membrane_status(&guest_env),
                    "note": note,
                }),
            })
        } else {
            let out = run_docker_lab_foreground(
                &self.image,
                &req,
                &exe,
                network_none,
                &security,
                &guest_env,
            )
            .await?;
            if !out.status.success() {
                return Err(PluginRuntimeError::DockerLab(format!(
                    "docker run exit {:?}: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            Ok(SpawnReceipt {
                backend: "docker_lab".into(),
                plugin_id: req.plugin_id,
                detail: json!({
                    "image": self.image,
                    "phase": "5.2",
                    "egress_mode": mode,
                    "docklock_docker_security": !security.is_empty(),
                    "security_grade": if security.is_empty() { "lab" } else { "docker_intelligence" },
                    "network_isolated": network_none,
                    "egress_allowlist_len": req.egress_allowlist.len(),
                    "foreground": true,
                    "exit_code": out.status.code(),
                    "isolation_membrane": crate::isolation_membrane::membrane_status(&guest_env),
                    "note": note,
                }),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_req(env: Vec<(String, String)>) -> SpawnRequest {
        SpawnRequest {
            plugin_id: "p".into(),
            program: PathBuf::from("/bin/true"),
            args: vec![],
            cwd: None,
            env,
            egress_allowlist: vec![],
            workspace_host_mount: None,
            docker_run_detached: false,
        }
    }

    #[test]
    fn docklock_cage_env_enables_security_args() {
        let req = sample_req(vec![
            ("CONNECTOR_DOCKLOCK_VOLATILE".into(), "1".into()),
            ("CONNECTOR_DOCKER_LAB_EGRESS".into(), "deny_all".into()),
        ]);
        let args = docklock_intelligence_security_args(&req);
        assert!(args.iter().any(|a| a == "--cap-drop"));
        assert!(args.iter().any(|a| a == "ALL"));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert!(args.iter().any(|a| a == "--ipc"));
        assert_eq!(docker_lab_egress_mode(Some(&req)), "deny_all");
    }

    #[test]
    fn network_allow_env_enriches_allowlist() {
        let mut req = sample_req(vec![(
            "CONNECTOR_DOCKLOCK_NETWORK_ALLOW".into(),
            "api.example.com,other:8443".into(),
        )]);
        enrich_egress_allowlist(&mut req);
        assert_eq!(req.egress_allowlist.len(), 2);
        assert!(req.egress_allowlist[0].contains("api.example.com"));
        assert!(req.egress_allowlist[1].contains("8443"));
    }

    #[test]
    fn membrane_forces_deny_all_even_if_unrestricted() {
        let req = sample_req(vec![
            ("CONNECTOR_LLM_DISTRUST".into(), "1".into()),
            ("CONNECTOR_DOCKER_LAB_EGRESS".into(), "unrestricted".into()),
        ]);
        assert_eq!(docker_lab_egress_mode(Some(&req)), "deny_all");
        assert!(!docklock_intelligence_security_args(&req).is_empty());
    }
}
