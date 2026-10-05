//! Phase **5.7.2** — Windows **WSL2** microVM egress: run TAP + **`iptables` / `ip6tables`** **inside** the distro
//! when **`CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables`** (parity with native Linux `microvm_egress_linux`).

use std::path::{Path, PathBuf};

use connector_microvm::NetworkIfaceConfig;
use serde_json::{json, Value};
use tokio::process::Command;

use crate::docker_egress;
use crate::error::PluginRuntimeError;

const WSL_EGRESS_APPLY_PY: &str = include_str!("../assets/connector-microvm-wsl-egress-apply.py");

/// True when **`wsl.exe -d <distro>`** can run **`iptables`** + **`ip`** (and **`ip6tables`** if any **`AAAA`** caps resolve).
#[inline]
pub(crate) fn wsl_distro_supports_iptables_enforce(distro: &str, needs_v6: bool) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let probe = if needs_v6 {
        "command -v iptables >/dev/null 2>&1 && command -v ip >/dev/null 2>&1 && command -v ip6tables >/dev/null 2>&1 && iptables -V >/dev/null 2>&1 && ip6tables -V >/dev/null 2>&1"
    } else {
        "command -v iptables >/dev/null 2>&1 && command -v ip >/dev/null 2>&1 && iptables -V >/dev/null 2>&1"
    };
    let out = std::process::Command::new("wsl.exe")
        .args(["-d", distro, "--", "bash", "-lc", probe])
        .status();
    matches!(out, Ok(s) if s.success())
}

pub(crate) fn materialize_wsl_egress_apply_script() -> Result<PathBuf, PluginRuntimeError> {
    if let Ok(p) = std::env::var("CONNECTOR_WSL_EGRESS_APPLY") {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return Ok(pb);
        }
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "wsl_egress_apply_missing".into(),
            detail: format!("CONNECTOR_WSL_EGRESS_APPLY is not a file: {}", pb.display()),
        });
    }
    let path = std::env::temp_dir().join("connector-microvm-wsl-egress-apply.py");
    std::fs::write(&path, WSL_EGRESS_APPLY_PY.as_bytes()).map_err(|e| PluginRuntimeError::MicrovmWsl {
        code: "wsl_egress_apply_materialize".into(),
        detail: e.to_string(),
    })?;
    Ok(path)
}

fn allow_resolver_dns_from_env() -> bool {
    let raw = std::env::var("CONNECTOR_MICROVM_ALLOW_RESOLVER_DNS")
        .or_else(|_| std::env::var("CONNECTOR_DOCKER_LAB_ALLOW_RESOLVER_DNS"))
        .unwrap_or_else(|_| "1".into());
    let s = raw.trim().to_ascii_lowercase();
    !matches!(s.as_str(), "0" | "off" | "false" | "no")
}

fn parse_last_json_line(stdout: &[u8]) -> Value {
    for raw in stdout.split(|b| *b == b'\n').rev() {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            return v;
        }
    }
    json!({})
}

/// Run egress setup inside WSL; returns **`network_iface`**, **`ip=`** boot fragment, and telemetry (**`detail`**).
pub(crate) async fn apply_wsl_microvm_tap_egress(
    distro: &str,
    vm_id: &str,
    allowlist: &[String],
    script_host_path: &Path,
    win_path_to_wsl: impl Fn(&str, &Path) -> Result<String, PluginRuntimeError>,
) -> Result<(NetworkIfaceConfig, String, Value), PluginRuntimeError> {
    let tcp_dests = docker_egress::resolve_allowlist_tcp_dests(allowlist)
        .await
        .map_err(|e| PluginRuntimeError::MicrovmWsl {
            code: "egress_dns".into(),
            detail: e.to_string(),
        })?;
    let mut v4: Vec<(String, u16)> = Vec::new();
    let mut v6: Vec<(String, u16)> = Vec::new();
    use std::net::IpAddr;
    for (a, p) in tcp_dests {
        match a {
            IpAddr::V4(v) => v4.push((v.to_string(), p)),
            IpAddr::V6(v) => v6.push((v.to_string(), p)),
        }
    }
    v4.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    v4.dedup();
    v6.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    v6.dedup();
    if v4.is_empty() && v6.is_empty() {
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "egress_no_dests".into(),
            detail: "no TCP destinations after DNS resolution".into(),
        });
    }

    let spec = json!({
        "vm_id": vm_id,
        "v4": v4.iter().map(|(a,p)| json!([a, p])).collect::<Vec<_>>(),
        "v6": v6.iter().map(|(a,p)| json!([a, p])).collect::<Vec<_>>(),
        "allow_resolver_dns": allow_resolver_dns_from_env(),
    });
    let host_json = std::env::temp_dir().join(format!("connector-wsl-egress-{vm_id}.json"));
    std::fs::write(&host_json, serde_json::to_vec_pretty(&spec).map_err(|e| PluginRuntimeError::MicrovmWsl {
        code: "egress_spec_write".into(),
        detail: e.to_string(),
    })?)
    .map_err(|e| PluginRuntimeError::MicrovmWsl {
        code: "egress_spec_write".into(),
        detail: e.to_string(),
    })?;

    let json_wsl = win_path_to_wsl(distro, &host_json)?;
    let script_wsl = win_path_to_wsl(distro, script_host_path)?;
    let py = std::env::var("CONNECTOR_WSL_PYTHON").unwrap_or_else(|_| "python3".into());

    let out = Command::new("wsl.exe")
        .arg("-d")
        .arg(distro)
        .arg("--")
        .arg(&py)
        .arg(&script_wsl)
        .arg(&json_wsl)
        .output()
        .await
        .map_err(|e| PluginRuntimeError::MicrovmWsl {
            code: "wsl_egress_exec".into(),
            detail: e.to_string(),
        })?;

    let parsed = parse_last_json_line(&out.stdout);
    if !out.status.success() || parsed.get("ok") != Some(&json!(true)) {
        let msg = parsed
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or_else(|| {
                if out.status.success() {
                    "wsl egress apply returned non-ok"
                } else {
                    "wsl egress apply process failed"
                }
            });
        let code = parsed
            .get("code")
            .and_then(|c| c.as_str())
            .unwrap_or("apply_failed");
        return Err(PluginRuntimeError::MicrovmWsl {
            code: code.to_string(),
            detail: format!(
                "{msg} stderr={}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }

    let iface_id = parsed
        .get("network_iface")
        .and_then(|n| n.get("iface_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("eth0")
        .to_string();
    let host_dev = parsed
        .get("network_iface")
        .and_then(|n| n.get("host_dev_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if host_dev.is_empty() {
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "egress_bad_iface".into(),
            detail: "apply script returned empty host_dev_name".into(),
        });
    }
    let ip_boot = parsed
        .get("ip_boot_arg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if ip_boot.is_empty() {
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "egress_bad_boot".into(),
            detail: "apply script returned empty ip_boot_arg".into(),
        });
    }
    let detail = parsed.get("detail").cloned().unwrap_or(json!({}));
    Ok((
        NetworkIfaceConfig {
            iface_id,
            host_dev_name: host_dev,
        },
        ip_boot,
        detail,
    ))
}

/// Fire-and-forget cleanup inside WSL when Firecracker PID exits (paths must be **WSL** `wslpath` forms).
pub(crate) fn spawn_wsl_egress_cleanup_watcher(
    distro: &str,
    py: &str,
    script_wsl: &str,
    detail_json_wsl: &str,
    firecracker_pid: u32,
) {
    if !cfg!(windows) || firecracker_pid == 0 {
        return;
    }
    let _ = std::process::Command::new("wsl.exe")
        .arg("-d")
        .arg(distro)
        .arg("--")
        .arg(py)
        .arg(script_wsl)
        .arg("--cleanup-watch")
        .arg("--watch-pid")
        .arg(firecracker_pid.to_string())
        .arg("--detail-json")
        .arg(detail_json_wsl)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
