use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use async_trait::async_trait;
use connector_microvm::{BootSource, Drive, FirecrackerVmConfig, GuestMachineConfig, MicrovmHost, NetworkIfaceConfig, VsockConfig};
use serde_json::json;

use crate::error::PluginRuntimeError;
use crate::types::{IsolationRuntime, SpawnReceipt, SpawnRequest};
use crate::PluginIsolationBackend;

const WSL_LAUNCHER_PY: &str = include_str!("../assets/connector-microvm-wsl-launch.py");

#[derive(Debug, Clone)]
pub struct MicrovmPluginBackend {
    host: MicrovmHost,
}

impl MicrovmPluginBackend {
    pub fn new(api_socket: Option<PathBuf>) -> Self {
        let firecracker_bin = std::env::var("CONNECTOR_FIRECRACKER_BIN").ok().map(PathBuf::from);
        Self {
            host: MicrovmHost::new(api_socket).with_firecracker_bin(firecracker_bin),
        }
    }
}

#[async_trait]
impl PluginIsolationBackend for MicrovmPluginBackend {
    fn kind(&self) -> IsolationRuntime {
        IsolationRuntime::Microvm
    }

    async fn spawn(&self, req: SpawnRequest) -> Result<SpawnReceipt, PluginRuntimeError> {
        let membrane = crate::isolation_membrane::membrane_enforced(&req.env);
        let mut req = req;
        if membrane {
            req.egress_allowlist.clear();
            req.env = crate::isolation_membrane::sanitize_guest_env(&req.env);
        }
        let egress_mode = if membrane {
            "deny_all"
        } else {
            microvm_egress_mode()
        };
        let validated_egress = validate_microvm_egress_policy(egress_mode, &req.egress_allowlist)?;
        let egress_enforce = if membrane {
            "none"
        } else {
            microvm_egress_enforce_mode()
        };
        let egress_needs_host_enforcement =
            !membrane && egress_mode != "deny_all" && !req.egress_allowlist.is_empty();
        let vm_id = req
            .plugin_id
            .replace('/', "_")
            .replace(':', "_")
            .replace('.', "_");
        let kernel_path = std::env::var("CONNECTOR_MICROVM_KERNEL")
            .ok()
            .or_else(|| option_env!("CONNECTOR_VENDORED_MICROVM_KERNEL_PATH").map(|s| s.to_string()))
            .ok_or_else(|| {
                PluginRuntimeError::Microvm(
                    "missing kernel path; set CONNECTOR_MICROVM_KERNEL or provide vendored kernel".into(),
                )
            })?;
        let rootfs_path = std::env::var("CONNECTOR_MICROVM_ROOTFS")
            .ok()
            .or_else(|| option_env!("CONNECTOR_VENDORED_MICROVM_ROOTFS_PATH").map(|s| s.to_string()))
            .ok_or_else(|| {
                PluginRuntimeError::Microvm(
                    "missing rootfs path; set CONNECTOR_MICROVM_ROOTFS or provide vendored rootfs".into(),
                )
            })?;
        let guest_cid = std::env::var("CONNECTOR_MICROVM_GUEST_CID_BASE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(52_000)
            .saturating_add((fxhash(&vm_id) % 8_000) as u32);
        let vm_agent_path = std::env::var("CONNECTOR_VM_AGENT_GUEST_PATH")
            .unwrap_or_else(|_| "/sbin/connector-vm-agent".to_string());

        if std::env::consts::OS == "macos" {
            let enforce_resolution =
                microvm_egress_enforce_resolution(egress_enforce, egress_needs_host_enforcement, false, None);
            if enforce_resolution
                .get("status")
                .and_then(|v| v.as_str())
                == Some("error")
            {
                return Err(PluginRuntimeError::Microvm(
                    enforce_resolution
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("microvm egress enforce unavailable")
                        .to_string(),
                ));
            }
            let base = std::env::var("CONNECTOR_MICROVM_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| std::env::temp_dir().join("connector-microvm"));
            std::fs::create_dir_all(&base).map_err(|e| PluginRuntimeError::Microvm(e.to_string()))?;
            let vsock_path = base.join(format!("{}.vsock", vm_id));
            let port = crate::microvm_vsock_agent::agent_vsock_port();
            let listen_path = crate::microvm_vsock_agent::guest_listen_uds_path(&vsock_path, port);
            let mut boot_args =
                build_boot_args(&vsock_path, &vm_agent_path, &req.plugin_id, &vm_id, &req.args);
            if membrane {
                append_membrane_boot_args(&mut boot_args);
            }
            return spawn_via_macos_sidecar(
                &vm_id,
                &kernel_path,
                &rootfs_path,
                &vsock_path,
                &boot_args,
                &req.plugin_id,
                &listen_path,
                port,
                egress_mode,
                &validated_egress,
                enforce_resolution,
            );
        }

        if std::env::consts::OS == "windows" {
            return spawn_windows_wsl2(
                &vm_id,
                &kernel_path,
                &rootfs_path,
                guest_cid,
                &vm_agent_path,
                &req,
                &egress_mode,
                &validated_egress,
                egress_enforce,
                egress_needs_host_enforcement,
            )
            .await;
        }

        let base = std::env::var("CONNECTOR_MICROVM_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("connector-microvm"));
        std::fs::create_dir_all(&base).map_err(|e| PluginRuntimeError::Microvm(e.to_string()))?;
        let api_socket = base.join(format!("{}.sock", vm_id));
        let log_path = base.join(format!("{}.log", vm_id));
        let metrics_path = base.join(format!("{}.metrics.fifo", vm_id));
        let vsock_path = base.join(format!("{}.vsock", vm_id));
        let port = crate::microvm_vsock_agent::agent_vsock_port();
        let listen_path = crate::microvm_vsock_agent::guest_listen_uds_path(&vsock_path, port);
        #[cfg(target_os = "linux")]
        let (vsock_first_tx, vsock_first_rx) = mpsc::channel::<String>();
        #[cfg(target_os = "linux")]
        {
            let tier_path = std::env::var("CONNECTOR_MICROVM_TIER_STATE_FILE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from);
            let tier_on = crate::microvm_vsock_agent::tier_signal_replies_enabled();
            let expected_ticket = req
                .env
                .iter()
                .find(|(k, _)| k == "CONNECTOR_VSOCK_TICKET")
                .map(|(_, v)| v.clone());
            let require_ticket = req
                .env
                .iter()
                .any(|(k, v)| {
                    k == "CONNECTOR_VSOCK_TICKET_REQUIRE"
                        && matches!(
                            v.trim().to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        )
                })
                || std::env::var("CONNECTOR_VSOCK_TICKET_REQUIRE")
                    .map(|v| {
                        matches!(
                            v.trim().to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        )
                    })
                    .unwrap_or(false);
            crate::microvm_vsock_agent::spawn_guest_initiated_vsock_listener(
                listen_path.clone(),
                req.plugin_id.clone(),
                tier_path,
                tier_on,
                vsock_first_tx,
                expected_ticket,
                require_ticket,
            )?;
        }
        let mut boot_args =
            build_boot_args(&vsock_path, &vm_agent_path, &req.plugin_id, &vm_id, &req.args);
        if membrane {
            append_membrane_boot_args(&mut boot_args);
        }
        // Isolation membrane: never attach TAP — vsock-only to Connector.
        let mut network_iface: Option<NetworkIfaceConfig> = None;
        let mut microvm_egress_enforce_detail = serde_json::Value::Null;

        #[cfg(target_os = "linux")]
        if !membrane
            && crate::microvm_egress_linux::microvm_egress_enforce_iptables_requested()
            && !req.egress_allowlist.is_empty()
            && egress_mode != "deny_all"
        {
            let (iface, ip_arg, detail) = crate::microvm_egress_linux::apply_microvm_tap_egress_linux(
                &vm_id,
                &req.egress_allowlist,
            )
            .await?;
            network_iface = Some(iface);
            boot_args.push(ip_arg);
            if let Some(extra) = detail.get("extra_boot_args").and_then(|v| v.as_array()) {
                for e in extra {
                    if let Some(s) = e.as_str() {
                        if !s.is_empty() {
                            boot_args.push(s.to_string());
                        }
                    }
                }
            }
            microvm_egress_enforce_detail = detail;
        }

        let network_iface_attached = network_iface.is_some();
        let cfg = FirecrackerVmConfig {
            vm_id: vm_id.clone(),
            api_socket_path: api_socket.to_string_lossy().to_string(),
            log_path: log_path.to_string_lossy().to_string(),
            machine_config: GuestMachineConfig {
                vcpu_count: 1,
                mem_mib: 256,
                smt: false,
                track_dirty_pages: false,
            },
            boot_source: BootSource {
                kernel_image_path: kernel_path.clone(),
                boot_args: Some(boot_args.join(" ")),
                initrd_path: None,
            },
            drives: vec![Drive {
                drive_id: "rootfs".to_string(),
                path_on_host: rootfs_path.clone(),
                is_root_device: true,
                is_read_only: false,
            }],
            network_iface,
            vsock: Some(VsockConfig {
                guest_cid,
                uds_path: vsock_path.to_string_lossy().to_string(),
            }),
            metrics_path: Some(metrics_path.to_string_lossy().to_string()),
        };
        let slot = self
            .host
            .ensure_slot(&cfg.vm_id)
            .map_err(|e| PluginRuntimeError::Microvm(e.to_string()))?;
        let plan = self
            .host
            .start(&cfg)
            .map_err(|e| PluginRuntimeError::Microvm(e.to_string()))?;
        #[cfg(target_os = "linux")]
        let probe = vsock_agent_probe_json(&listen_path, port, Some(vsock_first_rx));
        #[cfg(not(target_os = "linux"))]
        let probe = vsock_agent_probe_json(&listen_path, port, None);
        if crate::microvm_require_heartbeat()
            && probe.get("status").and_then(|v| v.as_str()) != Some("heartbeat_received")
        {
            if let Some(pid) = plan.get("pid").and_then(|v| v.as_u64()) {
                #[cfg(unix)]
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                #[cfg(not(unix))]
                let _ = pid;
            }
            return Err(PluginRuntimeError::Microvm(
                "microvm_heartbeat_required — guest vsock agent did not heartbeat; kernel/rootfs assets are not claimed live".into(),
            ));
        }
        let mut microvm_egress_cleanup_watcher = serde_json::Value::Null;
        #[cfg(target_os = "linux")]
        if !microvm_egress_enforce_detail.is_null() {
            microvm_egress_cleanup_watcher = if let Some(pid) = plan
                .get("pid")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok())
            {
                crate::microvm_egress_linux::start_microvm_egress_cleanup_watcher(
                    pid,
                    &microvm_egress_enforce_detail,
                )
            } else {
                json!({
                    "status": "skipped",
                    "reason": "missing_plan_pid"
                })
            };
        }
        Ok(SpawnReceipt {
            backend: "microvm".into(),
            plugin_id: req.plugin_id,
            detail: json!({
                "phase": "5.3_live",
                "microvm_egress_mode": egress_mode,
                "microvm_egress_allowlist_normalized": validated_egress,
                "microvm_egress_enforce": microvm_egress_enforce_detail,
                "microvm_egress_cleanup_watcher": microvm_egress_cleanup_watcher,
                "slot": slot,
                "plan": plan,
                "kernel_path": kernel_path,
                "rootfs_path": rootfs_path,
                "vm_agent_path": vm_agent_path,
                "vsock_path": vsock_path,
                "vsock_probe": probe,
                "egress_allowlist_len": req.egress_allowlist.len(),
                "tier_idle_suspend_policy_ms_for_guest": tier_idle_suspend_policy_ms_for_guest(),
                "isolation_membrane": crate::isolation_membrane::membrane_status(&req.env),
                "network_iface_attached": network_iface_attached,
                "note": if membrane {
                    "isolation membrane: vsock-only microVM; no TAP/guest TCP; effects via Connector broker only"
                } else if microvm_egress_enforce_detail.is_null() {
                    "microVM spawned; set CONNECTOR_MICROVM_EGRESS_ENFORCE=iptables on Linux for TAP+FORWARD allowlist (Phase 5.7.2)."
                } else {
                    "microVM spawned with host iptables FORWARD allowlist + NAT; guest needs kernel ip= bootarg support; cleanup watcher is armed for VM pid exit."
                }
            }),
        })
    }
}

/// Phase **5.4.3** — when **`CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS`** > 0, propagate policy into the guest
/// cmdline (`connector.plugin_idle_suspend_after_ms=…`) for **`connector-vm-agent`** / future suspend hooks.
fn tier_idle_suspend_policy_ms_for_guest() -> Option<u64> {
    let v = std::env::var("CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS").ok()?;
    let ms = v.trim().parse::<u64>().ok()?;
    (ms > 0).then_some(ms)
}

fn append_membrane_boot_args(boot_args: &mut Vec<String>) {
    boot_args.push("connector.llm_distrust=1".into());
    boot_args.push("connector.broker_only=1".into());
    boot_args.push("connector.zt_handshake=1".into());
    boot_args.push("connector.effect_exclusivity=1".into());
    boot_args.push("connector.guest_egress=deny_all".into());
}

fn build_boot_args(
    vsock_path: &Path,
    vm_agent_path: &str,
    plugin_id: &str,
    vm_id: &str,
    args: &[String],
) -> Vec<String> {
    let membrane = crate::isolation_membrane::membrane_enforced(&[]);
    let mut boot_args = vec![
        "console=ttyS0".to_string(),
        "reboot=k".to_string(),
        "panic=1".to_string(),
        format!("connector.vm_agent={}", vm_agent_path),
        format!("connector.plugin_id={}", plugin_id),
        format!("connector.vsock_path={}", vsock_path.display()),
    ];
    if !args.is_empty() {
        boot_args.push(format!("connector.plugin_args={}", args.join(",")));
    }
    if let Ok(v) = std::env::var("CONNECTOR_CONDO_GUEST_HEARTBEAT_URL") {
        let v = v.trim();
        if !v.is_empty() {
            boot_args.push(format!("connector.condo_heartbeat_url={}", v));
        }
    } else if let Ok(v) = std::env::var("CONNECTOR_API_URL") {
        let v = v.trim();
        if !v.is_empty() {
            boot_args.push(format!(
                "connector.condo_heartbeat_url={}/api/v1/kernel/plugin-condos/guest-heartbeat",
                v.trim_end_matches('/')
            ));
        }
    }
    // Never put API keys / tokens on the guest cmdline under isolation membrane.
    if !membrane {
        if let Ok(v) = std::env::var("CONNECTOR_CONDO_GUEST_HEARTBEAT_TOKEN") {
            let v = v.trim();
            if !v.is_empty() {
                boot_args.push(format!("connector.condo_heartbeat_token={}", v));
            }
        } else if let Ok(v) = std::env::var("CONNECTOR_API_KEY") {
            let v = v.trim();
            if !v.is_empty() {
                boot_args.push(format!("connector.condo_heartbeat_token={}", v));
            }
        }
    }
    if let Ok(v) = std::env::var("CONNECTOR_CONDO_ID") {
        let v = v.trim();
        if !v.is_empty() {
            boot_args.push(format!("connector.condo_id={}", v));
        }
    }
    if let Ok(v) = std::env::var("CONNECTOR_CONDO_GUEST_ID") {
        let v = v.trim();
        if !v.is_empty() {
            boot_args.push(format!("connector.condo_guest_id={}", v));
        }
    }
    if let Ok(v) = std::env::var("CONNECTOR_CONDO_TARGET_POOL") {
        let v = v.trim();
        if !v.is_empty() {
            boot_args.push(format!("connector.condo_target_pool={}", v));
        }
    }
    if let Some(ms) = tier_idle_suspend_policy_ms_for_guest() {
        boot_args.push(format!("connector.plugin_idle_suspend_after_ms={ms}"));
    }
    let port = crate::microvm_vsock_agent::agent_vsock_port();
    boot_args.push(format!("connector.vsock_agent_port={port}"));
    boot_args.push(format!("connector.vm_id={}", vm_id));
    boot_args
}

/// After Firecracker **`InstanceStart`**, optionally wait for the first guest heartbeat on the
/// guest-initiated listen path `{uds_path}_{port}` (Linux only — host thread is spawned before `start()`).
fn vsock_agent_probe_json(
    listen_path: &Path,
    port: u32,
    first_rx: Option<mpsc::Receiver<String>>,
) -> serde_json::Value {
    let first = first_rx
        .and_then(|rx| rx.recv_timeout(Duration::from_secs(5)).ok())
        .unwrap_or_default();
    json!({
        "listener_path": listen_path,
        "agent_vsock_listen_suffix": format!("_{port}"),
        "agent_vsock_port": port,
        "first_heartbeat_sample": if first.is_empty() {
            serde_json::Value::Null
        } else {
            json!(first)
        },
        "status": if first.is_empty() {
            "waiting_for_guest_agent"
        } else {
            "heartbeat_received"
        },
        "tier_signal_replies": crate::microvm_vsock_agent::tier_signal_replies_enabled(),
    })
}

fn spawn_via_macos_sidecar(
    vm_id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    vsock_path: &std::path::Path,
    boot_args: &[String],
    plugin_id: &str,
    listen_path: &Path,
    port: u32,
    egress_mode: &str,
    validated_egress: &serde_json::Value,
    egress_enforce_resolution: serde_json::Value,
) -> Result<SpawnReceipt, PluginRuntimeError> {
    let sidecar = std::env::var("CONNECTOR_MACOS_VZ_SIDECAR")
        .ok()
        .or_else(|| option_env!("CONNECTOR_VENDORED_FIRECRACKER_PATH").map(|s| s.to_string()))
        .ok_or_else(|| PluginRuntimeError::Microvm("missing CONNECTOR_MACOS_VZ_SIDECAR".into()))?;
    let payload = json!({
        "vm_id": vm_id,
        "kernel_path": kernel_path,
        "rootfs_path": rootfs_path,
        "vsock_path": vsock_path,
        "boot_args": boot_args,
    });
    let out = std::process::Command::new(&sidecar)
        .arg("--json")
        .arg(payload.to_string())
        .output()
        .map_err(|e| PluginRuntimeError::Microvm(format!("spawn macOS sidecar: {}", e)))?;
    if !out.status.success() {
        return Err(PluginRuntimeError::Microvm(format!(
            "macOS sidecar failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let detail: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| json!({"ok": true, "raw": String::from_utf8_lossy(&out.stdout)}));
    let probe = vsock_agent_probe_json(listen_path, port, None);
    if crate::microvm_require_heartbeat()
        && probe.get("status").and_then(|v| v.as_str()) != Some("heartbeat_received")
    {
        return Err(PluginRuntimeError::Microvm(
            "microvm_heartbeat_required — guest vsock agent did not heartbeat; kernel/rootfs assets are not claimed live".into(),
        ));
    }
    Ok(SpawnReceipt {
        backend: "microvm".into(),
        plugin_id: plugin_id.to_string(),
        detail: json!({
            "phase": "5.3_live_macos",
            "provider": "virtualization_framework_sidecar",
            "microvm_egress_mode": egress_mode,
            "microvm_egress_allowlist_normalized": validated_egress,
            "microvm_egress_enforce": egress_enforce_resolution,
            "tier_idle_suspend_policy_ms_for_guest": tier_idle_suspend_policy_ms_for_guest(),
            "detail": detail,
            "vsock_probe": probe,
        }),
    })
}

async fn spawn_windows_wsl2(
    vm_id: &str,
    kernel_path: &str,
    rootfs_path: &str,
    guest_cid: u32,
    vm_agent_path: &str,
    req: &SpawnRequest,
    egress_mode: &str,
    validated_egress: &serde_json::Value,
    egress_enforce: &str,
    egress_needs_host_enforcement: bool,
) -> Result<SpawnReceipt, PluginRuntimeError> {
    let distro = std::env::var("CONNECTOR_WSL_DISTRO").unwrap_or_else(|_| "Ubuntu".to_string());
    let distro = distro.trim();
    if distro.is_empty() {
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "invalid_distro".into(),
            detail: "CONNECTOR_WSL_DISTRO is empty".into(),
        });
    }

    let mut wsl_ipt_capable = false;
    if egress_enforce == "iptables"
        && egress_needs_host_enforcement
        && egress_mode != "deny_all"
        && !req.egress_allowlist.is_empty()
    {
        let tcp = crate::docker_egress::resolve_allowlist_tcp_dests(&req.egress_allowlist)
            .await
            .map_err(|e| PluginRuntimeError::MicrovmWsl {
                code: "egress_dns".into(),
                detail: e.to_string(),
            })?;
        let needs_v6 = tcp.iter().any(|(a, _)| matches!(a, std::net::IpAddr::V6(_)));
        wsl_ipt_capable = crate::microvm_egress_wsl::wsl_distro_supports_iptables_enforce(distro, needs_v6);
    }

    let enforce_resolution = microvm_egress_enforce_resolution(
        egress_enforce,
        egress_needs_host_enforcement,
        wsl_ipt_capable,
        if wsl_ipt_capable {
            Some("wsl2_distro_iptables")
        } else {
            None
        },
    );
    if enforce_resolution
        .get("status")
        .and_then(|v| v.as_str())
        == Some("error")
    {
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "egress_enforce_unavailable".into(),
            detail: enforce_resolution
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("egress enforce unavailable on windows/wsl path")
                .to_string(),
        });
    }

    let wsl_root = std::env::var("CONNECTOR_MICROVM_WSL_STATE_DIR")
        .unwrap_or_else(|_| "/tmp/connector-microvm".to_string());
    let wsl_root = wsl_root.trim_end_matches('/').to_string();

    wsl_mkdir_p(distro, &wsl_root)?;

    let api_socket = format!("{}/{}.sock", wsl_root, vm_id);
    let log_path = format!("{}/{}.log", wsl_root, vm_id);
    let metrics_path = format!("{}/{}.metrics.fifo", wsl_root, vm_id);
    let vsock_s = format!("{}/{}.vsock", wsl_root, vm_id);
    let vsock_pb = PathBuf::from(&vsock_s);
    let port = crate::microvm_vsock_agent::agent_vsock_port();
    let listen_path = crate::microvm_vsock_agent::guest_listen_uds_path(&vsock_pb, port);
    let probe = vsock_agent_probe_json(&listen_path, port, None);
    let mut boot_args = build_boot_args(&vsock_pb, vm_agent_path, &req.plugin_id, vm_id, &req.args);
    if crate::isolation_membrane::membrane_enforced(&req.env) {
        append_membrane_boot_args(&mut boot_args);
    }
    let mut network_iface: Option<NetworkIfaceConfig> = None;
    let mut microvm_egress_enforce_detail = serde_json::Value::Null;
    let mut egress_script_host: Option<PathBuf> = None;

    if egress_enforce == "iptables"
        && egress_needs_host_enforcement
        && wsl_ipt_capable
        && egress_mode != "deny_all"
        && !req.egress_allowlist.is_empty()
    {
        let script_host = crate::microvm_egress_wsl::materialize_wsl_egress_apply_script()?;
        let (iface, ip_arg, detail) = crate::microvm_egress_wsl::apply_wsl_microvm_tap_egress(
            distro,
            vm_id,
            &req.egress_allowlist,
            &script_host,
            |d, p| win_path_to_wsl(d, p),
        )
        .await?;
        network_iface = Some(iface);
        boot_args.push(ip_arg);
        if let Some(extra) = detail.get("extra_boot_args").and_then(|v| v.as_array()) {
            for e in extra {
                if let Some(s) = e.as_str() {
                    if !s.is_empty() {
                        boot_args.push(s.to_string());
                    }
                }
            }
        }
        microvm_egress_enforce_detail = detail;
        egress_script_host = Some(script_host);
    }

    let fc_host = std::env::var("CONNECTOR_FIRECRACKER_BIN")
        .ok()
        .or_else(|| option_env!("CONNECTOR_VENDORED_FIRECRACKER_PATH").map(|s| s.to_string()))
        .ok_or_else(|| {
            PluginRuntimeError::MicrovmWsl {
                code: "firecracker_bin_unset".into(),
                detail: "set CONNECTOR_FIRECRACKER_BIN to a path your WSL distro can execute".into(),
            }
        })?;

    let kernel_wsl = maybe_translate_host_path_for_wsl(distro, kernel_path)?;
    let rootfs_wsl = maybe_translate_host_path_for_wsl(distro, rootfs_path)?;
    let fc_wsl = maybe_translate_host_path_for_wsl(distro, &fc_host)?;

    let cfg = FirecrackerVmConfig {
        vm_id: vm_id.to_string(),
        api_socket_path: api_socket,
        log_path,
        machine_config: GuestMachineConfig {
            vcpu_count: 1,
            mem_mib: 256,
            smt: false,
            track_dirty_pages: false,
        },
        boot_source: BootSource {
            kernel_image_path: kernel_wsl.clone(),
            boot_args: Some(boot_args.join(" ")),
            initrd_path: None,
        },
        drives: vec![Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: rootfs_wsl.clone(),
            is_root_device: true,
            is_read_only: false,
        }],
        network_iface,
        vsock: Some(VsockConfig {
            guest_cid,
            uds_path: vsock_s.clone(),
        }),
        metrics_path: Some(metrics_path.clone()),
    };

    let mut cfg_val = serde_json::to_value(&cfg).map_err(|e| PluginRuntimeError::MicrovmWsl {
        code: "config_serialize".into(),
        detail: e.to_string(),
    })?;
    if let Some(obj) = cfg_val.as_object_mut() {
        obj.insert("firecracker_bin".into(), json!(fc_wsl.clone()));
    }

    let host_tmp = std::env::temp_dir();
    let cfg_file = host_tmp.join(format!("connector-microvm-{}-cfg.json", vm_id));
    std::fs::write(&cfg_file, serde_json::to_vec_pretty(&cfg_val).map_err(|e| PluginRuntimeError::MicrovmWsl {
        code: "config_write".into(),
        detail: e.to_string(),
    })?)
    .map_err(|e| PluginRuntimeError::MicrovmWsl {
        code: "config_write".into(),
        detail: e.to_string(),
    })?;

    let launcher_path = materialize_wsl_launcher_script()?;
    let cfg_wsl = win_path_to_wsl(distro, &cfg_file)?;
    let launcher_wsl = resolve_wsl_launcher_path(distro, &launcher_path)?;

    let py = std::env::var("CONNECTOR_WSL_PYTHON").unwrap_or_else(|_| "python3".into());

    let output = std::process::Command::new("wsl.exe")
        .arg("-d")
        .arg(distro)
        .arg("--")
        .arg(&py)
        .arg(&launcher_wsl)
        .arg(&cfg_wsl)
        .output()
        .map_err(|e| PluginRuntimeError::MicrovmWsl {
            code: "wsl_exec".into(),
            detail: format!("wsl.exe spawn failed: {e}"),
        })?;

    let receipt = parse_wsl_launcher_json(&output.stdout);
    if !output.status.success() || receipt.get("ok") == Some(&json!(false)) {
        if receipt.get("ok") == Some(&json!(false)) {
            return Err(wsl_receipt_error(&receipt));
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let hint = if stderr.contains("There is no distribution") || stderr.contains("WSL_E_DISTRO_NOT_FOUND") {
            " (is CONNECTOR_WSL_DISTRO installed?)"
        } else if stderr.contains("WSL") && stderr.contains("not recognized") {
            " (is WSL installed?)"
        } else {
            ""
        };
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "wsl_process_failed".into(),
            detail: format!(
                "status={:?} stderr={}{} stdout={}",
                output.status.code(),
                stderr,
                hint,
                String::from_utf8_lossy(&output.stdout)
            ),
        });
    }

    let mut microvm_egress_cleanup_watcher = serde_json::Value::Null;
    let mut enforce_out = enforce_resolution.clone();
    if !microvm_egress_enforce_detail.is_null() {
        if let Some(obj) = enforce_out.as_object_mut() {
            obj.insert(
                "iptables_forward_detail".into(),
                microvm_egress_enforce_detail.clone(),
            );
        }
        if let (Some(pid), Some(script_host)) = (
            receipt
                .get("pid")
                .and_then(|v| v.as_u64())
                .and_then(|n| u32::try_from(n).ok()),
            egress_script_host.as_ref(),
        ) {
            let watch_path = host_tmp.join(format!("connector-wsl-egress-watch-{vm_id}.json"));
            let _ = std::fs::write(
                &watch_path,
                serde_json::to_vec(&microvm_egress_enforce_detail).unwrap_or_default(),
            );
            if let (Ok(detail_wsl), Ok(script_wsl)) = (
                win_path_to_wsl(distro, &watch_path),
                win_path_to_wsl(distro, script_host),
            ) {
                crate::microvm_egress_wsl::spawn_wsl_egress_cleanup_watcher(
                    distro,
                    &py,
                    &script_wsl,
                    &detail_wsl,
                    pid,
                );
                microvm_egress_cleanup_watcher = json!({
                    "status": "armed",
                    "mode": "wsl_pid_exit",
                    "watched_pid": pid,
                });
            }
        }
    }

    Ok(SpawnReceipt {
        backend: "microvm".into(),
        plugin_id: req.plugin_id.clone(),
        detail: json!({
            "phase": "5.3_live_windows_wsl2",
            "provider": "wsl2_firecracker_bridge",
            "microvm_egress_mode": egress_mode,
            "microvm_egress_allowlist_normalized": validated_egress,
            "microvm_egress_enforce": enforce_out,
            "microvm_egress_cleanup_watcher": microvm_egress_cleanup_watcher,
            "wsl_distro": distro,
            "kernel_path_host": kernel_path,
            "rootfs_path_host": rootfs_path,
            "kernel_path_wsl": kernel_wsl,
            "rootfs_path_wsl": rootfs_wsl,
            "firecracker_bin_wsl": fc_wsl,
            "wsl_state_dir": wsl_root,
            "vsock_path_wsl": vsock_s,
            "vsock_probe": probe,
            "launcher_receipt": receipt,
            "egress_allowlist_len": req.egress_allowlist.len(),
            "tier_idle_suspend_policy_ms_for_guest": tier_idle_suspend_policy_ms_for_guest(),
        }),
    })
}

fn materialize_wsl_launcher_script() -> Result<PathBuf, PluginRuntimeError> {
    if let Ok(p) = std::env::var("CONNECTOR_WSL_LAUNCHER") {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return Ok(pb);
        }
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "launcher_missing".into(),
            detail: format!("CONNECTOR_WSL_LAUNCHER is not a file: {}", pb.display()),
        });
    }
    let path = std::env::temp_dir().join("connector-microvm-wsl-launch.py");
    std::fs::write(&path, WSL_LAUNCHER_PY.as_bytes()).map_err(|e| PluginRuntimeError::MicrovmWsl {
        code: "launcher_materialize".into(),
        detail: e.to_string(),
    })?;
    Ok(path)
}

fn resolve_wsl_launcher_path(distro: &str, host_path: &Path) -> Result<String, PluginRuntimeError> {
    win_path_to_wsl(distro, host_path)
}

#[cfg(windows)]
fn win_path_to_wsl(distro: &str, win: &Path) -> Result<String, PluginRuntimeError> {
    let win_s = win.to_string_lossy();
    let out = std::process::Command::new("wsl.exe")
        .args([ "-d", distro, "wslpath", "-u", win_s.trim_matches('"') ])
        .output()
        .map_err(|e| PluginRuntimeError::MicrovmWsl {
            code: "wslpath_exec".into(),
            detail: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "wslpath_failed".into(),
            detail: format!(
                "wslpath -u {}: {}",
                win.display(),
                String::from_utf8_lossy(&out.stderr)
            ),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(not(windows))]
fn win_path_to_wsl(_distro: &str, win: &Path) -> Result<String, PluginRuntimeError> {
    Ok(win.to_string_lossy().into_owned())
}

fn maybe_translate_host_path_for_wsl(distro: &str, path: &str) -> Result<String, PluginRuntimeError> {
    let t = path.trim();
    if t.is_empty() {
        return Ok(t.to_string());
    }
    if t.starts_with('/') && !t.starts_with("//") {
        return Ok(t.to_string());
    }
    win_path_to_wsl(distro, Path::new(t))
}

fn wsl_mkdir_p(distro: &str, wsl_dir: &str) -> Result<(), PluginRuntimeError> {
    let out = std::process::Command::new("wsl.exe")
        .args(["-d", distro, "--", "mkdir", "-p", wsl_dir])
        .output()
        .map_err(|e| PluginRuntimeError::MicrovmWsl {
            code: "wsl_mkdir_exec".into(),
            detail: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(PluginRuntimeError::MicrovmWsl {
            code: "wsl_mkdir_failed".into(),
            detail: format!(
                "mkdir -p {}: {}",
                wsl_dir,
                String::from_utf8_lossy(&out.stderr)
            ),
        });
    }
    Ok(())
}

fn parse_wsl_launcher_json(stdout: &[u8]) -> serde_json::Value {
    for raw in stdout.split(|b| *b == b'\n').rev() {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            return v;
        }
    }
    json!({})
}

fn wsl_receipt_error(v: &serde_json::Value) -> PluginRuntimeError {
    let code = v
        .get("code")
        .and_then(|c| c.as_str())
        .unwrap_or("launcher_failed")
        .to_string();
    let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let detail = v.get("detail").cloned().unwrap_or(json!({}));
    let detail_str = if detail.is_null() || detail.as_object().map(|o| o.is_empty()).unwrap_or(false) {
        msg
    } else {
        format!("{} | {}", msg, detail)
    };
    PluginRuntimeError::MicrovmWsl { code, detail: detail_str }
}

pub(crate) fn fxhash(s: &str) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn microvm_egress_mode() -> &'static str {
    let raw = std::env::var("CONNECTOR_MICROVM_EGRESS_MODE").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || matches!(v.as_str(), "deny_all" | "deny-all" | "none" | "off") {
        "deny_all"
    } else if matches!(
        v.as_str(),
        "allowlist_strict" | "allowlist-strict" | "manifest_strict"
    ) {
        "allowlist_strict"
    } else {
        "custom"
    }
}

fn microvm_egress_enforce_mode() -> &'static str {
    let raw = std::env::var("CONNECTOR_MICROVM_EGRESS_ENFORCE").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || matches!(v.as_str(), "off" | "none" | "disabled") {
        "none"
    } else if matches!(v.as_str(), "iptables" | "iptables_forward" | "forward_iptables") {
        "iptables"
    } else {
        "custom"
    }
}

fn microvm_egress_enforce_required() -> bool {
    let raw = std::env::var("CONNECTOR_MICROVM_EGRESS_ENFORCE_REQUIRED").unwrap_or_default();
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn microvm_egress_enforce_resolution(
    enforce_mode: &str,
    needs_host_enforcement: bool,
    host_supports_iptables: bool,
    provider_when_active: Option<&str>,
) -> serde_json::Value {
    if enforce_mode == "none" || !needs_host_enforcement {
        return json!({
            "requested": enforce_mode,
            "required": microvm_egress_enforce_required(),
            "status": "not_requested",
        });
    }
    if enforce_mode == "iptables" && host_supports_iptables {
        return json!({
            "requested": enforce_mode,
            "required": microvm_egress_enforce_required(),
            "status": "active",
            "provider": provider_when_active.unwrap_or("linux_host_iptables"),
        });
    }
    let required = microvm_egress_enforce_required();
    json!({
        "requested": enforce_mode,
        "required": required,
        "status": if required { "error" } else { "degraded" },
        "reason": "CONNECTOR_MICROVM_EGRESS_ENFORCE is requested but this host path does not provide iptables enforcement (Linux host or WSL2 distro with iptables/ip; Phase 5.7.2)",
    })
}

fn parse_outbound_host_port(cap: &str) -> Option<(String, u16)> {
    let rest = cap.strip_prefix("network.outbound:")?;
    if let Some(inner) = rest.strip_prefix('[') {
        let (addr_part, after) = inner.split_once("]:")?;
        let port: u16 = after.parse().ok()?;
        let host = addr_part.trim();
        if host.is_empty() {
            return None;
        }
        return Some((host.to_string(), port));
    }
    let (host, port_s) = rest.rsplit_once(':')?;
    let port: u16 = port_s.parse().ok()?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn validate_microvm_egress_policy(
    mode: &str,
    allowlist: &[String],
) -> Result<serde_json::Value, PluginRuntimeError> {
    let mut normalized: Vec<String> = Vec::new();
    for cap in allowlist {
        let Some((host, port)) = parse_outbound_host_port(cap) else {
            return Err(PluginRuntimeError::Microvm(format!(
                "invalid network.outbound capability for microvm: {}",
                cap
            )));
        };
        if host.contains('*') {
            return Err(PluginRuntimeError::Microvm(format!(
                "wildcards are rejected in microvm network.outbound allowlist: {}",
                cap
            )));
        }
        normalized.push(format!("{host}:{port}"));
    }
    normalized.sort();
    normalized.dedup();

    match mode {
        "deny_all" => {
            if !normalized.is_empty() {
                return Err(PluginRuntimeError::Microvm(format!(
                    "microvm egress denied: {} outbound destinations requested but CONNECTOR_MICROVM_EGRESS_MODE=deny_all",
                    normalized.len()
                )));
            }
        }
        "allowlist_strict" => {
            if normalized.is_empty() {
                return Err(PluginRuntimeError::Microvm(
                    "microvm allowlist_strict requires at least one network.outbound destination"
                        .into(),
                ));
            }
        }
        _ => {}
    }
    Ok(json!(normalized))
}
