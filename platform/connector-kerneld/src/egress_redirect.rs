//! T2 — Transparent egress kernel redirect (eBPF connect4 + nft REDIRECT).
//!
//! Loads `connector_connect_redirect.bpf.o` and/or applies nftables
//! `redirect to :port` so agent dials hit the Connector egress proxy hop.

use anyhow::{anyhow, Context, Result};
use serde_json::json;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_PIN_ROOT: &str = "/sys/fs/bpf/connector";
const PROG_NAME: &str = "connector_connect_redirect";

fn pin_root() -> PathBuf {
    std::env::var("CONNECTOR_EBPF_PIN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_PIN_ROOT))
}

fn redirect_object() -> PathBuf {
    if let Ok(p) = std::env::var("CONNECTOR_EBPF_CONNECT_OBJ") {
        return PathBuf::from(p);
    }
    let candidates = [
        PathBuf::from("platform/ebpf/connector_connect_redirect.bpf.o"),
        PathBuf::from("/usr/lib/connector/ebpf/connector_connect_redirect.bpf.o"),
    ];
    for c in candidates {
        if c.is_file() {
            return c;
        }
    }
    PathBuf::from("platform/ebpf/connector_connect_redirect.bpf.o")
}

fn bpftool() -> Result<&'static str> {
    for bin in ["bpftool", "/usr/sbin/bpftool", "/usr/bin/bpftool"] {
        if Command::new(bin)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Ok(bin);
        }
    }
    Err(anyhow!("bpftool not found"))
}

fn run(bin: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("exec {bin} {:?}", args))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{bin} {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn agent_redirect_dir(agent_pid: &str) -> PathBuf {
    pin_root().join(sanitize(agent_pid)).join("connect_redirect")
}

pub fn probe_redirect_loaded(agent_pid: &str) -> bool {
    let d = agent_redirect_dir(agent_pid);
    d.join("prog").exists() || d.join(PROG_NAME).exists()
}

fn proxy_listen() -> (Ipv4Addr, u16) {
    let host = std::env::var("CONNECTOR_EGRESS_PROXY_IP").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("CONNECTOR_EGRESS_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(19090);
    let ip: Ipv4Addr = host.parse().unwrap_or(Ipv4Addr::LOCALHOST);
    (ip, port)
}

/// Load connect4 redirect program, pin, set proxy_cfg map, optionally attach.
pub fn load_connect_redirect(agent_pid: &str, cgroup_path: Option<&str>) -> Result<serde_json::Value> {
    let bin = bpftool()?;
    let obj = redirect_object();
    if !obj.is_file() {
        return Err(anyhow!(
            "connect redirect object missing at {} — make -C platform/ebpf",
            obj.display()
        ));
    }
    let pin_dir = agent_redirect_dir(agent_pid);
    fs::create_dir_all(&pin_dir)?;
    let prog_pin = pin_dir.join("prog");
    let _ = fs::remove_file(&prog_pin);

    run(
        bin,
        &[
            "prog",
            "load",
            obj.to_str().unwrap(),
            prog_pin.to_str().unwrap(),
            "type",
            "cgroup/sock_addr",
            "pinmaps",
            pin_dir.to_str().unwrap(),
        ],
    )
    .or_else(|_| {
        // Older bpftool: type cgroup/connect4
        run(
            bin,
            &[
                "prog",
                "load",
                obj.to_str().unwrap(),
                prog_pin.to_str().unwrap(),
                "type",
                "cgroup/connect4",
                "pinmaps",
                pin_dir.to_str().unwrap(),
            ],
        )
    })
    .context("bpftool prog load connect_redirect")?;

    let (ip, port) = proxy_listen();
    let ip_u32 = u32::from(ip);
    let map_candidates = [
        pin_dir.join("proxy_cfg"),
        pin_dir.join("maps").join("proxy_cfg"),
    ];
    let mut map_updated = false;
    for map_pin in &map_candidates {
        if !map_pin.exists() {
            continue;
        }
        for (key, val) in [(0u32, 1u32), (1u32, ip_u32), (2u32, port as u32)] {
            if update_map_u32(bin, map_pin, key, val).is_ok() {
                map_updated = true;
            }
        }
        break;
    }

    let mut attached = false;
    let mut attach_detail = "skipped_no_cgroup".to_string();
    if let Some(cg) = cgroup_path.map(str::trim).filter(|s| !s.is_empty()) {
        for attach_type in ["connect4", "sock_addr"] {
            match run(
                bin,
                &[
                    "cgroup",
                    "attach",
                    cg,
                    attach_type,
                    "pinned",
                    prog_pin.to_str().unwrap(),
                ],
            ) {
                Ok(_) => {
                    attached = true;
                    attach_detail = format!("attached_{attach_type}:{cg}");
                    break;
                }
                Err(e) => attach_detail = format!("attach_try_{attach_type}:{e:#}"),
            }
        }
    }

    Ok(json!({
        "ok": true,
        "schema": "connector.kerneld.egress_redirect.v1",
        "mechanism": "cgroup_connect4_rewrite",
        "ebpf_redirect_loaded": probe_redirect_loaded(agent_pid),
        "prog_pin": prog_pin.display().to_string(),
        "proxy_ip": ip.to_string(),
        "proxy_port": port,
        "map_updated": map_updated,
        "attached": attached,
        "attach_detail": attach_detail,
        "agent_pid": agent_pid,
        "honesty": "Kernel rewrites connect() to Connector egress proxy — TLS terminate still at proxy hop",
    }))
}

fn update_map_u32(bin: &str, map_pin: &Path, key: u32, val: u32) -> Result<()> {
    let key_bytes = key.to_ne_bytes();
    let val_bytes = val.to_ne_bytes();
    let mut args: Vec<String> = vec![
        "map".into(),
        "update".into(),
        "pinned".into(),
        map_pin.display().to_string(),
        "key".into(),
        "hex".into(),
    ];
    for b in key_bytes {
        args.push(format!("{b:02x}"));
    }
    args.push("value".into());
    args.push("hex".into());
    for b in val_bytes {
        args.push(format!("{b:02x}"));
    }
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run(bin, &args_ref)?;
    Ok(())
}

/// nftables transparent redirect fallback (CAP_NET_ADMIN).
pub fn apply_nft_redirect(agent_pid: &str) -> Result<serde_json::Value> {
    let (_, port) = proxy_listen();
    let table = format!("connector_egress_{}", sanitize(agent_pid));
    // Idempotent: delete then add.
    let _ = Command::new("nft").args(["delete", "table", "inet", &table]).output();
    let script = if std::env::var("CONNECTOR_EGRESS_NFT_ALL_TCP")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
    {
        format!(
            "table inet {table} {{\n  chain output {{\n    type nat hook output priority -100; policy accept;\n    meta l4proto tcp tcp dport != {port} redirect to :{port}\n  }}\n}}\n"
        )
    } else {
        format!(
            "table inet {table} {{\n  chain output {{\n    type nat hook output priority -100; policy accept;\n    meta mark & 0xff000000 == 0xcd000000 meta l4proto tcp tcp dport != {port} redirect to :{port}\n  }}\n}}\n"
        )
    };
    let tmp = std::env::temp_dir().join(format!("connector-nft-{}.nft", sanitize(agent_pid)));
    fs::write(&tmp, &script)?;
    let out = Command::new("nft")
        .args(["-f", tmp.to_str().unwrap()])
        .output()
        .context("nft -f")?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft redirect apply failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(json!({
        "ok": true,
        "schema": "connector.kerneld.nft_redirect.v1",
        "mechanism": "nft_output_redirect",
        "table": table,
        "proxy_port": port,
        "agent_pid": agent_pid,
        "honesty": "nft REDIRECT to Connector egress proxy — requires CAP_NET_ADMIN; TLS at proxy",
    }))
}

pub fn status_json(agent_pid: Option<&str>) -> serde_json::Value {
    let (ip, port) = proxy_listen();
    let loaded = agent_pid
        .map(probe_redirect_loaded)
        .unwrap_or(false);
    json!({
        "schema": "connector.kerneld.egress_redirect_status.v1",
        "ebpf_redirect_loaded": loaded,
        "object_path": redirect_object().display().to_string(),
        "object_present": redirect_object().is_file(),
        "proxy_ip": ip.to_string(),
        "proxy_port": port,
        "nft_table_prefix": "connector_egress_",
        "require_env": "CONNECTOR_TRANSPARENT_EGRESS_KERNEL",
        "honesty": "Kernel MITM bar = connect4 rewrite and/or nft REDIRECT to local Connector proxy (not arbitrary TLS terminate)",
    })
}

pub fn require_kernel_redirect() -> bool {
    matches!(
        std::env::var("CONNECTOR_TRANSPARENT_EGRESS_KERNEL")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}
